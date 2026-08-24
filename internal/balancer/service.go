// Package balancer manages the egress default route for general (unmarked)
// traffic across multiple WAN links.
//
// Two modes are supported, selected by the "routing_balance" setting:
//
//   - "failover" (default): the balancer is inactive and the legacy per-table
//     failover service stays in charge. Production behaviour is unchanged.
//
//   - "balance": the balancer owns the default route in the target table and
//     installs a *weighted multipath* route across all online links, e.g.
//
//     ip route replace default table main \
//     nexthop via 192.168.15.1 dev enp5s0 weight 3 onlink \
//     nexthop via 192.168.18.1 dev enp3s0 weight 1 onlink
//
// Applying a new route from the UI is protected by an auto-rollback timer: the
// previous default is captured first and automatically restored unless the
// caller confirms within the arm window. This guarantees that a bad change can
// never permanently cut internet access.
package balancer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

const (
	settingKey      = "routing_balance"
	defaultTable    = "main"
	defaultArmSecs  = 90
	maxKernelWeight = 256 // Linux multipath nexthop weight range is 1..256.

	defaultSustainSamples    = 3   // consecutive degraded checks before eviction
	defaultEvictCooldownSecs = 120 // min gap between evictions per link
)

// ModeFailover keeps the balancer inactive (legacy behaviour).
const ModeFailover = "failover"

// ModeBalance makes the balancer own the default route.
const ModeBalance = "balance"

// Schedule sets link weights at a given time on selected weekdays. Applying a
// schedule mutates link weights and (in balance mode) rebuilds the route.
type Schedule struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Enabled bool           `json:"enabled"`
	Days    []int          `json:"days"` // 0=Sunday .. 6=Saturday
	At      string         `json:"at"`   // "HH:MM" local time
	Weights map[string]int `json:"weights"`
}

// Config is the persisted balancer configuration (stored as JSON in settings).
type Config struct {
	Mode       string     `json:"mode"`
	Table      string     `json:"table"`
	ArmSeconds int        `json:"arm_seconds"`
	Schedules  []Schedule `json:"schedules"`

	// Active flow eviction: when a link stays degraded for
	// DegradedSustainSamples consecutive health checks, drop its in-flight
	// conntrack flows so established connections (a video call) re-hash onto a
	// healthy WAN instead of staying pinned to the bad one. OFF by default —
	// eviction resets those connections (they reconnect on the good link).
	EvictOnDegrade         bool `json:"evict_on_degrade"`
	DegradedSustainSamples int  `json:"degraded_sustain_samples"` // checks before acting
	EvictCooldownSecs      int  `json:"evict_cooldown_seconds"`   // min gap between evictions/link
}

func (c *Config) normalize() {
	if c.Mode != ModeBalance {
		c.Mode = ModeFailover
	}
	if c.Table == "" {
		c.Table = defaultTable
	}
	if c.ArmSeconds <= 0 {
		c.ArmSeconds = defaultArmSecs
	}
	if c.DegradedSustainSamples <= 0 {
		c.DegradedSustainSamples = defaultSustainSamples
	}
	if c.EvictCooldownSecs <= 0 {
		c.EvictCooldownSecs = defaultEvictCooldownSecs
	}
	// Never expose a nil slice: it marshals to JSON null and crashes clients
	// that read schedules.length / .map directly.
	if c.Schedules == nil {
		c.Schedules = []Schedule{}
	}
}

// Nexthop is one WAN link's contribution to the multipath default route.
type Nexthop struct {
	LinkID     string  `json:"link_id"`
	Name       string  `json:"name"`
	Gateway    string  `json:"gateway"`
	Interface  string  `json:"interface"`
	RawWeight  int     `json:"raw_weight"`
	Weight     int     `json:"weight"` // normalized to the kernel range 1..256
	Online     bool    `json:"online"`
	Status     string  `json:"status"`      // online | degraded | offline | ...
	PacketLoss float64 `json:"packet_loss"` // last measured, %
	LatencyMs  float64 `json:"latency_ms"`  // last measured
}

// Plan is the computed routing intent plus live context for the UI.
type Plan struct {
	Mode           string    `json:"mode"`
	Table          string    `json:"table"`
	Nexthops       []Nexthop `json:"nexthops"` // online links that will carry traffic
	Excluded       []Nexthop `json:"excluded"` // disabled/offline links left out
	Command        string    `json:"command"`  // human-readable ip route command
	CurrentDefault string    `json:"current_default"`
	Pending        bool      `json:"pending"`        // an auto-rollback is armed
	PendingExpiry  int64     `json:"pending_expiry"` // unix seconds, 0 if none
	ArmSeconds     int       `json:"arm_seconds"`
}

type pendingRollback struct {
	restore []string // ip args to restore the previous default
	timer   *time.Timer
	expiry  time.Time
}

// Service builds and applies the multipath default route.
type Service struct {
	db       *storage.DB
	exec     firewall.Executor
	linkSvc  *links.Service
	alertSvc *alerts.Service

	aiClient *ai.Client
	tsdbSvc  *tsdb.Service

	mu      sync.Mutex
	pending *pendingRollback

	schedMu   sync.Mutex
	lastFired map[string]string // schedule ID -> "2006-01-02 15:04" last applied

	rebuildMu sync.Mutex
	lastSig   string // signature of the last-applied nexthop set (skip no-op rebuilds)

	evictMu       sync.Mutex
	evictCooldown map[string]time.Time // link ID -> next allowed eviction time
}

// NewService creates a balancer Service.
func NewService(db *storage.DB, exec firewall.Executor, linkSvc *links.Service, alertSvc *alerts.Service) *Service {
	return &Service{
		db: db, exec: exec, linkSvc: linkSvc, alertSvc: alertSvc,
		lastFired:     map[string]string{},
		evictCooldown: map[string]time.Time{},
	}
}

// SetAI wires the optional AI advisory layer. If never called, OnLinkChange
// skips the immediate-analysis trigger entirely — the AI layer is opt-in and
// its absence changes nothing about failover/balance behavior.
func (s *Service) SetAI(client *ai.Client, tsdbSvc *tsdb.Service) {
	s.aiClient = client
	s.tsdbSvc = tsdbSvc
}

// LoadConfig reads the persisted configuration (with defaults applied).
func (s *Service) LoadConfig() Config {
	var c Config
	raw, _ := s.db.GetSetting(settingKey)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	c.normalize()
	return c
}

// SaveConfig persists the configuration.
func (s *Service) SaveConfig(c Config) error {
	c.normalize()
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.db.SetSetting(settingKey, string(out))
}

// Active reports whether balance mode is currently selected.
func (s *Service) Active() bool {
	return s.LoadConfig().Mode == ModeBalance
}

// Plan computes the intended multipath route from the current links.
func (s *Service) Plan(ctx context.Context) (Plan, error) {
	cfg := s.LoadConfig()
	return s.planWith(ctx, cfg)
}

func (s *Service) planWith(ctx context.Context, cfg Config) (Plan, error) {
	all, err := s.linkSvc.List()
	if err != nil {
		return Plan{}, err
	}

	chosen, excluded := selectNexthops(all, s.upInterfaces(ctx))

	p := Plan{
		Mode:       cfg.Mode,
		Table:      cfg.Table,
		Nexthops:   chosen,
		Excluded:   excluded,
		ArmSeconds: cfg.ArmSeconds,
	}
	if args := buildReplaceArgs(cfg.Table, chosen); args != nil {
		p.Command = "ip " + strings.Join(args, " ")
	}

	cur, _ := s.currentDefault(ctx, cfg.Table)
	p.CurrentDefault = cur

	s.mu.Lock()
	if s.pending != nil {
		p.Pending = true
		p.PendingExpiry = s.pending.expiry.Unix()
	}
	s.mu.Unlock()

	return p, nil
}

// Apply installs the weighted multipath default route. When arm is true the
// previous default is captured and auto-restored after the arm window unless
// Confirm is called first.
func (s *Service) Apply(ctx context.Context, arm bool) (Plan, error) {
	cfg := s.LoadConfig()
	plan, err := s.planWith(ctx, cfg)
	if err != nil {
		return Plan{}, err
	}
	if len(plan.Nexthops) == 0 {
		return plan, fmt.Errorf("nenhum link WAN online para balancear — rota não alterada")
	}

	// Capture the current default so we can roll back.
	backupArgs, backupRaw, err := s.captureRestore(ctx, cfg.Table)
	if err != nil {
		slog.Warn("balancer: could not capture current default for rollback", "err", err)
	}

	args := buildReplaceArgs(cfg.Table, plan.Nexthops)
	if _, err := s.exec.Execute(ctx, "ip", args...); err != nil {
		return plan, fmt.Errorf("aplicar rota: %w", err)
	}
	// Record what we just installed so the periodic reconcile agrees with the
	// kernel and doesn't re-apply (or, after a rollback, fight it) needlessly.
	s.rebuildMu.Lock()
	s.lastSig = routeSignature(plan.Nexthops)
	s.rebuildMu.Unlock()
	slog.Info("balancer: applied multipath default", "table", cfg.Table,
		"nexthops", len(plan.Nexthops), "armed", arm)

	// Cancel any previous arm, then arm a new rollback if requested.
	s.cancelPending()
	if arm && backupArgs != nil {
		s.armRollback(backupArgs, backupRaw, time.Duration(cfg.ArmSeconds)*time.Second)
	}

	return s.planWith(ctx, cfg)
}

// Confirm cancels a pending auto-rollback (the operator kept the change).
func (s *Service) Confirm() bool {
	return s.cancelPending()
}

// Rollback immediately restores the captured previous default route.
func (s *Service) Rollback(ctx context.Context) error {
	s.mu.Lock()
	p := s.pending
	s.pending = nil
	s.mu.Unlock()
	if p == nil {
		return fmt.Errorf("nenhuma alteração pendente para reverter")
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	return s.restore(ctx, p.restore)
}

// Rebuild recomputes and applies the route. It is idempotent: if the desired
// nexthop set is unchanged since the last apply it does nothing (so the periodic
// reconcile is quiet). Used both on link state changes and on a timer, so a link
// whose interface comes back up is re-added even without an explicit event.
func (s *Service) Rebuild(ctx context.Context) error {
	cfg := s.LoadConfig()
	if cfg.Mode != ModeBalance {
		return nil
	}

	// Don't fight an armed manual Apply: while a rollback is pending, that flow
	// owns the route for its window (otherwise the reconcile re-imposes the very
	// route a rollback is meant to undo).
	s.mu.Lock()
	pending := s.pending != nil
	s.mu.Unlock()
	if pending {
		return nil
	}

	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()

	plan, err := s.planWith(ctx, cfg)
	if err != nil {
		return err
	}
	sig := routeSignature(plan.Nexthops)
	if len(plan.Nexthops) == 0 {
		// Alert exactly once on entering the empty state. A distinct sentinel is
		// used (not routeSignature([])=="") so the very first reconcile at boot —
		// where lastSig is still "" — is not mistaken for "already alerted".
		if s.lastSig == emptySig {
			return fmt.Errorf("no up interfaces")
		}
		s.lastSig = emptySig
		// Tipo próprio, e não o pega-tudo (issue #147): isto é um ESTADO, e
		// estado precisa de quem o feche. Como rule_error, ficava vermelho para
		// sempre — em produção um desses durou seis dias numa caixa saudável,
		// enquanto a condição real durou minutos.
		_ = s.alertSvc.BalancerNoWAN("O balanceamento não encontrou nenhuma interface WAN ativa. A rota atual foi mantida, então a rede continua saindo pelo caminho de antes.")
		return fmt.Errorf("no up interfaces")
	}
	// A TRANSIÇÃO DE VOLTA, que é a metade que faltava. Só quando vínhamos do
	// estado vazio: chamar isto em toda reconciliação transformaria a
	// recuperação em ruído, e ruído de recuperação ensina a ignorar recuperação
	// tão bem quanto vermelho permanente ensina a ignorar vermelho.
	if s.lastSig == emptySig {
		_ = s.alertSvc.BalancerWANBack(fmt.Sprintf("O balanceamento voltou a encontrar caminho (%d saída(s) ativa(s)).", len(plan.Nexthops)))
	}
	if sig == s.lastSig {
		return nil // nothing changed
	}
	args := buildReplaceArgs(cfg.Table, plan.Nexthops)
	if _, err := s.exec.Execute(ctx, "ip", args...); err != nil {
		return fmt.Errorf("rebuild route: %w", err) // keep lastSig so we retry next tick
	}
	s.lastSig = sig
	slog.Info("balancer: rebuilt multipath default", "table", cfg.Table, "nexthops", len(plan.Nexthops))
	return nil
}

// emptySig marks the "no up interfaces" state; distinct from routeSignature([])
// (== "") so the first reconcile at boot isn't mistaken for "already alerted".
const emptySig = "\x00empty"

// routeSignature is a stable fingerprint of a nexthop set, used to skip no-op
// rebuilds. It includes Gateway and Interface (not just link+weight) so a WAN
// whose gateway/interface changes — e.g. a DHCP renewal — is re-applied to the
// kernel instead of silently leaving the route pointing at the stale gateway.
func routeSignature(nhs []Nexthop) string {
	parts := make([]string, len(nhs))
	for i, n := range nhs {
		parts[i] = fmt.Sprintf("%s|%s|%s|%d", n.LinkID, n.Gateway, n.Interface, n.Weight)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ─── WAN policy-routing bootstrap (replaces /etc/network/linkguard-routing.sh) ─

const steerKey = "wan_steer"

// SteerConfig is the per-secondary-WAN policy routing LinkGuard now owns on
// startup (previously bootstrapped by an external script via rc.local): a
// routing table with the WAN's default + the LAN route, plus an `ip rule` that
// sends fwmark-tagged (host-steered) traffic to that table.
type SteerConfig struct {
	Enabled   bool   `json:"enabled"`
	Mark      string `json:"mark"`      // e.g. "0x12c"
	Table     string `json:"table"`     // rt_tables name or number, e.g. "sumicity"
	Gateway   string `json:"gateway"`   // secondary WAN gateway
	Interface string `json:"interface"` // secondary WAN interface
	LanCIDR   string `json:"lan_cidr"`  // e.g. "192.168.3.0/24"
	LanVia    string `json:"lan_via"`   // e.g. "192.168.3.3"
	LanDev    string `json:"lan_dev"`   // e.g. "br10"
	Priority  int    `json:"priority"`  // ip rule priority (default 32765)
}

var (
	reSteerTable = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)
	reSteerMark  = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$`)
	reSteerIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
)

// steerValid guards the wan_steer setting: it is applied to `ip route`/`ip rule`
// and can arrive via backup restore, so every field is charset-constrained.
func steerValid(c SteerConfig) bool {
	if !reSteerTable.MatchString(c.Table) {
		return false
	}
	if c.Mark != "" && !reSteerMark.MatchString(c.Mark) {
		return false
	}
	if c.Interface != "" && !reSteerIface.MatchString(c.Interface) {
		return false
	}
	if c.LanDev != "" && !reSteerIface.MatchString(c.LanDev) {
		return false
	}
	if c.Gateway != "" && net.ParseIP(c.Gateway) == nil {
		return false
	}
	if c.LanVia != "" && net.ParseIP(c.LanVia) == nil {
		return false
	}
	if c.LanCIDR != "" {
		if _, _, err := net.ParseCIDR(c.LanCIDR); err != nil {
			return false
		}
	}
	return true
}

// EnsureSteerRouting applies the host-steering policy routing idempotently. Safe
// to call repeatedly (startup + reconcile). No-op unless a wan_steer setting is
// present and enabled.
func (s *Service) EnsureSteerRouting(ctx context.Context) {
	raw, _ := s.db.GetSetting(steerKey)
	if raw == "" {
		s.limparAlertaDeSteer()
		return
	}
	var c SteerConfig
	if json.Unmarshal([]byte(raw), &c) != nil || !c.Enabled || c.Table == "" {
		// Recurso desligado é condição RESOLVIDA, não condição ignorada: quem
		// desligou consertou o problema que o alerta descrevia.
		s.limparAlertaDeSteer()
		return
	}
	if !steerValid(c) {
		slog.Warn("balancer: wan_steer inválido (campos fora do padrão) — ignorado")
		return
	}
	// OS ERROS DAQUI NÃO PODEM SER DESCARTADOS, E ERAM.
	//
	// Este bloco escreve rota e regra de política. Quando o alvo não existe
	// mais — tabela de um provedor antigo, interface renomeada — os comandos
	// falham, e falhavam com `_, _ =`. O efeito é invisível e duradouro: a
	// chain mark_hosts continua gravando a marca, o painel continua listando os
	// hosts fixados, e sem regra que atenda a marca o pacote cai na tabela
	// principal e sai por onde o balanceamento mandar.
	//
	// Medido na máquina de produção: `wan_steer` apontando para a tabela
	// "sumicity", que não está em /etc/iproute2/rt_tables, e para a interface
	// "enp3s0", renomeada para "lg-wan-giga" há meses. Oito hosts fixados, marca
	// 0x12c gravada em todos, nenhuma regra procurando 0x12c, e um download
	// saindo pelas duas WANs ao mesmo tempo. Nada em log nenhum.
	var falhas []string
	if c.Gateway != "" && c.Interface != "" {
		if out, err := s.exec.Execute(ctx, "ip", "route", "replace", "default",
			"via", c.Gateway, "dev", c.Interface, "onlink", "table", c.Table); err != nil {
			falhas = append(falhas, fmt.Sprintf("rota padrão na tabela %s: %v (%s)", c.Table, err, strings.TrimSpace(out)))
		}
	}
	if c.LanCIDR != "" && c.LanVia != "" && c.LanDev != "" {
		if out, err := s.exec.Execute(ctx, "ip", "route", "replace", c.LanCIDR,
			"via", c.LanVia, "dev", c.LanDev, "table", c.Table); err != nil {
			falhas = append(falhas, fmt.Sprintf("rota da LAN na tabela %s: %v (%s)", c.Table, err, strings.TrimSpace(out)))
		}
	}
	if c.Mark != "" {
		out, _ := s.exec.ExecuteRead(ctx, "ip", "rule", "show")
		// Rule lines look like: "32765:\tfrom all fwmark 0x12c lookup sumicity".
		if !(strings.Contains(out, "fwmark "+c.Mark) && strings.Contains(out, "lookup "+c.Table)) {
			args := []string{"rule", "add", "fwmark", c.Mark, "lookup", c.Table}
			if c.Priority > 0 {
				args = append(args, "priority", fmt.Sprintf("%d", c.Priority))
			}
			if saida, err := s.exec.Execute(ctx, "ip", args...); err != nil {
				falhas = append(falhas, fmt.Sprintf("regra fwmark %s → tabela %s: %v (%s)", c.Mark, c.Table, err, strings.TrimSpace(saida)))
			}
		}
	}

	// E a conferência é do ESTADO, não do código de saída: a regra pode já
	// existir de antes, e pode ter sumido depois de um comando que "deu certo".
	// O que decide é ela estar lá agora.
	s.conferirSteer(ctx, c, falhas)
}

// conferirSteer confirma que a regra de política que dá sentido à marca existe
// de verdade, e ALERTA quando não existe.
//
// Sem isto o defeito é mudo por construção: quem olha o painel vê os hosts
// fixados, quem olha o nftables vê a marca sendo gravada, e o único lugar onde
// a verdade aparece é um `ip rule show` que ninguém roda.
func (s *Service) conferirSteer(ctx context.Context, c SteerConfig, falhas []string) {
	if c.Mark == "" {
		return
	}
	out, err := s.exec.ExecuteRead(ctx, "ip", "rule", "show")
	if err != nil {
		slog.Warn("balancer: não consegui conferir se o direcionamento por WAN está valendo", "err", err)
		return
	}
	if strings.Contains(out, "fwmark "+c.Mark) && strings.Contains(out, "lookup "+c.Table) {
		if len(falhas) > 0 {
			slog.Warn("balancer: direcionamento por WAN está valendo, mas parte da configuração falhou",
				"falhas", strings.Join(falhas, "; "))
		}
		s.limparAlertaDeSteer()
		return
	}
	motivo := strings.Join(falhas, "; ")
	if motivo == "" {
		motivo = fmt.Sprintf("nenhuma regra procura a marca %s", c.Mark)
	}

	// QUEM NÃO TEM APARELHO FIXADO NÃO TEM PROBLEMA, E NÃO PODE TER ALERTA.
	//
	// O alerta existe para dizer "os aparelhos que você fixou estão saindo pelo
	// caminho errado". Sem nenhum aparelho fixado, a frase não descreve nada: a
	// configuração está morta e não está prejudicando ninguém. Alertar assim
	// mesmo transforma o painel num vermelho permanente sobre um recurso sem
	// usuário — e vermelho permanente ensina a ignorar vermelho, que é o mesmo
	// motivo pelo qual o BalancerNoWAN ganhou tipo próprio na #147.
	//
	// Fica em log, porque a configuração continua quebrada e alguém que fixar um
	// aparelho amanhã precisa ter onde ver o porquê de não ter funcionado.
	fixados, err := s.contarFixados(ctx, c.Mark)
	if err != nil {
		// Não saber quantos são não é motivo para calar: o alerta erra para o
		// lado de avisar, que é o lado barato.
		slog.Warn("balancer: não consegui contar os aparelhos fixados; alertando por precaução", "err", err)
	} else if fixados == 0 {
		slog.Warn("balancer: o direcionamento por WAN está configurado e não vale, mas nenhum aparelho está fixado nele",
			"marca", c.Mark, "tabela", c.Table, "motivo", motivo)
		// Sem aparelho fixado não há quem sofra, e um alerta levantado quando
		// havia precisa ser fechado agora que não há mais.
		s.limparAlertaDeSteer()
		return
	}

	slog.Error("balancer: o direcionamento por WAN NÃO está valendo; os hosts fixados saem pelo balanceamento",
		"marca", c.Mark, "tabela", c.Table, "interface", c.Interface, "aparelhos_fixados", fixados, "motivo", motivo)
	if s.alertSvc != nil {
		_ = s.alertSvc.SteerInativo(c.Mark, c.Table, c.Interface, motivo, fixados)
	}
}

// limparAlertaDeSteer fecha o alerta de direcionamento inativo quando a
// condição que ele descreve deixou de existir — o recurso passou a valer, foi
// desligado, ou não tem mais nenhum aparelho fixado.
func (s *Service) limparAlertaDeSteer() {
	if s.alertSvc != nil {
		s.alertSvc.SteerAtivo()
	}
}

// contarFixados diz quantos aparelhos do map host_wan carregam a marca dada.
//
// A comparação é NUMÉRICA e não textual: o nft imprime a marca preenchida com
// zeros ("0x0000012c") e a configuração guarda a forma curta ("0x12c"). Comparar
// as duas como texto daria zero sempre, e o alerta que este contador existe para
// segurar nunca mais apareceria — um silêncio que se pareceria com conserto.
func (s *Service) contarFixados(ctx context.Context, marca string) (int, error) {
	alvo, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(marca), "0x"), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("marca %q não é hexadecimal: %w", marca, err)
	}
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "map", "inet", "linkguard", "host_wan")
	if err != nil {
		return 0, fmt.Errorf("ler o map host_wan: %w", err)
	}
	var n int
	for _, m := range reMarcaDoMap.FindAllStringSubmatch(out, -1) {
		if v, err := strconv.ParseUint(m[1], 16, 32); err == nil && v == alvo {
			n++
		}
	}
	return n, nil
}

// reMarcaDoMap casa o lado direito de cada elemento do host_wan: "ip : 0x...".
var reMarcaDoMap = regexp.MustCompile(`:\s*0x([0-9a-fA-F]+)`)

// OnLinkChange is the monitor callback used while in balance mode. Besides
// rebuilding the route, it raises alerts on up/down/degraded transitions so the
// notification channels (WhatsApp, e-mail, …) fire — otherwise a single link
// dropping while balancing would be silent.
func (s *Service) OnLinkChange(link *storage.Link, oldStatus, newStatus string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	slog.Info("balancer: link change", "link", link.Name, "from", oldStatus, "to", newStatus)

	switch newStatus {
	case links.StatusOffline:
		_ = s.alertSvc.LinkOffline(link.Name, link.ID)
	case links.StatusOnline:
		_ = s.alertSvc.LinkOnline(link.Name, link.ID)
	case links.StatusDegraded:
		_ = s.alertSvc.LinkDegraded(link.Name, link.ID, link.LatencyMs, link.PacketLoss)
	}

	// Optional AI advisory layer: fires only on a severe, already-confirmed
	// transition (offline, or degraded past the hysteresis threshold this
	// callback only receives once Project 2's fix is in place). Runs in its
	// own goroutine with its own timeout — never blocks the route rebuild
	// below, and any failure is swallowed inside TriggerImmediate itself.
	if s.aiClient != nil && (newStatus == links.StatusOffline || newStatus == links.StatusDegraded) {
		go ai.TriggerImmediate(context.Background(), s.aiClient, s.tsdbSvc, s.alertSvc, s.db, link)
	}

	if err := s.Rebuild(ctx); err != nil {
		slog.Warn("balancer: rebuild on link change failed", "link", link.Name, "err", err)
	}
}

// ─── active flow eviction ────────────────────────────────────────────────────

// evictDecision reports whether an eviction should proceed for a degraded link,
// applying the three guards: the EvictOnDegrade toggle, the per-link cooldown,
// and the presence of a healthy (online) alternative to move flows onto.
func evictDecision(cfg Config, degraded storage.Link, all []storage.Link, cooldownUntil, now time.Time) (bool, string) {
	if !cfg.EvictOnDegrade {
		return false, "eviction disabled"
	}
	if now.Before(cooldownUntil) {
		return false, "cooldown active"
	}
	for _, l := range all {
		if l.ID == degraded.ID {
			continue
		}
		if l.Enabled && l.Status == links.StatusOnline {
			return true, ""
		}
	}
	return false, "no healthy alternative"
}

// EvictDegraded drops the in-flight conntrack flows of a link that has been
// degraded for the sustained threshold, so established connections (a video
// call) re-hash onto a healthy WAN instead of staying pinned to the bad one.
// It is edge-triggered by the monitor and no-ops unless balance mode is active
// and all guards in evictDecision pass. Eviction resets the affected NAT'd
// connections; they reconnect on the healthy link.
func (s *Service) EvictDegraded(ctx context.Context, link *storage.Link) {
	if link == nil {
		return
	}
	cfg := s.LoadConfig()
	if cfg.Mode != ModeBalance {
		return
	}
	all, err := s.db.GetLinks()
	if err != nil {
		slog.Warn("evict: get links", "err", err)
		return
	}

	s.evictMu.Lock()
	until := s.evictCooldown[link.ID]
	s.evictMu.Unlock()

	if proceed, reason := evictDecision(cfg, *link, all, until, time.Now()); !proceed {
		slog.Info("evict: skipped", "link", link.Name, "reason", reason)
		return
	}

	// Demote the degraded link first (idempotent) so flows re-hashed by the flush
	// don't land back on it.
	if err := s.Rebuild(ctx); err != nil {
		slog.Warn("evict: rebuild before flush failed", "link", link.Name, "err", err)
	}

	ip := s.interfaceIPv4(ctx, link.Interface)
	if ip == "" {
		slog.Warn("evict: no IPv4 for interface, aborting flush", "link", link.Name, "iface", link.Interface)
		return
	}

	// Flows egressing this WAN are masqueraded to its IP, so their conntrack reply
	// destination is that IP: -q targets exactly those flows, not a global flush.
	// conntrack -D exits non-zero when nothing matched — not a real error here.
	if _, err := s.exec.Execute(ctx, "conntrack", "-D", "-q", ip); err != nil {
		slog.Info("evict: conntrack flush returned non-zero (often 'nothing to delete')",
			"link", link.Name, "ip", ip, "err", err)
	}

	s.evictMu.Lock()
	s.evictCooldown[link.ID] = time.Now().Add(time.Duration(cfg.EvictCooldownSecs) * time.Second)
	s.evictMu.Unlock()

	_ = s.alertSvc.Failover(link.Name, "conexões migradas de link degradado")
	slog.Info("evict: flushed flows from degraded link", "link", link.Name, "ip", ip)
}

// InterfaceIPv4 é interfaceIPv4 exportada para quem precisa da mesma resposta
// sem ter um balancer em mãos — hoje o DDNS (#129), que precisa saber o
// endereço atual de cada WAN. Exportar em vez de copiar: duas leituras do
// mesmo `ip addr` com parsers diferentes divergem no primeiro formato
// inesperado, e o sintoma seria o nome de DNS apontando para lugar nenhum.
func InterfaceIPv4(ctx context.Context, exec firewall.Executor, iface string) string {
	return (&Service{exec: exec}).interfaceIPv4(ctx, iface)
}

// interfaceIPv4 returns the first global IPv4 address configured on iface, or ""
// if none (or the lookup fails).
func (s *Service) interfaceIPv4(ctx context.Context, iface string) string {
	out, err := s.exec.ExecuteRead(ctx, "ip", "-o", "-4", "addr", "show", "dev", iface, "scope", "global")
	if err != nil || strings.TrimSpace(out) == "" {
		return ""
	}
	return parseInterfaceIPv4(out)
}

// parseInterfaceIPv4 extracts the first "inet <addr>/<prefix>" address from the
// output of `ip -o -4 addr show`, returning the bare address (no prefix).
func parseInterfaceIPv4(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				addr := f[i+1]
				if slash := strings.IndexByte(addr, '/'); slash >= 0 {
					addr = addr[:slash]
				}
				return addr
			}
		}
	}
	return ""
}

// ─── scheduled rebalancing ───────────────────────────────────────────────────

// Run starts the scheduler loop. Every minute it checks for enabled schedules
// whose weekday + time match "now" and applies their link weights (rebuilding
// the route when in balance mode). Each schedule fires at most once per minute.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx, time.Now())
			// Reconcile the host-steering policy routing (tables + ip rule) and
			// the balanced default. Both are idempotent/no-op when unchanged.
			s.EnsureSteerRouting(ctx)
			_ = s.Rebuild(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context, now time.Time) {
	cfg := s.LoadConfig()
	if len(cfg.Schedules) == 0 {
		return
	}
	weekday := int(now.Weekday()) // 0=Sunday
	hhmm := now.Format("15:04")
	minuteKey := now.Format("2006-01-02 15:04")

	for _, sch := range cfg.Schedules {
		if !sch.Enabled || sch.At != hhmm || !containsInt(sch.Days, weekday) {
			continue
		}
		s.schedMu.Lock()
		already := s.lastFired[sch.ID] == minuteKey
		if !already {
			s.lastFired[sch.ID] = minuteKey
		}
		s.schedMu.Unlock()
		if already {
			continue
		}
		slog.Info("balancer: applying schedule", "name", sch.Name, "at", sch.At)
		if err := s.ApplySchedule(ctx, sch); err != nil {
			slog.Error("balancer: schedule apply failed", "name", sch.Name, "err", err)
			_ = s.alertSvc.RuleError(fmt.Sprintf("Agendamento de balanceamento '%s' falhou: %v", sch.Name, err))
		}
	}
}

// ApplySchedule writes the schedule's per-link weights and rebuilds the route
// when balance mode is active.
func (s *Service) ApplySchedule(ctx context.Context, sch Schedule) error {
	for linkID, w := range sch.Weights {
		l, err := s.linkSvc.Get(linkID)
		if err != nil || l == nil {
			slog.Warn("balancer: schedule references unknown link", "link_id", linkID)
			continue
		}
		l.Weight = w
		if err := s.linkSvc.Update(l); err != nil {
			return fmt.Errorf("update link %s weight: %w", l.Name, err)
		}
	}
	return s.Rebuild(ctx)
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ─── internals ───────────────────────────────────────────────────────────────

func (s *Service) currentDefault(ctx context.Context, table string) (string, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show", "default", "table", table)
	return strings.TrimSpace(out), err
}

// captureRestore reads the current default route in the table and returns the
// ip args that would restore it, plus the raw text for display.
func (s *Service) captureRestore(ctx context.Context, table string) ([]string, string, error) {
	raw, err := s.currentDefault(ctx, table)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(raw) == "" {
		return nil, "", nil
	}
	args := restoreArgsFromShow(raw, table)
	return args, raw, nil
}

func (s *Service) armRollback(restore []string, raw string, d time.Duration) {
	expiry := time.Now().Add(d)
	timer := time.AfterFunc(d, func() {
		s.mu.Lock()
		p := s.pending
		s.pending = nil
		s.mu.Unlock()
		if p == nil {
			return
		}
		slog.Warn("balancer: auto-rollback fired (no confirmation)", "restore", strings.Join(restore, " "))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.restore(ctx, restore); err != nil {
			slog.Error("balancer: auto-rollback failed", "err", err)
			_ = s.alertSvc.RuleError("Balanceamento: auto-rollback falhou — verifique o roteamento")
		} else {
			_ = s.alertSvc.RuleError("Balanceamento revertido automaticamente (sem confirmação)")
		}
	})
	s.mu.Lock()
	s.pending = &pendingRollback{restore: restore, timer: timer, expiry: expiry}
	s.mu.Unlock()
	slog.Info("balancer: rollback armed", "expires_in", d.String(), "raw", raw)
}

func (s *Service) cancelPending() bool {
	s.mu.Lock()
	p := s.pending
	s.pending = nil
	s.mu.Unlock()
	if p == nil {
		return false
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	return true
}

func (s *Service) restore(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("nada para restaurar")
	}
	if _, err := s.exec.Execute(ctx, "ip", args...); err != nil {
		return fmt.Errorf("restaurar rota: %w", err)
	}
	slog.Info("balancer: default route restored", "cmd", "ip "+strings.Join(args, " "))
	return nil
}

func toNexthop(l storage.Link) Nexthop {
	return Nexthop{
		LinkID:     l.ID,
		Name:       l.Name,
		Gateway:    l.Gateway,
		Interface:  l.Interface,
		RawWeight:  l.Weight,
		Status:     l.Status,
		PacketLoss: l.PacketLoss,
		LatencyMs:  l.LatencyMs,
		Online:     l.Status == links.StatusOnline || l.Status == links.StatusDegraded,
	}
}

// demotedWeight is the tiny weight given to a non-primary link so it stays in
// the route (its health probe keeps working and it can self-heal) while carrying
// almost no traffic.
const demotedWeight = 1

// selectNexthops builds the multipath default with a degradation-aware policy.
//
// KEY invariant: every interface-UP link stays in the route as a nexthop, so its
// health probe (which routes via the main table) always has a path and the link
// can recover on its own. Instead of removing a bad link (which strands its
// probe and it can never rejoin), we DEMOTE it to weight 1 — ~0.4% of traffic —
// which is effectively "switched away from" while remaining self-healing.
//
// Primary carriers (full configured weight) are chosen as:
//   - any healthy (online) link → all healthy links;
//   - else the single LEAST-degraded link (lowest loss, then latency);
//   - else every up link (all probing bad but physically up — safety net).
//
// Interface-DOWN links are excluded entirely (a down device makes `ip route
// replace` fail); they rejoin as demoted nexthops the moment their link is up.
// ifaceUp maps interface → physically up; nil means "unknown" (no filtering).
func selectNexthops(all []storage.Link, ifaceUp map[string]bool) (chosen, excluded []Nexthop) {
	isUp := func(iface string) bool { return ifaceUp == nil || ifaceUp[iface] }

	excluded = []Nexthop{}
	var up []storage.Link
	for _, l := range all {
		if !l.Enabled || l.Gateway == "" || l.Interface == "" {
			if l.Gateway != "" || l.Interface != "" {
				excluded = append(excluded, toNexthop(l))
			}
			continue
		}
		if !isUp(l.Interface) {
			excluded = append(excluded, toNexthop(l)) // rejoins when its interface is up
			continue
		}
		up = append(up, l)
	}
	if len(up) == 0 {
		return []Nexthop{}, excluded
	}

	var healthy, degraded, others []storage.Link
	for _, l := range up {
		switch l.Status {
		case links.StatusOnline:
			healthy = append(healthy, l)
		case links.StatusDegraded:
			degraded = append(degraded, l)
		default:
			others = append(others, l)
		}
	}
	primary := map[string]bool{}
	switch {
	case len(healthy) > 0:
		for _, l := range healthy {
			primary[l.ID] = true
		}
	case len(degraded) > 0:
		sort.Slice(degraded, func(i, j int) bool {
			if degraded[i].PacketLoss != degraded[j].PacketLoss {
				return degraded[i].PacketLoss < degraded[j].PacketLoss
			}
			return degraded[i].LatencyMs < degraded[j].LatencyMs
		})
		primary[degraded[0].ID] = true
	default:
		for _, l := range others {
			primary[l.ID] = true
		}
	}

	// Normalize weights among the primary carriers only.
	var primaryNH []Nexthop
	for _, l := range up {
		if primary[l.ID] {
			primaryNH = append(primaryNH, toNexthop(l))
		}
	}
	normalizeWeights(primaryNH)
	weightByID := map[string]int{}
	for _, nh := range primaryNH {
		weightByID[nh.LinkID] = nh.Weight
	}

	chosen = []Nexthop{}
	for _, l := range up {
		nh := toNexthop(l)
		if w, ok := weightByID[l.ID]; ok {
			nh.Weight = w
		} else {
			nh.Weight = demotedWeight
		}
		chosen = append(chosen, nh)
	}
	return chosen, excluded
}

// upInterfaces returns the set of physically-up interfaces (operstate UP).
// Returns nil on error, which selectNexthops treats as "don't filter".
func (s *Service) upInterfaces(ctx context.Context) map[string]bool {
	out, err := s.exec.ExecuteRead(ctx, "ip", "-br", "link", "show")
	if err != nil {
		return nil
	}
	return parseUpInterfaces(out)
}

func parseUpInterfaces(out string) map[string]bool {
	up := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Treat UNKNOWN as up too: tun/ppp/VPN WAN devices commonly report
		// operstate UNKNOWN even when fully working, so excluding them would drop
		// a healthy link from the route. Only an explicit DOWN counts as down.
		if len(f) >= 2 && (f[1] == "UP" || f[1] == "UNKNOWN") {
			up[strings.TrimSuffix(f[0], ":")] = true
		}
	}
	return up
}

// normalizeWeights scales raw link weights into the kernel range 1..256 while
// preserving their ratios. Equal/zero raw weights yield an equal split.
func normalizeWeights(nhs []Nexthop) {
	maxRaw := 0
	for _, n := range nhs {
		if n.RawWeight > maxRaw {
			maxRaw = n.RawWeight
		}
	}
	for i := range nhs {
		if maxRaw <= 0 {
			nhs[i].Weight = 1
			continue
		}
		w := (nhs[i].RawWeight*maxKernelWeight + maxRaw/2) / maxRaw // round
		if w < 1 {
			w = 1
		}
		if w > maxKernelWeight {
			w = maxKernelWeight
		}
		nhs[i].Weight = w
	}
}

// buildReplaceArgs builds the `ip route replace default ...` argument list for
// the given nexthops. Returns nil if there are no nexthops.
func buildReplaceArgs(table string, nhs []Nexthop) []string {
	if len(nhs) == 0 {
		return nil
	}
	if table == "" {
		table = defaultTable
	}
	args := []string{"route", "replace", "default", "table", table}
	for _, n := range nhs {
		w := n.Weight
		if w < 1 {
			w = 1
		}
		args = append(args, "nexthop", "via", n.Gateway, "dev", n.Interface,
			"weight", fmt.Sprintf("%d", w), "onlink")
	}
	return args
}

// restoreArgsFromShow turns `ip route show default` output back into args for
// `ip route replace`, handling both single-path and multipath forms.
func restoreArgsFromShow(show, table string) []string {
	if table == "" {
		table = defaultTable
	}
	flat := strings.Join(strings.Fields(show), " ") // collapse newlines/tabs
	if flat == "" {
		return nil
	}
	args := []string{"route", "replace", "default", "table", table}

	if strings.Contains(flat, "nexthop") {
		// Multipath: split on "nexthop" and reconstruct each leg.
		parts := strings.Split(flat, "nexthop")
		for _, p := range parts {
			f := strings.Fields(p)
			leg := parseNexthopFields(f)
			if leg != nil {
				args = append(args, leg...)
			}
		}
		if len(args) == 5 { // only the prefix, nothing parsed
			return nil
		}
		return args
	}

	// Single path: "default via GW dev IF [onlink] ..."
	f := strings.Fields(flat)
	if len(f) > 0 && f[0] == "default" {
		f = f[1:]
	}
	leg := parseSinglePathFields(f)
	if leg == nil {
		return nil
	}
	return append(args, leg...)
}

func parseNexthopFields(f []string) []string {
	var via, dev, weight string
	onlink := false
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "via":
			if i+1 < len(f) {
				via = f[i+1]
				i++
			}
		case "dev":
			if i+1 < len(f) {
				dev = f[i+1]
				i++
			}
		case "weight":
			if i+1 < len(f) {
				weight = f[i+1]
				i++
			}
		case "onlink":
			onlink = true
		}
	}
	if via == "" || dev == "" {
		return nil
	}
	out := []string{"nexthop", "via", via, "dev", dev}
	if weight != "" {
		out = append(out, "weight", weight)
	}
	if onlink {
		out = append(out, "onlink")
	}
	return out
}

// parseSinglePathFields reconstructs a single-path default (no nexthop keyword)
// preserving via/dev/onlink.
func parseSinglePathFields(f []string) []string {
	var via, dev string
	onlink := false
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "via":
			if i+1 < len(f) {
				via = f[i+1]
				i++
			}
		case "dev":
			if i+1 < len(f) {
				dev = f[i+1]
				i++
			}
		case "onlink":
			onlink = true
		}
	}
	if via == "" && dev == "" {
		return nil
	}
	var out []string
	if via != "" {
		out = append(out, "via", via)
	}
	if dev != "" {
		out = append(out, "dev", dev)
	}
	if onlink {
		out = append(out, "onlink")
	}
	return out
}
