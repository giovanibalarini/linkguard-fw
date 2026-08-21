package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Result reports what a restore applied.
type Result struct {
	Settings     int
	Reservations int
	Blocklist    int
	// SkippedLocal é quantas chaves de estado local da máquina foram
	// ignoradas — ver machineLocalSettingKeys.
	SkippedLocal int
}

// ValidationError é a recusa de um backup mal formado ou hostil: nada foi
// gravado, e a mensagem já está no idioma do painel, pronta para virar o corpo
// de um 400. Quem chama distingue isto de um erro de banco (que vira 500) com
// errors.As.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// ErrBadPassphrase é senha errada ou arquivo que não decifra/não é um backup.
// Deliberadamente uma única condição: distinguir "senha errada" de "arquivo
// corrompido" na resposta contaria ao atacante qual das duas ele acertou.
var ErrBadPassphrase = errors.New("senha incorreta ou arquivo inválido")

// ErrLockedOut é a trava por tentativas repetidas com senha errada.
var ErrLockedOut = errors.New("muitas tentativas com senha incorreta")

// ─── Restore-time validation (input-validation-audit.md finding #1) ──────────
//
// ExportSettings dumps every row of the settings table with no filtering
// (that's deliberate — see its own doc comment — secrets simply never live
// there). Restore used to write every one of those rows straight back with
// db.SetSetting(k, v), with no validator in between: a crafted or corrupted
// .lgbak file could put anything at all into netsvc_config or the DNS
// blocklist, both of which reach a root daemon's config file
// (unbound.conf/kea-dhcp4.conf) by string concatenation elsewhere in this
// codebase (see internal/keaunbound.GenerateUnboundConfig, which now also
// defends itself independently — see that function's own fix — but restore
// is the entry point that made the gap reachable in practice, since it is
// the one place these values can land in the DB with no handler in front of
// them at all).
//
// knownSettingsValidators maps the settings keys this restore path
// recognizes as structured config with an existing, reusable validator to a
// function that parses+validates a raw settings value and returns a
// (nil-safe) error describing why it was rejected. Every key NOT in this
// map is restored exactly as before this fix — see the Apply doc comment
// for why that's a deliberate choice, not an oversight.
var knownSettingsValidators = map[string]func(raw string) error{
	netsvcCfgKey:          validateNetsvcConfigRestore,
	ntpCfgKey:             validateNTPConfigRestore,
	monitoringSettingsKey: validateMonitoringConfigRestore,
}

// machineLocalSettingKeys are the settings rows that describe the state of
// *this* machine rather than the operator's configuration, and therefore
// must never be written by a restore — a backup file is a configuration
// document, not a snapshot of another box's runtime.
//
// They are skipped silently (counted and logged, not rejected): a backup
// legitimately produced by Export always carries them — ExportSettings
// dumps the whole settings table — so refusing the file would make every
// real backup unrestorable. "This doesn't travel" is the right semantics,
// not "this is invalid".
//
//   - nft_live_snapshot: read at bootstrap (cmd/linkguard-fw/main.go) and
//     handed to `nft -f` as root. Restoring it would let a backup file
//     redefine THIS machine's linkguard table from another machine's state —
//     including on a fresh install, the documented restore scenario, where
//     EnsureTable reports a new table and the snapshot IS loaded (C-2).
//
//     The blast radius stops at the linkguard table: the payload carries no
//     "flush ruleset", and internal/nftables/restore_test.go asserts its
//     absence precisely so that foreign tables (docker, tailscale) survive —
//     neither daemon recreates its table without a restart. The guard stays
//     anyway: redefining this box's firewall from someone else's snapshot is
//     damage on its own.
//
//   - firewall_rules_imported: the one-time-import latch. BackupData has no
//     field for the firewall rules themselves, so restoring the latch writes
//     "already imported" onto a machine that received no rules: the next
//     boot skips ImportOnce and ReconcileUserRules empties the live
//     user_rules chain against an empty table (C-3).
//     TODO: firewall_rules ainda não é exportado no backup; incluí-las é
//     feature à parte (ver Crítico 3 da revisão final).
//
//   - firewall_rules_apply / netsvc_last_apply: results of an apply that
//     happened on the source machine. Restored, the panel would report a
//     success (or failure) that never took place here.
var machineLocalSettingKeys = map[string]bool{
	nftables.LiveSnapshotSettingKey:  true,
	firewallrules.ImportedSettingKey: true,
	firewallrules.ApplyStatusKey:     true,
	netsvcApplyStatusKey:             true,
}

// As três chaves abaixo espelham constantes não exportadas de
// internal/api/handlers (netsvc.go, ntp.go) e de internal/monitoring.
// Repetidas como literais em vez de importadas: são identificadores privados
// daqueles pacotes, e internal/api/handlers importa este pacote — a
// importação inversa seria ciclo. O acoplamento real é com a linha do banco,
// não com o pacote: mudar a chave lá sem mudar aqui quebraria a restauração
// daquela chave, e é por isso que os testes de restore usam o literal.
const (
	netsvcCfgKey          = "netsvc_config"
	netsvcApplyStatusKey  = "netsvc_last_apply"
	ntpCfgKey             = "ntp_config"
	monitoringSettingsKey = "monitoring"
)

// validateNetsvcConfigRestore parses a netsvc_config settings blob and runs
// every field through the same checks NetsvcHandler.UpdateDHCPConfig and
// UpdateDNSConfig apply to an admin-submitted value (see
// internal/api/handlers/netsvc.go) — same validate.Iface/validate.Domain
// calls, same net.ParseIP/ParseCIDR checks, field for field. A value accepted
// here is exactly as injection-safe against unbound.conf/kea-dhcp4.conf as one
// that came in through the panel.
func validateNetsvcConfigRestore(raw string) error {
	var cfg netsvc.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("netsvc_config: JSON inválido: %w", err)
	}
	if cfg.Interface != "" && !validate.Iface(cfg.Interface) {
		return fmt.Errorf("netsvc_config: interface inválida: %q", cfg.Interface)
	}
	if cfg.SubnetCIDR != "" {
		if _, _, err := net.ParseCIDR(cfg.SubnetCIDR); err != nil {
			return fmt.Errorf("netsvc_config: sub-rede (subnet_cidr) inválida: %q", cfg.SubnetCIDR)
		}
	}
	for _, v := range []string{cfg.RangeStart, cfg.RangeEnd, cfg.Gateway} {
		if v != "" && net.ParseIP(v) == nil {
			return fmt.Errorf("netsvc_config: endereço IP inválido: %q", v)
		}
	}
	if cfg.DomainSuffix != "" && !validate.Domain(cfg.DomainSuffix) {
		return fmt.Errorf("netsvc_config: domínio (domain_suffix) inválido: %q", cfg.DomainSuffix)
	}
	for _, d := range cfg.DNSToClients {
		if d != "" && net.ParseIP(d) == nil {
			return fmt.Errorf("netsvc_config: DNS (dns_to_clients) inválido: %q", d)
		}
	}
	for _, u := range cfg.Upstreams {
		if u != "" && net.ParseIP(u) == nil {
			return fmt.Errorf("netsvc_config: upstream inválido: %q", u)
		}
	}
	return nil
}

// validateNTPConfigRestore parses an ntp_config settings blob and runs it
// through the same checks NTPHandler.UpdateNTPConfig applies (see ntp.go):
// validate.NTPServer per server, timesync.ValidateAllowedNetworks for the
// list — including its own "no open wildcard" guard. Timezone is
// deliberately NOT validated here: UpdateNTPConfig itself accepts it as
// free text today (input-validation-audit.md finding #12, a lower-severity,
// separate gap this fix does not close) — mirroring "the same validation
// the API applies" means mirroring that gap too, not inventing a new,
// stricter rule restore alone would enforce.
func validateNTPConfigRestore(raw string) error {
	var cfg timesync.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("ntp_config: JSON inválido: %w", err)
	}
	for _, srv := range cfg.Servers {
		if srv != "" && !validate.NTPServer(srv) {
			return fmt.Errorf("ntp_config: servidor NTP inválido: %q", srv)
		}
	}
	if err := timesync.ValidateAllowedNetworks(cfg.AllowedNetworks); err != nil {
		return fmt.Errorf("ntp_config: %w", err)
	}
	return nil
}

// validateMonitoringConfigRestore parses a monitoring settings blob into its
// typed struct. MonitoringHandler.SetConfig applies no field-level
// validation today (input-validation-audit.md finding #10, a separate,
// lower-severity gap this fix does not close) — so "the same validation the
// API applies" is, honestly, just the structural JSON check below. This is
// still worth doing: it rejects a blob whose shape doesn't match
// monitoring.Config at all (e.g. "services" sent as an object instead of an
// array) instead of writing a value LoadConfig would then have to silently
// paper over.
func validateMonitoringConfigRestore(raw string) error {
	var cfg monitoring.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("monitoring: JSON inválido: %w", err)
	}
	return nil
}

// Apply valida o backup inteiro e grava settings, reservas DHCP e blocklist de
// DNS numa transação só. Não reinicia serviço nenhum (o operador reaplica
// DHCP/DNS/firewall depois) e não toca em usuários/papéis nem em links WAN, de
// modo que uma restauração nunca tranca o operador para fora nem mexe no
// roteamento vivo.
//
// Ou vale inteira ou nada acontece, nos dois estágios: a validação recusa o
// arquivo antes de qualquer escrita (*ValidationError), e a escrita é uma
// transação (o erro sobe; o banco fica como estava).
//
// Chaves de settings fora de knownSettingsValidators são gravadas como vêm —
// decisão deliberada: a tabela de settings é o depósito de configuração do
// painel inteiro, e inventar aqui uma regra que o handler correspondente não
// aplica faria a restauração recusar valores que o painel aceita.
func Apply(db *storage.DB, data BackupData) (Result, error) {
	// Valida a carga inteira antes de gravar qualquer coisa — ver o comentário
	// de knownSettingsValidators. Um backup que falha aqui deixa o banco
	// exatamente como estava: nada abaixo deste ponto roda se algum check
	// acima não passou.
	for k, v := range data.Settings {
		if validateFn, ok := knownSettingsValidators[k]; ok {
			if err := validateFn(v); err != nil {
				return Result{}, invalid("backup contém %s inválido — nada foi restaurado: %s", k, err.Error())
			}
		}
	}
	normalizedBlocklist := make([]string, 0, len(data.Blocklist))
	for _, d := range data.Blocklist {
		nd := strings.ToLower(strings.TrimSpace(d))
		if !validate.Domain(nd) {
			return Result{}, invalid("backup contém domínio de bloqueio inválido — nada foi restaurado: %s", d)
		}
		normalizedBlocklist = append(normalizedBlocklist, nd)
	}
	normalizedReservations := make([]storage.DHCPReservation, 0, len(data.Reservations))
	for _, rsv := range data.Reservations {
		mac := validate.NormalizeMAC(rsv.MAC)
		if mac == "" {
			return Result{}, invalid("backup contém reserva DHCP com MAC inválido — nada foi restaurado: %s", rsv.MAC)
		}
		ip := strings.TrimSpace(rsv.IP)
		// Mesma guarda do handler (#152): o restore refaz o banco SEM passar por
		// ele, e todo campo em que este caminho for mais permissivo é um jeito
		// de plantar um valor que a tela nunca deixaria entrar. Um backup tirado
		// antes da guarda pode conter um endereço IPv6 aqui.
		if !validate.IPv4(ip) {
			return Result{}, invalid("backup contém reserva DHCP com endereço que não é IPv4 — nada foi restaurado: %s", rsv.IP)
		}
		normalizedReservations = append(normalizedReservations, storage.DHCPReservation{MAC: mac, IP: ip, Hostname: rsv.Hostname})
	}

	// As chaves de estado local da máquina saem antes da escrita — são estado
	// desta caixa, não configuração. Ver machineLocalSettingKeys para o que
	// cada uma faria com este equipamento se fosse restaurada.
	toRestore := make(map[string]string, len(data.Settings))
	skippedLocal := 0
	for k, v := range data.Settings {
		if machineLocalSettingKeys[k] {
			skippedLocal++
			continue
		}
		toRestore[k] = v
	}

	// Uma transação para as três coleções. Antes eram três laços com o erro
	// engolido e HTTP 200 no fim: uma falha de banco no meio deixava metade da
	// configuração restaurada e reportava sucesso, com um contador menor como
	// única pista. A promessa de "nada foi restaurado", que a validação acima
	// já fazia, agora vale também para a escrita.
	counts, err := db.ApplyRestore(storage.RestorePayload{
		Settings:     toRestore,
		Reservations: normalizedReservations,
		Blocklist:    normalizedBlocklist,
	})
	if err != nil {
		return Result{}, err
	}

	res := Result{
		Settings:     counts.Settings,
		Reservations: counts.Reservations,
		Blocklist:    counts.Blocklist,
		SkippedLocal: skippedLocal,
	}
	if skippedLocal > 0 {
		slog.Info("restore de backup: chaves de estado local da máquina ignoradas",
			"ignoradas", skippedLocal, "restauradas", res.Settings)
	}
	return res, nil
}

// ─── Trava por tentativas (força bruta na senha do backup) ───────────────────

const (
	// MaxRestoreAttempts é quantas senhas erradas seguidas um mesmo usuário
	// pode tentar antes da trava.
	MaxRestoreAttempts = 5
	// RestoreLockout é quanto tempo a trava dura.
	RestoreLockout = 5 * time.Minute
)

// restoreAttempts tracks consecutive wrong-passphrase restore attempts for a
// single authenticated user, so a lockout can kick in independently of IP
// (the restore endpoint already requires system.write, so "who" is always
// known — unlike login, which has no user identity to key on yet).
type restoreAttempts struct {
	count     int
	lockUntil time.Time
}

// RestoreLimiter é a proteção contra força bruta na senha do backup: conta
// tentativas erradas por usuário, tranca por RestoreLockout depois de
// MaxRestoreAttempts, e serializa as tentativas daquele usuário.
//
// A serialização não é enfeite. "checar trava" -> "decifrar (lento, scrypt)"
// -> "registrar falha" é uma sequência check-then-act partida em seções
// críticas separadas: N requisições simultâneas do *mesmo* usuário podem
// todas ler "não trancado" antes de qualquer uma registrar a falha, porque o
// decrypt no meio é caro de propósito. Isso deixava um atacante disparar
// tentativas em paralelo e furar o limite de 5 inteiro (confirmado 0/20
// bloqueadas na revisão da Task 11). Restore segura o mutex do usuário
// durante toda a sequência checar-decifrar-registrar-aplicar, então a próxima
// tentativa sempre enxerga a falha anterior já registrada. Usuários
// diferentes usam mutexes diferentes e não se serializam entre si — isto não
// é uma trava global de restauração.
//
// O zero value não serve; use NewRestoreLimiter.
type RestoreLimiter struct {
	mu       sync.Mutex
	attempts map[string]*restoreAttempts
	locks    map[string]*sync.Mutex
}

// NewRestoreLimiter creates an empty RestoreLimiter.
func NewRestoreLimiter() *RestoreLimiter {
	return &RestoreLimiter{
		attempts: map[string]*restoreAttempts{},
		locks:    map[string]*sync.Mutex{},
	}
}

// lockFor returns the per-userID mutex, creating it on first use.
func (l *RestoreLimiter) lockFor(userID string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := l.locks[userID]
	if m == nil {
		m = &sync.Mutex{}
		l.locks[userID] = m
	}
	return m
}

func (l *RestoreLimiter) lockedOut(userID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[userID]
	return a != nil && time.Now().Before(a.lockUntil)
}

// LockedOut informa se userID está trancado agora. É um atalho para quem quer
// recusar cedo, antes de gastar trabalho lendo a requisição — o handler HTTP
// usa isto para que um usuário trancado receba a mesma resposta de "tentativas
// demais" mesmo quando o corpo que ele mandou é inválido.
//
// Não substitui a checagem de Restore: esta lê fora do mutex do usuário e
// portanto é só um palpite momentâneo. A checagem que vale é a de Restore, que
// roda com o mutex daquele usuário na mão.
func (l *RestoreLimiter) LockedOut(userID string) bool { return l.lockedOut(userID) }

func (l *RestoreLimiter) recordFailure(userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[userID]
	if a == nil {
		a = &restoreAttempts{}
		l.attempts[userID] = a
	}
	a.count++
	if a.count >= MaxRestoreAttempts {
		a.lockUntil = time.Now().Add(RestoreLockout)
		a.count = 0
	}
}

func (l *RestoreLimiter) reset(userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, userID)
}

// Restore decifra o arquivo com a senha dada e aplica o backup, contando a
// tentativa na trava de força bruta de userID.
//
// A senha vem sempre de quem chama, nunca do segredo configurado localmente —
// o cenário principal de restauração é uma máquina *diferente* da que gerou o
// backup, então supor "a senha local tem que ser a mesma" estaria errado mais
// vezes do que certo.
//
// Erros que quem chama distingue: ErrLockedOut (tentativas demais),
// ErrBadPassphrase (senha errada ou arquivo que não é um backup),
// *ValidationError (backup recusado, nada gravado) e qualquer outro erro
// (falha de banco — a transação já reverteu, nada foi gravado).
func Restore(db *storage.DB, lim *RestoreLimiter, userID string, ciphertext []byte, passphrase string) (Result, error) {
	// Serializa por usuário: ver RestoreLimiter para por que isto é necessário
	// para fechar a corrida da trava, e por que é por usuário e não global.
	userLock := lim.lockFor(userID)
	userLock.Lock()
	defer userLock.Unlock()

	if lim.lockedOut(userID) {
		return Result{}, ErrLockedOut
	}
	data, err := DecryptRestore(ciphertext, passphrase)
	if err != nil {
		lim.recordFailure(userID)
		return Result{}, ErrBadPassphrase
	}
	lim.reset(userID)
	return Apply(db, data)
}
