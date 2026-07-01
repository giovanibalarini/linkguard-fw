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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const (
	settingKey      = "routing_balance"
	defaultTable    = "main"
	defaultArmSecs  = 90
	maxKernelWeight = 256 // Linux multipath nexthop weight range is 1..256.
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

	mu      sync.Mutex
	pending *pendingRollback

	schedMu   sync.Mutex
	lastFired map[string]string // schedule ID -> "2006-01-02 15:04" last applied
}

// NewService creates a balancer Service.
func NewService(db *storage.DB, exec firewall.Executor, linkSvc *links.Service, alertSvc *alerts.Service) *Service {
	return &Service{db: db, exec: exec, linkSvc: linkSvc, alertSvc: alertSvc, lastFired: map[string]string{}}
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

// Rebuild recomputes and applies the route without arming a rollback. Used by
// the link monitor when a WAN changes state while in balance mode.
func (s *Service) Rebuild(ctx context.Context) error {
	cfg := s.LoadConfig()
	if cfg.Mode != ModeBalance {
		return nil
	}
	plan, err := s.planWith(ctx, cfg)
	if err != nil {
		return err
	}
	if len(plan.Nexthops) == 0 {
		_ = s.alertSvc.RuleError("Balanceamento: nenhum link WAN online — rota mantida")
		return fmt.Errorf("no online links")
	}
	args := buildReplaceArgs(cfg.Table, plan.Nexthops)
	if _, err := s.exec.Execute(ctx, "ip", args...); err != nil {
		return fmt.Errorf("rebuild route: %w", err)
	}
	slog.Info("balancer: rebuilt multipath default", "table", cfg.Table, "nexthops", len(plan.Nexthops))
	return nil
}

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
		_ = s.alertSvc.LinkDegraded(link.Name, link.ID)
	}

	if err := s.Rebuild(ctx); err != nil {
		slog.Warn("balancer: rebuild on link change failed", "link", link.Name, "err", err)
	}
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

// selectNexthops applies the degradation-aware policy, over links whose
// interface is physically UP (a down interface can never be a valid nexthop —
// `ip route replace` rejects the whole command otherwise):
//   - any healthy (online) link → use ONLY those (degraded links sit out);
//   - else any degraded link → the single LEAST-degraded (lowest loss, then
//     latency), stay until one normalizes;
//   - else any UP interface whose probe is failing (stale/soft) → use it anyway
//     as a SAFETY NET rather than leave an empty default (which would black-hole
//     all traffic incl. DNS). The kernel still routes around truly-dead paths.
//
// ifaceUp maps interface name → physically up; a nil map means "unknown", in
// which case no interface filtering is applied.
func selectNexthops(all []storage.Link, ifaceUp map[string]bool) (chosen, excluded []Nexthop) {
	isUp := func(iface string) bool { return ifaceUp == nil || ifaceUp[iface] }

	healthy, degraded, upOthers := []Nexthop{}, []Nexthop{}, []Nexthop{}
	excluded = []Nexthop{}
	for _, l := range all {
		if !l.Enabled || l.Gateway == "" || l.Interface == "" {
			if l.Gateway != "" || l.Interface != "" {
				excluded = append(excluded, toNexthop(l))
			}
			continue
		}
		nh := toNexthop(l)
		if !isUp(l.Interface) { // interface down → never a nexthop
			excluded = append(excluded, nh)
			continue
		}
		switch l.Status {
		case links.StatusOnline:
			healthy = append(healthy, nh)
		case links.StatusDegraded:
			degraded = append(degraded, nh)
		default:
			upOthers = append(upOthers, nh)
		}
	}

	switch {
	case len(healthy) > 0:
		chosen = healthy
		excluded = append(excluded, degraded...)
		excluded = append(excluded, upOthers...)
	case len(degraded) > 0:
		sort.Slice(degraded, func(i, j int) bool {
			if degraded[i].PacketLoss != degraded[j].PacketLoss {
				return degraded[i].PacketLoss < degraded[j].PacketLoss
			}
			return degraded[i].LatencyMs < degraded[j].LatencyMs
		})
		chosen = degraded[:1:1]
		excluded = append(excluded, degraded[1:]...)
		excluded = append(excluded, upOthers...)
	case len(upOthers) > 0:
		chosen = upOthers // safety net: never leave an empty default
	default:
		chosen = []Nexthop{}
	}

	normalizeWeights(chosen)
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
		if len(f) >= 2 && f[1] == "UP" {
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
