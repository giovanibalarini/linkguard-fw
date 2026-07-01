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

	rebuildMu sync.Mutex
	lastSig   string // signature of the last-applied nexthop set (skip no-op rebuilds)
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

// Rebuild recomputes and applies the route. It is idempotent: if the desired
// nexthop set is unchanged since the last apply it does nothing (so the periodic
// reconcile is quiet). Used both on link state changes and on a timer, so a link
// whose interface comes back up is re-added even without an explicit event.
func (s *Service) Rebuild(ctx context.Context) error {
	cfg := s.LoadConfig()
	if cfg.Mode != ModeBalance {
		return nil
	}

	s.rebuildMu.Lock()
	defer s.rebuildMu.Unlock()

	plan, err := s.planWith(ctx, cfg)
	if err != nil {
		return err
	}
	sig := routeSignature(plan.Nexthops)
	if sig == s.lastSig {
		return nil // nothing changed
	}
	if len(plan.Nexthops) == 0 {
		s.lastSig = sig // remember the empty state so we alert only once
		_ = s.alertSvc.RuleError("Balanceamento: nenhuma interface WAN ativa — rota mantida")
		return fmt.Errorf("no up interfaces")
	}
	args := buildReplaceArgs(cfg.Table, plan.Nexthops)
	if _, err := s.exec.Execute(ctx, "ip", args...); err != nil {
		return fmt.Errorf("rebuild route: %w", err) // keep lastSig so we retry next tick
	}
	s.lastSig = sig
	slog.Info("balancer: rebuilt multipath default", "table", cfg.Table, "nexthops", len(plan.Nexthops))
	return nil
}

// routeSignature is a stable fingerprint of a nexthop set (link + weight),
// used to skip no-op rebuilds.
func routeSignature(nhs []Nexthop) string {
	parts := make([]string, len(nhs))
	for i, n := range nhs {
		parts[i] = fmt.Sprintf("%s:%d", n.LinkID, n.Weight)
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

// EnsureSteerRouting applies the host-steering policy routing idempotently. Safe
// to call repeatedly (startup + reconcile). No-op unless a wan_steer setting is
// present and enabled.
func (s *Service) EnsureSteerRouting(ctx context.Context) {
	raw, _ := s.db.GetSetting(steerKey)
	if raw == "" {
		return
	}
	var c SteerConfig
	if json.Unmarshal([]byte(raw), &c) != nil || !c.Enabled || c.Table == "" {
		return
	}
	if c.Gateway != "" && c.Interface != "" {
		_, _ = s.exec.Execute(ctx, "ip", "route", "replace", "default",
			"via", c.Gateway, "dev", c.Interface, "onlink", "table", c.Table)
	}
	if c.LanCIDR != "" && c.LanVia != "" && c.LanDev != "" {
		_, _ = s.exec.Execute(ctx, "ip", "route", "replace", c.LanCIDR,
			"via", c.LanVia, "dev", c.LanDev, "table", c.Table)
	}
	if c.Mark != "" {
		out, _ := s.exec.ExecuteRead(ctx, "ip", "rule", "show")
		// Rule lines look like: "32765:\tfrom all fwmark 0x12c lookup sumicity".
		if !(strings.Contains(out, "fwmark "+c.Mark) && strings.Contains(out, "lookup "+c.Table)) {
			args := []string{"rule", "add", "fwmark", c.Mark, "lookup", c.Table}
			if c.Priority > 0 {
				args = append(args, "priority", fmt.Sprintf("%d", c.Priority))
			}
			_, _ = s.exec.Execute(ctx, "ip", args...)
		}
	}
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
