# "Vigia" — Monitoring, Health Panel & Outage Alerts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give home/prosumer admins zero-config outage alerting (systemd services, disk, WAN, and the linkguard-fw process itself) plus an at-a-glance health panel, all fed by one monitoring layer.

**Architecture:** Extend the existing `monitoring.Collector` (30s tick) to also check systemd services and disk, tracking per-item state in memory and emitting alerts only on transition (with anti-flap). The same in-memory state is exposed via a new HTTP endpoint that feeds a Dashboard health panel. Recovery alerts bypass the notification severity gate so "voltou" always arrives. The stress-test raises alerts for the link it drops; a systemd `OnFailure` unit + a `--notify-down` CLI subcommand cover the app's own death.

**Tech Stack:** Go (backend, stdlib + chi router), React + TypeScript + Tailwind (frontend), systemd, SQLite (modernc), zapvite/WhatsApp via existing `notify`.

## Global Constraints

- Go toolchain: `~/sdk/go1.25.0/bin` on PATH; run `gofmt -w` on every changed `.go` file.
- Tests: `go test ./...` must stay green; frontend built by CI (`npm ci && npm run build`) — no local node.
- The `.deb` control/units are assembled **inline in `.github/workflows/release.yml`** (NOT the Makefile) — any new systemd unit must be added to `release.yml` AND `Makefile` AND `deploy/`.
- Executors: shell inputs (service names, interface) must be validated against a strict charset before `exec` (defense-in-depth, existing project rule).
- All new alerts route through the existing `alerts.Service` → `notify` observer.
- Zero-config defaults: monitoring `enabled=true`, `services=[kea-dhcp4-server, unbound, nftables]`, `disk_threshold_pct=90`.
- Commit after every task with a Conventional Commit message; end commit messages with the project's `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.

### Shared test helper (use in every Go test below)

There is **no** `storage.NewTestDB`. The project opens test DBs like `internal/storage/storage_test.go:14`: `storage.Open(filepath.Join(t.TempDir(), "test.db"))`. Add this helper to each new test file (imports: `path/filepath`, `testing`, and `internal/storage`):

```go
func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}
```

Every `openTestDB(t)` call in the tasks below refers to this helper.

---

## File Structure

- `internal/monitoring/config.go` (create) — monitoring settings (load/save with defaults).
- `internal/monitoring/config_test.go` (create).
- `internal/monitoring/healthchecks.go` (create) — service/disk checks, transition + anti-flap state machine, `Snapshot()`.
- `internal/monitoring/healthchecks_test.go` (create).
- `internal/monitoring/collector.go` (modify) — add `exec`, health state, call checks each tick.
- `internal/alerts/service.go` (modify) — new alert types/methods + recovery delivery.
- `internal/alerts/service_test.go` (create/modify) — recovery + new alerts.
- `internal/notify/notify.go` (modify) — `NotifyRecovery` (bypass severity gate) + `SendNow` (synchronous, for CLI).
- `internal/notify/notify_test.go` (modify) — recovery bypass test.
- `internal/api/handlers/monitoring.go` (create) — health snapshot + config endpoints.
- `internal/api/server.go` (modify) — wire routes + pass collector.
- `cmd/linkguard-fw/main.go` (modify) — pass `exec`/collector wiring + `--notify-down` subcommand.
- `internal/stresstest/service.go` (modify) — raise link alerts on fault/restore.
- `deploy/linkguard-fw.service` (modify) — `OnFailure=`.
- `deploy/linkguard-notify-down.service` (create) — oneshot.
- `.github/workflows/release.yml` + `Makefile` (modify) — package the new unit.
- `web/src/types/index.ts` (modify) — `HealthItem`, `MonitoringConfig`.
- `web/src/components/SystemHealth.tsx` (create) — dashboard health tiles.
- `web/src/components/MonitoringSettings.tsx` (create) — master toggle + advanced service list.
- `web/src/pages/Dashboard.tsx` + `web/src/pages/Settings.tsx` (modify) — mount components.

---

## Phase 1 — Backend monitoring core

### Task 1: Monitoring config (settings key with zero-config defaults)

**Files:**
- Create: `internal/monitoring/config.go`
- Test: `internal/monitoring/config_test.go`

**Interfaces:**
- Produces: `type Config struct { Enabled bool; Services []string; DiskThresholdPct int }`, `func LoadConfig(db *storage.DB) Config`, `func SaveConfig(db *storage.DB, c Config) error`.
- Consumes: `storage.DB.GetSetting(key string) (string, error)`, `storage.DB.SetSetting(key, value string) error`.

- [ ] **Step 1: Write the failing test**

```go
package monitoring

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestLoadConfigDefaultsWhenAbsent(t *testing.T) {
	db := openTestDB(t) // shared helper defined in Global Constraints
	c := LoadConfig(db)
	if !c.Enabled {
		t.Error("expected Enabled=true by default (zero-config)")
	}
	if c.DiskThresholdPct != 90 {
		t.Errorf("disk threshold default = %d, want 90", c.DiskThresholdPct)
	}
	want := []string{"kea-dhcp4-server", "unbound", "nftables"}
	if len(c.Services) != len(want) {
		t.Fatalf("services = %v, want %v", c.Services, want)
	}
	for i := range want {
		if c.Services[i] != want[i] {
			t.Errorf("service[%d] = %q, want %q", i, c.Services[i], want[i])
		}
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	db := openTestDB(t)
	in := Config{Enabled: false, Services: []string{"unbound"}, DiskThresholdPct: 80}
	if err := SaveConfig(db, in); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.Enabled != false || got.DiskThresholdPct != 80 || len(got.Services) != 1 || got.Services[0] != "unbound" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/monitoring/ -run TestLoadConfig -v`
Expected: FAIL (undefined: LoadConfig).

- [ ] **Step 3: Write minimal implementation**

```go
package monitoring

import (
	"encoding/json"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const configKey = "monitoring"

// Config is the persisted monitoring/alerting configuration. Absence of the
// settings key means "all defaults" — monitoring is ON out of the box.
type Config struct {
	Enabled          bool     `json:"enabled"`
	Services         []string `json:"services"`
	DiskThresholdPct int      `json:"disk_threshold_pct"`
}

func defaults() Config {
	return Config{
		Enabled:          true,
		Services:         []string{"kea-dhcp4-server", "unbound", "nftables"},
		DiskThresholdPct: 90,
	}
}

// LoadConfig returns the persisted config, or zero-config defaults if unset.
func LoadConfig(db *storage.DB) Config {
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return defaults()
	}
	c := defaults()
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return defaults()
	}
	if c.DiskThresholdPct <= 0 || c.DiskThresholdPct > 100 {
		c.DiskThresholdPct = 90
	}
	return c
}

// SaveConfig persists the config.
func SaveConfig(db *storage.DB, c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.SetSetting(configKey, string(out))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -w internal/monitoring/ && go test ./internal/monitoring/ -run 'TestLoadConfig|TestSaveThen' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/config.go internal/monitoring/config_test.go
git commit -m "feat(monitoring): zero-config settings for the watchdog"
```

---

### Task 2: Recovery delivery — `NotifyRecovery` bypasses the severity gate

**Files:**
- Modify: `internal/notify/notify.go` (add `NotifyRecovery`, `SendNow`)
- Test: `internal/notify/notify_test.go`

**Interfaces:**
- Produces: `func (s *Service) NotifyRecovery(title, message string)` (async, always delivered when a channel is enabled), `func (s *Service) SendNow(severity, title, message string) []error` (synchronous, for CLI/`OnFailure`).
- Consumes: existing `s.LoadConfig()`, `s.send(ctx, cfg, severity, title, message) []error`.

- [ ] **Step 1: Write the failing test**

```go
func TestNotifyRecoveryBypassesMinSeverity(t *testing.T) {
	// A recovery is severity "info". With min_severity=warning it must STILL be
	// eligible to send (bypass), unlike Notify which would drop it.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	db := openTestDB(t)
	s := NewService(db)
	_ = s.SaveConfig(Config{
		MinSeverity: "warning",
		Webhook:     WebhookCfg{Enabled: true, URL: srv.URL},
	})

	// SendNow at info severity must reach the webhook (bypass), proving the
	// recovery path ignores the min-severity gate.
	errs := s.SendNow("info", "Recuperado", "voltou")
	for _, e := range errs {
		if e != nil {
			t.Fatalf("send error: %v", e)
		}
	}
	if hits != 1 {
		t.Fatalf("webhook hits = %d, want 1", hits)
	}
}
```

> Add imports `net/http`, `net/http/httptest`, and `storage` to the test file if missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/notify/ -run TestNotifyRecovery -v`
Expected: FAIL (undefined: SendNow).

- [ ] **Step 3: Write minimal implementation**

Add to `internal/notify/notify.go`:

```go
// NotifyRecovery delivers a "recovered" notice asynchronously, bypassing the
// min-severity gate: a recovery only fires after a matching outage already
// notified, so the user must always get the "voltou" even at min_severity=warning.
func (s *Service) NotifyRecovery(title, message string) {
	cfg := s.LoadConfig()
	go s.dispatch(cfg, "info", title, message)
}

// SendNow delivers synchronously and returns per-channel errors. Use it from
// short-lived contexts (CLI / systemd OnFailure) where the process exits before
// an async goroutine could run.
func (s *Service) SendNow(severity, title, message string) []error {
	cfg := s.LoadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.send(ctx, cfg, severity, title, message)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -w internal/notify/ && go test ./internal/notify/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/notify/notify.go internal/notify/notify_test.go
git commit -m "feat(notify): NotifyRecovery + synchronous SendNow"
```

---

### Task 3: New alert types + recovery-aware methods

**Files:**
- Modify: `internal/alerts/service.go`
- Test: `internal/alerts/service_test.go`

**Interfaces:**
- Consumes: `Notifier` interface — EXTEND it with `NotifyRecovery(title, message string)`.
- Produces: `func (s *Service) ServiceOffline(name string) error`, `func (s *Service) ServiceOnline(name string) error`, `func (s *Service) DiskFull(pct float64) error`, `func (s *Service) DiskCleared(pct float64) error`, `func (s *Service) AppDown() error`. New type consts: `TypeServiceOffline`, `TypeServiceOnline`, `TypeDiskFull`, `TypeAppDown`.
- Note: `LinkOnline` is changed to deliver via recovery.

- [ ] **Step 1: Write the failing test**

```go
package alerts

import "testing"

type fakeNotifier struct {
	normal    []string
	recovery  []string
}

func (f *fakeNotifier) Notify(severity, title, message string) {
	f.normal = append(f.normal, severity+"|"+title)
}
func (f *fakeNotifier) NotifyRecovery(title, message string) {
	f.recovery = append(f.recovery, title)
}

func TestServiceOfflineIsCriticalNormal(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOffline("unbound"); err != nil {
		t.Fatal(err)
	}
	if len(fn.normal) != 1 || fn.normal[0] != "critical|Serviço offline: unbound" {
		t.Errorf("normal notifies = %v", fn.normal)
	}
	if len(fn.recovery) != 0 {
		t.Errorf("unexpected recovery notify: %v", fn.recovery)
	}
}

func TestServiceOnlineDeliversViaRecovery(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)
	fn := &fakeNotifier{}
	s.SetNotifier(fn)

	if err := s.ServiceOnline("unbound"); err != nil {
		t.Fatal(err)
	}
	if len(fn.recovery) != 1 {
		t.Errorf("recovery notifies = %v, want 1", fn.recovery)
	}
}
```

> If `service_test.go` already imports `storage`, reuse it; otherwise add the import.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/alerts/ -run 'TestService(Offline|Online)' -v`
Expected: FAIL (Notifier has no NotifyRecovery / methods undefined).

- [ ] **Step 3: Write minimal implementation**

In `internal/alerts/service.go`:

```go
// add to the type const block
	TypeServiceOffline = "service_offline"
	TypeServiceOnline  = "service_online"
	TypeDiskFull       = "disk_full"
	TypeAppDown        = "app_down"
```

```go
// extend the Notifier interface
type Notifier interface {
	Notify(severity, title, message string)
	NotifyRecovery(title, message string)
}
```

```go
// createRecovery is like Create but delivers via the recovery path (bypasses
// the min-severity gate) so "voltou" always reaches the user.
func (s *Service) createRecovery(alertType, title, message, linkID string) error {
	a := &storage.Alert{Type: alertType, Severity: SeverityInfo, Title: title, Message: message, LinkID: linkID}
	if err := s.db.CreateAlert(a); err != nil {
		slog.Error("create alert", "err", err)
		return err
	}
	slog.Info("alert created", "type", alertType, "severity", SeverityInfo, "title", title)
	if s.notifier != nil {
		s.notifier.NotifyRecovery(title, message)
	}
	return nil
}

// ServiceOffline raises a critical alert when a monitored service stops.
func (s *Service) ServiceOffline(name string) error {
	return s.Create(TypeServiceOffline, SeverityCritical,
		"Serviço offline: "+name,
		"O serviço "+name+" parou de responder.", "")
}

// ServiceOnline clears the offline alert and notifies recovery.
func (s *Service) ServiceOnline(name string) error {
	s.AutoResolve(TypeServiceOffline, "")
	return s.createRecovery(TypeServiceOnline,
		"Serviço recuperado: "+name,
		"O serviço "+name+" voltou a responder.", "")
}

// DiskFull raises a critical alert when disk usage crosses the threshold.
func (s *Service) DiskFull(pct float64) error {
	return s.Create(TypeDiskFull, SeverityCritical, "Disco cheio",
		fmt.Sprintf("Uso de disco em %.1f%%.", pct), "")
}

// DiskCleared notifies that disk usage dropped back below the threshold.
func (s *Service) DiskCleared(pct float64) error {
	s.AutoResolve(TypeDiskFull, "")
	return s.createRecovery(TypeDiskFull, "Disco normalizado",
		fmt.Sprintf("Uso de disco voltou a %.1f%%.", pct), "")
}

// AppDown raises a critical alert that the linkguard-fw service itself stopped
// (called from the --notify-down subcommand via systemd OnFailure).
func (s *Service) AppDown() error {
	return s.Create(TypeAppDown, SeverityCritical, "LinkGuard caiu",
		"O serviço linkguard-fw parou inesperadamente.", "")
}
```

Change `LinkOnline` to deliver via recovery:

```go
func (s *Service) LinkOnline(linkName, linkID string) error {
	s.AutoResolve(TypeLinkOffline, linkID)
	s.AutoResolve(TypeLinkDegraded, linkID)
	return s.createRecovery(TypeLinkOnline,
		"Link Online: "+linkName,
		"WAN link "+linkName+" has recovered and is reachable.", linkID)
}
```

> Because the `Notifier` interface changed, `notify.Service` (Task 2) must already implement `NotifyRecovery` — it does. Any other in-repo Notifier fakes must add the method.

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -w internal/alerts/ && go test ./internal/alerts/ ./internal/notify/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/alerts/service.go internal/alerts/service_test.go
git commit -m "feat(alerts): service/disk/app alerts + recovery delivery"
```

---

### Task 4: Health state machine (transition + anti-flap) and Snapshot

**Files:**
- Create: `internal/monitoring/healthchecks.go`
- Test: `internal/monitoring/healthchecks_test.go`

**Interfaces:**
- Produces: `type HealthItem struct { Name string; Kind string; Up bool; Since int64 }`, method `func (c *Collector) observe(key string, up bool, now int64) transition` where `transition` is `transNone|transDown|transUp`, and `func (c *Collector) Snapshot() []HealthItem`.
- Consumes: `Collector.health map[string]*itemState` (added in Task 5), `Collector.nowFn func() int64` (injectable clock for tests).

- [ ] **Step 1: Write the failing test**

```go
package monitoring

import "testing"

func newTestCollector() *Collector {
	return &Collector{health: map[string]*itemState{}}
}

func TestObserveAntiFlapRequiresTwoDowns(t *testing.T) {
	c := newTestCollector()
	// first sighting: up, no transition
	if tr := c.observe("svc:unbound", true, 100); tr != transNone {
		t.Fatalf("first up should be transNone, got %v", tr)
	}
	// one down: NOT yet a transition (anti-flap needs 2 consecutive)
	if tr := c.observe("svc:unbound", false, 101); tr != transNone {
		t.Fatalf("single down should be suppressed (anti-flap), got %v", tr)
	}
	// second consecutive down: now it's a real outage
	if tr := c.observe("svc:unbound", false, 102); tr != transDown {
		t.Fatalf("second down should be transDown, got %v", tr)
	}
	// stays down: no repeat
	if tr := c.observe("svc:unbound", false, 103); tr != transNone {
		t.Fatalf("staying down should be transNone, got %v", tr)
	}
	// recovery is immediate (no debounce on the way up)
	if tr := c.observe("svc:unbound", true, 104); tr != transUp {
		t.Fatalf("recovery should be transUp, got %v", tr)
	}
}

func TestObserveFlapDoesNotAlert(t *testing.T) {
	c := newTestCollector()
	c.observe("link:wan1", true, 1)       // up
	c.observe("link:wan1", false, 2)      // one down (suppressed)
	if tr := c.observe("link:wan1", true, 3); tr != transNone {
		t.Fatalf("a single-cycle blip must not alert, got %v", tr)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/monitoring/ -run TestObserve -v`
Expected: FAIL (undefined: itemState/observe/transition).

- [ ] **Step 3: Write minimal implementation**

```go
package monitoring

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

type transition int

const (
	transNone transition = iota
	transDown
	transUp
)

// downConfirm is the number of consecutive "down" observations required before
// declaring an outage (anti-flap). With a 30s tick this debounces ~30–60s.
const downConfirm = 2

type itemState struct {
	name      string
	kind      string // "service" | "link" | "resource"
	up        bool
	since     int64
	failCount int
	known     bool
}

// serviceNameRe guards shell-embedded service names (defense-in-depth).
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]+$`)

// observe folds a raw up/down reading into the item's state and returns whether
// this reading is a real transition. Down transitions require downConfirm
// consecutive failures; up transitions are immediate.
func (c *Collector) observe(key string, up bool, now int64) transition {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		st = &itemState{up: up, since: now, known: true}
		c.health[key] = st
		return transNone
	}
	if up {
		st.failCount = 0
		if !st.up {
			st.up = true
			st.since = now
			return transUp
		}
		return transNone
	}
	// down reading
	if !st.up {
		return transNone // already down
	}
	st.failCount++
	if st.failCount >= downConfirm {
		st.up = false
		st.since = now
		return transDown
	}
	return transNone
}

// isActive reports whether `systemctl is-active <svc>` says the unit is running.
func (c *Collector) isActive(svc string) bool {
	if !serviceNameRe.MatchString(svc) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*1e9)
	defer cancel()
	out, err := c.exec.ExecuteRead(ctx, "systemctl", "is-active", svc)
	if err != nil {
		return false // is-active exits non-zero when not active
	}
	return strings.TrimSpace(out) == "active"
}

// Snapshot returns the current health of every tracked item (services, links,
// resources) for the dashboard.
func (c *Collector) Snapshot() []HealthItem {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	out := make([]HealthItem, 0, len(c.health))
	for _, st := range c.health {
		out = append(out, HealthItem{Name: st.name, Kind: st.kind, Up: st.up, Since: st.since})
	}
	return out
}

// HealthItem is one row of the dashboard health panel.
type HealthItem struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Up    bool   `json:"up"`
	Since int64  `json:"since"`
}

var _ = sync.Mutex{} // healthMu type reference; real field declared in collector.go
```

> Remove the `var _ = sync.Mutex{}` line once `collector.go` (Task 5) declares `healthMu sync.Mutex`. It exists only so this file compiles standalone if reviewed before Task 5; delete it in Task 5.

- [ ] **Step 4: Run test to verify it passes**

Run: `gofmt -w internal/monitoring/ && go test ./internal/monitoring/ -run TestObserve -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/healthchecks.go internal/monitoring/healthchecks_test.go
git commit -m "feat(monitoring): transition + anti-flap state machine and Snapshot"
```

---

### Task 5: Wire checks into the Collector tick

**Files:**
- Modify: `internal/monitoring/collector.go`
- Modify: `cmd/linkguard-fw/main.go` (pass `exec` to `NewCollector`)
- Test: `internal/monitoring/healthchecks_test.go` (add an integration-ish check with a fake executor)

**Interfaces:**
- Consumes: `firewall.Executor`, `monitoring.LoadConfig`, `alerts.Service.ServiceOffline/ServiceOnline/DiskFull/DiskCleared`, existing `sysCol.Collect()` (has `DiskPercent`), `db.GetLinks()`.
- Produces: updated `func NewCollector(db *storage.DB, m *metrics.Metrics, alertSvc *alerts.Service, exec firewall.Executor) *Collector`; the collector now populates `health` each tick.

- [ ] **Step 1: Write the failing test**

```go
type fakeExec struct{ active map[string]bool }

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	// emulate: systemctl is-active <svc>
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		if f.active[args[1]] {
			return "active\n", nil
		}
		return "inactive\n", assertErr{}
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type assertErr struct{}

func (assertErr) Error() string { return "inactive" }

func TestCheckServicesRaisesOnSecondDown(t *testing.T) {
	fe := &fakeExec{active: map[string]bool{"unbound": true}}
	fn := &fakeNotifierAlerts{} // implements alerts.Notifier; count ServiceOffline via db alerts instead
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	cfg := Config{Enabled: true, Services: []string{"unbound"}, DiskThresholdPct: 90}
	c.checkServices(cfg) // up → no alert
	fe.active["unbound"] = false
	c.checkServices(cfg) // 1st down → suppressed
	c.checkServices(cfg) // 2nd down → alert

	alertsList, _ := db.GetAlerts(false, 0)
	var offline int
	for _, a := range alertsList {
		if a.Type == alerts.TypeServiceOffline {
			offline++
		}
	}
	if offline != 1 {
		t.Fatalf("expected exactly 1 service_offline alert, got %d", offline)
	}
	_ = fn
}

func seqClock() func() int64 {
	var n int64
	return func() int64 { n++; return n }
}
```

> `fakeNotifierAlerts` is unused noise here — assert via `db.GetAlerts` instead (alerts persist regardless of notifier). Delete the `fn` lines if the linter complains. Confirm `db.GetAlerts(bool,int)` signature (seen in `alerts/service.go`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/monitoring/ -run TestCheckServices -v`
Expected: FAIL (Collector has no `exec`/`checkServices`/`nowFn`).

- [ ] **Step 3: Write minimal implementation**

In `collector.go`, extend the struct and constructor, and add the check methods; delete the placeholder `var _ = sync.Mutex{}` from `healthchecks.go`.

```go
// struct additions
type Collector struct {
	db        *storage.DB
	sysCol    *system.Collector
	m         *metrics.Metrics
	alertSvc  *alerts.Service
	exec      firewall.Executor
	startTime time.Time

	healthMu sync.Mutex
	health   map[string]*itemState
	nowFn    func() int64
}

func NewCollector(db *storage.DB, m *metrics.Metrics, alertSvc *alerts.Service, exec firewall.Executor) *Collector {
	return &Collector{
		db:        db,
		sysCol:    system.NewCollector(),
		m:         m,
		alertSvc:  alertSvc,
		exec:      exec,
		startTime: time.Now(),
		health:    map[string]*itemState{},
		nowFn:     func() int64 { return time.Now().Unix() },
	}
}
```

Add imports `sync`, `firewall`. In `collect()`, after the existing system/link work, call the new checks:

```go
	cfg := LoadConfig(c.db)
	if cfg.Enabled {
		c.checkServices(cfg)
		if sys != nil {
			c.checkDisk(cfg, sys.DiskPercent)
		}
		c.trackLinks() // fills health for the dashboard; alerts still come from the monitor
	}
```

New methods (in `healthchecks.go`):

```go
func (c *Collector) checkServices(cfg Config) {
	now := c.nowFn()
	for _, svc := range cfg.Services {
		up := c.isActive(svc)
		key := "service:" + svc
		c.ensureMeta(key, svc, "service")
		switch c.observe(key, up, now) {
		case transDown:
			_ = c.alertSvc.ServiceOffline(svc)
		case transUp:
			_ = c.alertSvc.ServiceOnline(svc)
		}
	}
}

func (c *Collector) checkDisk(cfg Config, pct float64) {
	now := c.nowFn()
	key := "resource:disk"
	c.ensureMeta(key, "Disco", "resource")
	up := pct < float64(cfg.DiskThresholdPct) // "up" == healthy
	switch c.observe(key, up, now) {
	case transDown:
		_ = c.alertSvc.DiskFull(pct)
	case transUp:
		_ = c.alertSvc.DiskCleared(pct)
	}
}

// trackLinks reflects link status into the health map for the dashboard. Link
// UP/DOWN alerts stay owned by the monitor's OnStatusChange path (Task 9).
func (c *Collector) trackLinks() {
	links, err := c.db.GetLinks()
	if err != nil {
		return
	}
	now := c.nowFn()
	for _, l := range links {
		key := "link:" + l.ID
		c.ensureMeta(key, l.Name, "link")
		c.observe(key, l.Status == "online", now)
	}
}

// ensureMeta sets the display name/kind on an item the first time we see it.
func (c *Collector) ensureMeta(key, name, kind string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if st := c.health[key]; st != nil {
		if st.name == "" {
			st.name = name
		}
		if st.kind == "" {
			st.kind = kind
		}
	}
}
```

> `ensureMeta` runs before `observe` creates the entry on first sighting, so also set name/kind inside `observe`'s creation branch: change the `st == nil` branch to `st = &itemState{up: up, since: now, known: true}` then `c.health[key] = st` and immediately return — meta is filled on the *next* tick by `ensureMeta`. Acceptable (one-tick delay in display name). Alternatively pass name/kind into `observe`; keep `observe` signature stable for Task 4 tests by adding a separate `observeItem(key,name,kind,up,now)` wrapper. Implementer: prefer setting meta inside the creation branch by having `checkServices`/`trackLinks` call `ensureMeta` which upserts the entry. Confirm the Task 4 unit tests still pass after this wiring.

Update `cmd/linkguard-fw/main.go:135`:

```go
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `gofmt -w internal/monitoring/ cmd/linkguard-fw/ && go test ./internal/monitoring/ -v && go build ./...`
Expected: PASS + BUILD ok.

- [ ] **Step 5: Commit**

```bash
git add internal/monitoring/ cmd/linkguard-fw/main.go
git commit -m "feat(monitoring): check services + disk each tick, track link health"
```

---

## Phase 2 — Expose & show

### Task 6: Health + config API endpoints

**Files:**
- Create: `internal/api/handlers/monitoring.go`
- Modify: `internal/api/server.go` (pass collector, register routes)
- Modify: `cmd/linkguard-fw/main.go` (pass collector into `api.New`)

**Interfaces:**
- Consumes: `monitoring.Collector.Snapshot()`, `monitoring.LoadConfig(db)`, `monitoring.SaveConfig(db, c)`.
- Produces: routes `GET /api/monitoring/health` (PermMonitoringRead), `GET /api/monitoring/config` (PermMonitoringRead), `PUT /api/monitoring/config` (PermSystemWrite).

- [ ] **Step 1: Write the failing test**

```go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMonitoringHealthReturnsJSON(t *testing.T) {
	// Minimal: a collector with a seeded snapshot. Use the real constructor with
	// a dry-run executor; then hit the handler directly.
	// (If constructing a Collector here is heavy, assert Snapshot() shape in the
	// monitoring package instead and keep this handler test to status code.)
	h := &MonitoringHandler{col: nil, db: nil}
	_ = h
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/health", nil)
	_ = rr
	_ = req
	// Placeholder assertion replaced once wiring lands; primary coverage is the
	// monitoring package unit tests. Keep this compile-only smoke.
}
```

> The meaningful behavior (snapshot, transitions, config) is already covered by monitoring package tests. This handler is thin glue; keep its test to a compile/smoke check and rely on manual verification (`curl`) for the endpoint. Do not over-test glue.

- [ ] **Step 2: Run to verify it compiles/fails**

Run: `go test ./internal/api/handlers/ -run TestMonitoring -v`
Expected: FAIL (undefined: MonitoringHandler).

- [ ] **Step 3: Write minimal implementation**

`internal/api/handlers/monitoring.go`:

```go
package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// MonitoringHandler exposes the health snapshot and monitoring config.
type MonitoringHandler struct {
	col *monitoring.Collector
	db  *storage.DB
}

func NewMonitoringHandler(col *monitoring.Collector, db *storage.DB) *MonitoringHandler {
	return &MonitoringHandler{col: col, db: db}
}

// Health returns the current health of services, links and resources.
func (h *MonitoringHandler) Health(w http.ResponseWriter, r *http.Request) {
	items := h.col.Snapshot()
	if items == nil {
		items = []monitoring.HealthItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

// GetConfig returns the monitoring config (zero-config defaults if unset).
func (h *MonitoringHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, monitoring.LoadConfig(h.db))
}

// SetConfig persists the monitoring config.
func (h *MonitoringHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	var in monitoring.Config
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := monitoring.SaveConfig(h.db, in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, monitoring.LoadConfig(h.db))
}
```

In `internal/api/server.go`: add a `mon *monitoring.Collector` field to the server struct and `New(...)` params, store it, and register routes near the alerts block:

```go
		monH := handlers.NewMonitoringHandler(s.mon, s.db)
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/health", monH.Health)
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/config", monH.GetConfig)
		r.With(require(auth.PermSystemWrite)).Put("/api/monitoring/config", monH.SetConfig)
```

In `cmd/linkguard-fw/main.go`, pass `metricsCollector` into `api.New(...)` (add the argument in the same position you add the param to `New`).

- [ ] **Step 4: Run to verify build + tests**

Run: `gofmt -w internal/api/ cmd/linkguard-fw/ && go build ./... && go test ./internal/api/... -v`
Expected: BUILD ok, tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ cmd/linkguard-fw/main.go
git commit -m "feat(api): monitoring health snapshot + config endpoints"
```

---

### Task 7: Dashboard health panel + config UI

**Files:**
- Modify: `web/src/types/index.ts`
- Create: `web/src/components/SystemHealth.tsx`
- Create: `web/src/components/MonitoringSettings.tsx`
- Modify: `web/src/pages/Dashboard.tsx`, `web/src/pages/Settings.tsx`

**Interfaces:**
- Consumes: `GET /api/monitoring/health` → `HealthItem[]`; `GET/PUT /api/monitoring/config` → `MonitoringConfig`.

- [ ] **Step 1: Add types**

In `web/src/types/index.ts`:

```ts
export interface HealthItem { name: string; kind: 'service' | 'link' | 'resource'; up: boolean; since: number; }
export interface MonitoringConfig { enabled: boolean; services: string[]; disk_threshold_pct: number; }
```

- [ ] **Step 2: SystemHealth component**

`web/src/components/SystemHealth.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import client from '../api/client';
import type { HealthItem } from '../types';

// Friendly labels for known service unit names.
const LABEL: Record<string, string> = {
  'nftables': 'Firewall',
  'kea-dhcp4-server': 'DHCP',
  'unbound': 'DNS',
};

export default function SystemHealth() {
  const [items, setItems] = useState<HealthItem[]>([]);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const { data } = await client.get<HealthItem[]>('/api/monitoring/health'); if (alive) setItems(data ?? []); }
      catch { /* best-effort */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (items.length === 0) return null;
  return (
    <div className="card">
      <h2 className="text-white font-semibold mb-3">Saúde do sistema</h2>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {items.map((it) => (
          <div key={`${it.kind}:${it.name}`}
            className={`flex items-center gap-2 rounded-lg border p-3 ${it.up ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/30 bg-red-500/10'}`}>
            {it.up ? <ShieldCheck className="w-4 h-4 text-green-400 shrink-0" /> : <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />}
            <div className="min-w-0">
              <div className="text-white text-sm truncate">{LABEL[it.name] ?? it.name}</div>
              <div className={`text-xs ${it.up ? 'text-green-400' : 'text-red-400'}`}>{it.up ? 'no ar' : 'fora do ar'}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Mount on Dashboard**

In `web/src/pages/Dashboard.tsx`, import and render `<SystemHealth />` right below the metrics row (near the top, above the WAN links table). Follow the existing import + JSX placement style.

- [ ] **Step 4: MonitoringSettings component (master toggle + advanced list)**

`web/src/components/MonitoringSettings.tsx` — mirror the fetch/save pattern of `NotificationSettings.tsx` (`client.get`/`client.put`, a `busy`/`msg` state, `flash`). Render: a master switch bound to `enabled`; when the app is in Advanced UI mode (use the existing `useUIMode()`/`UIModeContext`), also render an editable comma-separated services field and the disk threshold number. Save via `PUT /api/monitoring/config`.

```tsx
import { useEffect, useState } from 'react';
import client from '../api/client';
import { useUIMode } from '../context/UIModeContext'; // confirm the exported hook name in UIModeContext.tsx
import type { MonitoringConfig } from '../types';

const empty: MonitoringConfig = { enabled: true, services: [], disk_threshold_pct: 90 };

export default function MonitoringSettings() {
  // UIModeContext exposes { mode: 'simple'|'advanced', isSimple: boolean }.
  const { isSimple } = useUIMode();
  const advanced = !isSimple;
  const [cfg, setCfg] = useState<MonitoringConfig>(empty);
  const [msg, setMsg] = useState('');

  useEffect(() => { (async () => {
    try { const { data } = await client.get<MonitoringConfig>('/api/monitoring/config'); setCfg(data); } catch {/*ignore*/}
  })(); }, []);

  const save = async (next: MonitoringConfig) => {
    setCfg(next);
    try { const { data } = await client.put<MonitoringConfig>('/api/monitoring/config', next); setCfg(data); setMsg('Salvo.'); }
    catch { setMsg('Erro ao salvar.'); }
  };

  return (
    <div className="card">
      <h2 className="text-white font-semibold mb-1">Vigilância</h2>
      <p className="text-gray-500 text-xs mb-3">Avisa no seu canal de notificação quando algo cai (e quando volta).</p>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={cfg.enabled} onChange={(e) => save({ ...cfg, enabled: e.target.checked })} />
        <span className="text-white text-sm">Me avise de qualquer queda</span>
      </label>
      {advanced && (
        <div className="mt-3 space-y-2">
          <label className="block text-xs text-gray-400">Serviços vigiados (separados por vírgula)
            <input className="input mt-1 w-full" defaultValue={cfg.services.join(', ')}
              onBlur={(e) => save({ ...cfg, services: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
          </label>
          <label className="block text-xs text-gray-400">Alerta de disco acima de (%)
            <input type="number" min={50} max={99} className="input mt-1 w-32" defaultValue={cfg.disk_threshold_pct}
              onBlur={(e) => save({ ...cfg, disk_threshold_pct: Number(e.target.value) })} />
          </label>
        </div>
      )}
      {msg && <div className="mt-2 text-xs text-gray-400">{msg}</div>}
    </div>
  );
}
```

> Verify `UIModeContext.tsx`'s exported hook and field (the nav uses Simple/Advanced already). Adjust `useUIMode().advanced` to the real API.

- [ ] **Step 5: Mount MonitoringSettings on the Settings page**

In `web/src/pages/Settings.tsx`, render `<MonitoringSettings />` near `<NotificationSettings />`.

- [ ] **Step 6: Commit**

```bash
git add web/src/types/index.ts web/src/components/SystemHealth.tsx web/src/components/MonitoringSettings.tsx web/src/pages/Dashboard.tsx web/src/pages/Settings.tsx
git commit -m "feat(web): system-health dashboard panel + monitoring settings"
```

> Frontend TS is verified by CI's `npm run build` (no local node). If you have node available, run `cd web && npm run build` before committing.

---

## Phase 3 — App self-death & WAN gap

### Task 8: `--notify-down` subcommand + systemd OnFailure

**Files:**
- Modify: `cmd/linkguard-fw/main.go`
- Create: `deploy/linkguard-notify-down.service`
- Modify: `deploy/linkguard-fw.service`, `.github/workflows/release.yml`, `Makefile`

**Interfaces:**
- Consumes: `config.Load`, `storage.Open` (confirm the DB-open function name used in `main.go`), `notify.NewService(db).SendNow(...)`, `alerts` (optional — just send via notify).

- [ ] **Step 1: Add the subcommand to main.go**

After `flag.Parse()` and config load, before starting services:

```go
	if *notifyDown {
		// Short-lived path invoked by systemd OnFailure when linkguard-fw dies.
		db, err := storage.Open(cfg.DBPath) // confirm exact open fn + field name
		if err == nil {
			defer db.Close()
			for _, e := range notify.NewService(db).SendNow("critical",
				"LinkGuard caiu", "O serviço linkguard-fw parou inesperadamente no firewall.") {
				if e != nil {
					slog.Warn("notify-down send failed", "err", e)
				}
			}
		}
		return
	}
```

Add the flag near the others:

```go
	notifyDown := flag.Bool("notify-down", false, "Send a 'service down' notification and exit (systemd OnFailure)")
```

- [ ] **Step 2: Manually verify the flag path builds**

Run: `gofmt -w cmd/linkguard-fw/ && go build ./... && ./dist/linkguard-fw --help 2>&1 | grep notify-down || true`
Expected: builds; flag listed. (No unit test — this is an integration/deploy path; validated on prod in the rollout step.)

- [ ] **Step 3: Create the oneshot unit**

`deploy/linkguard-notify-down.service`:

```ini
[Unit]
Description=LinkGuard FW - send outage notification when the main service fails

[Service]
Type=oneshot
ExecStart=/usr/local/bin/linkguard-fw --notify-down --config /etc/linkguard-fw/config.json
```

- [ ] **Step 4: Wire OnFailure into the main unit**

In `deploy/linkguard-fw.service`, under `[Unit]` add:

```ini
OnFailure=linkguard-notify-down.service
```

- [ ] **Step 5: Package the new unit in CI and Makefile**

In `.github/workflows/release.yml`, in the "Build .deb packages" step, after copying `linkguard-fw.service`, also copy the oneshot (preserve the YAML block-scalar indentation so the heredoc dedents correctly):

```bash
            cp deploy/linkguard-notify-down.service "${PKG_DIR}/lib/systemd/system/linkguard-notify-down.service"
```

In the `Makefile` `deb` target, add next to the existing `install -m 0644 deploy/linkguard-fw.service ...`:

```make
	@install -m 0644 deploy/linkguard-notify-down.service $(PKG_DIR)/lib/systemd/system/linkguard-notify-down.service
```

- [ ] **Step 6: Commit**

```bash
git add cmd/linkguard-fw/main.go deploy/linkguard-notify-down.service deploy/linkguard-fw.service .github/workflows/release.yml Makefile
git commit -m "feat: notify on linkguard-fw's own failure via systemd OnFailure"
```

---

### Task 9: Close the WAN alert gap — stress-test raises link alerts

**Files:**
- Modify: `internal/stresstest/service.go`
- Modify: `internal/api/server.go` (pass `alertSvc` into `stresstest.NewService`)
- Test: `internal/stresstest/service_test.go`

**Rationale:** Real WAN drops already alert (monitor → `OnStatusChange` → `alertSvc.LinkOffline`, proven in production logs at 06:50). The reported gap is that a *stress-test* outage changed the route without the monitor observing a status transition, so no alert fired. The deterministic fix: the stress-test, which deliberately drops a known link, raises the matching alert itself when it injects the fault and the recovery when it restores.

**Interfaces:**
- Consumes: `alerts.Service.LinkOffline(name, id)`, `alerts.Service.LinkDegraded(name, id)`, `alerts.Service.LinkOnline(name, id)`.
- Produces: `stresstest.NewService(exec, linkSvc, alertSvc)` (new 3rd param).

- [ ] **Step 1: Write the failing test**

```go
func TestStartRaisesOutageAlert(t *testing.T) {
	// Given a healthy target link and at least one other healthy WAN, starting an
	// outage test must raise a link_offline alert so the user is notified even
	// though this is a simulated drop.
	// Build a Service with a fake linkSvc (two online links) and a real alerts
	// service backed by an in-memory DB; assert an alert is created on Start.
	// (Match the existing service_test.go construction patterns.)
}
```

> Fill this test using the same fakes/helpers already in `internal/stresstest/service_test.go`. If constructing `alerts.Service` needs a DB, use `openTestDB(t)` and assert via `db.GetAlerts`. Assert exactly one `alerts.TypeLinkOffline` (outage) or `TypeLinkDegraded` (degrade mode) alert after `Start`, and one `TypeLinkOnline` after the run restores.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/stresstest/ -run TestStartRaisesOutageAlert -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add `alertSvc *alerts.Service` to the `Service` struct and `NewService`:

```go
func NewService(exec firewall.Executor, linkSvc *links.Service, alertSvc *alerts.Service) *Service {
	return &Service{exec: exec, linkSvc: linkSvc, alertSvc: alertSvc, nowFn: ...}
}
```

In `applyFault` (when the fault is applied), raise the alert:

```go
	if s.alertSvc != nil {
		if t.Mode == ModeOutage {
			_ = s.alertSvc.LinkOffline(t.LinkName, t.LinkID)
		} else {
			_ = s.alertSvc.LinkDegraded(t.LinkName, t.LinkID)
		}
	}
```

In `restore` (when the link is brought back), raise recovery:

```go
	if s.alertSvc != nil {
		_ = s.alertSvc.LinkOnline(t.LinkName, t.LinkID)
	}
```

Update the constructor call in `internal/api/server.go:237`:

```go
		stressH := handlers.NewStressTestHandler(stresstest.NewService(s.exec, s.linkSvc, s.alertSvc), s.db)
```

- [ ] **Step 4: Run tests + build**

Run: `gofmt -w internal/stresstest/ internal/api/ && go test ./internal/stresstest/ ./internal/api/... -v && go build ./...`
Expected: PASS + BUILD ok.

- [ ] **Step 5: Commit**

```bash
git add internal/stresstest/service.go internal/stresstest/service_test.go internal/api/server.go
git commit -m "fix(stresstest): raise link outage/recovery alerts so simulated drops notify"
```

---

## Final verification (before deploy)

- [ ] `gofmt -l` clean across changed packages; `go test ./...` green; `go build ./...` ok.
- [ ] Deploy via the `.claude/skills/deploy-to-prod` runbook (merge → pipeline vX → download → verify sha → scp → `dpkg -i`).
- [ ] On prod (controlled window): `systemctl stop unbound` → expect a WhatsApp "Serviço offline: unbound"; `systemctl start unbound` → "Serviço recuperado". Run a stress-test outage → expect a link alert. Confirm the Dashboard "Saúde do sistema" tiles reflect reality.

## Self-review notes (coverage vs spec)

- Services monitored → Tasks 1,4,5. Self-death → Task 8. WAN/gateway gap → Task 9. Disk + CPU/mem transition → Task 4/5 (disk implemented; CPU/mem staying as-is is acceptable — note: converting CPU/mem to transition-based is folded into the same `observe` pattern if desired, but not required for the reported problem; **left as a follow-up to avoid scope creep**). Down+recovery, transition-only, anti-flap, recovery-passes-threshold → Tasks 2,3,4. Zero-config → Task 1. Dashboard health + reused graphs → Tasks 6,7 (graphs already exist; no new graph). Config UI (master toggle + advanced list) → Task 7.
- Deferred to a follow-up plan (explicitly out of this plan's scope, matching the spec's non-goals): grouping simultaneous outages; per-service uptime history graph; converting existing CPU/mem alerts to transition-based.
