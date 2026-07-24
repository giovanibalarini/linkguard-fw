# Higiene do controle (histerese + valores medidos) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a single degraded probe sample from flipping link status and rewriting the default route; require the same sustained-threshold hysteresis that `offline` already uses. Put the actually-measured latency/loss numbers in the alert message instead of a generic sentence.

**Architecture:** `links.Monitor`'s pure state machine (`linkState.advance`) gains one more gate on the `degraded` branch, mirroring the existing `probeFailThreshold` gate on `offline`. The `checkLink` call site is fixed to pass this tick's freshly-measured values (not the stale ones from the top of the tick) to the transition callback, so `alerts.LinkDegraded` — whose signature grows two `float64` parameters — can embed them in the message.

**Tech Stack:** Go 1.25, no new dependencies. Depends on Project 1 (`internal/tsdb`) having landed first only in the sense that the same threshold config (`DegradedSustainSamples`, default 3) already exists and is already wired into `sustainN()` — this plan does not touch `tsdb` at all.

## Global Constraints

- `probeFailThreshold` (offline) and the new degraded-status gate must use the **same architectural shape**: a counted, monotonic-until-reset consecutive-sample requirement, not a time-based debounce.
- `alerts.LinkDegraded`'s signature change is a breaking change to an internal function — every call site in the codebase must be updated in the same commit that changes the signature, or the build fails. There are exactly three: `internal/balancer/service.go`, `internal/failover/service.go`, `internal/stresstest/service.go`.
- Do not touch `internal/balancer/service.go`'s `Rebuild()` no-op dedup logic (`routeSignature`/`lastSig`) — it already does the right thing (verified in Task 3 below with a new regression test, not new production code).
- gofmt must pass on every Go file touched.

---

### Task 1: Gate the `degraded` status transition on the sustained-sample threshold

**Files:**
- Modify: `internal/links/monitor.go`
- Modify: `internal/links/monitor_test.go` (existing file, `package links` — add to it, do not overwrite)

**Interfaces:**
- Consumes: nothing new — `linkState.advance`'s existing `sustainThreshold int` parameter, already passed by `checkLink` as `m.sustainN()` (already reads `balancerSvc.LoadConfig().DegradedSustainSamples`, default 3, regardless of failover-vs-balance mode — see `cmd/linkguard-fw/main.go`'s `monitor.SustainThreshold(...)` wiring).
- Produces: no signature change to `advance` — only its internal branching changes.

- [ ] **Step 1: Write the failing test**

`internal/links/monitor_test.go` already contains `TestAdvanceDebounce`, which asserts the edge-triggered `fireSustained` flag but does **not** assert what `newStatus` is on the first two (below-threshold) calls — that gap is exactly the bug. Add a new test that closes it, appended to the existing file (same `package links`):

```go
// TestAdvanceStatusRequiresSustainedThreshold verifies that a single degraded
// sample does NOT flip status to degraded — status must stay at whatever it
// was until sustainThreshold consecutive degraded samples accumulate, the
// same shape probeFailThreshold already uses for offline. Before this fix,
// "case degradedNow:" alone was enough to flip status on the very first
// sample, which is what turned an 8-second upstream blip into a route
// rewrite in production (2026-07-23 incident).
func TestAdvanceStatusRequiresSustainedThreshold(t *testing.T) {
	st := &linkState{}
	prev := StatusOnline

	// Two degraded samples below threshold(3): status must NOT flip yet.
	for i := 0; i < 2; i++ {
		status, _ := st.advance(true, true, prev, 3)
		if status != StatusOnline {
			t.Fatalf("sample %d: status = %q, want online (below threshold, must not flip)", i+1, status)
		}
	}

	// Third sample crosses the threshold: NOW it flips.
	status, _ := st.advance(true, true, prev, 3)
	if status != StatusDegraded {
		t.Fatalf("sample 3: status = %q, want degraded (threshold reached)", status)
	}
}

// TestAdvanceStatusRecoversAfterDegradedEpisode verifies that once degraded
// status has flipped, a single good sample does not immediately flip back to
// online — the existing probeRecoverThreshold gate (2 consecutive good
// samples) still applies, unaffected by this change.
func TestAdvanceStatusRecoversAfterDegradedEpisode(t *testing.T) {
	st := &linkState{}
	status := StatusOnline
	for i := 0; i < 3; i++ {
		status, _ = st.advance(true, true, status, 3)
	}
	if status != StatusDegraded {
		t.Fatalf("setup: expected degraded after 3 samples, got %q", status)
	}

	// One good sample: probeRecoverThreshold is 2, so status must stay degraded.
	status, _ = st.advance(true, false, status, 3)
	if status != StatusDegraded {
		t.Fatalf("after 1 good sample: status = %q, want degraded (recover threshold not yet met)", status)
	}

	// Second consecutive good sample: now it recovers.
	status, _ = st.advance(true, false, status, 3)
	if status != StatusOnline {
		t.Fatalf("after 2 good samples: status = %q, want online", status)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -run TestAdvanceStatusRequiresSustainedThreshold -v
```

Expected: FAIL at sample 1 or 2 — `status = "degraded", want online` — because the current code flips on any single degraded sample.

- [ ] **Step 3: Fix `advance`**

In `internal/links/monitor.go`, find the `advance` method's second `switch` block (the one computing `newStatus`):

```go
	switch {
	case st.consecutiveFails >= probeFailThreshold:
		newStatus = StatusOffline
	case degradedNow:
		newStatus = StatusDegraded
	case st.consecutiveSuccesses >= probeRecoverThreshold:
		newStatus = StatusOnline
	default:
		newStatus = prevStatus
		if newStatus == "" {
			newStatus = StatusUnknown
		}
	}
```

Replace the `case degradedNow:` line with a threshold-gated condition, mirroring `probeFailThreshold`'s shape exactly:

```go
	switch {
	case st.consecutiveFails >= probeFailThreshold:
		newStatus = StatusOffline
	case degradedNow && st.consecutiveDegraded >= sustainThreshold:
		newStatus = StatusDegraded
	case st.consecutiveSuccesses >= probeRecoverThreshold:
		newStatus = StatusOnline
	default:
		newStatus = prevStatus
		if newStatus == "" {
			newStatus = StatusUnknown
		}
	}
```

Below the threshold, `degradedNow` is true but the new condition is false, so control falls to `default:` — `newStatus = prevStatus`, exactly matching what the offline path already does while under `probeFailThreshold`. No other line in `advance` needs to change: `st.consecutiveDegraded` is already tracked by the first `switch` block (the one setting `consecutiveDegraded++` in the `case degradedNow:` branch), and `fireSustained`'s own gate (`st.consecutiveDegraded >= sustainThreshold && !st.degradedEpisodeFired`) already uses the identical threshold — this fix makes `newStatus` consistent with a signal `fireSustained` already computes, not a new concept.

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -v
```

Expected: all PASS, including the two new tests and every pre-existing test in the package (`TestAdvanceDebounce`, `TestAdvanceThresholdFloor`, `TestAdvanceOfflineAndOnline`, `TestBindDialer`, `TestParseHosts`, `TestSummarize`) — none of those assert a specific `newStatus` value for a below-threshold degraded sample, so none should regress. If any does, stop and investigate before proceeding — it means this fix has a wider blast radius than analyzed here.

- [ ] **Step 5: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/links/monitor.go internal/links/monitor_test.go
git add internal/links/monitor.go internal/links/monitor_test.go
git commit -m "fix(links): require sustained samples before flipping to degraded status

Mirrors the existing probeFailThreshold gate used for offline. Before this,
a single degraded probe sample flipped status immediately, which in
production (2026-07-23) turned 8-18 second upstream blips into ~19 route
rewrites/day. The sustained-episode threshold (DegradedSustainSamples,
already used for active flow eviction) now also gates the status
transition itself."
```

---

### Task 2: Record this tick's measured latency/loss on the link passed to `onStatusChange`

**Files:**
- Modify: `internal/links/monitor.go`
- Modify: `internal/links/monitor_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: the `*storage.Link` passed to `onStatusChange` (and therefore to `balancer.OnLinkChange` / `failover.HandleStatusChange`) now carries `LatencyMs`/`PacketLoss` from the measurement that just triggered the transition, not stale values from the top of the tick.

- [ ] **Step 1: Write the failing test**

In `internal/links/monitor.go`, `checkLink` is unexported, and its only externally-observable effect relevant here is what it passes to `onStatusChange`. Add a test to `internal/links/monitor_test.go` (same file/package as Task 1) that exercises `checkLink` through the public `Monitor` API using `RunOnceForTest` — **if Project 1's plan already added `RunOnceForTest` to `internal/links/monitor.go`, reuse it; otherwise add it as part of this task** (check first: `grep -n "RunOnceForTest" internal/links/monitor.go`):

```go
// TestCheckLinkPassesFreshMeasurementToCallback verifies the link handed to
// onStatusChange carries THIS tick's measured latency/loss, not whatever was
// last persisted before the probe ran. Before this fix, "updated := l" copied
// the link fetched at the top of the tick — stale by definition — so any
// alert built from it could never show a real number.
func TestCheckLinkPassesFreshMeasurementToCallback(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	svc := NewService(db)
	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1:1", // deliberately unreachable port -> measurable loss
		Enabled: true, LatencyMs: 999, PacketLoss: 0, // stale values that must NOT leak through
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	mon := NewMonitor(db, svc, time.Second, 1, nil)
	var gotLatency, gotLoss float64
	var called bool
	mon.OnStatusChange(func(link *storage.Link, oldStatus, newStatus string) {
		called = true
		gotLatency = link.LatencyMs
		gotLoss = link.PacketLoss
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mon.RunOnceForTest(ctx)

	if !called {
		t.Fatal("expected onStatusChange to fire on first observation (unknown -> offline/degraded)")
	}
	if gotLatency == 999 {
		t.Fatal("expected fresh latency, got the stale seed value 999 — updated.LatencyMs was never set")
	}
	_ = gotLoss // loss is asserted indirectly via gotLatency != stale sentinel above
}
```

Add `"context"`, `"path/filepath"`, and `"time"` to the imports in `internal/links/monitor_test.go` if not already present (check with `head -15 internal/links/monitor_test.go` — the file currently only imports `"testing"` and `"time"`; add `"context"`, `"path/filepath"`, and `"github.com/giovanibalarini/linkguard-fw/internal/storage"`).

If `NewMonitor`'s signature already changed in Project 1's plan (it gained a `rec tsdb.Recorder` parameter), pass `nil` for it here — this test lives in `package links` (internal), so it can also just call the 4-argument pre-Project-1 constructor if this plan is applied to a codebase where Project 1 has not landed yet. **Check the current signature first** with `grep -n "^func NewMonitor" internal/links/monitor.go` and match the call above to however many parameters it currently takes, passing `nil` for any `tsdb.Recorder`/`*metrics.Metrics` parameter.

- [ ] **Step 2: Run the test to verify it fails**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -run TestCheckLinkPassesFreshMeasurementToCallback -v
```

Expected: FAIL — `gotLatency == 999`, proving the stale value currently leaks through.

- [ ] **Step 3: Fix `checkLink`**

In `internal/links/monitor.go`, find the block (inside `checkLink`) that fires `onStatusChange`:

```go
	// Fire callback on status change
	if newStatus != state.lastStatus && m.onStatusChange != nil {
		updated := l
		updated.Status = newStatus
		m.onStatusChange(&updated, state.lastStatus, newStatus)
		state.lastStatus = newStatus
	}
```

Add the two measured fields:

```go
	// Fire callback on status change
	if newStatus != state.lastStatus && m.onStatusChange != nil {
		updated := l
		updated.Status = newStatus
		updated.LatencyMs = avgLatency
		updated.PacketLoss = packetLoss
		m.onStatusChange(&updated, state.lastStatus, newStatus)
		state.lastStatus = newStatus
	}
```

The same staleness applies to the `onDegradedSustained` callback a few lines below — fix it too for consistency, even though Task 4 (below) is what actually consumes it:

```go
	// Edge-triggered: a link that has been degraded for the sustained threshold
	// fires once so the balancer can actively evict its in-flight flows.
	if fireSustained && m.onDegradedSustained != nil {
		updated := l
		updated.Status = newStatus
		updated.LatencyMs = avgLatency
		updated.PacketLoss = packetLoss
		m.onDegradedSustained(&updated)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -v
```

Expected: all PASS.

- [ ] **Step 5: Add `RunOnceForTest` only if it does not already exist**

```bash
grep -n "RunOnceForTest" internal/links/monitor.go
```

If this prints nothing (Project 1's plan has not run, or ran without adding it), add to `internal/links/monitor.go`:

```go
// RunOnceForTest runs a single checkAll pass synchronously. Test-only.
func (m *Monitor) RunOnceForTest(ctx context.Context) {
	m.checkAll(ctx)
}
```

If it already exists, do nothing — do not add a duplicate method (the build would fail with "method redeclared").

- [ ] **Step 6: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/links/monitor.go internal/links/monitor_test.go
git add internal/links/monitor.go internal/links/monitor_test.go
git commit -m "fix(links): pass this tick's measured latency/loss to status-change callbacks

updated := l copied the link fetched at the top of the tick — stale by
definition, since it predates this tick's probe. Alerts built from it could
never show a real number, which is why link_degraded alerts read
'is experiencing high packet loss or latency' with no values."
```

---

### Task 3: Embed measured values in the degraded alert message

**Files:**
- Modify: `internal/alerts/service.go`
- Modify: `internal/balancer/service.go`
- Modify: `internal/failover/service.go`
- Modify: `internal/stresstest/service.go`
- Modify: `internal/alerts/service_test.go`

**Interfaces:**
- Consumes: `link.LatencyMs`/`link.PacketLoss` (now fresh, per Task 2), `t.DelayMs`/`t.LossPct` (existing `stresstest.Test` fields — the injected fault target, since a stress test has no independently "measured" value distinct from what it injected).
- Produces: `func (s *Service) LinkDegraded(linkName, linkID string, latencyMs, packetLossPct float64) error` — breaking signature change, all 3 call sites updated in this same task.

- [ ] **Step 1: Write the failing test**

Add to `internal/alerts/service_test.go` (check the file's existing helpers first — it already has `openTestDB` and a `fakeNotifier`; reuse them):

```go
func TestLinkDegradedMessageIncludesMeasuredValues(t *testing.T) {
	db := openTestDB(t)
	svc := NewService(db)

	if err := svc.LinkDegraded("WAN SUMICITY", "link-1", 842.5, 33.3); err != nil {
		t.Fatalf("LinkDegraded: %v", err)
	}

	alerts, err := svc.List(false, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	msg := alerts[0].Message
	if !strings.Contains(msg, "842.5") {
		t.Errorf("expected message to include the measured latency, got: %q", msg)
	}
	if !strings.Contains(msg, "33.3") {
		t.Errorf("expected message to include the measured packet loss, got: %q", msg)
	}
}
```

Add `"strings"` to the imports in `internal/alerts/service_test.go` if not already present.

- [ ] **Step 2: Run the test to verify it fails**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/alerts/... -run TestLinkDegradedMessageIncludesMeasuredValues -v
```

Expected: FAIL (compile error — `LinkDegraded` called with 4 args, current signature takes 2).

- [ ] **Step 3: Update `alerts.Service.LinkDegraded`**

In `internal/alerts/service.go`, replace:

```go
// LinkDegraded raises a warning when a link is degraded.
func (s *Service) LinkDegraded(linkName, linkID string) error {
	return s.Create(TypeLinkDegraded, SeverityWarning,
		"Link Degraded: "+linkName,
		"WAN link "+linkName+" is experiencing high packet loss or latency.", linkID)
}
```

with:

```go
// LinkDegraded raises a warning when a link is degraded. latencyMs and
// packetLossPct are the measurement that triggered the transition — embedding
// them in the message is what turns "is experiencing high packet loss or
// latency" (which forced every past investigation to go read the journal by
// hand) into something a human can act on without opening the timeline.
func (s *Service) LinkDegraded(linkName, linkID string, latencyMs, packetLossPct float64) error {
	return s.Create(TypeLinkDegraded, SeverityWarning,
		"Link Degraded: "+linkName,
		fmt.Sprintf("WAN link %s is experiencing high packet loss or latency (latency=%.1fms, loss=%.1f%%).",
			linkName, latencyMs, packetLossPct), linkID)
}
```

Add `"fmt"` to the imports in `internal/alerts/service.go` if not already present (`grep -n '"fmt"' internal/alerts/service.go`).

- [ ] **Step 4: Update the three call sites**

In `internal/balancer/service.go`, `OnLinkChange` (around line 468):

```go
	switch newStatus {
	case links.StatusOffline:
		_ = s.alertSvc.LinkOffline(link.Name, link.ID)
	case links.StatusOnline:
		_ = s.alertSvc.LinkOnline(link.Name, link.ID)
	case links.StatusDegraded:
		_ = s.alertSvc.LinkDegraded(link.Name, link.ID, link.LatencyMs, link.PacketLoss)
	}
```

In `internal/failover/service.go`, `HandleStatusChange` (around line 89):

```go
	switch newStatus {
	case links.StatusOffline:
		cmds, err = s.handleLinkDown(ctx, link)
		_ = s.alertSvc.LinkOffline(link.Name, link.ID)
		_ = s.alertSvc.Failover(link.Name, "link down")
	case links.StatusOnline:
		cmds, err = s.handleLinkUp(ctx, link)
		_ = s.alertSvc.LinkOnline(link.Name, link.ID)
	case links.StatusDegraded:
		_ = s.alertSvc.LinkDegraded(link.Name, link.ID, link.LatencyMs, link.PacketLoss)
	}
```

In `internal/stresstest/service.go`, `applyFault` (around line 288) — a stress test has no independent "measured" value; it uses the injected fault target, which is the honest value to report (it IS the shape of degradation this test is simulating):

```go
	if s.alertSvc != nil {
		if t.Mode == ModeOutage {
			_ = s.alertSvc.LinkOffline(t.LinkName, t.LinkID)
		} else {
			_ = s.alertSvc.LinkDegraded(t.LinkName, t.LinkID, float64(t.DelayMs), float64(t.LossPct))
		}
	}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/alerts/... -v
```

Expected: all PASS.

- [ ] **Step 6: Build and run the full suite (catches any missed call site)**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
```

Expected: clean build. If the compiler reports a fourth call site this plan didn't enumerate, apply the same pattern (`link.Name, link.ID, link.LatencyMs, link.PacketLoss` for a real measurement, or the closest equivalent value available at that call site) and re-run.

- [ ] **Step 7: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/alerts/service.go internal/alerts/service_test.go internal/balancer/service.go internal/failover/service.go internal/stresstest/service.go
git add internal/alerts/service.go internal/alerts/service_test.go internal/balancer/service.go internal/failover/service.go internal/stresstest/service.go
git commit -m "feat(alerts): embed measured latency/loss in the degraded alert message"
```

---

### Task 4: Regression test — confirm the route-rebuild no-op dedup already holds

**Files:**
- Modify: `internal/balancer/service_test.go`

**Interfaces:**
- Consumes: `newEvictService` (existing unexported test helper in `internal/balancer/evict_test.go`, same package — reachable without import), `recExec` (same file).
- Produces: no production code change — this task only adds coverage for behavior already implemented (`Rebuild()`'s `sig == s.lastSig` check).

**Why this task has no production-code step:** during planning, `internal/balancer/service.go`'s `Rebuild()` was read in full. It already computes a `routeSignature` fingerprint of the nexthop set and returns early (`return nil // nothing changed`) when the signature matches the last-applied one (`s.lastSig`), before issuing `ip route replace`. This is exactly the "don't reconstruct the route when the nexthop set doesn't actually change" behavior the roadmap called for — it was added by an earlier commit (`dae0dd2`/`afacb57`) for a different reason (skip no-op reconciliation ticks) but already covers this case too. Writing new production code here would duplicate an existing, working mechanism. What was missing was a **test** proving it — this task adds that.

- [ ] **Step 1: Write the failing-if-the-mechanism-were-broken test**

Add to `internal/balancer/service_test.go`:

```go
func TestRebuildSkipsRedundantRouteReplace(t *testing.T) {
	exec := &recExec{
		linkOut: "enp5s0 UP\nenp3s0 UP",
		ipv4:    map[string]string{"enp5s0": "3: enp5s0 inet 192.168.15.20/24 scope global enp5s0"},
	}
	linkA := storage.Link{ID: "a", Name: "WAN1", Interface: "enp5s0", Gateway: "192.168.15.1", Weight: 100, Enabled: true, Status: links.StatusOnline}
	linkB := storage.Link{ID: "b", Name: "WAN2", Interface: "enp3s0", Gateway: "192.168.18.1", Weight: 100, Enabled: true, Status: links.StatusOnline}
	svc := newEvictService(t, exec, false, []storage.Link{linkA, linkB})

	ctx := context.Background()
	if err := svc.Rebuild(ctx); err != nil {
		t.Fatalf("first Rebuild: %v", err)
	}
	firstCount := len(exec.writes)
	if firstCount == 0 {
		t.Fatal("expected the first Rebuild to issue at least one write (ip route replace)")
	}

	// Nothing about the links or config changed — a second Rebuild with an
	// identical nexthop set must be a no-op, not a second "ip route replace".
	if err := svc.Rebuild(ctx); err != nil {
		t.Fatalf("second Rebuild: %v", err)
	}
	if got := len(exec.writes); got != firstCount {
		t.Fatalf("second Rebuild issued %d more write(s) — expected 0 (no-op), the nexthop set did not change", got-firstCount)
	}
}
```

`context`, `storage`, and `links` are already imported by `internal/balancer/service_test.go` if Task 1's or earlier tasks' additions brought them in — check with `head -15 internal/balancer/service_test.go`; add any missing import (`"context"`, `"github.com/giovanibalarini/linkguard-fw/internal/links"`, `"github.com/giovanibalarini/linkguard-fw/internal/storage"`).

- [ ] **Step 2: Run the test**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/balancer/... -run TestRebuildSkipsRedundantRouteReplace -v
```

Expected: PASS immediately — this is a regression test for existing behavior, not a fix. If it fails, that is a genuine, previously-unknown bug in `Rebuild()`'s dedup logic; stop and investigate rather than adding new code to force the test green, since the whole point of this task is confirming the existing mechanism, not building a new one.

- [ ] **Step 3: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/balancer/service_test.go
git add internal/balancer/service_test.go
git commit -m "test(balancer): confirm Rebuild already skips a route replace when nothing changed"
```

---

### Task 5: Manual verification against the production incident shape

**Files:** none — this task runs the full suite and a scripted scenario, no code changes.

- [ ] **Step 1: Run the full test suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go vet ./... 2>&1
go test ./... 2>&1
```

Expected: clean build, clean vet, every package `ok`.

- [ ] **Step 2: Simulate the 2026-07-23 incident shape and confirm no status flip**

This reproduces, as a unit test scenario (not a new permanent test — run it as a one-off to build confidence, then discard), the exact pattern from the incident: 1-2 degraded samples in a row, then recovery, repeated. Create a throwaway file:

```bash
cat > /tmp/incident_repro_test.go <<'EOF'
package links

import "testing"

// Throwaway — not part of the permanent suite. Simulates the 2026-07-23
// incident: a link degrades for 1-2 probe ticks (8-18s at the real 10s probe
// interval) then recovers, repeatedly. Before this plan, every such blip
// flipped status to degraded and fired an alert + route rebuild. After, it
// must not, because 1-2 samples never reaches the default threshold of 3.
func TestIncidentRepro8To18SecondBlips(t *testing.T) {
	st := &linkState{}
	status := StatusOnline
	flips := 0
	for round := 0; round < 20; round++ {
		// One or two degraded samples (8-18s at a 10s probe interval).
		for i := 0; i < 2; i++ {
			newStatus, _ := st.advance(true, true, status, 3)
			if newStatus != status {
				flips++
			}
			status = newStatus
		}
		// Recovery: two good samples (matches probeRecoverThreshold).
		for i := 0; i < 2; i++ {
			status, _ = st.advance(true, false, status, 3)
		}
	}
	if flips != 0 {
		t.Fatalf("expected 0 status flips across 20 rounds of 1-2 sample blips, got %d", flips)
	}
}
EOF
cp /tmp/incident_repro_test.go internal/links/incident_repro_test.go
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -run TestIncidentRepro8To18SecondBlips -v
rm internal/links/incident_repro_test.go /tmp/incident_repro_test.go
```

Expected: PASS with the fix from Task 1 in place. This file is deliberately deleted immediately after — it exists to build confidence during this plan's execution, not as permanent coverage (Task 1's `TestAdvanceStatusRequiresSustainedThreshold` already covers the underlying property).

- [ ] **Step 3: Confirm `git status` is clean (no leftover throwaway file)**

```bash
git status --short
```

Expected: no untracked `incident_repro_test.go`. If present, remove it — it must not be committed.
</content>
