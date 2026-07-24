# Substrato tsdb + linha do tempo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `internal/trafficrrd` (traffic-only, average-only) with `internal/tsdb`, a generic time-series substrate that records `min/avg/max` per bucket for any gauge and open/close intervals for any state, then serve a correlated diagnostic timeline over one API endpoint.

**Architecture:** `internal/tsdb` owns two SQLite tables (`metric_samples`, `state_intervals`), rollup, and pruning behind a `Recorder` interface (`Gauge`, `State`). Producers (`links.Monitor`, `monitoring.Collector`, the 1s traffic sampler that used to live in `trafficrrd`) call `Recorder` methods; `Gauge` never touches disk on the calling goroutine — it only mutates an in-memory bucket, and the `tsdb` service's own 1s ticker goroutine does all writes. `GET /api/monitoring/timeline` and the existing `GET /api/system/traffic-history` both read from `tsdb`.

**Tech Stack:** Go 1.25, `modernc.org/sqlite` (existing driver, no new dependency), React + Recharts (existing frontend stack).

## Global Constraints

- Migration is idempotent (`CREATE TABLE IF NOT EXISTS`, run on every boot), matching the existing `db.migrate()` pattern in `internal/storage/storage.go`.
- `Recorder.Gauge()` and `Recorder.State()` must never perform disk I/O on the calling goroutine — the caller (e.g. `links.Monitor.checkLink`, which measures the value the whole diagnostic exists to preserve) must not have its timing affected by database writes.
- Rollup must propagate `min`→`min`, `max`→`max`, and a count-weighted average for `avg` — never re-derive min/max from an already-averaged bucket.
- `traffic_samples` is renamed, not dropped, during migration — data loss is not acceptable for a table with ~1 month of production history.
- `GET /api/system/traffic-history` keeps its existing request/response contract (used by the current frontend); it is reimplemented on top of `tsdb`, not removed.
- gofmt must pass on every Go file touched (`export PATH="$HOME/sdk/go1.25.0/bin:$PATH"; gofmt -l <file>`).

---

### Task 1: Schema — `metric_samples` and `state_intervals`

**Files:**
- Modify: `internal/storage/storage.go` (add two `CREATE TABLE` constants, register in `migrate()`)
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: two tables queryable by later tasks via `db.Conn()` — `metric_samples(series, label, step_seconds, ts_unix, v_min, v_avg, v_max)` and `state_intervals(kind, label, state, started_at, ended_at)`.

- [ ] **Step 1: Add the schema constants**

In `internal/storage/storage.go`, add these constants near `createTrafficSamplesTable` (around line 247):

```go
const createMetricSamplesTable = `
CREATE TABLE IF NOT EXISTS metric_samples (
    series        TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    step_seconds  INTEGER NOT NULL,
    ts_unix       INTEGER NOT NULL,
    v_min         REAL NOT NULL,
    v_avg         REAL NOT NULL,
    v_max         REAL NOT NULL,
    PRIMARY KEY (series, label, step_seconds, ts_unix)
);`

const createStateIntervalsTable = `
CREATE TABLE IF NOT EXISTS state_intervals (
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    state      TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    PRIMARY KEY (kind, label, started_at)
);`

const createStateIntervalsOpenIndex = `
CREATE INDEX IF NOT EXISTS idx_state_intervals_open
ON state_intervals(kind, label) WHERE ended_at IS NULL;`
```

- [ ] **Step 2: Register the migrations**

In `internal/storage/storage.go`, add the three new constants to the `migrations` slice in `migrate()` (around line 55), after `createTrafficSamplesTable`:

```go
	migrations := []string{
		createUsersTable,
		createRolesTable,
		createRolePermissionsTable,
		createUserRolesTable,
		createLinksTable,
		createAlertsTable,
		createAuditLogsTable,
		createFailoverEventsTable,
		createRoutingPoliciesTable,
		createIptablesBackupsTable,
		createSettingsTable,
		createTrafficSamplesTable,
		createMetricSamplesTable,
		createStateIntervalsTable,
		createStateIntervalsOpenIndex,
		createHostMetadataTable,
		createDHCPReservationsTable,
		createDNSBlocklistTable,
		insertDefaultAdmin,
	}
```

- [ ] **Step 3: Write the failing test**

Add to `internal/storage/storage_test.go`:

```go
func TestMetricSamplesAndStateIntervalsTablesExist(t *testing.T) {
	db := newTestDB(t)

	_, err := db.Conn().Exec(`INSERT INTO metric_samples
		(series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"link.latency_ms", "WAN VIVO", 10, 1000, 10.0, 15.0, 20.0)
	if err != nil {
		t.Fatalf("insert metric_samples: %v", err)
	}

	_, err = db.Conn().Exec(`INSERT INTO state_intervals
		(kind, label, state, started_at, ended_at) VALUES (?, ?, ?, ?, ?)`,
		"link", "WAN SUMICITY", "degraded", 1000, nil)
	if err != nil {
		t.Fatalf("insert state_intervals: %v", err)
	}
}
```

- [ ] **Step 4: Run test to verify it fails, then passes**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run TestMetricSamplesAndStateIntervalsTablesExist -v
```

Expected before Steps 1–2: FAIL with `no such table: metric_samples`. After: PASS.

- [ ] **Step 5: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -l internal/storage/storage.go internal/storage/storage_test.go
git add internal/storage/storage.go internal/storage/storage_test.go
git commit -m "feat(storage): add metric_samples and state_intervals tables"
```

---

### Task 2: Repository functions for the two tables

**Files:**
- Modify: `internal/storage/repository.go` (add types + functions near the existing `TrafficSample` functions, ~line 1038)
- Modify: `internal/storage/models.go` (add `MetricSample`, `StateInterval` types)
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: `db.conn *sql.DB` (unexported field, functions are methods on `*DB` in the same package).
- Produces:
  - `type MetricSample struct { Series, Label string; StepSeconds int; TsUnix int64; VMin, VAvg, VMax float64 }`
  - `type StateInterval struct { Kind, Label, State string; StartedAt int64; EndedAt *int64 }`
  - `func (db *DB) UpsertMetricSample(s MetricSample) error`
  - `func (db *DB) GetMetricSamples(series, label string, stepSeconds int, fromUnix, toUnix int64) ([]MetricSample, error)`
  - `func (db *DB) PruneMetricSamples(stepSeconds int, olderThanUnix int64) error`
  - `func (db *DB) OpenStateInterval(kind, label, state string, startedAt int64) error`
  - `func (db *DB) CloseOpenStateInterval(kind, label string, endedAt int64) error`
  - `func (db *DB) GetStateIntervals(kind, label string, fromUnix, toUnix int64) ([]StateInterval, error)`

- [ ] **Step 1: Add the types**

In `internal/storage/models.go`, add after the `TrafficSample` type (around line 172):

```go
// ─── MetricSample ────────────────────────────────────────────────────────────

// MetricSample stores min/avg/max for a named series+label at one bucket. The
// min/max are what let a rollup survive a short spike — averaging alone would
// dilute an 8-second degradation into invisibility inside a 60s bucket.
type MetricSample struct {
	Series      string  `json:"series"`
	Label       string  `json:"label"`
	StepSeconds int     `json:"step_seconds"`
	TsUnix      int64   `json:"ts_unix"`
	VMin        float64 `json:"v_min"`
	VAvg        float64 `json:"v_avg"`
	VMax        float64 `json:"v_max"`
}

// ─── StateInterval ───────────────────────────────────────────────────────────

// StateInterval is a span of time a (kind, label) spent in one state — a link
// being "degraded", a service being "down". EndedAt is nil while the interval
// is still open (the current state).
type StateInterval struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	State     string `json:"state"`
	StartedAt int64  `json:"started_at"`
	EndedAt   *int64 `json:"ended_at,omitempty"`
}
```

- [ ] **Step 2: Add the repository functions**

In `internal/storage/repository.go`, add after `PruneTrafficSamples` (around line 1080):

```go
// ─── Metric Samples ──────────────────────────────────────────────────────────

// UpsertMetricSample writes or overwrites one bucket. Called only from the
// tsdb service's own writer goroutine, never from a measurement call site.
func (db *DB) UpsertMetricSample(s MetricSample) error {
	_, err := db.conn.Exec(`
		INSERT INTO metric_samples (series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(series, label, step_seconds, ts_unix)
		DO UPDATE SET v_min=excluded.v_min, v_avg=excluded.v_avg, v_max=excluded.v_max`,
		s.Series, s.Label, s.StepSeconds, s.TsUnix, s.VMin, s.VAvg, s.VMax)
	return err
}

// GetMetricSamples returns samples for one series+label+step between timestamps.
func (db *DB) GetMetricSamples(series, label string, stepSeconds int, fromUnix, toUnix int64) ([]MetricSample, error) {
	rows, err := db.conn.Query(`
		SELECT series, label, step_seconds, ts_unix, v_min, v_avg, v_max
		FROM metric_samples
		WHERE series = ? AND label = ? AND step_seconds = ? AND ts_unix BETWEEN ? AND ?
		ORDER BY ts_unix ASC`, series, label, stepSeconds, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MetricSample
	for rows.Next() {
		var s MetricSample
		if err := rows.Scan(&s.Series, &s.Label, &s.StepSeconds, &s.TsUnix, &s.VMin, &s.VAvg, &s.VMax); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneMetricSamples deletes buckets of one step older than the cutoff.
func (db *DB) PruneMetricSamples(stepSeconds int, olderThanUnix int64) error {
	_, err := db.conn.Exec(`
		DELETE FROM metric_samples
		WHERE step_seconds = ? AND ts_unix < ?`, stepSeconds, olderThanUnix)
	return err
}

// ─── State Intervals ─────────────────────────────────────────────────────────

// OpenStateInterval starts a new interval. Callers must close any prior open
// interval for the same (kind, label) first — CloseOpenStateInterval — or the
// two will overlap.
func (db *DB) OpenStateInterval(kind, label, state string, startedAt int64) error {
	_, err := db.conn.Exec(`
		INSERT INTO state_intervals (kind, label, state, started_at, ended_at)
		VALUES (?, ?, ?, ?, NULL)`, kind, label, state, startedAt)
	return err
}

// CloseOpenStateInterval ends whatever interval is currently open for
// (kind, label). No-op if none is open (first observation ever for that label).
func (db *DB) CloseOpenStateInterval(kind, label string, endedAt int64) error {
	_, err := db.conn.Exec(`
		UPDATE state_intervals SET ended_at = ?
		WHERE kind = ? AND label = ? AND ended_at IS NULL`, endedAt, kind, label)
	return err
}

// GetStateIntervals returns intervals for (kind, label) that overlap
// [fromUnix, toUnix] — including an interval that started before fromUnix and
// is still open, or ended after toUnix.
func (db *DB) GetStateIntervals(kind, label string, fromUnix, toUnix int64) ([]StateInterval, error) {
	rows, err := db.conn.Query(`
		SELECT kind, label, state, started_at, ended_at
		FROM state_intervals
		WHERE kind = ? AND label = ?
		  AND started_at <= ?
		  AND (ended_at IS NULL OR ended_at >= ?)
		ORDER BY started_at ASC`, kind, label, toUnix, fromUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StateInterval
	for rows.Next() {
		var s StateInterval
		var ended sql.NullInt64
		if err := rows.Scan(&s.Kind, &s.Label, &s.State, &s.StartedAt, &ended); err != nil {
			return nil, err
		}
		if ended.Valid {
			s.EndedAt = &ended.Int64
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
```

- [ ] **Step 3: Write the failing tests**

Add to `internal/storage/storage_test.go`:

```go
func TestUpsertAndGetMetricSamples(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 10,
		TsUnix: 1000, VMin: 10, VAvg: 15, VMax: 20,
	}); err != nil {
		t.Fatalf("UpsertMetricSample: %v", err)
	}
	// Overwrite same bucket — should update, not duplicate.
	if err := db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 10,
		TsUnix: 1000, VMin: 5, VAvg: 12, VMax: 25,
	}); err != nil {
		t.Fatalf("UpsertMetricSample overwrite: %v", err)
	}

	got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", 10, 0, 2000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 sample after overwrite, got %d", len(got))
	}
	if got[0].VMin != 5 || got[0].VMax != 25 {
		t.Fatalf("expected overwritten min=5 max=25, got min=%v max=%v", got[0].VMin, got[0].VMax)
	}
}

func TestPruneMetricSamples(t *testing.T) {
	db := newTestDB(t)

	_ = db.UpsertMetricSample(storage.MetricSample{Series: "s", Label: "l", StepSeconds: 60, TsUnix: 100, VMin: 1, VAvg: 1, VMax: 1})
	_ = db.UpsertMetricSample(storage.MetricSample{Series: "s", Label: "l", StepSeconds: 60, TsUnix: 9000, VMin: 1, VAvg: 1, VMax: 1})

	if err := db.PruneMetricSamples(60, 5000); err != nil {
		t.Fatalf("PruneMetricSamples: %v", err)
	}

	got, err := db.GetMetricSamples("s", "l", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 || got[0].TsUnix != 9000 {
		t.Fatalf("expected only the newer sample to remain, got %v", got)
	}
}

func TestStateIntervalOpenAndClose(t *testing.T) {
	db := newTestDB(t)

	if err := db.OpenStateInterval("link", "WAN SUMICITY", "degraded", 1000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}

	got, err := db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 || got[0].EndedAt != nil {
		t.Fatalf("expected 1 open interval, got %v", got)
	}

	if err := db.CloseOpenStateInterval("link", "WAN SUMICITY", 1008); err != nil {
		t.Fatalf("CloseOpenStateInterval: %v", err)
	}

	got, err = db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 || got[0].EndedAt == nil || *got[0].EndedAt != 1008 {
		t.Fatalf("expected interval closed at 1008, got %v", got)
	}
}

func TestStateIntervalsDoNotOverlap(t *testing.T) {
	db := newTestDB(t)

	_ = db.OpenStateInterval("link", "WAN VIVO", "online", 1000)
	_ = db.CloseOpenStateInterval("link", "WAN VIVO", 1010)
	_ = db.OpenStateInterval("link", "WAN VIVO", "degraded", 1010)
	_ = db.CloseOpenStateInterval("link", "WAN VIVO", 1020)
	_ = db.OpenStateInterval("link", "WAN VIVO", "online", 1020)

	got, err := db.GetStateIntervals("link", "WAN VIVO", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 intervals, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		prevEnd := got[i-1].EndedAt
		if prevEnd == nil {
			t.Fatalf("interval %d has no end but is followed by another interval", i-1)
		}
		if *prevEnd != got[i].StartedAt {
			t.Fatalf("gap or overlap between interval %d (ends %d) and %d (starts %d)", i-1, *prevEnd, i, got[i].StartedAt)
		}
	}
	if got[2].EndedAt != nil {
		t.Fatalf("expected the last interval to still be open, got ended_at=%v", *got[2].EndedAt)
	}
}
```

- [ ] **Step 4: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run 'TestUpsertAndGetMetricSamples|TestPruneMetricSamples|TestStateInterval' -v
```

Expected before Step 2: FAIL with `undefined: storage.MetricSample` (or similar). After: PASS.

- [ ] **Step 5: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/repository.go internal/storage/models.go internal/storage/storage_test.go
git add internal/storage/repository.go internal/storage/models.go internal/storage/storage_test.go
git commit -m "feat(storage): repository functions for metric samples and state intervals"
```

---

### Task 3: `internal/tsdb` package — `Recorder`, bucketing, rollup

**Files:**
- Create: `internal/tsdb/service.go`
- Create: `internal/tsdb/schema.go`
- Test: `internal/tsdb/service_test.go`

**Interfaces:**
- Consumes: `*storage.DB` with the methods from Task 2.
- Produces:
  - `type Recorder interface { Gauge(series, label string, v float64); State(kind, label, state string) }`
  - `func NewService(db *storage.DB) *Service`
  - `func (s *Service) Run(ctx context.Context)` — starts the 1s ticker that flushes closed buckets and runs the 1s traffic sampler (absorbed from `trafficrrd`)
  - `func (s *Service) Gauge(series, label string, v float64)`
  - `func (s *Service) State(kind, label, state string)`
  - `nativeStep(series string) int` — internal lookup table (10 for `link.*`, 30 for `sys.*`, 1 for `if.*`)

- [ ] **Step 1: Define the series registry**

Create `internal/tsdb/schema.go`:

```go
package tsdb

import "strings"

// nativeSteps maps a series name prefix to the cadence (in seconds) its
// producer measures at. Gauge() looks this up so callers never have to know
// or pass a step — the tsdb package is the single owner of bucketing.
var nativeSteps = map[string]int{
	"link.":  10,
	"sys.":   30,
	"if.":    1,
}

// derivedSteps are the rollup degrees every series gets in addition to its
// native step, in seconds: 1 minute, 15 minutes, 1 hour.
var derivedSteps = []int{60, 900, 3600}

func nativeStep(series string) int {
	for prefix, step := range nativeSteps {
		if strings.HasPrefix(series, prefix) {
			return step
		}
	}
	// Unknown series: treat as 10s native (safe default; producers are
	// expected to use a registered prefix).
	return 10
}
```

- [ ] **Step 2: Write the failing rollup test**

Create `internal/tsdb/service_test.go`:

```go
package tsdb_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestGaugeDoesNotBlockOnDisk(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// Gauge must return essentially instantly — it only touches an in-memory
	// bucket. If this took disk-write time, the test would be flaky under
	// load; instead assert it's well under a millisecond budget.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		svc.Gauge("link.latency_ms", "WAN VIVO", float64(i))
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("1000 Gauge() calls took %v — Gauge must be memory-only", elapsed)
	}
}

func TestRollupPreservesMinAndMax(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// Feed one native-step (10s) bucket's worth of samples with a spike in
	// the middle, then force-flush and verify the max survived.
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 10.0)
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 2000.0) // the spike
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 12.0)

	svc.FlushForTest(1000) // internal test hook — see Step 3

	got, err := db.GetMetricSamples("link.latency_ms", "WAN SUMICITY", 10, 0, 2000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(got))
	}
	if got[0].VMax != 2000.0 {
		t.Fatalf("expected max=2000 (the spike) to survive, got %v", got[0].VMax)
	}
	if got[0].VMin != 10.0 {
		t.Fatalf("expected min=10, got %v", got[0].VMin)
	}
	wantAvg := (10.0 + 2000.0 + 12.0) / 3
	if got[0].VAvg != wantAvg {
		t.Fatalf("expected avg=%v, got %v", wantAvg, got[0].VAvg)
	}
}

func TestRollupPropagatesMaxAcrossDegrees(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.Gauge("link.latency_ms", "WAN VIVO", 5000.0)
	svc.FlushForTest(60) // closes the native 10s bucket AND rolls into 60/900/3600

	for _, step := range []int{60, 900, 3600} {
		got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", step, 0, 100000)
		if err != nil {
			t.Fatalf("GetMetricSamples step=%d: %v", step, err)
		}
		if len(got) != 1 || got[0].VMax != 5000.0 {
			t.Fatalf("step=%d: expected max=5000 to propagate, got %v", step, got)
		}
	}
}

func TestStateTransitionOpensAndClosesInterval(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.StateForTest("link", "WAN SUMICITY", "online", 1000)
	svc.StateForTest("link", "WAN SUMICITY", "degraded", 1008)

	got, err := db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 intervals (online then degraded), got %d", len(got))
	}
	if got[0].State != "online" || got[0].EndedAt == nil || *got[0].EndedAt != 1008 {
		t.Fatalf("expected first interval online, closed at 1008; got %+v", got[0])
	}
	if got[1].State != "degraded" || got[1].EndedAt != nil {
		t.Fatalf("expected second interval degraded, still open; got %+v", got[1])
	}
}

func TestStateSameValueTwiceDoesNotReopen(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.StateForTest("service", "unbound", "up", 1000)
	svc.StateForTest("service", "unbound", "up", 1010) // no change — must be a no-op

	got, err := db.GetStateIntervals("service", "unbound", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 interval (no reopen on same state), got %d", len(got))
	}
}
```

- [ ] **Step 3: Implement the service**

Create `internal/tsdb/service.go`:

```go
// Package tsdb is the generic time-series substrate for LinkGuard: gauges with
// min/avg/max per bucket, and states as intervals. It absorbs what used to be
// internal/trafficrrd (traffic-only, average-only) — traffic is now just one
// more series.
package tsdb

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Recorder is the write surface producers use. Gauge accumulates a reading
// into the current bucket in memory; it must never block on disk — the
// service's own goroutine does all writes, on its own ticker. State opens a
// new interval only when the state actually changes.
type Recorder interface {
	Gauge(series, label string, v float64)
	State(kind, label, state string)
}

type bucket struct {
	start        int64
	min, max     float64
	sum          float64
	count        int
}

type openState struct {
	state     string
	startedAt int64
}

// Service is the tsdb writer/reader. One instance per process, shared by every
// producer via the Recorder interface.
type Service struct {
	db *storage.DB

	mu      sync.Mutex
	pending map[int]map[seriesLabel]*bucket // step -> (series,label) -> current bucket

	stateMu sync.Mutex
	states  map[stateKey]*openState

	lastPrune time.Time
}

type seriesLabel struct{ series, label string }
type stateKey struct{ kind, label string }

// NewService creates a tsdb Service.
func NewService(db *storage.DB) *Service {
	s := &Service{
		db:      db,
		pending: make(map[int]map[seriesLabel]*bucket),
		states:  make(map[stateKey]*openState),
	}
	for _, step := range append([]int{1, 10, 30}, derivedSteps...) {
		s.pending[step] = make(map[seriesLabel]*bucket)
	}
	return s
}

// Gauge accumulates one reading into the in-memory bucket for series+label at
// its native step. Memory-only — see the package doc.
func (s *Service) Gauge(series, label string, v float64) {
	step := nativeStep(series)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accumulate(step, series, label, v, time.Now().Unix())
}

// accumulate must be called with s.mu held.
func (s *Service) accumulate(step int, series, label string, v float64, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			s.flushBucket(step, series, label, b)
		}
		b = &bucket{start: bucketStart, min: v, max: v, sum: v, count: 1}
		s.pending[step][key] = b
		return
	}
	if v < b.min {
		b.min = v
	}
	if v > b.max {
		b.max = v
	}
	b.sum += v
	b.count++
}

// flushBucket writes a closed bucket to disk and, for the native steps (not
// the derived ones), feeds its average into every derived-step bucket so the
// rollup chain builds up incrementally rather than re-scanning raw data.
func (s *Service) flushBucket(step int, series, label string, b *bucket) {
	avg := b.sum / float64(b.count)
	_ = s.db.UpsertMetricSample(storage.MetricSample{
		Series: series, Label: label, StepSeconds: step,
		TsUnix: b.start, VMin: b.min, VAvg: avg, VMax: b.max,
	})
	if isDerivedStep(step) {
		return
	}
	for _, derived := range derivedSteps {
		s.rollInto(derived, series, label, b.min, avg, b.max, b.start)
	}
}

// rollInto merges one native bucket's min/avg/max into the current bucket of
// a longer (derived) step. min/max propagate directly; avg is folded as a new
// sample into a running mean — see mergeAvg.
func (s *Service) rollInto(step int, series, label string, min, avg, max float64, now int64) {
	key := seriesLabel{series, label}
	bucketStart := now - (now % int64(step))
	b := s.pending[step][key]
	if b == nil || b.start != bucketStart {
		if b != nil {
			s.flushBucket(step, series, label, b)
		}
		b = &bucket{start: bucketStart, min: min, max: max, sum: avg, count: 1}
		s.pending[step][key] = b
		return
	}
	if min < b.min {
		b.min = min
	}
	if max > b.max {
		b.max = max
	}
	b.sum += avg
	b.count++
}

func isDerivedStep(step int) bool {
	for _, d := range derivedSteps {
		if d == step {
			return true
		}
	}
	return false
}

// State opens a new interval for (kind, label) only if the state actually
// changed — repeating the same state is a no-op, matching the "state is a
// level, not an event" model.
func (s *Service) State(kind, label, state string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.transitionState(kind, label, state, time.Now().Unix())
}

// transitionState must be called with s.stateMu held.
func (s *Service) transitionState(kind, label, state string, now int64) {
	key := stateKey{kind, label}
	cur := s.states[key]
	if cur != nil && cur.state == state {
		return
	}
	if cur != nil {
		_ = s.db.CloseOpenStateInterval(kind, label, now)
	}
	_ = s.db.OpenStateInterval(kind, label, state, now)
	s.states[key] = &openState{state: state, startedAt: now}
}

// Run starts the 1s writer tick. It flushes any bucket whose window has
// closed and prunes old data periodically. Blocks until ctx is done.
func (s *Service) Run(ctx context.Context) {
	slog.Info("tsdb service started")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(time.Now().Unix())
		}
	}
}

func (s *Service) tick(now int64) {
	s.mu.Lock()
	for step, m := range s.pending {
		for key, b := range m {
			if now-(now%int64(step)) != b.start {
				s.flushBucket(step, key.series, key.label, b)
				delete(m, key)
			}
		}
	}
	s.mu.Unlock()

	if time.Since(s.lastPrune) > 2*time.Minute {
		s.prune(now)
		s.lastPrune = time.Now()
	}
}

func (s *Service) prune(now int64) {
	for step, keep := range profileRetention(s.profile()) {
		_ = s.db.PruneMetricSamples(step, now-int64(keep.Seconds()))
	}
}
```

- [ ] **Step 4: Add the test-only flush hooks**

Add to `internal/tsdb/service.go` (these exist so tests can force a deterministic flush instead of racing a real ticker — they are not part of the public `Recorder` interface):

```go
// FlushForTest forces every pending bucket whose window would have closed by
// "now" to flush, without waiting for the real ticker. Test-only.
func (s *Service) FlushForTest(now int64) {
	s.tick(now)
}

// StateForTest calls transitionState with an explicit timestamp instead of
// time.Now(), so interval tests are deterministic. Test-only.
func (s *Service) StateForTest(kind, label, state string, at int64) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.transitionState(kind, label, state, at)
}
```

- [ ] **Step 5: Add the retention profile (mirrors trafficrrd's, extended to all series)**

Add to `internal/tsdb/schema.go`:

```go
import "time"

// Supported profile IDs — unchanged from the old trafficrrd, same meaning.
const (
	Profile30d = "30d"
	Profile1y  = "1y"
	Profile5y  = "5y"
)

type stepRetention struct {
	StepSeconds int
	KeepFor     time.Duration
}

func profileRetention(profile string) []stepRetention {
	switch profile {
	case Profile1y:
		return []stepRetention{
			{1, 30 * time.Minute}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 14 * 24 * time.Hour}, {900, 180 * 24 * time.Hour}, {3600, 365 * 24 * time.Hour},
		}
	case Profile5y:
		return []stepRetention{
			{1, 15 * time.Minute}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 7 * 24 * time.Hour}, {900, 365 * 24 * time.Hour}, {3600, 5 * 365 * 24 * time.Hour},
		}
	default:
		return []stepRetention{
			{1, 2 * time.Hour}, {10, 48 * time.Hour}, {30, 48 * time.Hour},
			{60, 7 * 24 * time.Hour}, {900, 30 * 24 * time.Hour}, {3600, 90 * 24 * time.Hour},
		}
	}
}
```

- [ ] **Step 6: Add profile get/set (ported from trafficrrd, same settings key)**

Add to `internal/tsdb/service.go`, and add `profile string` + `profileMu sync.RWMutex` fields to the `Service` struct from Step 3:

```go
const retentionProfileSettingKey = "traffic_retention_profile"

func (s *Service) profile() string {
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	if s.profileCache == "" {
		return Profile30d
	}
	return s.profileCache
}

// GetProfile returns the active retention profile.
func (s *Service) GetProfile() string {
	return s.profile()
}

// SetProfile persists the retention profile and prunes immediately so a
// shorter profile takes effect right away instead of waiting for the next tick.
func (s *Service) SetProfile(profile string) error {
	if profile != Profile30d && profile != Profile1y && profile != Profile5y {
		return fmt.Errorf("invalid profile")
	}
	if err := s.db.SetSetting(retentionProfileSettingKey, profile); err != nil {
		return err
	}
	s.profileMu.Lock()
	s.profileCache = profile
	s.profileMu.Unlock()
	s.prune(time.Now().Unix())
	return nil
}
```

Update the `Service` struct in Step 3 to add:

```go
	profileMu    sync.RWMutex
	profileCache string
```

And update `NewService` to load the persisted profile:

```go
func NewService(db *storage.DB) *Service {
	s := &Service{
		db:      db,
		pending: make(map[int]map[seriesLabel]*bucket),
		states:  make(map[stateKey]*openState),
	}
	for _, step := range append([]int{1, 10, 30}, derivedSteps...) {
		s.pending[step] = make(map[seriesLabel]*bucket)
	}
	if p, _ := db.GetSetting(retentionProfileSettingKey); p != "" {
		s.profileCache = p
	}
	return s
}
```

Add `"fmt"` to the imports in `internal/tsdb/service.go`.

- [ ] **Step 7: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/tsdb/... -v
```

Expected before Steps 3–6: FAIL with `package tsdb is not in std` / compile errors. After: all PASS.

- [ ] **Step 8: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/tsdb/service.go internal/tsdb/schema.go internal/tsdb/service_test.go
go vet ./internal/tsdb/...
git add internal/tsdb/
git commit -m "feat(tsdb): Recorder, min/avg/max rollup, state intervals"
```

---

### Task 4: Traffic sampler (absorbed from trafficrrd) + `GetHistory` compatibility method

**Files:**
- Create: `internal/tsdb/traffic.go`
- Modify: `internal/tsdb/service.go` (call the sampler from `Run`)
- Test: `internal/tsdb/traffic_test.go`

**Interfaces:**
- Consumes: `system.Collector.Collect() (system.Metrics, error)` (existing, unchanged — see `internal/system/system.go`).
- Produces: `func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error)` — same contract `internal/api/handlers/system.go`'s `TrafficHistory` handler already calls on `trafficrrd.Service`, so the handler needs no logic change, only a type swap (Task 7).

- [ ] **Step 1: Write the failing test**

Create `internal/tsdb/traffic_test.go`:

```go
package tsdb_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestGetHistoryUnknownRangeDefaultsTo12h(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	res, err := svc.GetHistory("eth0", "not-a-real-range")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if res.Step != 60 {
		t.Fatalf("expected default range to use step=60 (12h/60s), got %d", res.Step)
	}
}

func TestGetHistoryRequiresInterface(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	if _, err := svc.GetHistory("", "12h"); err == nil {
		t.Fatal("expected error for empty interface")
	}
}
```

- [ ] **Step 2: Implement the traffic sampler and history query**

Create `internal/tsdb/traffic.go`:

```go
package tsdb

import (
	"fmt"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// TrafficSampler feeds the "if.rx_bps"/"if.tx_bps" series once a second from
// interface byte counters, mirroring what internal/trafficrrd used to do
// directly against the database — the difference is it now calls Gauge()
// instead of writing SQL itself.
type TrafficSampler struct {
	sysCol *system.Collector
	rec    Recorder

	prevCounters map[string]struct {
		ts int64
		rx uint64
		tx uint64
	}
}

// NewTrafficSampler creates a sampler that reports into rec (normally the
// same *Service — pass it as a Recorder).
func NewTrafficSampler(rec Recorder) *TrafficSampler {
	return &TrafficSampler{
		sysCol: system.NewCollector(),
		rec:    rec,
		prevCounters: make(map[string]struct {
			ts int64
			rx uint64
			tx uint64
		}),
	}
}

// SampleOnce reads current interface counters and reports the delta-derived
// rate for each interface. Call once per second.
func (t *TrafficSampler) SampleOnce(now int64) {
	snap, err := t.sysCol.Collect()
	if err != nil {
		return
	}
	for _, iface := range snap.Interfaces {
		if iface.Name == "lo" {
			continue
		}
		prev, ok := t.prevCounters[iface.Name]
		t.prevCounters[iface.Name] = struct {
			ts int64
			rx uint64
			tx uint64
		}{ts: now, rx: iface.RxBytes, tx: iface.TxBytes}
		if !ok {
			continue
		}
		dt := float64(now - prev.ts)
		if dt <= 0 {
			continue
		}
		rxDelta := float64(iface.RxBytes - prev.rx)
		txDelta := float64(iface.TxBytes - prev.tx)
		if rxDelta < 0 {
			rxDelta = 0
		}
		if txDelta < 0 {
			txDelta = 0
		}
		t.rec.Gauge("if.rx_bps", iface.Name, rxDelta/dt)
		t.rec.Gauge("if.tx_bps", iface.Name, txDelta/dt)
	}
}

// HistoryResponse is returned by the /api/system/traffic-history and
// /api/monitoring/timeline handlers for chart rendering — same shape the
// frontend already consumes from the old trafficrrd.HistoryResponse.
type HistoryResponse struct {
	Interface string                   `json:"interface"`
	Range     string                   `json:"range"`
	Step      int                      `json:"step_seconds"`
	Points    []storage.MetricSample   `json:"points"`
}

// GetHistory returns rx/tx history for one interface — drop-in replacement
// for the old trafficrrd.Service.GetHistory.
func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	step, dur := rangeToStepDuration(rangeID)
	toUnix := time.Now().Unix()
	fromUnix := toUnix - int64(dur.Seconds())

	points, err := s.db.GetMetricSamples("if.rx_bps", iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	return &HistoryResponse{Interface: iface, Range: rangeID, Step: step, Points: points}, nil
}

func rangeToStepDuration(rangeID string) (int, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(rangeID)) {
	case "5m":
		return 1, 5 * time.Minute
	case "30m":
		return 1, 30 * time.Minute
	case "12h":
		return 60, 12 * time.Hour
	case "30d":
		return 900, 30 * 24 * time.Hour
	case "1y":
		return 3600, 365 * 24 * time.Hour
	case "5y":
		return 3600, 5 * 365 * 24 * time.Hour
	default:
		return 60, 12 * time.Hour
	}
}
```

- [ ] **Step 3: Wire the sampler into `Run`**

In `internal/tsdb/service.go`, modify `Run` (from Task 3 Step 3) to sample traffic every tick:

```go
// Run starts the 1s writer tick. It flushes any bucket whose window has
// closed, samples interface traffic, and prunes old data periodically.
// Blocks until ctx is done.
func (s *Service) Run(ctx context.Context) {
	slog.Info("tsdb service started")
	sampler := NewTrafficSampler(s)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			sampler.SampleOnce(now)
			s.tick(now)
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/tsdb/... -v
```

Expected before Step 2: FAIL with `undefined: tsdb.NewTrafficSampler` (or compile error from `GetHistory`). After: all PASS, including Task 3's tests (no regression).

- [ ] **Step 5: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/tsdb/traffic.go internal/tsdb/traffic_test.go internal/tsdb/service.go
go vet ./internal/tsdb/...
git add internal/tsdb/
git commit -m "feat(tsdb): absorb the 1s interface traffic sampler from trafficrrd"
```

---

### Task 5: Migrate `traffic_samples` → `metric_samples`, retire `internal/trafficrrd`

**Files:**
- Modify: `internal/storage/storage.go` (add migration function, rename old table)
- Test: `internal/storage/storage_test.go`
- Delete: `internal/trafficrrd/service.go`

**Interfaces:**
- Consumes: `db.conn *sql.DB`, the `metric_samples` table from Task 1.
- Produces: `func (db *DB) migrateTrafficSamplesToMetricSamples() error`, called once from `migrate()`.

- [ ] **Step 1: Write the failing test**

Add to `internal/storage/storage_test.go`:

```go
func TestMigrateTrafficSamplesToMetricSamples(t *testing.T) {
	db := newTestDB(t)

	// Simulate a pre-migration row the way the old trafficrrd wrote it.
	_, err := db.Conn().Exec(`INSERT INTO traffic_samples
		(interface, step_seconds, ts_unix, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?)`,
		"eth0", 60, 5000, 1234.5, 6789.0)
	if err != nil {
		t.Fatalf("seed traffic_samples: %v", err)
	}

	if err := db.MigrateTrafficSamplesToMetricSamplesForTest(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rx, err := db.GetMetricSamples("if.rx_bps", "eth0", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples rx: %v", err)
	}
	if len(rx) != 1 || rx[0].VAvg != 1234.5 || rx[0].VMin != 1234.5 || rx[0].VMax != 1234.5 {
		t.Fatalf("expected 1 rx sample with min=avg=max=1234.5, got %v", rx)
	}

	tx, err := db.GetMetricSamples("if.tx_bps", "eth0", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples tx: %v", err)
	}
	if len(tx) != 1 || tx[0].VAvg != 6789.0 {
		t.Fatalf("expected 1 tx sample avg=6789.0, got %v", tx)
	}

	// Idempotent: running twice must not duplicate or error.
	if err := db.MigrateTrafficSamplesToMetricSamplesForTest(); err != nil {
		t.Fatalf("second migrate call: %v", err)
	}
	rx2, _ := db.GetMetricSamples("if.rx_bps", "eth0", 60, 0, 100000)
	if len(rx2) != 1 {
		t.Fatalf("expected migration to stay idempotent, got %d rx samples", len(rx2))
	}
}
```

- [ ] **Step 2: Rename the old table instead of dropping it**

In `internal/storage/storage.go`, change the `createTrafficSamplesTable` constant name reference — do not delete it, add a rename step that runs once. Add after `createStateIntervalsOpenIndex` in the `migrations` slice from Task 1 Step 2:

```go
const renameTrafficSamplesIfPresent = `
ALTER TABLE traffic_samples RENAME TO traffic_samples_pre_tsdb_migration;`
```

This must run **conditionally** — `ALTER TABLE ... RENAME` errors if `traffic_samples` no longer exists (already renamed on a prior boot) or never existed (fresh install). Do not add it to the plain `migrations` string slice; instead add a dedicated function called from `migrate()`:

```go
// migrateTrafficSamplesToMetricSamples copies every row from the legacy
// traffic_samples table into metric_samples as if.rx_bps/if.tx_bps, then
// renames (never drops) the old table so a fresh install or a second boot is
// a no-op. min=avg=max=value for migrated rows — the old table never recorded
// a spike, so there is nothing more honest to backfill.
func (db *DB) migrateTrafficSamplesToMetricSamples() error {
	var exists int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='traffic_samples'`).Scan(&exists)
	if err != nil {
		return err
	}
	if exists == 0 {
		return nil // already migrated on a prior boot, or fresh install
	}

	rows, err := db.conn.Query(`SELECT interface, step_seconds, ts_unix, rx_bps, tx_bps FROM traffic_samples`)
	if err != nil {
		return err
	}
	type legacyRow struct {
		iface           string
		step            int
		ts              int64
		rx, tx          float64
	}
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.iface, &r.step, &r.ts, &r.rx, &r.tx); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range legacy {
		if err := db.UpsertMetricSample(MetricSample{
			Series: "if.rx_bps", Label: r.iface, StepSeconds: r.step, TsUnix: r.ts,
			VMin: r.rx, VAvg: r.rx, VMax: r.rx,
		}); err != nil {
			return err
		}
		if err := db.UpsertMetricSample(MetricSample{
			Series: "if.tx_bps", Label: r.iface, StepSeconds: r.step, TsUnix: r.ts,
			VMin: r.tx, VAvg: r.tx, VMax: r.tx,
		}); err != nil {
			return err
		}
	}

	_, err = db.conn.Exec(`ALTER TABLE traffic_samples RENAME TO traffic_samples_pre_tsdb_migration`)
	return err
}

// MigrateTrafficSamplesToMetricSamplesForTest exposes the migration for tests
// in the storage_test package (which cannot call the unexported method
// directly). Test-only.
func (db *DB) MigrateTrafficSamplesToMetricSamplesForTest() error {
	return db.migrateTrafficSamplesToMetricSamples()
}
```

- [ ] **Step 3: Call the migration from `migrate()`**

In `internal/storage/storage.go`, modify `migrate()` (from Task 1) to run the migration function after the table-creation loop:

```go
func (db *DB) migrate() error {
	migrations := []string{
		// ... unchanged list from Task 1 ...
	}

	for _, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	if err := db.migrateTrafficSamplesToMetricSamples(); err != nil {
		return fmt.Errorf("migrate traffic_samples to metric_samples: %w", err)
	}

	return nil
}
```

Remove the `renameTrafficSamplesIfPresent` constant added in Step 2 above — it was superseded by the Go function doing the rename itself; do not leave dead code.

- [ ] **Step 4: Run test to verify it fails, then passes**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run TestMigrateTrafficSamplesToMetricSamples -v
```

Expected before Steps 2–3: FAIL with `undefined: db.MigrateTrafficSamplesToMetricSamplesForTest`. After: PASS.

- [ ] **Step 5: Run the full storage suite (regression check)**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -v
```

Expected: all PASS, including every test from Tasks 1–2.

- [ ] **Step 6: Delete `internal/trafficrrd`**

```bash
rm -rf internal/trafficrrd
```

This will break the build until Task 6 updates `main.go` and `internal/api` — that is expected and fixed in the next task. Do not run `go build` yet.

- [ ] **Step 7: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/storage.go internal/storage/storage_test.go
git add internal/storage/storage.go internal/storage/storage_test.go
git add -u internal/trafficrrd  # stages the deletion
git commit -m "feat(storage): migrate traffic_samples into metric_samples, retire trafficrrd"
```

---

### Task 6: Rewire `main.go` and `internal/api` from `trafficrrd` to `tsdb`

**Files:**
- Modify: `cmd/linkguard-fw/main.go`
- Modify: `internal/api/server.go`
- Modify: `internal/api/handlers/system.go`

**Interfaces:**
- Consumes: `tsdb.NewService(db) *tsdb.Service` (Task 3), `(*tsdb.Service).GetHistory` (Task 4), `(*tsdb.Service).Run(ctx)` (Task 4).
- Produces: nothing new — this task only swaps the dependency the rest of the codebase already points at.

- [ ] **Step 1: Update `main.go`**

In `cmd/linkguard-fw/main.go`, replace the import (line 39):

```go
	"github.com/giovanibalarini/linkguard-fw/internal/trafficrrd"
```
with:
```go
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
```

Replace line 146:
```go
	rrdSvc := trafficrrd.NewService(db)
```
with:
```go
	rrdSvc := tsdb.NewService(db)
```

Replace line 202 (`go rrdSvc.Run(ctx)`) — no change needed, the method name and signature are identical (`Run(ctx context.Context)`).

The `api.New(...)` call on line 158 passes `rrdSvc` positionally — its type changes from `*trafficrrd.Service` to `*tsdb.Service`, which requires updating the `Config`/`New` signature in Step 2 below before this compiles.

- [ ] **Step 2: Update `internal/api/server.go`**

Replace the import (in the import block, alongside the other internal packages):
```go
	"github.com/giovanibalarini/linkguard-fw/internal/trafficrrd"
```
with:
```go
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
```

Replace the `rrdSvc` field type in the `Server` struct:
```go
	rrdSvc      *trafficrrd.Service
```
with:
```go
	rrdSvc      *tsdb.Service
```

Replace the `rrdSvc` parameter type in `New(...)`:
```go
	sysCol *system.Collector, rrdSvc *trafficrrd.Service, promReg *prometheus.Registry,
```
with:
```go
	sysCol *system.Collector, rrdSvc *tsdb.Service, promReg *prometheus.Registry,
```

- [ ] **Step 3: Update `internal/api/handlers/system.go`**

Replace the import:
```go
	"github.com/giovanibalarini/linkguard-fw/internal/trafficrrd"
```
with:
```go
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
```

Replace the `rrdSvc` field type on `SystemHandler` and the constructor parameter type:
```go
type SystemHandler struct {
	sysCol *system.Collector
	db     *storage.DB
	rrdSvc *trafficrrd.Service
}

func NewSystemHandler(sysCol *system.Collector, db *storage.DB, rrdSvc *trafficrrd.Service) *SystemHandler {
	return &SystemHandler{sysCol: sysCol, db: db, rrdSvc: rrdSvc}
}
```
with:
```go
type SystemHandler struct {
	sysCol *system.Collector
	db     *storage.DB
	rrdSvc *tsdb.Service
}

func NewSystemHandler(sysCol *system.Collector, db *storage.DB, rrdSvc *tsdb.Service) *SystemHandler {
	return &SystemHandler{sysCol: sysCol, db: db, rrdSvc: rrdSvc}
}
```

The `TrafficHistory` handler body (`h.rrdSvc.GetHistory(iface, rangeID)`) needs no change — `tsdb.Service.GetHistory` has the identical signature defined in Task 4.

- [ ] **Step 4: Build to verify the rewire compiles**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
```

Expected: clean build, no output. If any other file references `trafficrrd`, the error will name it — fix by applying the same import/type swap.

- [ ] **Step 5: Run the full test suite (regression check)**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./... 2>&1
```

Expected: every package `ok`, none referencing `trafficrrd` (that package no longer exists).

- [ ] **Step 6: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -l cmd/linkguard-fw/main.go internal/api/server.go internal/api/handlers/system.go
git add cmd/linkguard-fw/main.go internal/api/server.go internal/api/handlers/system.go
git commit -m "refactor: rewire main.go and api server from trafficrrd to tsdb"
```

---

### Task 7: Wire producers — link monitor, service health, system resources

**Files:**
- Modify: `internal/links/monitor.go`
- Modify: `internal/monitoring/collector.go`
- Modify: `internal/monitoring/healthchecks.go`
- Modify: `cmd/linkguard-fw/main.go` (pass the `tsdb.Recorder` into `links.NewMonitor` and `monitoring.NewCollector`)
- Test: `internal/links/monitor_test.go` (create if it does not exist), `internal/monitoring/collector_test.go` (extend if present)

**Interfaces:**
- Consumes: `tsdb.Recorder` interface (Task 3) — `Gauge(series, label string, v float64)`, `State(kind, label, state string)`.
- Produces: nothing new publicly — this task makes existing measurement code points also call `Recorder`, in addition to what they already do (`UpdateStatus`, Prometheus gauges).

- [ ] **Step 1: Add a `Recorder` field to `links.Monitor`**

In `internal/links/monitor.go`, add an import and a field:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

type Monitor struct {
	db                  *storage.DB
	svc                 *Service
	interval            time.Duration
	probeCount          int
	rec                 tsdb.Recorder
	onStatusChange      func(link *storage.Link, oldStatus, newStatus string)
	onDegradedSustained func(link *storage.Link)
	sustainThreshold    func() int

	mu     sync.Mutex
	states map[string]*linkState
}
```

Update `NewMonitor` to accept it:

```go
// NewMonitor creates a new Monitor. probeCount is how many connectivity probes
// are sent per host per tick (≥1); more probes yield finer packet-loss/latency.
// rec receives every measurement for the diagnostic timeline — pass nil to
// disable (used in tests that don't care about history).
func NewMonitor(db *storage.DB, svc *Service, interval time.Duration, probeCount int, rec tsdb.Recorder) *Monitor {
	if probeCount < 1 {
		probeCount = 1
	}
	return &Monitor{
		db:         db,
		svc:        svc,
		interval:   interval,
		probeCount: probeCount,
		rec:        rec,
		states:     make(map[string]*linkState),
	}
}
```

- [ ] **Step 2: Record gauges and state in `checkLink`**

In `internal/links/monitor.go`, modify `checkLink` (the function that already computes `avgLatency, packetLoss := summarize(results)` and calls `state.advance(...)`) to also call the recorder. Insert right after `newStatus, fireSustained := state.advance(...)`, guarding every call with a nil check since `rec` may be nil in tests:

```go
	newStatus, fireSustained := state.advance(reachable, degradedNow, l.Status, m.sustainN())

	if m.rec != nil {
		m.rec.Gauge("link.latency_ms", l.Name, avgLatency)
		m.rec.Gauge("link.loss_pct", l.Name, packetLoss)
		m.rec.State("link", l.Name, newStatus)
	}
```

Place this **before** the `m.svc.UpdateStatus(...)` call so a failure in `UpdateStatus` (which returns early) never skips recording — the timeline must reflect what was measured even if the DB write for the "current value" fails.

- [ ] **Step 3: Update `main.go` to pass the recorder**

In `cmd/linkguard-fw/main.go`, `links.NewMonitor` is constructed before `rrdSvc` in the current ordering — move the `tsdb.NewService(db)` call earlier so it can be passed in. Reorder around line 146 and line 168:

```go
	rrdSvc := tsdb.NewService(db)
	// ... (sysCollector, promReg, appMetrics, metricsCollector as before) ...

	// moved down here, after rrdSvc exists:
	probeInterval := time.Duration(cfg.ProbeIntervalSeconds) * time.Second
	monitor := links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount, rrdSvc)
```

Concretely: cut the `rrdSvc := tsdb.NewService(db)` line from its current position (after `sysCollector := system.NewCollector()`) and move it up to right after `hostSvc := hosts.NewService(...)`, so it exists before `monitor := links.NewMonitor(...)` is constructed further down. Update the `links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount)` call to add `, rrdSvc` as the fifth argument.

- [ ] **Step 4: Write the failing test**

Create `internal/links/monitor_test.go` if it does not already exist (check first with `ls internal/links/*_test.go`); add:

```go
package links_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

type recorderSpy struct {
	gauges []struct{ series, label string; v float64 }
	states []struct{ kind, label, state string }
}

func (r *recorderSpy) Gauge(series, label string, v float64) {
	r.gauges = append(r.gauges, struct{ series, label string; v float64 }{series, label, v})
}
func (r *recorderSpy) State(kind, label, state string) {
	r.states = append(r.states, struct{ kind, label, state string }{kind, label, state})
}

func TestMonitorRecordsGaugesAndState(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	linkSvc := links.NewService(db)
	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1", Enabled: true,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	rec := &recorderSpy{}
	mon := links.NewMonitor(db, linkSvc, time.Second, 1, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mon.RunOnceForTest(ctx)

	foundLatency, foundLoss, foundState := false, false, false
	for _, g := range rec.gauges {
		if g.series == "link.latency_ms" && g.label == "WAN1" {
			foundLatency = true
		}
		if g.series == "link.loss_pct" && g.label == "WAN1" {
			foundLoss = true
		}
	}
	for _, s := range rec.states {
		if s.kind == "link" && s.label == "WAN1" {
			foundState = true
		}
	}
	if !foundLatency || !foundLoss || !foundState {
		t.Fatalf("expected latency, loss and state to be recorded; got gauges=%v states=%v", rec.gauges, rec.states)
	}
}

// compile-time check that tsdb.Recorder is satisfiable by recorderSpy
var _ tsdb.Recorder = (*recorderSpy)(nil)
```

This test needs a way to run one check synchronously — add a small test-only export in `internal/links/monitor.go`:

```go
// RunOnceForTest runs a single checkAll pass synchronously. Test-only.
func (m *Monitor) RunOnceForTest(ctx context.Context) {
	m.checkAll(ctx)
}
```

- [ ] **Step 5: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/links/... -run TestMonitorRecordsGaugesAndState -v
```

Expected before Steps 1–4: FAIL (compile error, `NewMonitor` argument count mismatch). After: PASS.

- [ ] **Step 6: Wire `monitoring.Collector` — CPU/mem/disk gauges + service state**

In `internal/monitoring/collector.go`, add a `rec tsdb.Recorder` field and constructor parameter, same pattern as Step 1:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

type Collector struct {
	db        *storage.DB
	sysCol    *system.Collector
	m         *metrics.Metrics
	alertSvc  *alerts.Service
	exec      firewall.Executor
	rec       tsdb.Recorder
	startTime time.Time

	healthMu sync.Mutex
	health   map[string]*itemState
	nowFn    func() int64
}

func NewCollector(db *storage.DB, m *metrics.Metrics, alertSvc *alerts.Service, exec firewall.Executor, rec tsdb.Recorder) *Collector {
	return &Collector{
		db:        db,
		sysCol:    system.NewCollector(),
		m:         m,
		alertSvc:  alertSvc,
		exec:      exec,
		rec:       rec,
		startTime: time.Now(),
		health:    map[string]*itemState{},
		nowFn:     func() int64 { return time.Now().Unix() },
	}
}
```

In `collect()`, inside the `else` branch that already sets `c.m.CPUPercent.Set(sys.CPUPercent)` etc. (around line 74–77), add:

```go
		c.m.CPUPercent.Set(sys.CPUPercent)
		c.m.MemPercent.Set(sys.MemPercent)
		c.m.DiskPercent.Set(sys.DiskPercent)
		c.m.UptimeSeconds.Set(sys.UptimeSeconds)

		if c.rec != nil {
			c.rec.Gauge("sys.cpu_pct", "", sys.CPUPercent)
			c.rec.Gauge("sys.mem_pct", "", sys.MemPercent)
			c.rec.Gauge("sys.disk_pct", "", sys.DiskPercent)
		}
```

- [ ] **Step 7: Record service state transitions**

In `internal/monitoring/healthchecks.go`, `checkServices` already computes `up` per service and calls `c.observe(key, up, now)`. Add a state recording call right after `c.ensureMeta(key, svc, "service")` inside `checkServices`:

```go
func (c *Collector) checkServices(cfg Config) {
	now := c.nowFn()
	for _, svc := range cfg.Services {
		up := c.isActive(svc)
		key := "service:" + svc
		tr := c.observe(key, up, now)
		c.ensureMeta(key, svc, "service")
		if c.rec != nil {
			state := "down"
			if up {
				state = "up"
			}
			c.rec.State("service", svc, state)
		}
		switch tr {
		case transDown:
			_ = c.alertSvc.ServiceOffline(svc)
		case transUp:
			_ = c.alertSvc.ServiceOnline(svc)
		}
	}
}
```

Note this records the **raw** reading every tick (30s), not the anti-flap-confirmed transition — the timeline should show what was actually observed, while alerts keep using the debounced `observe()` result. This is an intentional difference: the diagnostic view answers "what did we see", the alert answers "should a human be told".

- [ ] **Step 8: Update `main.go` for the `monitoring.NewCollector` call site**

In `cmd/linkguard-fw/main.go`, update line 150:
```go
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec)
```
to:
```go
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
```

(`rrdSvc` — the `tsdb.Service` — was already moved earlier in Step 3 above, so it exists at this point in the function.)

- [ ] **Step 9: Build and run the full suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
```

Expected: clean build, all tests pass, including any existing `internal/monitoring` tests (check `ls internal/monitoring/*_test.go` first and update any call to `NewCollector` there to pass `nil` as the new `rec` argument if the test doesn't care about it).

- [ ] **Step 10: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/links/monitor.go internal/links/monitor_test.go internal/monitoring/collector.go internal/monitoring/healthchecks.go cmd/linkguard-fw/main.go
git add internal/links/ internal/monitoring/ cmd/linkguard-fw/main.go
git commit -m "feat(tsdb): wire link monitor and health collector as producers"
```

---

### Task 8: Publish Prometheus link gauges at 10s cadence instead of 30s

**Files:**
- Modify: `internal/links/monitor.go`
- Modify: `internal/monitoring/collector.go`
- Modify: `cmd/linkguard-fw/main.go`

**Interfaces:**
- Consumes: `*metrics.Metrics` (existing, `internal/metrics/metrics.go`).
- Produces: nothing new — moves an existing side effect from one call site to another.

- [ ] **Step 1: Remove the 30s link gauge updates from the collector**

In `internal/monitoring/collector.go`, delete these three lines from `collect()` (around line 112–117):

```go
	for _, l := range links {
		statusVal := metrics.LinkStatusValue(l.Status)
		c.m.LinkStatus.WithLabelValues(l.Name, l.Interface).Set(statusVal)
		c.m.LinkLatency.WithLabelValues(l.Name, l.Interface).Set(l.LatencyMs)
		c.m.LinkLoss.WithLabelValues(l.Name, l.Interface).Set(l.PacketLoss)
	}
```

Keep the `links, err := c.db.GetLinks()` fetch and the `if err != nil { ... return }` guard above it — the unresolved-alerts count and `trackLinks()` calls right after still need `links` in scope... actually check: `trackLinks()` re-fetches its own `links` internally (confirmed by its own `links, err := c.db.GetLinks()` call), so once the loop above is deleted, the `links` variable fetched at the top of this section becomes unused. Delete the now-unused fetch too:

```go
	// Link metrics
	links, err := c.db.GetLinks()
	if err != nil {
		slog.Warn("fetch links for metrics", "err", err)
		return
	}
```

Replace with nothing (delete the block) — but the function still needs the early-return-on-error behavior removed carefully: check what code follows it (`AlertsTotal` count, then `if cfg.Enabled { c.trackLinks() }`) does NOT depend on `links`, so it's safe to delete this block entirely without adjusting what follows.

- [ ] **Step 2: Add the gauges to `links.Monitor`**

In `internal/links/monitor.go`, add a `*metrics.Metrics` field, following the same nil-guarded pattern as `rec`:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
)

type Monitor struct {
	db                  *storage.DB
	svc                 *Service
	interval            time.Duration
	probeCount          int
	rec                 tsdb.Recorder
	m                   *metrics.Metrics
	onStatusChange      func(link *storage.Link, oldStatus, newStatus string)
	onDegradedSustained func(link *storage.Link)
	sustainThreshold    func() int

	mu     sync.Mutex
	states map[string]*linkState
}

func NewMonitor(db *storage.DB, svc *Service, interval time.Duration, probeCount int, rec tsdb.Recorder, m *metrics.Metrics) *Monitor {
	if probeCount < 1 {
		probeCount = 1
	}
	return &Monitor{
		db:         db,
		svc:        svc,
		interval:   interval,
		probeCount: probeCount,
		rec:        rec,
		m:          m,
		states:     make(map[string]*linkState),
	}
}
```

In `checkLink`, extend the recorder block from Task 7 Step 2 to also set the Prometheus gauges:

```go
	if m.rec != nil {
		m.rec.Gauge("link.latency_ms", l.Name, avgLatency)
		m.rec.Gauge("link.loss_pct", l.Name, packetLoss)
		m.rec.State("link", l.Name, newStatus)
	}
	if m.m != nil {
		m.m.LinkStatus.WithLabelValues(l.Name, l.Interface).Set(metrics.LinkStatusValue(newStatus))
		m.m.LinkLatency.WithLabelValues(l.Name, l.Interface).Set(avgLatency)
		m.m.LinkLoss.WithLabelValues(l.Name, l.Interface).Set(packetLoss)
	}
```

- [ ] **Step 3: Update `main.go`**

In `cmd/linkguard-fw/main.go`, `appMetrics := metrics.New(promReg)` already exists (around line 149) but currently runs after `monitor := links.NewMonitor(...)` in source order. Move `appMetrics := metrics.New(promReg)` to before the `monitor := links.NewMonitor(...)` line, and update the call:

```go
	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)

	// ... (rrdSvc already moved earlier per Task 7 Step 3) ...

	probeInterval := time.Duration(cfg.ProbeIntervalSeconds) * time.Second
	monitor := links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount, rrdSvc, appMetrics)
```

Remove the now-duplicate later declaration of `promReg`/`appMetrics` if the reordering leaves one — there must be exactly one of each in the function.

- [ ] **Step 4: Build and run the full suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
```

Expected: clean build (watch for "declared and not used: metrics" in collector.go if the import became unused — it is still used by `metrics.LinkStatusValue` nowhere in collector.go anymore if that was the only use; check with `grep -n "metrics\." internal/monitoring/collector.go` and remove the import if genuinely unused). All tests pass.

- [ ] **Step 5: Manual verification against a running instance**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go run ./cmd/linkguard-fw/ --dry-run --debug --addr 127.0.0.1 --port 9997 &
sleep 12
curl -s http://127.0.0.1:9997/metrics | grep linkguard_link_latency_ms
kill %1
```

Expected: the gauge line appears (may show `0` with no links configured in a fresh dry-run DB — that's fine, the goal is confirming the metric is still registered and served, not a specific value).

- [ ] **Step 6: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/links/monitor.go internal/monitoring/collector.go cmd/linkguard-fw/main.go
git add internal/links/monitor.go internal/monitoring/collector.go cmd/linkguard-fw/main.go
git commit -m "perf(metrics): publish link gauges at probe cadence (10s) instead of 30s"
```

---

### Task 9: `GET /api/monitoring/timeline` endpoint

**Files:**
- Create: `internal/api/handlers/timeline.go`
- Modify: `internal/api/server.go` (construct handler, register route)
- Test: `internal/api/handlers/timeline_test.go`

**Interfaces:**
- Consumes: `tsdb.Service` (`GetMetricSamples`/`GetStateIntervals` are on `*storage.DB`, reachable via a small query method added to `tsdb.Service` in Step 1), `alerts.Service.List` (existing).
- Produces: `GET /api/monitoring/timeline?from=<unix>&to=<unix>&series=<csv>`, permission `monitoring.read`.

- [ ] **Step 1: Add a `Timeline` query method to `tsdb.Service`**

Add to `internal/tsdb/traffic.go` (it already has `HistoryResponse`; this is the sibling multi-series query):

```go
// TimelinePoint is one bucket of one series in a timeline response.
type TimelinePoint struct {
	Ts  int64   `json:"ts"`
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

// TimelineSeries is one series+label's points for a timeline response.
type TimelineSeries struct {
	Name   string          `json:"name"`
	Label  string          `json:"label"`
	Points []TimelinePoint `json:"points"`
}

// TimelineState is one interval for the states section of a timeline response.
type TimelineState struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	State     string `json:"state"`
	StartedAt int64  `json:"started_at"`
	EndedAt   *int64 `json:"ended_at,omitempty"`
}

// TimelineRequest names which series+label pairs and which state kind+label
// pairs to include.
type TimelineRequest struct {
	FromUnix, ToUnix int64
	Series           []SeriesLabel // exported alias of the internal seriesLabel key
	States           []StateKindLabel
}

// SeriesLabel and StateKindLabel are exported so callers outside the package
// (the API handler) can name what they want without reaching into internals.
type SeriesLabel struct{ Series, Label string }
type StateKindLabel struct{ Kind, Label string }

// Timeline answers a correlated multi-series, multi-state query for the
// diagnostic timeline. It picks the bucket step from the window width, the
// same rule GetHistory uses for a single series.
func (s *Service) Timeline(req TimelineRequest) (step int, series []TimelineSeries, states []TimelineState, err error) {
	dur := time.Duration(req.ToUnix-req.FromUnix) * time.Second
	step, _ = stepForDuration(dur)

	for _, sl := range req.Series {
		samples, err := s.db.GetMetricSamples(sl.Series, sl.Label, step, req.FromUnix, req.ToUnix)
		if err != nil {
			return 0, nil, nil, err
		}
		points := make([]TimelinePoint, len(samples))
		for i, sm := range samples {
			points[i] = TimelinePoint{Ts: sm.TsUnix, Min: sm.VMin, Avg: sm.VAvg, Max: sm.VMax}
		}
		series = append(series, TimelineSeries{Name: sl.Series, Label: sl.Label, Points: points})
	}

	for _, kl := range req.States {
		intervals, err := s.db.GetStateIntervals(kl.Kind, kl.Label, req.FromUnix, req.ToUnix)
		if err != nil {
			return 0, nil, nil, err
		}
		for _, iv := range intervals {
			states = append(states, TimelineState{
				Kind: iv.Kind, Label: iv.Label, State: iv.State,
				StartedAt: iv.StartedAt, EndedAt: iv.EndedAt,
			})
		}
	}

	return step, series, states, nil
}

// stepForDuration picks a bucket step by window width, same thresholds as
// rangeToStepDuration but keyed by an actual duration instead of a named range
// (the timeline endpoint takes from/to timestamps, not a preset range name).
func stepForDuration(d time.Duration) (int, error) {
	switch {
	case d <= 30*time.Minute:
		return 1, nil
	case d <= 12*time.Hour:
		return 60, nil
	case d <= 30*24*time.Hour:
		return 900, nil
	default:
		return 3600, nil
	}
}
```

- [ ] **Step 2: Write the failing handler test**

Create `internal/api/handlers/timeline_test.go`:

```go
package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestTimelineHandlerReturnsSeriesAndStates(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()
	_ = db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 60,
		TsUnix: now - now%60, VMin: 10, VAvg: 15, VMax: 20,
	})
	_ = db.OpenStateInterval("link", "WAN VIVO", "online", now-3600)

	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)
	h := handlers.NewTimelineHandler(tsdbSvc, alertSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/timeline?from="+itoa(now-7200)+"&to="+itoa(now)+"&series=link.latency_ms:WAN+VIVO&states=link:WAN+VIVO", nil)
	w := httptest.NewRecorder()
	h.Timeline(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !contains(body, "link.latency_ms") {
		t.Fatalf("expected response to contain the requested series, got: %s", body)
	}
	if !contains(body, "\"state\":\"online\"") {
		t.Fatalf("expected response to contain the open state interval, got: %s", body)
	}
}

func TestTimelineHandlerRequiresFromAndTo(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)
	h := handlers.NewTimelineHandler(tsdbSvc, alertSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/timeline", nil)
	w := httptest.NewRecorder()
	h.Timeline(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing from/to, got %d", w.Code)
	}
}

func itoa(n int64) string {
	return time.Unix(n, 0).Format("2006") // placeholder replaced below
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
```

Fix `itoa` — the placeholder above is wrong (it formats a year, not the integer). Replace it with:

```go
func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
```

Add `"strconv"` to the imports.

- [ ] **Step 3: Implement the handler**

Create `internal/api/handlers/timeline.go`:

```go
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// TimelineHandler serves the correlated diagnostic timeline: gauges (with
// min/avg/max), state intervals, and the alerts raised in the window — all
// against one shared time axis so the frontend can render them stacked.
type TimelineHandler struct {
	tsdbSvc  *tsdb.Service
	alertSvc *alerts.Service
}

func NewTimelineHandler(tsdbSvc *tsdb.Service, alertSvc *alerts.Service) *TimelineHandler {
	return &TimelineHandler{tsdbSvc: tsdbSvc, alertSvc: alertSvc}
}

type timelineResponse struct {
	StepSeconds int                    `json:"step_seconds"`
	Series      []tsdb.TimelineSeries  `json:"series"`
	States      []tsdb.TimelineState   `json:"states"`
	Alerts      []timelineAlert        `json:"alerts"`
}

type timelineAlert struct {
	Ts       int64  `json:"ts"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Timeline handles GET /api/monitoring/timeline?from=<unix>&to=<unix>&series=<csv of series:label>&states=<csv of kind:label>
func (h *TimelineHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		writeError(w, http.StatusBadRequest, "from and to are required (unix seconds)")
		return
	}
	from, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from")
		return
	}
	to, err := strconv.ParseInt(toStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to")
		return
	}
	if to <= from {
		writeError(w, http.StatusBadRequest, "to must be after from")
		return
	}

	req := tsdb.TimelineRequest{FromUnix: from, ToUnix: to}
	for _, sl := range parsePairs(r.URL.Query().Get("series")) {
		req.Series = append(req.Series, tsdb.SeriesLabel{Series: sl[0], Label: sl[1]})
	}
	for _, kl := range parsePairs(r.URL.Query().Get("states")) {
		req.States = append(req.States, tsdb.StateKindLabel{Kind: kl[0], Label: kl[1]})
	}

	step, series, states, err := h.tsdbSvc.Timeline(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if series == nil {
		series = []tsdb.TimelineSeries{}
	}
	if states == nil {
		states = []tsdb.TimelineState{}
	}

	all, err := h.alertSvc.List(false, 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	alertsOut := []timelineAlert{}
	for _, a := range all {
		ts := a.CreatedAt.Unix()
		if ts < from || ts > to {
			continue
		}
		alertsOut = append(alertsOut, timelineAlert{Ts: ts, Type: a.Type, Severity: a.Severity, Title: a.Title})
	}

	writeJSON(w, http.StatusOK, timelineResponse{
		StepSeconds: step, Series: series, States: states, Alerts: alertsOut,
	})
}

// parsePairs splits a CSV of "key:value" entries (label values may contain
// spaces, encoded as "+" by the query string — net/url already decodes that).
func parsePairs(csv string) [][2]string {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(csv, ",") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out = append(out, [2]string{kv[0], kv[1]})
	}
	return out
}
```

- [ ] **Step 4: Register the route**

In `internal/api/server.go`, inside `buildRouter`, in the block that already constructs `monH := handlers.NewMonitoringHandler(s.mon, s.db)` (around line 252), add:

```go
		monH := handlers.NewMonitoringHandler(s.mon, s.db)
		timelineH := handlers.NewTimelineHandler(s.rrdSvc, s.alertSvc)
```

And in the same permission-grouped block as the existing monitoring routes (`r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/health", monH.Health)`), add:

```go
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/timeline", timelineH.Timeline)
```

- [ ] **Step 5: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/api/handlers/... -run TestTimeline -v
```

Expected before Step 3: FAIL (compile error, `handlers.NewTimelineHandler` undefined). After: PASS.

- [ ] **Step 6: Build, full suite, gofmt, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
gofmt -w internal/api/handlers/timeline.go internal/api/handlers/timeline_test.go internal/api/server.go internal/tsdb/traffic.go
git add internal/api/handlers/timeline.go internal/api/handlers/timeline_test.go internal/api/server.go internal/tsdb/traffic.go
git commit -m "feat(api): GET /api/monitoring/timeline — correlated diagnostic view"
```

---

### Task 10: Frontend — period selector, correlated timeline, deep-link from alerts

**Files:**
- Modify: `web/src/pages/Monitoring.tsx`
- Modify: `web/src/types/index.ts` (add `TimelineResponse` type)

**Interfaces:**
- Consumes: `GET /api/monitoring/timeline` (Task 9).
- Produces: no new exported interfaces — this is a leaf UI change.

- [ ] **Step 1: Add the TypeScript response types**

In `web/src/types/index.ts`, add after the `WanLink` interface:

```typescript
export interface TimelinePoint {
  ts: number;
  min: number;
  avg: number;
  max: number;
}

export interface TimelineSeries {
  name: string;
  label: string;
  points: TimelinePoint[];
}

export interface TimelineState {
  kind: string;
  label: string;
  state: string;
  started_at: number;
  ended_at?: number;
}

export interface TimelineAlert {
  ts: number;
  type: string;
  severity: string;
  title: string;
}

export interface TimelineResponse {
  step_seconds: number;
  series: TimelineSeries[];
  states: TimelineState[];
  alerts: TimelineAlert[];
}
```

- [ ] **Step 2: Add the period selector and timeline fetch to `Monitoring.tsx`**

In `web/src/pages/Monitoring.tsx`, add imports and new state after the existing `useState` declarations (after line 21):

```typescript
import { useSearchParams } from 'react-router-dom';
import type { WanLink, SystemMetrics, TimelineResponse } from '../types';

// ... inside the component, after tickRef ...
  const [searchParams] = useSearchParams();
  const [periodHours, setPeriodHours] = useState(1);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);
```

Add a fetch function and effect, placed after the existing `fetchData` function (after line 55):

```typescript
  const fetchTimeline = async () => {
    setTimelineLoading(true);
    try {
      const at = searchParams.get('at');
      const centerSec = at ? Math.floor(new Date(at).getTime() / 1000) : Math.floor(Date.now() / 1000);
      const halfWindow = (periodHours * 3600) / 2;
      const from = centerSec - halfWindow;
      const to = centerSec + halfWindow;
      const series = links.map(l => `link.latency_ms:${l.name},link.loss_pct:${l.name}`).join(',');
      const states = links.map(l => `link:${l.name}`).join(',');
      const res = await client.get<TimelineResponse>('/api/monitoring/timeline', {
        params: { from, to, series, states },
      });
      setTimeline(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setTimelineLoading(false);
    }
  };

  useEffect(() => {
    if (links.length > 0) {
      fetchTimeline();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [links.length, periodHours, searchParams]);
```

- [ ] **Step 3: Render the period selector and correlated timeline card**

In `web/src/pages/Monitoring.tsx`, add a new card after the "CPU / Memory chart" card (after line 187, before the "Interface traffic" section):

```tsx
      {/* Correlated diagnostic timeline */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h2 className="text-white font-semibold">Linha do tempo</h2>
          </div>
          <div className="flex gap-2">
            {[1, 6, 24].map(h => (
              <button
                key={h}
                onClick={() => setPeriodHours(h)}
                className={`px-3 py-1 rounded text-xs ${periodHours === h ? 'bg-blue-600 text-white' : 'btn-secondary'}`}
              >
                {h === 1 ? '1h' : h === 6 ? '6h' : '24h'}
              </button>
            ))}
          </div>
        </div>
        {timelineLoading && !timeline && (
          <p className="text-gray-500 text-sm text-center py-12">Carregando linha do tempo…</p>
        )}
        {timeline && timeline.series.every(s => s.points.length === 0) && (
          <p className="text-gray-500 text-sm text-center py-12">Sem dados no período selecionado.</p>
        )}
        {timeline && timeline.series.some(s => s.points.length > 0) && (
          <div className="space-y-4">
            {links.map((link, i) => {
              const latSeries = timeline.series.find(s => s.name === 'link.latency_ms' && s.label === link.name);
              if (!latSeries || latSeries.points.length === 0) return null;
              const data = latSeries.points.map(p => ({
                time: new Date(p.ts * 1000).toLocaleTimeString(),
                min: p.min, avg: p.avg, max: p.max,
              }));
              return (
                <div key={link.id}>
                  <p className="text-gray-400 text-xs mb-1">{link.name} — latência (ms), faixa min–max</p>
                  <ResponsiveContainer width="100%" height={120}>
                    <LineChart data={data}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                      <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 10 }} />
                      <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                      <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
                      <Line type="monotone" dataKey="max" stroke={COLORS[i % COLORS.length]} strokeOpacity={0.3} dot={false} strokeWidth={1} />
                      <Line type="monotone" dataKey="avg" stroke={COLORS[i % COLORS.length]} dot={false} strokeWidth={2} />
                      <Line type="monotone" dataKey="min" stroke={COLORS[i % COLORS.length]} strokeOpacity={0.3} dot={false} strokeWidth={1} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              );
            })}
            {timeline.states.filter(s => s.state !== 'online' && s.state !== 'up').length > 0 && (
              <div>
                <p className="text-gray-400 text-xs mb-1">Episódios no período</p>
                <ul className="text-xs text-gray-300 space-y-1">
                  {timeline.states
                    .filter(s => s.state !== 'online' && s.state !== 'up')
                    .map((s, idx) => (
                      <li key={idx} className="flex justify-between">
                        <span>{s.label} → {s.state}</span>
                        <span className="text-gray-500">
                          {new Date(s.started_at * 1000).toLocaleTimeString()}
                          {s.ended_at ? ` – ${new Date(s.ended_at * 1000).toLocaleTimeString()}` : ' (em curso)'}
                        </span>
                      </li>
                    ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
```

- [ ] **Step 4: Manual verification**

```bash
cd web && npm run build 2>&1 | tail -30
```

Expected: build succeeds with no TypeScript errors. Fix any type mismatch the compiler reports (most likely a missing import or a field name typo) before moving on — this is a frontend build check, not optional.

- [ ] **Step 5: Commit**

```bash
git add web/src/pages/Monitoring.tsx web/src/types/index.ts
git commit -m "feat(web): correlated timeline with period selector on Monitoring page"
```

---

### Task 11: Prometheus scrape job + Grafana dashboard, versioned in `deploy/`

**Files:**
- Create: `deploy/prometheus/linkguard.yml`
- Create: `deploy/grafana/linkguard-dashboard.json`
- Modify: `README.md` (document the integration)

**Interfaces:**
- None — these are static config files, not code.

- [ ] **Step 1: Write the Prometheus scrape job**

Create `deploy/prometheus/linkguard.yml`:

```yaml
# LinkGuard FW Prometheus scrape job.
#
# Add this as a job under scrape_configs in /etc/prometheus/prometheus.yml.
# LinkGuard exposes /metrics with no auth, on the same address/port as the
# web panel (default 127.0.0.1:9997 — adjust the target if the panel listens
# elsewhere, e.g. cfg.ListenAddr/cfg.Port in /etc/linkguard-fw/config.json).
- job_name: linkguard
  scrape_interval: 10s
  static_configs:
    - targets: ['localhost:9997']
```

- [ ] **Step 2: Write a minimal Grafana dashboard**

Create `deploy/grafana/linkguard-dashboard.json`:

```json
{
  "title": "LinkGuard FW",
  "schemaVersion": 39,
  "panels": [
    {
      "title": "Link status",
      "type": "stat",
      "gridPos": { "h": 4, "w": 24, "x": 0, "y": 0 },
      "targets": [{ "expr": "linkguard_link_status", "legendFormat": "{{link}}" }]
    },
    {
      "title": "Link latency (ms)",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 4 },
      "targets": [{ "expr": "linkguard_link_latency_ms", "legendFormat": "{{link}}" }]
    },
    {
      "title": "Link packet loss (%)",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 4 },
      "targets": [{ "expr": "linkguard_link_packet_loss_percent", "legendFormat": "{{link}}" }]
    },
    {
      "title": "System resources",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 12 },
      "targets": [
        { "expr": "linkguard_system_cpu_percent", "legendFormat": "CPU %" },
        { "expr": "linkguard_system_memory_percent", "legendFormat": "Mem %" },
        { "expr": "linkguard_system_disk_percent", "legendFormat": "Disk %" }
      ]
    },
    {
      "title": "Unresolved alerts",
      "type": "stat",
      "gridPos": { "h": 4, "w": 24, "x": 0, "y": 20 },
      "targets": [{ "expr": "linkguard_alerts_unresolved_total" }]
    }
  ]
}
```

- [ ] **Step 3: Document the integration in README**

In `README.md`, add a new section after "## Prometheus Metrics" (find with `grep -n "## Prometheus Metrics" README.md`):

```markdown
### Grafana / external Prometheus

If you already run Prometheus on the box (or reachable from it), point it at
LinkGuard with the job in `deploy/prometheus/linkguard.yml` — copy its
contents into your `scrape_configs`. A starter Grafana dashboard is at
`deploy/grafana/linkguard-dashboard.json` (Dashboards → Import → paste the
file contents).

This is entirely optional — LinkGuard keeps its own history (see the
Monitoring page's timeline) and does not require Prometheus to function.

**Known pitfall:** if you migrated from bind9 to unbound (see the DHCP/DNS
docs), remove any leftover `job_name: bind` entry in your `prometheus.yml` —
it will show as a permanently-down target for a service that no longer runs.
```

- [ ] **Step 4: Commit**

```bash
git add deploy/prometheus/linkguard.yml deploy/grafana/linkguard-dashboard.json README.md
git commit -m "docs(deploy): Prometheus scrape job and Grafana dashboard for LinkGuard"
```
</content>
