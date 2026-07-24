# Camada de IA (BYOK) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin plug in their own Claude API key and get AI-assisted analysis of link degradation — a daily digest of the accumulated pattern, plus an immediate analysis on a genuinely severe, hysteresis-confirmed event — without the AI ever being in the path that decides failover, weight, or eviction.

**Architecture:** `internal/ai` wraps the official `anthropic-sdk-go` behind a small `Client`, gated by a `BudgetGuard` that refuses to call out once the monthly spend cap is hit. An `EvidenceBuilder` queries `internal/tsdb` (Project 1) for pre-computed facts — never raw series — and the two triggers (`immediate.go`, `digest.go`) are the only callers. The token lives in `internal/secrets` (Project 3); everything else (model, effort, budget, consent) lives in a JSON blob in `settings`, matching the existing `monitoring`/`notify` config pattern.

**Tech Stack:** Go 1.25, `github.com/anthropics/anthropic-sdk-go` (new dependency), React (existing frontend stack).

## Global Constraints

- **Depends on Project 1 (`internal/tsdb`) and Project 2 (hysteresis fix) having landed.** `EvidenceBuilder` queries `tsdb`, and the immediate trigger must consume the post-hysteresis status transition — calling it before Project 2 lands would fire on every raw degraded sample, which is the exact failure mode this whole roadmap exists to fix.
- **Depends on Project 3 (`internal/secrets`)** for the token. Do not add a raw `settings` key for the API token under any circumstance.
- The AI `Report.Recommendation` field is always rendered as plain text for a human to read. No code path parses it as a command or feeds it into `balancer`, `routes`, `firewall`, or any other action-taking package. This is verified by a test in Task 4, not just by convention.
- `internal/ai` must never block the balancer's route-rebuild path: the immediate trigger runs in its own goroutine with a short timeout, and any error (network down, budget exceeded, invalid key) is logged and swallowed — it never propagates back into `balancer.OnLinkChange`.
- Model IDs are stored and passed as plain strings (`ai_config.model` is a DB-persisted string, cast to `anthropic.Model` at the call site) — do not hardcode a single model as a Go constant, since the admin selects among three.
- Anywhere this plan is not 100% certain of an `anthropic-sdk-go` field or method name, it says so explicitly and gives a `go doc` command to verify before writing that line — per the project's rule to never guess SDK usage.
- gofmt must pass on every Go file touched.

---

### Task 1: Add the SDK dependency and `ai_reports` table

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `internal/storage/storage.go`
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Produces: table `ai_reports(id TEXT PRIMARY KEY, kind TEXT, summary TEXT, findings TEXT, recommendation TEXT, confidence TEXT, created_at DATETIME)`; the `anthropic-sdk-go` module available to import.

- [ ] **Step 1: Add the dependency**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go get github.com/anthropics/anthropic-sdk-go@latest
go mod tidy
```

Expected: `go.mod` gains a `require github.com/anthropics/anthropic-sdk-go vX.Y.Z` line; `go.sum` gains matching entries.

- [ ] **Step 2: Verify the exact SDK surface this plan relies on before writing code against it**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go doc github.com/anthropics/anthropic-sdk-go Client
go doc github.com/anthropics/anthropic-sdk-go MessageNewParams
go doc github.com/anthropics/anthropic-sdk-go ThinkingConfigParamUnion
go doc github.com/anthropics/anthropic-sdk-go Message.Usage
```

Read the output. Task 3 below is written against `anthropic.NewClient(option.WithAPIKey(...))`, `client.Messages.New(ctx, anthropic.MessageNewParams{...})`, `Thinking: anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}}`, and `response.Usage.InputTokens`/`response.Usage.OutputTokens` — these are the confirmed-stable parts of the API. If any `go doc` output above shows a different field or method name than what Task 3 uses, stop and adjust Task 3's code to match the installed SDK version before implementing it — do not force the plan's exact text over what the compiler and `go doc` actually say.

- [ ] **Step 3: Add the `ai_reports` schema constant**

In `internal/storage/storage.go`, add:

```go
const createAIReportsTable = `
CREATE TABLE IF NOT EXISTS ai_reports (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    summary        TEXT NOT NULL,
    findings       TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    created_at     DATETIME NOT NULL
);`
```

Add it to the `migrations` slice in `migrate()`, alongside the other table-creation constants (order relative to other independent tables does not matter).

- [ ] **Step 4: Add the model, repository functions, and test**

In `internal/storage/models.go`, add:

```go
// ─── AIReport ────────────────────────────────────────────────────────────────

// AIReport is one AI-generated analysis — either a scheduled digest or an
// immediate analysis of a severe event.
type AIReport struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"` // "digest" | "immediate"
	Summary        string    `json:"summary"`
	Findings       string    `json:"findings"`       // JSON-encoded []string
	Recommendation string    `json:"recommendation"` // always human-readable text, never a command
	Confidence     string    `json:"confidence"`     // "alta" | "média" | "baixa"
	CreatedAt      time.Time `json:"created_at"`
}
```

In `internal/storage/repository.go`, add:

```go
// ─── AI Reports ──────────────────────────────────────────────────────────────

// CreateAIReport inserts a new report, generating its ID.
func (db *DB) CreateAIReport(r *AIReport) error {
	r.ID = uuid.NewString()
	r.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO ai_reports (id, kind, summary, findings, recommendation, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Kind, r.Summary, r.Findings, r.Recommendation, r.Confidence, r.CreatedAt)
	return err
}

// ListAIReports returns the most recent reports, newest first.
func (db *DB) ListAIReports(limit int) ([]AIReport, error) {
	rows, err := db.conn.Query(`
		SELECT id, kind, summary, findings, recommendation, confidence, created_at
		FROM ai_reports ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AIReport{}
	for rows.Next() {
		var r AIReport
		if err := rows.Scan(&r.ID, &r.Kind, &r.Summary, &r.Findings, &r.Recommendation, &r.Confidence, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAIReport returns one report by ID, or nil if not found.
func (db *DB) GetAIReport(id string) (*AIReport, error) {
	var r AIReport
	err := db.conn.QueryRow(`
		SELECT id, kind, summary, findings, recommendation, confidence, created_at
		FROM ai_reports WHERE id = ?`, id).
		Scan(&r.ID, &r.Kind, &r.Summary, &r.Findings, &r.Recommendation, &r.Confidence, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
```

Check `internal/storage/repository.go`'s imports already include `"github.com/google/uuid"` (used elsewhere for `CreateLink`, `CreateAlert`, etc. — confirm with `grep -n "uuid\." internal/storage/repository.go | head -3`); it does, per the existing pattern, so no new import is needed.

Add to `internal/storage/storage_test.go`:

```go
func TestCreateAndListAIReports(t *testing.T) {
	db := newTestDB(t)

	r := &storage.AIReport{
		Kind: "digest", Summary: "19 episódios na SUMICITY, nenhum com perda de carrier",
		Findings: `["SUMICITY: 19 episódios, 8-18s cada"]`,
		Recommendation: "Considere abrir chamado com a operadora anexando este relatório.",
		Confidence: "alta",
	}
	if err := db.CreateAIReport(r); err != nil {
		t.Fatalf("CreateAIReport: %v", err)
	}
	if r.ID == "" {
		t.Error("expected ID to be set")
	}

	got, err := db.ListAIReports(10)
	if err != nil {
		t.Fatalf("ListAIReports: %v", err)
	}
	if len(got) != 1 || got[0].Summary != r.Summary {
		t.Fatalf("expected 1 report matching what was created, got %v", got)
	}

	one, err := db.GetAIReport(r.ID)
	if err != nil {
		t.Fatalf("GetAIReport: %v", err)
	}
	if one == nil || one.ID != r.ID {
		t.Fatalf("expected GetAIReport to find the created report, got %v", one)
	}
}

func TestGetAIReportMissingReturnsNil(t *testing.T) {
	db := newTestDB(t)
	got, err := db.GetAIReport("does-not-exist")
	if err != nil {
		t.Fatalf("GetAIReport: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for a missing report")
	}
}
```

- [ ] **Step 5: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/storage/... -run TestCreateAndListAIReports -v
go test ./internal/storage/... -run TestGetAIReportMissingReturnsNil -v
```

Expected before Step 3–4: FAIL (`no such table` / undefined symbols). After: PASS.

- [ ] **Step 6: gofmt and commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/storage/storage.go internal/storage/models.go internal/storage/repository.go internal/storage/storage_test.go
git add go.mod go.sum internal/storage/
git commit -m "feat(storage): add ai_reports table; add anthropic-sdk-go dependency"
```

---

### Task 2: `internal/ai` — config, budget guard, evidence builder

**Files:**
- Create: `internal/ai/config.go`
- Create: `internal/ai/budget.go`
- Create: `internal/ai/evidence.go`
- Test: `internal/ai/config_test.go`, `internal/ai/budget_test.go`, `internal/ai/evidence_test.go`

**Interfaces:**
- Consumes: `*storage.DB` (`GetSetting`/`SetSetting`, matching the `monitoring.Config` pattern), `*tsdb.Service` (Project 1's `Timeline` method).
- Produces:
  - `type Config struct { Enabled bool; Model string; Effort string; MonthlyBudgetUSD float64; SpentThisMonthUSD float64; BudgetResetAt time.Time; TelemetryConsent map[string]bool; DigestHour int }`
  - `func LoadConfig(db *storage.DB) Config`
  - `func SaveConfig(db *storage.DB, c Config) error`
  - `type BudgetGuard struct{ ... }`
  - `func NewBudgetGuard(db *storage.DB) *BudgetGuard`
  - `func (g *BudgetGuard) Check() error` — nil if under budget
  - `func (g *BudgetGuard) RecordSpend(usd float64) error`
  - `type Evidence struct { Period string; Links []LinkSummary; CarrierEvents int; TrafficLevel string; RecentAlerts []AlertRef }`
  - `func BuildEvidence(tsdbSvc *tsdb.Service, alertSvc *alerts.Service, linkNames []string, fromUnix, toUnix int64) (Evidence, error)`

- [ ] **Step 1: Write the failing config test**

Create `internal/ai/config_test.go`:

```go
package ai_test

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
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

func TestLoadConfigDefaults(t *testing.T) {
	db := newTestDB(t)
	c := ai.LoadConfig(db)

	if c.Enabled {
		t.Error("expected disabled by default (opt-in feature)")
	}
	if c.Model != "claude-opus-4-8" {
		t.Errorf("expected default model claude-opus-4-8, got %q", c.Model)
	}
	if c.MonthlyBudgetUSD != 5.0 {
		t.Errorf("expected default budget $5, got %v", c.MonthlyBudgetUSD)
	}
}

func TestSaveThenLoadConfigRoundTrips(t *testing.T) {
	db := newTestDB(t)
	want := ai.Config{
		Enabled: true, Model: "claude-haiku-4-5", Effort: "medium",
		MonthlyBudgetUSD: 10.0, DigestHour: 6,
		TelemetryConsent: map[string]bool{"hostname": false, "mac": false},
	}
	if err := ai.SaveConfig(db, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got := ai.LoadConfig(db)
	if got.Enabled != want.Enabled || got.Model != want.Model || got.MonthlyBudgetUSD != want.MonthlyBudgetUSD {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}
```

- [ ] **Step 2: Implement `config.go`**

Create `internal/ai/config.go`:

```go
// Package ai wraps the Claude API (BYOK) as an advisory layer: it explains
// degradation patterns and suggests calibration, but never decides failover,
// weight, or eviction — that stays in internal/balancer, deterministic and
// offline-capable. See docs/superpowers/specs/2026-07-24-camada-de-ia-byok-design.md.
package ai

import (
	"encoding/json"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const configKey = "ai_config"

// Config is the persisted, non-secret configuration for the AI layer. The
// API token itself is never here — see internal/secrets, key "ai_api_token".
type Config struct {
	Enabled           bool            `json:"enabled"`
	Model             string          `json:"model"`
	Effort            string          `json:"effort"`
	MonthlyBudgetUSD  float64         `json:"monthly_budget_usd"`
	SpentThisMonthUSD float64         `json:"spent_this_month_usd"`
	BudgetResetAt     time.Time       `json:"budget_reset_at"`
	TelemetryConsent  map[string]bool `json:"telemetry_consent"`
	DigestHour        int             `json:"digest_hour"`
}

func defaults() Config {
	return Config{
		Enabled: false, Model: "claude-opus-4-8", Effort: "high",
		MonthlyBudgetUSD: 5.0, DigestHour: 6,
		TelemetryConsent: map[string]bool{"hostname": false, "mac": false, "dns_queries": false},
	}
}

// LoadConfig returns the persisted config, or defaults (disabled) if unset.
func LoadConfig(db *storage.DB) Config {
	c := defaults()
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return c
	}
	_ = json.Unmarshal([]byte(raw), &c)
	if c.TelemetryConsent == nil {
		c.TelemetryConsent = map[string]bool{}
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

- [ ] **Step 3: Run the config test to verify it fails, then passes**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/ai/... -run 'TestLoadConfigDefaults|TestSaveThenLoadConfigRoundTrips' -v
```

Expected before Step 2: FAIL (package does not exist). After: PASS.

- [ ] **Step 4: Write the failing budget test**

Create `internal/ai/budget_test.go`:

```go
package ai_test

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
)

func TestBudgetGuardAllowsUnderBudget(t *testing.T) {
	db := newTestDB(t)
	g := ai.NewBudgetGuard(db)

	if err := g.Check(); err != nil {
		t.Fatalf("expected no error with zero spend, got %v", err)
	}
}

func TestBudgetGuardRefusesOverBudget(t *testing.T) {
	db := newTestDB(t)
	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	_ = ai.SaveConfig(db, cfg)

	g := ai.NewBudgetGuard(db)
	if err := g.RecordSpend(1.5); err != nil {
		t.Fatalf("RecordSpend: %v", err)
	}

	if err := g.Check(); err == nil {
		t.Fatal("expected Check to refuse once spend exceeds the monthly budget")
	}
}

func TestBudgetResetsOnNewMonth(t *testing.T) {
	db := newTestDB(t)
	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	cfg.SpentThisMonthUSD = 5.0 // already over budget
	cfg.BudgetResetAt = time.Now().Add(-24 * time.Hour) // reset date already passed
	_ = ai.SaveConfig(db, cfg)

	g := ai.NewBudgetGuard(db)
	if err := g.Check(); err != nil {
		t.Fatalf("expected Check to pass after the reset date, got %v", err)
	}
}
```

- [ ] **Step 5: Implement `budget.go`**

Create `internal/ai/budget.go`:

```go
package ai

import (
	"fmt"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// BudgetGuard is checked before every outbound call. Once the monthly cap is
// hit, it refuses further calls until the reset date — automatically and
// without exception, the same philosophy as the balancer never leaving the
// default route empty: a hard limit that protects the product from itself.
type BudgetGuard struct {
	db *storage.DB
}

// NewBudgetGuard creates a BudgetGuard.
func NewBudgetGuard(db *storage.DB) *BudgetGuard {
	return &BudgetGuard{db: db}
}

// Check returns an error if the monthly spend cap has been reached. Call this
// BEFORE making a request — it never touches the network itself.
func (g *BudgetGuard) Check() error {
	cfg := g.resetIfDue()
	if cfg.SpentThisMonthUSD >= cfg.MonthlyBudgetUSD {
		return fmt.Errorf("monthly AI budget of $%.2f reached (spent $%.2f) — resets %s",
			cfg.MonthlyBudgetUSD, cfg.SpentThisMonthUSD, cfg.BudgetResetAt.Format("2006-01-02"))
	}
	return nil
}

// RecordSpend adds usd to this month's running total.
func (g *BudgetGuard) RecordSpend(usd float64) error {
	cfg := g.resetIfDue()
	cfg.SpentThisMonthUSD += usd
	return SaveConfig(g.db, cfg)
}

// resetIfDue zeroes the spend counter and advances BudgetResetAt if the reset
// date has passed, persisting the reset before returning the fresh config.
func (g *BudgetGuard) resetIfDue() Config {
	cfg := LoadConfig(g.db)
	if cfg.BudgetResetAt.IsZero() {
		cfg.BudgetResetAt = nextMonthStart(time.Now())
		_ = SaveConfig(g.db, cfg)
		return cfg
	}
	if time.Now().After(cfg.BudgetResetAt) {
		cfg.SpentThisMonthUSD = 0
		cfg.BudgetResetAt = nextMonthStart(time.Now())
		_ = SaveConfig(g.db, cfg)
	}
	return cfg
}

func nextMonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, t.Location())
}
```

- [ ] **Step 6: Run the budget tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/ai/... -run 'TestBudgetGuard|TestBudgetResets' -v
```

Expected before Step 5: FAIL. After: PASS.

- [ ] **Step 7: Write the failing evidence test**

Create `internal/ai/evidence_test.go`:

```go
package ai_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestBuildEvidenceSummarizesEpisodesNotRawPoints(t *testing.T) {
	db := newTestDB(t)
	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)

	now := int64(100000)
	// Two degraded episodes for one link.
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-3600)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-1800)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-1790)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "degraded", now-900)
	tsdbSvc.StateForTest("link", "WAN SUMICITY", "online", now-885)

	ev, err := ai.BuildEvidence(tsdbSvc, alertSvc, []string{"WAN SUMICITY"}, now-7200, now)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	if len(ev.Links) != 1 {
		t.Fatalf("expected 1 link summary, got %d", len(ev.Links))
	}
	if ev.Links[0].EpisodeCount != 2 {
		t.Fatalf("expected 2 episodes counted, got %d", ev.Links[0].EpisodeCount)
	}
	if ev.Links[0].Name != "WAN SUMICITY" {
		t.Fatalf("expected link name WAN SUMICITY, got %q", ev.Links[0].Name)
	}
}
```

`tsdb.Service.StateForTest` is the test-only hook added in Project 1's plan (Task 3, Step 4) — confirm it exists with `grep -n "func (s \*Service) StateForTest" internal/tsdb/service.go` before relying on it; if Project 1's plan has not landed yet in this codebase, this task cannot proceed (see the Global Constraints dependency note).

- [ ] **Step 8: Implement `evidence.go`**

Create `internal/ai/evidence.go`:

```go
package ai

import (
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// LinkSummary is the pre-computed, per-link shape of an evidence window — the
// facts the model reasons over, never raw timeline points. ~800 tokens of
// facts is roughly 9x cheaper than a few thousand raw samples, and the model
// reasons better over facts than it does parsing a CSV of numbers.
type LinkSummary struct {
	Name          string  `json:"name"`
	EpisodeCount  int     `json:"episode_count"`
	MinEpisodeSec int     `json:"min_episode_sec"`
	MaxEpisodeSec int     `json:"max_episode_sec"`
	PeakLatencyMs float64 `json:"peak_latency_ms"`
	PeakLossPct   float64 `json:"peak_loss_pct"`
}

// AlertRef is a minimal alert reference — type/severity/time only, not the
// full message (the message is already summarized elsewhere in Evidence).
type AlertRef struct {
	Ts       int64  `json:"ts"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

// Evidence is what gets sent to the model — pre-computed facts about a
// window, never a raw series dump.
type Evidence struct {
	Period        string       `json:"period"`
	Links         []LinkSummary `json:"links"`
	CarrierEvents int          `json:"carrier_events"`
	TrafficLevel  string       `json:"traffic_level"`
	RecentAlerts  []AlertRef   `json:"recent_alerts"`
}

// BuildEvidence queries tsdb for the state intervals and gauge extremes of
// each named link in [fromUnix, toUnix] and reduces them to LinkSummary
// facts. This is the same underlying data the diagnostic timeline (Project 1)
// renders — reused here, not re-derived.
func BuildEvidence(tsdbSvc *tsdb.Service, alertSvc *alerts.Service, linkNames []string, fromUnix, toUnix int64) (Evidence, error) {
	ev := Evidence{
		Period: formatPeriod(fromUnix, toUnix),
		Links:  []LinkSummary{},
	}

	for _, name := range linkNames {
		_, series, states, err := tsdbSvc.Timeline(tsdb.TimelineRequest{
			FromUnix: fromUnix, ToUnix: toUnix,
			Series: []tsdb.SeriesLabel{
				{Series: "link.latency_ms", Label: name},
				{Series: "link.loss_pct", Label: name},
			},
			States: []tsdb.StateKindLabel{{Kind: "link", Label: name}},
		})
		if err != nil {
			return Evidence{}, err
		}
		ev.Links = append(ev.Links, summarizeLink(name, series, states))
	}

	all, err := alertSvc.List(false, 200)
	if err != nil {
		return Evidence{}, err
	}
	for _, a := range all {
		ts := a.CreatedAt.Unix()
		if ts < fromUnix || ts > toUnix {
			continue
		}
		ev.RecentAlerts = append(ev.RecentAlerts, AlertRef{Ts: ts, Type: a.Type, Severity: a.Severity})
	}
	ev.TrafficLevel = "ocioso" // conservative placeholder — refined by a follow-up
	// task once Project 1's if.rx_bps/if.tx_bps thresholds for "moderado"/
	// "saturado" are calibrated against real production traffic levels; do not
	// invent threshold numbers here without that data.

	return ev, nil
}

func summarizeLink(name string, series []tsdb.TimelineSeries, states []tsdb.TimelineState) LinkSummary {
	s := LinkSummary{Name: name}

	for _, st := range states {
		if st.State == "online" || st.State == "up" {
			continue
		}
		s.EpisodeCount++
		dur := 0
		if st.EndedAt != nil {
			dur = int(*st.EndedAt - st.StartedAt)
		}
		if s.MinEpisodeSec == 0 || dur < s.MinEpisodeSec {
			s.MinEpisodeSec = dur
		}
		if dur > s.MaxEpisodeSec {
			s.MaxEpisodeSec = dur
		}
	}

	for _, sr := range series {
		for _, p := range sr.Points {
			if sr.Name == "link.latency_ms" && p.Max > s.PeakLatencyMs {
				s.PeakLatencyMs = p.Max
			}
			if sr.Name == "link.loss_pct" && p.Max > s.PeakLossPct {
				s.PeakLossPct = p.Max
			}
		}
	}
	return s
}

func formatPeriod(fromUnix, toUnix int64) string {
	return fmtUnix(fromUnix) + "/" + fmtUnix(toUnix)
}
```

Add a small time-formatting helper — check first whether the codebase already has one (`grep -rn "func fmtUnix\|time.Unix(.*Format" internal/ --include=*.go | head -5`); if none exists, add to the bottom of `internal/ai/evidence.go`:

```go
import "time"

func fmtUnix(u int64) string {
	return time.Unix(u, 0).UTC().Format(time.RFC3339)
}
```

(Add `"time"` to the existing import block rather than a second `import` statement.)

- [ ] **Step 9: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/ai/... -v
```

Expected before Step 8: FAIL. After: all PASS.

- [ ] **Step 10: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/ai/
go vet ./internal/ai/...
git add internal/ai/
git commit -m "feat(ai): config, budget guard, evidence builder"
```

---

### Task 3: The Claude client and the `Recommendation`-is-never-an-action guarantee

**Files:**
- Create: `internal/ai/client.go`
- Test: `internal/ai/client_test.go`

**Interfaces:**
- Consumes: `secrets.Secrets.Get("ai_api_token")` (Project 3), `Evidence` (Task 2), the `anthropic-sdk-go` module (Task 1).
- Produces: `type Report struct { Summary, Recommendation, Confidence string; Findings []string }`, `type Client struct{...}`, `func NewClient(sec secrets.Secrets, budget *BudgetGuard, cfg func() Config) *Client`, `func (c *Client) Analyze(ctx context.Context, ev Evidence) (Report, error)`.

- [ ] **Step 1: Write the failing test for the never-an-action guarantee**

Create `internal/ai/client_test.go`:

```go
package ai_test

import (
	"reflect"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
)

// TestReportRecommendationIsPlainStringField is a structural guardrail, not a
// behavioral test: it fails to compile (and this comment fails to be true) if
// Recommendation is ever changed from a plain string to something a caller
// could dispatch as an action (e.g. a struct with a Command field). This is
// the invariant "the AI is never in the control loop" made mechanically
// checkable rather than a comment someone can miss in review.
func TestReportRecommendationIsPlainStringField(t *testing.T) {
	f, ok := reflect.TypeOf(ai.Report{}).FieldByName("Recommendation")
	if !ok {
		t.Fatal("Report has no Recommendation field")
	}
	if f.Type.Kind() != reflect.String {
		t.Fatalf("Report.Recommendation must be a plain string (human-readable text only), got %s — "+
			"a structured type here risks a future caller treating it as an executable action", f.Type.Kind())
	}
}
```

- [ ] **Step 2: Write the failing budget-gating test**

Add to `internal/ai/client_test.go`:

```go
import (
	"context"
	"errors"
	"path/filepath"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestAnalyzeRefusesWhenOverBudget(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	_ = sec.Set("ai_api_token", "sk-ant-test-key-not-real")

	cfg := ai.LoadConfig(db)
	cfg.MonthlyBudgetUSD = 1.0
	_ = ai.SaveConfig(db, cfg)

	budget := ai.NewBudgetGuard(db)
	_ = budget.RecordSpend(2.0) // already over the $1 cap

	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })

	_, err = client.Analyze(context.Background(), ai.Evidence{Period: "test"})
	if err == nil {
		t.Fatal("expected Analyze to refuse when over budget, without making any network call")
	}
	if !errors.Is(err, ai.ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
}

func TestAnalyzeRefusesWhenTokenNotConfigured(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	// token deliberately never set

	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })

	_, err = client.Analyze(context.Background(), ai.Evidence{Period: "test"})
	if err == nil {
		t.Fatal("expected Analyze to refuse when no token is configured")
	}
	if !errors.Is(err, ai.ErrTokenNotConfigured) {
		t.Fatalf("expected ErrTokenNotConfigured, got %v", err)
	}
}
```

- [ ] **Step 3: Implement the client**

Create `internal/ai/client.go`:

```go
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
)

// ErrBudgetExceeded is returned by Analyze when the monthly spend cap has
// been reached — checked before any network call.
var ErrBudgetExceeded = errors.New("ai: monthly budget exceeded")

// ErrTokenNotConfigured is returned by Analyze when no API token is set.
var ErrTokenNotConfigured = errors.New("ai: no API token configured")

const tokenSecretName = "ai_api_token"

// Report is the model's structured answer. Recommendation is ALWAYS plain
// text for a human to read — see TestReportRecommendationIsPlainStringField
// and the Global Constraints in this plan's document. Nothing in this
// package, or any caller, may treat it as an executable instruction.
type Report struct {
	Summary        string   `json:"summary"`
	Findings       []string `json:"findings"`
	Recommendation string   `json:"recommendation"`
	Confidence     string   `json:"confidence"`
}

// Client is the thin wrapper around the Claude API used by both triggers
// (immediate.go, digest.go).
type Client struct {
	sec    secrets.Secrets
	budget *BudgetGuard
	cfg    func() Config
}

// NewClient creates a Client. cfg is called fresh on every Analyze so a
// config change in the UI (model, effort) takes effect without a restart —
// same pattern as balancer.Monitor.SustainThreshold.
func NewClient(sec secrets.Secrets, budget *BudgetGuard, cfg func() Config) *Client {
	return &Client{sec: sec, budget: budget, cfg: cfg}
}

const systemPrompt = `Você analisa a saúde de links de internet (WAN) de um firewall multi-WAN a
partir de fatos já resumidos — nunca dados brutos. Responda ESTRITAMENTE com um
objeto JSON, sem nenhum texto antes ou depois, no formato:
{"summary": "1-2 frases", "findings": ["achado específico com número", ...],
"recommendation": "texto livre para um humano ler e decidir — nunca um
comando", "confidence": "alta|média|baixa"}
Sua recomendação NUNCA é executada automaticamente — é sempre lida por um
administrador humano, que decide o que fazer.`

// Analyze sends the evidence to the model and returns its structured Report.
// Checks the budget guard and token presence before any network call.
func (c *Client) Analyze(ctx context.Context, ev Evidence) (Report, error) {
	if err := c.budget.Check(); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrBudgetExceeded, err)
	}

	token, err := c.sec.Get(tokenSecretName)
	if err != nil {
		return Report{}, fmt.Errorf("read AI token: %w", err)
	}
	if strings.TrimSpace(token) == "" {
		return Report{}, ErrTokenNotConfigured
	}

	evJSON, err := json.Marshal(ev)
	if err != nil {
		return Report{}, fmt.Errorf("marshal evidence: %w", err)
	}

	cfg := c.cfg()
	client := anthropic.NewClient(option.WithAPIKey(token))

	resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(cfg.Model),
		MaxTokens: 1024,
		Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}},
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(string(evJSON))),
		},
	})
	if err != nil {
		return Report{}, fmt.Errorf("anthropic API call: %w", err)
	}

	// response.Usage carries InputTokens/OutputTokens on every Messages
	// response (verified in Task 1 Step 2 against the installed SDK version).
	cost := estimateCostUSD(cfg.Model, resp.Usage.InputTokens, resp.Usage.OutputTokens)
	if err := c.budget.RecordSpend(cost); err != nil {
		// The call already succeeded and cost real money — a bookkeeping
		// failure here must not discard the report the caller is about to
		// use, so this is logged by the caller's context, not fatal here.
		_ = err
	}

	var report Report
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			if uerr := json.Unmarshal([]byte(tb.Text), &report); uerr == nil {
				return report, nil
			}
		}
	}
	return Report{}, fmt.Errorf("no parseable JSON report in the model's response")
}

// estimateCostUSD prices a call at the per-model rates the admin sees in the
// UI (see the spec's model table). Prices are per-million-token; keep this in
// sync with docs/superpowers/specs/2026-07-24-camada-de-ia-byok-design.md §5
// if pricing changes.
func estimateCostUSD(model string, inputTokens, outputTokens int64) float64 {
	var inPer1M, outPer1M float64
	switch model {
	case "claude-opus-4-8":
		inPer1M, outPer1M = 5.0, 25.0
	case "claude-sonnet-5":
		inPer1M, outPer1M = 3.0, 15.0
	case "claude-haiku-4-5":
		inPer1M, outPer1M = 1.0, 5.0
	default:
		inPer1M, outPer1M = 5.0, 25.0 // conservative default: price as Opus
	}
	return float64(inputTokens)/1_000_000*inPer1M + float64(outputTokens)/1_000_000*outPer1M
}
```

**Before this compiles**, run the `go doc` checks from Task 1 Step 2 again and adjust any field/method name above that does not match the installed SDK version — this code is written against the confirmed Go SDK patterns documented in the project's `claude-api` skill reference as of this plan's writing, but SDK versions move; `go build` is the ground truth.

- [ ] **Step 4: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./internal/ai/... 2>&1
go test ./internal/ai/... -v
```

Expected: build succeeds (fix any field-name mismatch the compiler reports, per Step 3's note, before proceeding). Tests: all PASS, including `TestAnalyzeRefusesWhenOverBudget` and `TestAnalyzeRefusesWhenTokenNotConfigured` (both return before any network call, so they run offline and fast).

- [ ] **Step 5: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/ai/
go vet ./internal/ai/...
git add internal/ai/
git commit -m "feat(ai): Claude client with budget/token gating and the Recommendation-is-text guarantee"
```

---

### Task 4: Wire the two triggers

**Files:**
- Create: `internal/ai/immediate.go`
- Create: `internal/ai/digest.go`
- Modify: `internal/balancer/service.go` (call the immediate trigger from `OnLinkChange`)
- Modify: `cmd/linkguard-fw/main.go` (start the digest goroutine, wire the immediate trigger)
- Test: `internal/ai/immediate_test.go`

**Interfaces:**
- Consumes: `ai.Client.Analyze` (Task 3), `storage.Link` (existing).
- Produces: `func TriggerImmediate(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, link *storage.Link)` — fire-and-forget, never returns an error to the caller. `func RunDigest(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, linkNames func() []string)` — the daily loop.

- [ ] **Step 1: Write the failing test — immediate trigger never blocks or panics on failure**

Create `internal/ai/immediate_test.go`:

```go
package ai_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestTriggerImmediateNeverBlocksOnMissingToken(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })
	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)

	link := &storage.Link{ID: "a", Name: "WAN SUMICITY"}

	done := make(chan struct{})
	go func() {
		ai.TriggerImmediate(context.Background(), client, tsdbSvc, alertSvc, db, link)
		close(done)
	}()

	select {
	case <-done:
		// good: returned promptly even with no token configured
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerImmediate did not return promptly with a missing token — it must fail fast, not hang")
	}

	reports, err := db.ListAIReports(10)
	if err != nil {
		t.Fatalf("ListAIReports: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("expected no report to be created when the token is missing, got %d", len(reports))
	}
}
```

- [ ] **Step 2: Implement `immediate.go`**

Create `internal/ai/immediate.go`:

```go
package ai

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// evictCooldown reuses the same shape as balancer's per-link eviction
// cooldown: a link that keeps flapping in and out of "degraded" must not
// trigger a fresh immediate analysis (and spend) on every single flap.
var lastImmediateTrigger = map[string]time.Time{}
const immediateCooldown = 30 * time.Minute

// TriggerImmediate analyzes a single severe, hysteresis-confirmed transition
// (offline, or degraded sustained past the configured threshold). It is
// fire-and-forget: any failure (no token, over budget, network down, API
// error) is logged and swallowed. The deterministic alert for this
// transition has already fired by the time this is called — this only adds
// an optional AI explanation on top, never the alert itself.
func TriggerImmediate(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, link *storage.Link) {
	cfg := LoadConfig(db)
	if !cfg.Enabled {
		return
	}
	if last, ok := lastImmediateTrigger[link.ID]; ok && time.Since(last) < immediateCooldown {
		return
	}
	lastImmediateTrigger[link.ID] = time.Now()

	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	now := time.Now().Unix()
	ev, err := BuildEvidence(tsdbSvc, alertSvc, []string{link.Name}, now-3600, now)
	if err != nil {
		slog.Warn("ai: build evidence for immediate trigger failed", "link", link.Name, "err", err)
		return
	}

	report, err := client.Analyze(callCtx, ev)
	if err != nil {
		slog.Warn("ai: immediate analysis failed", "link", link.Name, "err", err)
		return
	}

	findingsJSON, _ := json.Marshal(report.Findings)
	if err := db.CreateAIReport(&storage.AIReport{
		Kind: "immediate", Summary: report.Summary, Findings: string(findingsJSON),
		Recommendation: report.Recommendation, Confidence: report.Confidence,
	}); err != nil {
		slog.Warn("ai: save immediate report failed", "err", err)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails, then passes**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/ai/... -run TestTriggerImmediateNeverBlocksOnMissingToken -v
```

Expected before Step 2: FAIL (package function undefined). After: PASS. Note this test passes even before `Enabled` gating works correctly, since `cfg.Enabled` defaults to `false` — that early return alone makes the test pass. This is fine: the test's job is proving the function returns promptly and cleanly, not proving every gating branch (those are covered by Task 3's budget/token tests, which `Analyze` — called from here — already relies on).

- [ ] **Step 4: Implement `digest.go`**

Create `internal/ai/digest.go`:

```go
package ai

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// RunDigest runs the once-a-day analysis loop. Blocks until ctx is done.
// linkNames is called fresh each day so newly-added WAN links are included
// without a restart.
func RunDigest(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, linkNames func() []string) {
	slog.Info("ai digest loop started")
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg := LoadConfig(db)
			if !cfg.Enabled {
				continue
			}
			if time.Now().Hour() != cfg.DigestHour {
				continue
			}
			if err := runOneDigest(ctx, client, tsdbSvc, alertSvc, db, linkNames()); err != nil {
				consecutiveFailures++
				slog.Warn("ai: digest failed", "err", err, "consecutive_failures", consecutiveFailures)
				if consecutiveFailures >= 2 {
					_ = alertSvc.Create("ai_digest_failing", "warning", "Resumo diário de IA não está funcionando",
						"O resumo diário do assistente de IA falhou por 2 dias seguidos. Verifique o token e o orçamento em Configurações → Assistente de IA.", "")
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

func runOneDigest(ctx context.Context, client *Client, tsdbSvc *tsdb.Service, alertSvc *alerts.Service, db *storage.DB, names []string) error {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	now := time.Now().Unix()
	ev, err := BuildEvidence(tsdbSvc, alertSvc, names, now-86400, now)
	if err != nil {
		return err
	}

	report, err := client.Analyze(callCtx, ev)
	if err != nil {
		return err
	}

	findingsJSON, _ := json.Marshal(report.Findings)
	return db.CreateAIReport(&storage.AIReport{
		Kind: "digest", Summary: report.Summary, Findings: string(findingsJSON),
		Recommendation: report.Recommendation, Confidence: report.Confidence,
	})
}
```

Check `alerts.Service.Create`'s exact signature before relying on the call above (`grep -n "func (s \*Service) Create" internal/alerts/service.go`) — confirmed earlier in this plan's research as `func (s *Service) Create(alertType, severity, title, message, linkID string) error`, matching the call in `RunDigest` above.

- [ ] **Step 5: Wire the immediate trigger into `balancer.OnLinkChange`**

In `internal/balancer/service.go`, `OnLinkChange` needs access to an `*ai.Client` (or a thin wrapper it can call without importing `internal/ai` directly and creating a cycle risk — check first: does `internal/ai` import `internal/balancer`? It does not, per this plan's file list, so `internal/balancer` importing `internal/ai` is safe). Add a field and wire the call:

```go
import (
	// ... existing imports ...
	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)
```

Add to the `Service` struct (find it near the top of `internal/balancer/service.go`):

```go
	aiClient *ai.Client
	tsdbSvc  *tsdb.Service
```

These are optional — `NewService`'s existing signature (`NewService(db *storage.DB, exec firewall.Executor, linkSvc *links.Service, alertSvc *alerts.Service) *Service`) stays unchanged (adding two more constructor parameters would ripple into every existing call site and test that constructs a balancer `Service`, most of which have nothing to do with AI). Instead, add setter methods, following the same pattern as `monitor.OnStatusChange(...)`:

```go
// SetAI wires the optional AI advisory layer. If never called, OnLinkChange
// skips the immediate-analysis trigger entirely — the AI layer is opt-in and
// its absence changes nothing about failover/balance behavior.
func (s *Service) SetAI(client *ai.Client, tsdbSvc *tsdb.Service) {
	s.aiClient = client
	s.tsdbSvc = tsdbSvc
}
```

In `OnLinkChange`, after the existing alert-raising `switch` block and before `s.Rebuild(ctx)`:

```go
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
```

- [ ] **Step 6: Wire everything in `main.go`**

In `cmd/linkguard-fw/main.go`, add the import:

```go
	"github.com/giovanibalarini/linkguard-fw/internal/ai"
```

After `balancerSvc := balancer.NewService(...)` and after `secretsSvc`/`rrdSvc` (the `tsdb.Service`) already exist per Project 1 and Project 3's plans, add:

```go
	aiBudget := ai.NewBudgetGuard(db)
	aiClient := ai.NewClient(secretsSvc, aiBudget, func() ai.Config { return ai.LoadConfig(db) })
	balancerSvc.SetAI(aiClient, rrdSvc)
```

Near the other `go xSvc.Run(ctx)` lines (after `go balancerSvc.Run(ctx)`), add:

```go
	go ai.RunDigest(ctx, aiClient, rrdSvc, alertSvc, db, func() []string {
		all, _ := db.GetLinks()
		names := make([]string, 0, len(all))
		for _, l := range all {
			if l.Enabled {
				names = append(names, l.Name)
			}
		}
		return names
	})
```

- [ ] **Step 7: Build and run the full suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
```

Expected: clean build, every package `ok`.

- [ ] **Step 8: gofmt, vet, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
gofmt -w internal/ai/ internal/balancer/service.go cmd/linkguard-fw/main.go
go vet ./...
git add internal/ai/ internal/balancer/service.go cmd/linkguard-fw/main.go
git commit -m "feat(ai): wire immediate and digest triggers into the balancer and main"
```

---

### Task 5: API endpoints

**Files:**
- Create: `internal/api/handlers/ai.go`
- Modify: `internal/api/server.go`
- Test: `internal/api/handlers/ai_test.go`

**Interfaces:**
- Consumes: `secrets.Secrets` (Project 3), `ai.Config`/`LoadConfig`/`SaveConfig`, `*storage.DB.ListAIReports`/`GetAIReport`.
- Produces:
  ```
  GET    /api/ai/status              perm: system.read
  PUT    /api/ai/token               perm: system.write
  DELETE /api/ai/token               perm: system.write
  POST   /api/ai/token/test          perm: system.write
  PUT    /api/ai/config              perm: system.write
  GET    /api/ai/reports             perm: monitoring.read
  GET    /api/ai/reports/{id}        perm: monitoring.read
  ```

- [ ] **Step 1: Write the failing tests**

Create `internal/api/handlers/ai_test.go`:

```go
package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newAITestHandler(t *testing.T) (*handlers.AIHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })
	return handlers.NewAIHandler(db, sec, client), db
}

func TestAIStatusNeverReturnsTheToken(t *testing.T) {
	h, db := newAITestHandler(t)
	dir := t.TempDir()
	key, _ := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	sec := secrets.NewService(db, key)
	_ = sec.Set("ai_api_token", "sk-ant-realsecretvalue")

	req := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if bytesContain(w.Body.Bytes(), []byte("sk-ant-realsecretvalue")) {
		t.Fatal("SECURITY: /api/ai/status leaked the raw token value")
	}
}

func TestSetTokenThenStatusShowsConfigured(t *testing.T) {
	h, _ := newAITestHandler(t)

	body, _ := json.Marshal(map[string]string{"token": "sk-ant-abcd1234wxyz7f2a"})
	req := httptest.NewRequest(http.MethodPut, "/api/ai/token", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SetToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("SetToken: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w2 := httptest.NewRecorder()
	h.Status(w2, req2)

	var resp struct {
		Configured bool   `json:"configured"`
		Hint       string `json:"hint"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Configured {
		t.Fatal("expected configured=true after SetToken")
	}
	if resp.Hint != "sk-ant-…7f2a" {
		t.Fatalf("expected hint sk-ant-…7f2a, got %q", resp.Hint)
	}
}

func TestDeleteTokenClearsConfigured(t *testing.T) {
	h, _ := newAITestHandler(t)

	body, _ := json.Marshal(map[string]string{"token": "sk-ant-abcd"})
	req := httptest.NewRequest(http.MethodPut, "/api/ai/token", bytes.NewReader(body))
	h.SetToken(httptest.NewRecorder(), req)

	delReq := httptest.NewRequest(http.MethodDelete, "/api/ai/token", nil)
	delW := httptest.NewRecorder()
	h.DeleteToken(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("DeleteToken: expected 200, got %d", delW.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w2 := httptest.NewRecorder()
	h.Status(w2, req2)
	var resp struct{ Configured bool `json:"configured"` }
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp.Configured {
		t.Fatal("expected configured=false after DeleteToken")
	}
}

func bytesContain(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && string(haystack) != "" &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if string(haystack[i:i+len(needle)]) == string(needle) {
					return true
				}
			}
			return false
		})()
}
```

- [ ] **Step 2: Implement the handler**

Create `internal/api/handlers/ai.go`:

```go
package handlers

import (
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const aiTokenSecretName = "ai_api_token"

// AIHandler exposes the AI layer's token, config, and report history.
type AIHandler struct {
	db     *storage.DB
	sec    secrets.Secrets
	client *ai.Client
}

func NewAIHandler(db *storage.DB, sec secrets.Secrets, client *ai.Client) *AIHandler {
	return &AIHandler{db: db, sec: sec, client: client}
}

type aiStatusResponse struct {
	Configured        bool    `json:"configured"`
	Hint              string  `json:"hint"`
	Enabled           bool    `json:"enabled"`
	Model             string  `json:"model"`
	Effort            string  `json:"effort"`
	MonthlyBudgetUSD  float64 `json:"monthly_budget_usd"`
	SpentThisMonthUSD float64 `json:"spent_this_month_usd"`
}

// Status reports configuration state — never the token itself.
func (h *AIHandler) Status(w http.ResponseWriter, r *http.Request) {
	configured, hint := h.sec.Status(aiTokenSecretName)
	cfg := ai.LoadConfig(h.db)
	writeJSON(w, http.StatusOK, aiStatusResponse{
		Configured: configured, Hint: hint,
		Enabled: cfg.Enabled, Model: cfg.Model, Effort: cfg.Effort,
		MonthlyBudgetUSD: cfg.MonthlyBudgetUSD, SpentThisMonthUSD: cfg.SpentThisMonthUSD,
	})
}

// SetToken stores the Claude API token. Write-only: this handler never
// returns the value it just stored, matching the updater's token pattern.
func (h *AIHandler) SetToken(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	tok := strings.TrimSpace(b.Token)
	if tok == "" {
		writeError(w, http.StatusBadRequest, "token vazio")
		return
	}
	if err := h.sec.Set(aiTokenSecretName, tok); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "ai.token.set", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

// DeleteToken removes the token, effectively disabling the AI layer's calls
// (Analyze returns ErrTokenNotConfigured).
func (h *AIHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	if err := h.sec.Delete(aiTokenSecretName); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "ai.token.delete", "system", "")
	writeJSON(w, http.StatusOK, map[string]bool{"configured": false})
}

// TestToken makes one cheap request to verify the configured token works.
func (h *AIHandler) TestToken(w http.ResponseWriter, r *http.Request) {
	report, err := h.client.Analyze(r.Context(), ai.Evidence{Period: "connection-test"})
	if err != nil {
		writeError(w, http.StatusBadGateway, "falha ao conectar: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "sample_summary": report.Summary})
}

// SetConfig persists the non-secret AI configuration.
func (h *AIHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg ai.Config
	if err := decodeJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	// Preserve spend tracking fields the client should never set directly.
	existing := ai.LoadConfig(h.db)
	cfg.SpentThisMonthUSD = existing.SpentThisMonthUSD
	cfg.BudgetResetAt = existing.BudgetResetAt
	if err := ai.SaveConfig(h.db, cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "ai.config.set", "system", "")
	writeJSON(w, http.StatusOK, ai.LoadConfig(h.db))
}

// ListReports returns recent AI reports.
func (h *AIHandler) ListReports(w http.ResponseWriter, r *http.Request) {
	reports, err := h.db.ListAIReports(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

// GetReport returns one report by ID.
func (h *AIHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chiURLParam(r, "id")
	report, err := h.db.GetAIReport(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "relatório não encontrado")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
```

`chiURLParam` — check the existing pattern other handlers use to read a chi URL param (e.g. `internal/api/handlers/vpn.go`'s `DeletePeer`, which reads `{id}`): `grep -n "chi.URLParam" internal/api/handlers/vpn.go`. Use whatever that call looks like verbatim (likely `chi.URLParam(r, "id")` from `github.com/go-chi/chi/v5`) instead of the placeholder `chiURLParam` name above — add the `"github.com/go-chi/chi/v5"` import and replace `chiURLParam(r, "id")` with the confirmed call.

- [ ] **Step 3: Register the routes**

In `internal/api/server.go`, inside `buildRouter`, in the same permission-grouped area as other system settings (near the update handler), add:

```go
		aiH := handlers.NewAIHandler(s.db, s.sec, s.aiClient)
		r.With(require(auth.PermSystemRead)).Get("/api/ai/status", aiH.Status)
		r.With(require(auth.PermSystemWrite)).Put("/api/ai/token", aiH.SetToken)
		r.With(require(auth.PermSystemWrite)).Delete("/api/ai/token", aiH.DeleteToken)
		r.With(require(auth.PermSystemWrite)).Post("/api/ai/token/test", aiH.TestToken)
		r.With(require(auth.PermSystemWrite)).Put("/api/ai/config", aiH.SetConfig)
		r.With(require(auth.PermMonitoringRead)).Get("/api/ai/reports", aiH.ListReports)
		r.With(require(auth.PermMonitoringRead)).Get("/api/ai/reports/{id}", aiH.GetReport)
```

This requires `Server` to also hold an `aiClient *ai.Client` field, constructed in `main.go` and passed through `api.New(...)` the same way `secretsSvc` was added in Project 3's plan — add it as one more field/parameter following that exact pattern (add `"github.com/giovanibalarini/linkguard-fw/internal/ai"` import, add `aiClient *ai.Client` to the `Server` struct, add it as a parameter to `New(...)`, set it in the struct literal, and append it to the call in `main.go`'s `api.New(...)` invocation).

- [ ] **Step 4: Run tests to verify they fail, then pass**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go test ./internal/api/handlers/... -run 'TestAIStatus|TestSetTokenThenStatus|TestDeleteToken' -v
```

Expected before Step 2: FAIL. After: PASS — in particular `TestAIStatusNeverReturnsTheToken` and `TestSetTokenThenStatusShowsConfigured`'s hint-format assertion.

- [ ] **Step 5: Build, full suite, gofmt, commit**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go test ./... 2>&1
gofmt -w internal/api/handlers/ai.go internal/api/handlers/ai_test.go internal/api/server.go cmd/linkguard-fw/main.go
git add internal/api/handlers/ai.go internal/api/handlers/ai_test.go internal/api/server.go cmd/linkguard-fw/main.go
git commit -m "feat(api): AI layer endpoints — status, token, config, reports"
```

---

### Task 6: Frontend — "Assistente de IA" settings section

**Files:**
- Create: `web/src/components/AISettings.tsx`
- Modify: `web/src/pages/Settings.tsx`
- Modify: `web/src/types/index.ts`

**Interfaces:**
- Consumes: `GET /api/ai/status`, `PUT /api/ai/token`, `DELETE /api/ai/token`, `POST /api/ai/token/test`, `PUT /api/ai/config` (Task 5).

- [ ] **Step 1: Add the TypeScript types**

In `web/src/types/index.ts`, add:

```typescript
export interface AIStatus {
  configured: boolean;
  hint: string;
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  spent_this_month_usd: number;
}

export interface AIConfig {
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  telemetry_consent: Record<string, boolean>;
  digest_hour: number;
}
```

- [ ] **Step 2: Read the existing Settings page structure**

```bash
grep -n "TwoFactorSettings\|NotificationSettings\|import.*from '../components" web/src/pages/Settings.tsx | head -20
```

Use the output to mirror exactly how an existing settings component (`TwoFactorSettings` or `NotificationSettings`) is imported and rendered in `Settings.tsx` — the new `AISettings` component slots in the same way.

- [ ] **Step 3: Implement the component**

Create `web/src/components/AISettings.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { Sparkles, Check, X } from 'lucide-react';
import client from '../api/client';
import type { AIStatus, AIConfig } from '../types';

const MODELS = [
  { id: 'claude-opus-4-8', label: 'Claude Opus 4.8', desc: 'Melhor análise — recomendado' },
  { id: 'claude-sonnet-5', label: 'Claude Sonnet 5', desc: 'Equilíbrio' },
  { id: 'claude-haiku-4-5', label: 'Claude Haiku 4.5', desc: 'Mais barato' },
];

const CONSENT_FIELDS: { key: string; label: string }[] = [
  { key: 'hostname', label: 'Nome do host' },
  { key: 'mac', label: 'Endereço MAC' },
  { key: 'dns_queries', label: 'Consultas DNS' },
];

export default function AISettings() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [token, setToken] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<'ok' | 'fail' | null>(null);
  const [budget, setBudget] = useState(5);
  const [model, setModel] = useState('claude-opus-4-8');
  const [enabled, setEnabled] = useState(false);
  const [consent, setConsent] = useState<Record<string, boolean>>({});

  const load = async () => {
    const res = await client.get<AIStatus>('/api/ai/status');
    setStatus(res.data);
    setBudget(res.data.monthly_budget_usd);
    setModel(res.data.model);
    setEnabled(res.data.enabled);
  };

  useEffect(() => { load(); }, []);

  const saveToken = async () => {
    if (!token.trim()) return;
    setSaving(true);
    try {
      await client.put('/api/ai/token', { token });
      setToken('');
      await load();
    } finally {
      setSaving(false);
    }
  };

  const removeToken = async () => {
    setSaving(true);
    try {
      await client.delete('/api/ai/token');
      await load();
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      await client.post('/api/ai/token/test');
      setTestResult('ok');
    } catch {
      setTestResult('fail');
    } finally {
      setTesting(false);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const body: AIConfig = {
        enabled, model, effort: 'high', monthly_budget_usd: budget,
        telemetry_consent: consent, digest_hour: 6,
      };
      await client.put('/api/ai/config', body);
      await load();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <Sparkles className="w-4 h-4 text-purple-400" />
        <h2 className="text-white font-semibold">Assistente de IA</h2>
      </div>
      <p className="text-gray-500 text-sm">
        Análise opcional de padrões de degradação usando sua própria chave da API do Claude.
        Nunca decide failover, peso ou expulsão de link — só explica e sugere.
      </p>

      {!status?.configured ? (
        <div className="flex gap-2">
          <input
            type="password"
            placeholder="sk-ant-..."
            value={token}
            onChange={e => setToken(e.target.value)}
            className="input flex-1"
          />
          <button onClick={saveToken} disabled={saving} className="btn-primary">Salvar token</button>
        </div>
      ) : (
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-300">Token configurado: <span className="font-mono">{status.hint}</span></span>
          <div className="flex gap-2">
            <button onClick={testConnection} disabled={testing} className="btn-secondary">
              {testing ? 'Testando…' : 'Testar conexão'}
            </button>
            <button onClick={removeToken} disabled={saving} className="btn-secondary text-red-400">Remover</button>
          </div>
        </div>
      )}

      {testResult === 'ok' && (
        <p className="text-emerald-400 text-xs flex items-center gap-1"><Check className="w-3 h-3" /> Conexão funcionando.</p>
      )}
      {testResult === 'fail' && (
        <p className="text-red-400 text-xs flex items-center gap-1"><X className="w-3 h-3" /> Falha ao conectar — confira o token.</p>
      )}

      {status?.configured && (
        <>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            Ativar análise automática
          </label>

          <div>
            <p className="text-gray-500 text-xs mb-2">Modelo</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {MODELS.map(m => (
                <button
                  key={m.id}
                  onClick={() => setModel(m.id)}
                  className={`p-2 rounded border text-left text-xs ${model === m.id ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700'}`}
                >
                  <p className="text-white font-medium">{m.label}</p>
                  <p className="text-gray-500">{m.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <div>
            <p className="text-gray-500 text-xs mb-1">Orçamento mensal (USD)</p>
            <input
              type="number" min={1} step={0.5}
              value={budget}
              onChange={e => setBudget(parseFloat(e.target.value))}
              className="input w-32"
            />
            <p className="text-gray-600 text-xs mt-1">
              Gasto este mês: ${status?.spent_this_month_usd.toFixed(2) ?? '0.00'} de ${status?.monthly_budget_usd.toFixed(2) ?? budget.toFixed(2)}
            </p>
          </div>

          <div>
            <p className="text-gray-500 text-xs mb-2">Enviar para análise (além dos números de latência/perda, sempre enviados):</p>
            <div className="space-y-1">
              {CONSENT_FIELDS.map(f => (
                <label key={f.key} className="flex items-center gap-2 text-sm text-gray-300">
                  <input
                    type="checkbox"
                    checked={consent[f.key] ?? false}
                    onChange={e => setConsent(c => ({ ...c, [f.key]: e.target.checked }))}
                  />
                  {f.label}
                </label>
              ))}
            </div>
          </div>

          <button onClick={saveConfig} disabled={saving} className="btn-primary">Salvar configurações</button>
        </>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Render it in `Settings.tsx`**

Following the exact import/render pattern found in Step 2, add:

```tsx
import AISettings from '../components/AISettings';
// ... alongside the other settings sections ...
<AISettings />
```

- [ ] **Step 5: Build and verify**

```bash
cd web && npm run build 2>&1 | tail -30
```

Expected: clean build. Fix any TypeScript error the compiler reports (missing import, prop mismatch) before proceeding.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/AISettings.tsx web/src/pages/Settings.tsx web/src/types/index.ts
git commit -m "feat(web): Assistente de IA settings — token, model, budget, consent"
```

---

### Task 7: Manual end-to-end verification (dry-run)

**Files:** none — verification only.

- [ ] **Step 1: Full build and test suite**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... 2>&1
go vet ./... 2>&1
go test ./... 2>&1
cd web && npm run build 2>&1 | tail -20
```

Expected: everything clean.

- [ ] **Step 2: Run the app and exercise the AI settings UI manually**

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go run ./cmd/linkguard-fw/ --dry-run --debug --addr 127.0.0.1 --port 9997
```

In a browser: log in, go to Configurações → Assistente de IA. Confirm:
- No token configured shows the token input, not the model/budget/consent controls.
- Saving an obviously-fake token (e.g. `sk-ant-test-not-real`) shows `configured: true` with a hint like `sk-ant-…real`.
- "Testar conexão" against the fake token shows the failure state (since it's not a real key) — confirms the failure path renders correctly, not just the happy path.
- Removing the token returns to the "no token configured" state.

This step requires a human at a browser — it is not automatable in this plan, and per the project's own verification standards, "manual verification pending" should be stated as such rather than implied as done by the automated steps above.
</content>
