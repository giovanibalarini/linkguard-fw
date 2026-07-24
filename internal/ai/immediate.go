package ai

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// lastImmediateTrigger tracks the last immediate-trigger time per link ID
// (see immediateCooldown below). lastImmediateTriggerMu guards it: DEVIATION
// from the plan's literal code — the plan showed this as a bare package-level
// map with no synchronization. balancer.OnLinkChange invokes TriggerImmediate
// as `go ai.TriggerImmediate(...)`, so two different links transitioning close
// in time call this concurrently with different map keys. Go maps are not
// safe for concurrent read+write even across distinct keys (a write can
// trigger a rehash that a concurrent reader observes mid-flight); this was
// confirmed empirically with `go test -race` against 200 concurrent calls
// across 4 link IDs, which reliably reported a DATA RACE at the map
// read/write in this function (see task-4-report.md for the full -race
// output). A sync.Mutex guarding the map is the minimal fix, matching the
// mutex-guards-map pattern already used throughout internal/balancer
// (evictMu/evictCooldown, schedMu/lastFired).
var (
	lastImmediateTriggerMu sync.Mutex
	lastImmediateTrigger   = map[string]time.Time{}
)

// evictCooldown reuses the same shape as balancer's per-link eviction
// cooldown: a link that keeps flapping in and out of "degraded" must not
// trigger a fresh immediate analysis (and spend) on every single flap.
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

	lastImmediateTriggerMu.Lock()
	last, onCooldown := lastImmediateTrigger[link.ID]
	onCooldown = onCooldown && time.Since(last) < immediateCooldown
	if !onCooldown {
		lastImmediateTrigger[link.ID] = time.Now()
	}
	lastImmediateTriggerMu.Unlock()
	if onCooldown {
		return
	}

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
