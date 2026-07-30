package monitoring

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// journalLastVerifySettingKey persists the unix timestamp of the last
// journalctl --verify run, so JournalScheduler knows whether it's time to
// run again across restarts (mirrors backup.LastRunSettingKey).
const journalLastVerifySettingKey = "journal_last_verify"

// journalTickInterval is how often JournalScheduler wakes up to check
// whether it's time to run for real — coarse, matching backup.Scheduler's
// tickInterval, since day-granularity scheduling doesn't need anything
// finer.
const journalTickInterval = 1 * time.Hour

// JournalScheduler periodically runs `journalctl --verify` and alerts if it
// finds corruption. It runs on its own ticker, separate from Collector's 30s
// loop, because `journalctl --verify` is slow on a large/busy journal (seen
// taking tens of seconds in production) — running it inside the 30s tick
// would stall every other check for that long. It shares the Collector's
// observe()/ensureMeta() bookkeeping (same package, unexported fields
// reachable directly) so the journal-integrity item gets anti-flap dedup and
// shows up on the dashboard panel for free, like every other check — the
// tradeoff is that a corrupt-journal alert only fires on the SECOND
// consecutive weekly finding (worst case ~1 extra week of delay), which is
// acceptable given this alert is explicitly Warning-severity /
// "degrades observability, not an outage" (see the design spec).
type JournalScheduler struct {
	col *Collector
}

// NewJournalScheduler creates a JournalScheduler bound to an existing
// Collector (reuses its db/exec/alertSvc/health map).
func NewJournalScheduler(col *Collector) *JournalScheduler {
	return &JournalScheduler{col: col}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (j *JournalScheduler) Run(ctx context.Context) {
	slog.Info("journal integrity scheduler started", "tick_interval", journalTickInterval)
	ticker := time.NewTicker(journalTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.maybeRun(ctx)
		}
	}
}

// maybeRun checks the master toggle and the configured interval against the
// last-run timestamp, and calls RunOnce only if it's actually time.
func (j *JournalScheduler) maybeRun(ctx context.Context) {
	cfg := LoadConfig(j.col.db)
	if !cfg.Enabled {
		return
	}
	interval := time.Duration(cfg.JournalVerifyIntervalDays) * 24 * time.Hour
	last := j.lastVerify()
	if last != 0 && time.Since(time.Unix(last, 0)) < interval {
		return
	}
	j.RunOnce(ctx)
}

// RunOnce runs `journalctl --verify` immediately and raises/clears
// alerts.TypeJournalCorrupt on a confirmed transition (see the anti-flap
// tradeoff documented on JournalScheduler).
func (j *JournalScheduler) RunOnce(ctx context.Context) {
	out, err := j.col.exec.ExecuteRead(ctx, "journalctl", "--verify")
	_ = j.col.db.SetSetting(journalLastVerifySettingKey, strconv.FormatInt(time.Now().Unix(), 10))

	combined := out
	if err != nil {
		combined += " " + err.Error()
	}
	clean := !strings.Contains(combined, "FAIL")

	now := j.col.nowFn()
	tr := j.col.observe("journal:integrity", clean, now)
	j.col.ensureMeta("journal:integrity", "journal-integrity", "resource")
	switch tr {
	case transDown:
		_ = j.col.alertSvc.JournalCorrupt(firstFailLine(combined))
	case transUp:
		_ = j.col.alertSvc.JournalOK()
	}
}

func (j *JournalScheduler) lastVerify() int64 {
	raw, _ := j.col.db.GetSetting(journalLastVerifySettingKey)
	v, _ := strconv.ParseInt(raw, 10, 64)
	return v
}

// firstFailLine extracts the first "FAIL:" line from journalctl --verify's
// output for use in the alert message, falling back to a generic message if
// none is found (e.g. the failure came from ExecuteRead's own error, not a
// FAIL: line).
func firstFailLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "FAIL") {
			return strings.TrimSpace(line)
		}
	}
	return "corrupção detectada"
}
