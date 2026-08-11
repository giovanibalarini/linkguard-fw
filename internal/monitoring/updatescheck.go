package monitoring

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/sysupdates"
)

// updatesLastRunSettingKey persists the unix timestamp of the last check so
// the interval survives restarts (mirrors journalLastVerifySettingKey).
const updatesLastRunSettingKey = "sysupdates_last_run"

// updatesTickInterval is how often the scheduler wakes to decide whether it
// is time to check for real — coarse, like JournalScheduler's.
const updatesTickInterval = 1 * time.Hour

// UpdatesScheduler periodically reports pending system package updates.
//
// It runs on its own ticker rather than inside the Collector's 30s loop
// because shelling out to apt is comparatively slow, and pending updates
// change on the order of days — not seconds.
//
// Deliberate split between panel and notification: the health item goes down
// for ANY pending update (so the operator sees it just by looking at the
// dashboard, which is the whole point), but a push alert only fires for
// SECURITY updates — routine package churn would train the operator to
// ignore the notification channel.
type UpdatesScheduler struct {
	col *Collector
}

// NewUpdatesScheduler creates a scheduler bound to an existing Collector
// (reuses its db/exec/alertSvc/health bookkeeping).
func NewUpdatesScheduler(col *Collector) *UpdatesScheduler {
	return &UpdatesScheduler{col: col}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (u *UpdatesScheduler) Run(ctx context.Context) {
	slog.Info("system updates scheduler started", "tick_interval", updatesTickInterval)
	ticker := time.NewTicker(updatesTickInterval)
	defer ticker.Stop()

	u.maybeRun(ctx) // check once at startup instead of waiting a full tick
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.maybeRun(ctx)
		}
	}
}

func (u *UpdatesScheduler) maybeRun(ctx context.Context) {
	cfg := LoadConfig(u.col.db)
	if !cfg.Enabled {
		return
	}
	interval := time.Duration(cfg.UpdatesCheckIntervalHours) * time.Hour
	last := u.lastRun()
	if last != 0 && time.Since(time.Unix(last, 0)) < interval {
		return
	}
	u.RunOnce(ctx)
}

// RunOnce checks for pending updates immediately and updates the health item
// and (for security updates) the alert.
func (u *UpdatesScheduler) RunOnce(ctx context.Context) {
	rep, err := sysupdates.Check(ctx, u.col.exec)
	_ = u.col.db.SetSetting(updatesLastRunSettingKey, strconv.FormatInt(time.Now().Unix(), 10))
	if err != nil {
		slog.Warn("não foi possível verificar atualizações do sistema", "err", err)
		return // no verdict rather than a false "up to date"
	}

	u.col.setLastUpdatesReport(rep)

	tr := u.col.observe("system:updates", rep.Total == 0, u.col.nowFn())
	u.col.ensureMeta("system:updates", "system-updates", "resource")

	if rep.Security > 0 {
		if tr == transDown {
			_ = u.col.alertSvc.SecurityUpdatesPending(describeUpdates(rep))
		}
		return
	}
	if tr == transUp {
		_ = u.col.alertSvc.SecurityUpdatesNone()
	}
}

// describeUpdates renders a short, operator-readable summary naming the
// security packages (capped so a large backlog doesn't produce a wall of
// text in a Telegram/e-mail notification).
func describeUpdates(rep sysupdates.Report) string {
	const maxNamed = 5
	names := make([]string, 0, maxNamed)
	for _, p := range rep.Packages {
		if !p.Security {
			continue
		}
		if len(names) == maxNamed {
			names = append(names, "…")
			break
		}
		names = append(names, p.Name)
	}
	return fmt.Sprintf("%d de segurança (de %d no total): %s",
		rep.Security, rep.Total, strings.Join(names, ", "))
}

func (u *UpdatesScheduler) lastRun() int64 {
	raw, _ := u.col.db.GetSetting(updatesLastRunSettingKey)
	v, _ := strconv.ParseInt(raw, 10, 64)
	return v
}
