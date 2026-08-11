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

	// Unconditional (not maybeRun's interval-gated check) so the panel is
	// never left blank for up to a whole interval after a restart: without
	// this, restarting within the configured interval meant ensureMeta
	// never ran, LastUpdatesReport() returned a zero Report, and the UI's
	// total>0 guard hid the section entirely — indistinguishable from "no
	// updates pending". apt-get --just-print is a lock-free, read-only
	// simulation that takes a few hundred ms, and Run already executes in
	// its own goroutine, so this is safe to do unconditionally on every
	// start.
	u.RunOnce(ctx)
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

	// Panel: down for ANY pending update, so the operator sees it just by
	// looking at the dashboard. This bypasses observe's anti-flap debounce
	// (see setHealthDirect's doc comment) — apt's cached package state,
	// read a few times a day, cannot flap, and requiring two consecutive
	// readings before the tile turns red would just delay the truth by a
	// full check interval (and reset on every restart).
	u.col.setHealthDirect("system:updates", rep.Total == 0, u.col.nowFn())
	u.col.ensureMeta("system:updates", "system-updates", "resource")

	// Notification: driven by its OWN security-scoped transition, deliberately
	// NOT by the panel's transition above. The panel's transition is derived
	// from rep.Total, so tying the alert to it meant (a) the alert could never
	// clear while any routine package stayed pending, and (b) a newly-appeared
	// security update raised no alert at all if the panel was already down for
	// an unrelated package. On a live Debian box, routine updates are pending
	// most of the time, so both were the common case rather than edge cases.
	//
	// No anti-flap debounce here on purpose: this reads apt's cached state
	// every few hours, and that state does not flap like a network probe.
	securityNow := rep.Security > 0
	wasPending, known := u.col.securityUpdatesState()
	u.col.setSecurityUpdatesState(securityNow)
	switch {
	case securityNow && (!known || !wasPending):
		_ = u.col.alertSvc.SecurityUpdatesPending(describeUpdates(rep))
	case !securityNow && known && wasPending:
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
