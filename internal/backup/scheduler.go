package backup

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Schedule values accepted by ScheduleSettingKey.
const (
	ScheduleOff     = "off"
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
	ScheduleMonthly = "monthly"
)

// ScheduleSettingKey and LastRunSettingKey are internal/storage settings
// (same mechanism as traffic_retention_profile / netsvc_last_apply).
const (
	ScheduleSettingKey = "backup_schedule"
	LastRunSettingKey  = "backup_last_run"
)

var scheduleInterval = map[string]time.Duration{
	ScheduleDaily:   24 * time.Hour,
	ScheduleWeekly:  7 * 24 * time.Hour,
	ScheduleMonthly: 30 * 24 * time.Hour,
}

// tickInterval is how often the scheduler wakes up to check whether it's time
// to run — coarse enough that daily/weekly/monthly all resolve correctly
// without a real cron.
const tickInterval = 1 * time.Hour

// RunStatus is the persisted result of the most recent scheduled (or manual
// "enviar agora") backup send, surfaced in the UI — same shape as netsvc's
// applyStatus.
type RunStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // unix seconds, 0 if never run
}

// emailSender is the subset of notify.Service that Scheduler needs, narrowed
// to a local interface so tests can inject a fake without a real SMTP server.
// *notify.Service satisfies this today with no changes needed there.
type emailSender interface {
	SendEmailAttachment(subject, body string, attachment []byte, filename string) error
}

// Scheduler periodically encrypts and e-mails a backup, per the admin-
// configured schedule.
type Scheduler struct {
	db      *storage.DB
	sec     secrets.Secrets
	sender  emailSender
	alerts  *alerts.Service
	version string
}

// NewScheduler creates a Scheduler.
func NewScheduler(db *storage.DB, sec secrets.Secrets, sender emailSender, alertSvc *alerts.Service, version string) *Scheduler {
	return &Scheduler{db: db, sec: sec, sender: sender, alerts: alertSvc, version: version}
}

// Run starts the scheduler loop and blocks until ctx is done.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("backup scheduler started", "tick_interval", tickInterval)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.maybeRun(ctx)
		}
	}
}

// maybeRun checks the configured schedule and the last-run timestamp, and
// calls RunOnce only if enough time has passed since the last attempt.
func (s *Scheduler) maybeRun(ctx context.Context) {
	schedule, _ := s.db.GetSetting(ScheduleSettingKey)
	interval, ok := scheduleInterval[schedule]
	if !ok {
		return // off, or unset
	}
	last := s.lastRun()
	if last.At != 0 && time.Since(time.Unix(last.At, 0)) < interval {
		return
	}
	if err := s.RunOnce(ctx); err != nil {
		slog.Error("scheduled backup failed", "err", err)
	}
}

// RunOnce builds, encrypts, and e-mails a backup immediately — used by the
// ticker loop and by the "enviar agora" button alike. It always records the
// result in LastRunSettingKey, and raises/clears alerts.TypeBackupFailed only
// on a state transition (never on repeated success or repeated failure,
// including "first ever run" counting as a transition either way) — a
// routine daily send never spams a new alert or recovery notification.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	prev := s.lastRun()
	neverRan := prev.At == 0

	encrypted, err := EncryptSnapshot(s.db, s.sec, s.version)
	if err == nil {
		err = s.sender.SendEmailAttachment(
			"Backup automático do LinkGuard FW",
			"Segue em anexo o backup cifrado da configuração. Guarde a senha configurada em Configurações → Backup — sem ela este arquivo não pode ser aberto.",
			encrypted, "linkguard-backup.lgbak")
	}

	st := RunStatus{OK: err == nil, At: time.Now().Unix()}
	if err != nil {
		st.Error = err.Error()
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = s.db.SetSetting(LastRunSettingKey, string(b))
	}

	switch {
	case err == nil && (neverRan || !prev.OK):
		_ = s.alerts.BackupSucceeded()
	case err != nil && (neverRan || prev.OK):
		_ = s.alerts.BackupFailed(err.Error())
	}

	_ = ctx // reserved for a future cancellable send path; encrypt+SMTP today have no cancellation point
	return err
}

// LastRunStatus returns the persisted result of the most recent send attempt.
func (s *Scheduler) LastRunStatus() RunStatus {
	return s.lastRun()
}

func (s *Scheduler) lastRun() RunStatus {
	var st RunStatus
	if raw, _ := s.db.GetSetting(LastRunSettingKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	return st
}
