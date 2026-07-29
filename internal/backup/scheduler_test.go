package backup_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeEmailSender struct {
	err   error
	calls int
}

func (f *fakeEmailSender) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	f.calls++
	return f.err
}

type fakeSchedulerNotifier struct {
	normal   []string
	recovery []string
}

func (f *fakeSchedulerNotifier) Notify(severity, title, message string) {
	f.normal = append(f.normal, severity+"|"+title)
}
func (f *fakeSchedulerNotifier) NotifyRecovery(title, message string) {
	f.recovery = append(f.recovery, title)
}

func newSchedulerTestDeps(t *testing.T) (*storage.DB, *secrets.Service) {
	t.Helper()
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	return db, sec
}

func TestRunOnceRecordsLastRunOnSuccess(t *testing.T) {
	db, sec := newSchedulerTestDeps(t)
	alertSvc := alerts.NewService(db)
	sender := &fakeEmailSender{}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected 1 send attempt, got %d", sender.calls)
	}
	status := sched.LastRunStatus()
	if !status.OK {
		t.Fatalf("expected OK last-run status, got %+v", status)
	}
	if status.At == 0 {
		t.Fatal("expected non-zero At timestamp")
	}
}

func TestRunOnceAlertsOnlyOnStateTransition(t *testing.T) {
	db, sec := newSchedulerTestDeps(t)
	alertSvc := alerts.NewService(db)
	fn := &fakeSchedulerNotifier{}
	alertSvc.SetNotifier(fn)
	sender := &fakeEmailSender{err: fmt.Errorf("smtp indisponível")}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	// First run ever, and it fails: must alert — this IS the transition into
	// a bad state, even with no prior "success" to transition away from.
	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error from first RunOnce")
	}
	if len(fn.normal) != 1 {
		t.Fatalf("expected 1 alert after first failure, got %d: %v", len(fn.normal), fn.normal)
	}

	// Second run, still failing: same state as before, must NOT alert again.
	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error from second RunOnce")
	}
	if len(fn.normal) != 1 {
		t.Fatalf("expected still 1 alert after repeated failure, got %d: %v", len(fn.normal), fn.normal)
	}

	// Third run succeeds: transition failure→success, must alert (recovery).
	sender.err = nil
	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(fn.recovery) != 1 {
		t.Fatalf("expected 1 recovery notification, got %d: %v", len(fn.recovery), fn.recovery)
	}

	// Fourth run also succeeds: same state as before, must NOT alert again.
	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(fn.recovery) != 1 {
		t.Fatalf("expected still 1 recovery notification after repeated success, got %d: %v", len(fn.recovery), fn.recovery)
	}
}

func TestRunOnceWithoutPassphraseReturnsError(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	alertSvc := alerts.NewService(db)
	sender := &fakeEmailSender{}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	if err := sched.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when no passphrase is configured")
	}
	if sender.calls != 0 {
		t.Fatalf("expected no send attempt without a passphrase, got %d calls", sender.calls)
	}
}
