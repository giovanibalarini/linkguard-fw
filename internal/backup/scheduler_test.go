package backup_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeEmailSender struct {
	err   error
	calls int
	// delay, if set, is slept inside SendEmailAttachment before returning —
	// used to widen the window for a concurrency test to expose a race if
	// Scheduler.RunOnce were not serialized.
	delay time.Duration
}

func (f *fakeEmailSender) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
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

// TestRunOnceSerializesConcurrentCalls proves that concurrent RunOnce calls
// (e.g. the ticker loop and a manual "enviar agora" click landing at the same
// time, or two admin tabs double-clicking) are serialized end-to-end rather
// than racing: exactly one e-mail per call, but only ONE alert transition
// overall — never a duplicate alert from two goroutines both reading the same
// stale "prev" status before either persisted its result. Run with -race to
// also confirm there's no data race in RunOnce itself.
func TestRunOnceSerializesConcurrentCalls(t *testing.T) {
	db, sec := newSchedulerTestDeps(t)
	alertSvc := alerts.NewService(db)
	fn := &fakeSchedulerNotifier{}
	alertSvc.SetNotifier(fn)
	// Every send succeeds; a small sleep inside SendEmailAttachment widens the
	// window in which two unserialized RunOnce calls would overlap.
	sender := &fakeEmailSender{delay: 5 * time.Millisecond}
	sched := backup.NewScheduler(db, sec, sender, alertSvc, "v-test")

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = sched.RunOnce(context.Background())
		}()
	}
	wg.Wait()

	if sender.calls != n {
		t.Fatalf("expected %d send attempts, got %d", n, sender.calls)
	}
	// This is the first run ever, so exactly one call transitions
	// neverRan->success and raises the recovery notification; every other
	// concurrent call must see prev.OK == true (from whichever call actually
	// ran first under the lock) and stay silent.
	if len(fn.recovery) != 1 {
		t.Fatalf("expected exactly 1 recovery notification despite %d concurrent RunOnce calls, got %d: %v", n, len(fn.recovery), fn.recovery)
	}
	if len(fn.normal) != 0 {
		t.Fatalf("expected no failure alerts, got %d: %v", len(fn.normal), fn.normal)
	}

	status := sched.LastRunStatus()
	if !status.OK {
		t.Fatalf("expected OK last-run status after concurrent successful runs, got %+v", status)
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
