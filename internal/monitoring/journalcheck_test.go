package monitoring

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
)

func TestJournalRunOnceRaisesOnSecondCorruptRun(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "PASS: /var/log/journal/foo/system.journal\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // clean -> no alert
	fe.journalOut = "FAIL: /var/log/journal/foo/system@abc.journal~ (Mensagem inválida)\n"
	j.RunOnce(context.Background()) // 1st corrupt -> suppressed (anti-flap)
	j.RunOnce(context.Background()) // 2nd corrupt -> alert

	al, _ := db.GetAlerts(false, 0)
	n := 0
	for _, a := range al {
		if a.Type == alerts.TypeJournalCorrupt {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 journal_corrupt alert, got %d", n)
	}
}

func TestJournalRunOnceRecoversAfterClean(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "FAIL: something\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // 1st corrupt -> suppressed
	j.RunOnce(context.Background()) // 2nd corrupt -> alert
	fe.journalOut = "PASS: everything\n"
	j.RunOnce(context.Background()) // clean -> recovery

	al, _ := db.GetAlerts(false, 0)
	var open int
	for _, a := range al {
		if a.Type == alerts.TypeJournalCorrupt && a.ResolvedAt == nil {
			open++
		}
	}
	if open != 0 {
		t.Fatalf("expected the journal_corrupt alert to be auto-resolved, %d still open", open)
	}
}

func TestJournalMaybeRunSkipsBeforeInterval(t *testing.T) {
	db := openTestDB(t)
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "PASS: ok\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.RunOnce(context.Background()) // establishes journalLastVerifySettingKey = now
	before := j.lastVerify()
	j.maybeRun(context.Background()) // interval (7 days default) hasn't elapsed -> must not re-run
	after := j.lastVerify()
	if before != after {
		t.Fatalf("maybeRun ran again before the configured interval elapsed: before=%d after=%d", before, after)
	}
}

func TestJournalMaybeRunSkipsWhenDisabled(t *testing.T) {
	db := openTestDB(t)
	if err := SaveConfig(db, Config{Enabled: false, JournalVerifyIntervalDays: 7}); err != nil {
		t.Fatal(err)
	}
	as := alerts.NewService(db)
	fe := &fakeExec{journalOut: "FAIL: something\n"}
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}
	j := NewJournalScheduler(c)

	j.maybeRun(context.Background())

	al, _ := db.GetAlerts(false, 0)
	if len(al) != 0 {
		t.Fatalf("cfg.Enabled=false must skip the check entirely, got %d alerts", len(al))
	}
}
