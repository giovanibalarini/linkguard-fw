package monitoring

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
)

func newTestCollector() *Collector {
	return &Collector{health: map[string]*itemState{}}
}

func TestObserveAntiFlapRequiresTwoDowns(t *testing.T) {
	c := newTestCollector()
	// first sighting: up, no transition
	if tr := c.observe("svc:unbound", true, 100); tr != transNone {
		t.Fatalf("first up should be transNone, got %v", tr)
	}
	// one down: NOT yet a transition (anti-flap needs 2 consecutive)
	if tr := c.observe("svc:unbound", false, 101); tr != transNone {
		t.Fatalf("single down should be suppressed (anti-flap), got %v", tr)
	}
	// second consecutive down: now it's a real outage
	if tr := c.observe("svc:unbound", false, 102); tr != transDown {
		t.Fatalf("second down should be transDown, got %v", tr)
	}
	// stays down: no repeat
	if tr := c.observe("svc:unbound", false, 103); tr != transNone {
		t.Fatalf("staying down should be transNone, got %v", tr)
	}
	// recovery is immediate (no debounce on the way up)
	if tr := c.observe("svc:unbound", true, 104); tr != transUp {
		t.Fatalf("recovery should be transUp, got %v", tr)
	}
}

func TestObserveFlapDoesNotAlert(t *testing.T) {
	c := newTestCollector()
	c.observe("link:wan1", true, 1)  // up
	c.observe("link:wan1", false, 2) // one down (suppressed)
	if tr := c.observe("link:wan1", true, 3); tr != transNone {
		t.Fatalf("a single-cycle blip must not alert, got %v", tr)
	}
}

type fakeExec struct{ active map[string]bool }

func (f *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) { return "", nil }
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	// emulate: systemctl is-active <svc>
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		if f.active[args[1]] {
			return "active\n", nil
		}
		return "inactive\n", assertErr{}
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type assertErr struct{}

func (assertErr) Error() string { return "inactive" }

func TestCheckServicesRaisesOnSecondDown(t *testing.T) {
	fe := &fakeExec{active: map[string]bool{"unbound": true}}
	db := openTestDB(t)
	as := alerts.NewService(db)
	c := &Collector{db: db, alertSvc: as, exec: fe, health: map[string]*itemState{}, nowFn: seqClock()}

	cfg := Config{Enabled: true, Services: []string{"unbound"}, DiskThresholdPct: 90}
	c.checkServices(cfg) // up → no alert
	fe.active["unbound"] = false
	c.checkServices(cfg) // 1st down → suppressed
	c.checkServices(cfg) // 2nd down → alert

	alertsList, _ := db.GetAlerts(false, 0)
	var offline int
	for _, a := range alertsList {
		if a.Type == alerts.TypeServiceOffline {
			offline++
		}
	}
	if offline != 1 {
		t.Fatalf("expected exactly 1 service_offline alert, got %d", offline)
	}
}

func seqClock() func() int64 {
	var n int64
	return func() int64 { n++; return n }
}
