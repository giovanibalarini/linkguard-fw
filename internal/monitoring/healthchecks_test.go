package monitoring

import "testing"

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
