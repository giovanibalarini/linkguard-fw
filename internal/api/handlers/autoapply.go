package handlers

import (
	"sync"
	"time"
)

// autoApplier coalesces a burst of change events into a single debounced run:
// each schedule() (re)arms a timer, so several quick edits (e.g. adding a few
// DHCP reservations in a row) collapse into ONE apply once things go quiet.
type autoApplier struct {
	mu    sync.Mutex
	timer *time.Timer
	delay time.Duration
	run   func()
}

func newAutoApplier(delay time.Duration, run func()) *autoApplier {
	return &autoApplier{delay: delay, run: run}
}

// schedule (re)arms the debounce timer; the run fires only after `delay` of
// quiet since the last schedule().
func (a *autoApplier) schedule() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil {
		a.timer.Stop()
	}
	a.timer = time.AfterFunc(a.delay, a.run)
}
