package handlers

import (
	"sync/atomic"
	"testing"
	"time"
)

// A burst of schedule() calls within the debounce window must coalesce into a
// single run — so cadastrar várias reservas seguidas dispara UM reload só.
func TestAutoApplierCoalesces(t *testing.T) {
	var runs int32
	a := newAutoApplier(40*time.Millisecond, func() { atomic.AddInt32(&runs, 1) })

	for i := 0; i < 6; i++ {
		a.schedule()
		time.Sleep(3 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond)

	if got := atomic.LoadInt32(&runs); got != 1 {
		t.Errorf("expected 1 coalesced run, got %d", got)
	}
}

// Two bursts separated by more than the debounce window run twice.
func TestAutoApplierSeparateBurstsRunTwice(t *testing.T) {
	var runs int32
	a := newAutoApplier(30*time.Millisecond, func() { atomic.AddInt32(&runs, 1) })

	a.schedule()
	time.Sleep(90 * time.Millisecond)
	a.schedule()
	time.Sleep(90 * time.Millisecond)

	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Errorf("expected 2 runs for 2 separated bursts, got %d", got)
	}
}
