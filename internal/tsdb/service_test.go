package tsdb_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestGaugeDoesNotBlockOnDisk(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// Gauge must return essentially instantly — it only touches an in-memory
	// bucket. If this took disk-write time, the test would be flaky under
	// load; instead assert it's well under a millisecond budget.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		svc.Gauge("link.latency_ms", "WAN VIVO", float64(i))
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("1000 Gauge() calls took %v — Gauge must be memory-only", elapsed)
	}
}

func TestRollupPreservesMinAndMax(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// Feed one native-step (10s) bucket's worth of samples with a spike in
	// the middle, then force-flush and verify the max survived.
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 10.0)
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 2000.0) // the spike
	svc.Gauge("link.latency_ms", "WAN SUMICITY", 12.0)

	svc.FlushForTest(1000) // internal test hook — see Step 3

	// Gauge() timestamps buckets using real wall-clock time (time.Now()), so
	// the query window must span real "now" rather than a small literal
	// range near the Unix epoch.
	now := time.Now().Unix()
	got, err := db.GetMetricSamples("link.latency_ms", "WAN SUMICITY", 10, now-60, now+60)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(got))
	}
	if got[0].VMax != 2000.0 {
		t.Fatalf("expected max=2000 (the spike) to survive, got %v", got[0].VMax)
	}
	if got[0].VMin != 10.0 {
		t.Fatalf("expected min=10, got %v", got[0].VMin)
	}
	wantAvg := (10.0 + 2000.0 + 12.0) / 3
	if got[0].VAvg != wantAvg {
		t.Fatalf("expected avg=%v, got %v", wantAvg, got[0].VAvg)
	}
}

func TestRollupPropagatesMaxAcrossDegrees(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.Gauge("link.latency_ms", "WAN VIVO", 5000.0)
	svc.FlushForTest(60) // closes the native 10s bucket AND rolls into 60/900/3600

	// See TestRollupPreservesMinAndMax: query window must span real "now".
	now := time.Now().Unix()
	for _, step := range []int{60, 900, 3600} {
		got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", step, now-3600, now+3600)
		if err != nil {
			t.Fatalf("GetMetricSamples step=%d: %v", step, err)
		}
		if len(got) != 1 || got[0].VMax != 5000.0 {
			t.Fatalf("step=%d: expected max=5000 to propagate, got %v", step, got)
		}
	}
}

func TestStateTransitionOpensAndClosesInterval(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.StateForTest("link", "WAN SUMICITY", "online", 1000)
	svc.StateForTest("link", "WAN SUMICITY", "degraded", 1008)

	got, err := db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 intervals (online then degraded), got %d", len(got))
	}
	if got[0].State != "online" || got[0].EndedAt == nil || *got[0].EndedAt != 1008 {
		t.Fatalf("expected first interval online, closed at 1008; got %+v", got[0])
	}
	if got[1].State != "degraded" || got[1].EndedAt != nil {
		t.Fatalf("expected second interval degraded, still open; got %+v", got[1])
	}
}

func TestStateSameValueTwiceDoesNotReopen(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	svc.StateForTest("service", "unbound", "up", 1000)
	svc.StateForTest("service", "unbound", "up", 1010) // no change — must be a no-op

	got, err := db.GetStateIntervals("service", "unbound", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 interval (no reopen on same state), got %d", len(got))
	}
}

// TestConcurrentGaugeAndStateWhileRunning calls Gauge and State from many
// goroutines while Run's own ticker goroutine is simultaneously flushing —
// this is the real-world shape (producers on their own goroutines, the
// service's ticker on its own). It doesn't assert on values; its only job is
// to give `go test -race` something to catch if the locking around the
// pending-bucket map or the state map is wrong.
func TestConcurrentGaugeAndStateWhileRunning(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	ctx, cancel := context.WithCancel(context.Background())
	var runWg sync.WaitGroup
	runWg.Add(1)
	go func() {
		defer runWg.Done()
		svc.Run(ctx)
	}()

	var producers sync.WaitGroup
	for g := 0; g < 8; g++ {
		producers.Add(1)
		go func(g int) {
			defer producers.Done()
			label := fmt.Sprintf("WAN %d", g)
			for i := 0; i < 200; i++ {
				svc.Gauge("link.latency_ms", label, float64(i))
				if i%50 == 0 {
					svc.State("link", label, "online")
				}
				if i%75 == 0 {
					svc.State("link", label, "degraded")
				}
			}
		}(g)
	}
	producers.Wait()

	cancel()
	runWg.Wait()
}
