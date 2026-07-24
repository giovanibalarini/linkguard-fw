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

// TestGaugeDoesNotBlockOnDiskAcrossBucketRollover specifically exercises the
// rollover code path: a Gauge() call whose bucket-start differs from the
// current pending bucket's start (i.e. it closes the previous bucket). Before
// the fix, accumulate() flushed the just-closed bucket to disk inline, on the
// caller's own goroutine, so this exact call would block for disk-write time.
// TestGaugeDoesNotBlockOnDisk (the tight loop above) never crosses a bucket
// boundary and so never caught this. This test also verifies the closed
// bucket isn't lost: it's queued and later flushed by tick().
func TestGaugeDoesNotBlockOnDiskAcrossBucketRollover(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// First sample opens native bucket [1000,1010).
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 1.0, 1000)

	// Second sample lands at t=1010 — a different 10s bucket — forcing
	// accumulate() to close the [1000,1010) bucket on this call. This must
	// stay memory-only; no s.db call may happen on this goroutine.
	start := time.Now()
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 2.0, 1010)
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Fatalf("Gauge() call that closes a bucket (rollover) took %v — must stay memory-only, never write to disk on the caller's goroutine", elapsed)
	}

	// The closed bucket must not be lost: force a flush and confirm it made
	// it to disk with its correct values.
	svc.FlushForTest(1500) // > 1010 (closes the rollover bucket's native window) but well under any retention cutoff
	got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", 10, 0, 1000000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	var closedBucket *storage.MetricSample
	for i := range got {
		if got[i].TsUnix == 1000 {
			closedBucket = &got[i]
		}
	}
	if closedBucket == nil {
		t.Fatalf("expected the bucket closed by the rollover to eventually be flushed, got %+v", got)
	}
	if closedBucket.VAvg != 1.0 || closedBucket.VMin != 1.0 || closedBucket.VMax != 1.0 {
		t.Fatalf("expected the closed bucket's avg/min/max to be 1.0 (unaffected by the sample that caused the rollover), got %+v", closedBucket)
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

	// Feed several distinct native (10s) buckets, all within the same 60s
	// derived window, with different values so avg diverges from max. A
	// single-sample test (avg == min == max trivially) would pass even if
	// VMax were wrongly derived from the average instead of tracked
	// independently — this uses GaugeForTest with explicit timestamps so
	// each call lands in its own native bucket deterministically.
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 10.0, 0)    // native bucket [0,10)
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 20.0, 10)   // closes [0,10), opens [10,20)
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 5000.0, 20) // closes [10,20), opens [20,30) -- the spike
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 30.0, 30)   // closes [20,30), opens [30,40)

	// Force-close everything, including the still-open last native bucket,
	// and roll it all into 60/900/3600. Needs to be > 3600 to force-close
	// every derived window too, but kept small enough to stay well under any
	// retention profile's prune cutoff — tick() prunes on its very first call
	// (lastPrune starts zero-valued), and a too-large "now" here would delete
	// the very rows this test just wrote.
	svc.FlushForTest(3700)

	wantAvg := (10.0 + 20.0 + 5000.0 + 30.0) / 4 // one raw sample per native bucket, so weights are equal here
	for _, step := range []int{60, 900, 3600} {
		got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", step, 0, 1000000)
		if err != nil {
			t.Fatalf("GetMetricSamples step=%d: %v", step, err)
		}
		if len(got) != 1 {
			t.Fatalf("step=%d: expected 1 bucket, got %d: %+v", step, len(got), got)
		}
		if got[0].VMax != 5000.0 {
			t.Fatalf("step=%d: expected max=5000 (the spike) to propagate, got %v", step, got[0].VMax)
		}
		if got[0].VMin != 10.0 {
			t.Fatalf("step=%d: expected min=10 to propagate, got %v", step, got[0].VMin)
		}
		if got[0].VAvg != wantAvg {
			t.Fatalf("step=%d: expected avg=%v, got %v", step, wantAvg, got[0].VAvg)
		}
		if got[0].VAvg == got[0].VMax {
			t.Fatalf("step=%d: test invariant broken — avg equals max, this test can't distinguish tracked-max from derived-from-avg", step)
		}
	}
}

// TestRollupAverageIsCountWeighted proves the derived-step average is
// weighted by how many raw samples fed each contributing native bucket, not
// a naive average-of-averages across contributing buckets. A native bucket
// with 9 samples must outweigh a native bucket with 1 sample in the derived
// average.
func TestRollupAverageIsCountWeighted(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// First native (10s) bucket [0,10): 9 samples at 0.0.
	for i := 0; i < 9; i++ {
		svc.GaugeForTest("link.latency_ms", "WAN VIVO", 0.0, 0)
	}
	// Second native (10s) bucket [10,20): 1 sample at 100.0. This closes the
	// first bucket and opens the second.
	svc.GaugeForTest("link.latency_ms", "WAN VIVO", 100.0, 10)

	svc.FlushForTest(3700) // force-close everything (see comment above) and roll up

	got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", 60, 0, 1000000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 bucket, got %d: %+v", len(got), got)
	}
	// Count-weighted: (9*0.0 + 1*100.0) / 10 = 10.0.
	// A naive average-of-averages would instead give (0.0+100.0)/2 = 50.0.
	const wantAvg = 10.0
	if got[0].VAvg != wantAvg {
		t.Fatalf("expected count-weighted avg=%v, got %v (average-of-averages would wrongly give 50)", wantAvg, got[0].VAvg)
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
