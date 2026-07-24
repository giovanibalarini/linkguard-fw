package tsdb_test

import (
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestGetHistoryUnknownRangeDefaultsTo12h(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	res, err := svc.GetHistory("eth0", "not-a-real-range")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if res.Step != 60 {
		t.Fatalf("expected default range to use step=60 (12h/60s), got %d", res.Step)
	}
}

func TestGetHistoryRequiresInterface(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	if _, err := svc.GetHistory("", "12h"); err == nil {
		t.Fatal("expected error for empty interface")
	}
}

// TestGetHistoryMergesRxAndTxOnSamePoint is the regression test for the
// frontend contract break: the old implementation only queried if.rx_bps and
// returned generic storage.MetricSample fields (series/label/v_avg/...)
// instead of rx_bps/tx_bps, so this test would have failed against that
// code (tx_bps would always be 0, and the JSON shape wouldn't even have a
// tx_bps field). It seeds both if.rx_bps and if.tx_bps for the same
// interface/timestamp and asserts a single point in the response carries
// both non-zero values, matching what web/src/pages/Interfaces.tsx reads
// (p.rx_bps and p.tx_bps off the same point).
func TestGetHistoryMergesRxAndTxOnSamePoint(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	// if.* series are native step 1s (see nativeSteps in schema.go), so with
	// range "5m" (step=1) each Gauge sample is its own bucket once closed by
	// a subsequent sample at the next second. GetHistory queries a window
	// anchored on real time.Now(), so the seeded timestamp must be recent
	// wall-clock time rather than an arbitrary epoch offset.
	now := time.Now().Unix()
	ts := now - 10

	svc.GaugeForTest("if.rx_bps", "eth0", 500.0, ts)
	svc.GaugeForTest("if.tx_bps", "eth0", 200.0, ts)
	// Close the buckets opened above by sampling again one second later.
	svc.GaugeForTest("if.rx_bps", "eth0", 999.0, ts+1)
	svc.GaugeForTest("if.tx_bps", "eth0", 999.0, ts+1)
	svc.FlushForTest(now)

	res, err := svc.GetHistory("eth0", "5m")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if res.Interface != "eth0" || res.Range != "5m" || res.Step != 1 {
		t.Fatalf("unexpected response header: %+v", res)
	}

	var found *struct{ RxBps, TxBps float64 }
	for _, p := range res.Points {
		if p.Timestamp != ts {
			continue
		}
		if p.Interface != "eth0" {
			t.Fatalf("point Interface = %q, want eth0", p.Interface)
		}
		found = &struct{ RxBps, TxBps float64 }{p.RxBps, p.TxBps}
	}
	if found == nil {
		t.Fatalf("expected a point at ts=%d, got points=%+v", ts, res.Points)
	}
	if found.RxBps != 500.0 {
		t.Fatalf("expected rx_bps=500 on the point, got %v", found.RxBps)
	}
	if found.TxBps != 200.0 {
		t.Fatalf("expected tx_bps=200 on the same point, got %v", found.TxBps)
	}
}

// fakeRecorder is a Recorder that just records every Gauge call, so
// TrafficSampler tests can assert on exactly what it would have reported
// without a real Service/database involved.
type fakeRecorder struct {
	mu     sync.Mutex
	gauges []gaugeCall
}

type gaugeCall struct {
	series, label string
	v             float64
}

func (f *fakeRecorder) Gauge(series, label string, v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gauges = append(f.gauges, gaugeCall{series, label, v})
}

func (f *fakeRecorder) State(kind, label, state string) {}

func (f *fakeRecorder) calls() []gaugeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gaugeCall(nil), f.gauges...)
}

func TestSampleOnceFirstCallOnlySeedsAndReportsNothing(t *testing.T) {
	rec := &fakeRecorder{}
	sampler := tsdb.NewTrafficSampler(rec)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "eth0", RxBytes: 1000, TxBytes: 500},
	}, 0)

	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("expected no Gauge calls on the first observation of an interface (nothing to compute a rate from yet), got %+v", calls)
	}
}

func TestSampleOnceComputesDeltaRate(t *testing.T) {
	rec := &fakeRecorder{}
	sampler := tsdb.NewTrafficSampler(rec)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "eth0", RxBytes: 1000, TxBytes: 500},
	}, 0)
	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "eth0", RxBytes: 11000, TxBytes: 2500}, // +10000 rx, +2000 tx over 10s
	}, 10)

	calls := rec.calls()
	rx, tx := findGauge(t, calls, "if.rx_bps", "eth0"), findGauge(t, calls, "if.tx_bps", "eth0")
	if rx != 1000.0 {
		t.Fatalf("expected rx rate = 10000 bytes / 10s = 1000, got %v", rx)
	}
	if tx != 200.0 {
		t.Fatalf("expected tx rate = 2000 bytes / 10s = 200, got %v", tx)
	}
}

// TestSampleOnceClampsNegativeDeltaToZero covers a counter reset or 64-bit
// wraparound: the raw delta goes negative, and SampleOnce must report 0
// instead of a negative (or huge, if computed as unsigned wraparound) rate.
func TestSampleOnceClampsNegativeDeltaToZero(t *testing.T) {
	rec := &fakeRecorder{}
	sampler := tsdb.NewTrafficSampler(rec)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "eth0", RxBytes: 5000, TxBytes: 5000},
	}, 0)
	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "eth0", RxBytes: 100, TxBytes: 100}, // counter reset: lower than before
	}, 5)

	calls := rec.calls()
	rx, tx := findGauge(t, calls, "if.rx_bps", "eth0"), findGauge(t, calls, "if.tx_bps", "eth0")
	if rx != 0.0 {
		t.Fatalf("expected rx rate clamped to 0 on counter reset, got %v", rx)
	}
	if tx != 0.0 {
		t.Fatalf("expected tx rate clamped to 0 on counter reset, got %v", tx)
	}
}

// TestSampleOnceSkipsLoopback ensures the loopback interface never reports
// if.rx_bps/if.tx_bps — it's explicitly excluded because it's not a WAN/LAN
// link the frontend charts.
func TestSampleOnceSkipsLoopback(t *testing.T) {
	rec := &fakeRecorder{}
	sampler := tsdb.NewTrafficSampler(rec)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "lo", RxBytes: 1000, TxBytes: 1000},
	}, 0)
	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "lo", RxBytes: 2000, TxBytes: 2000},
	}, 10)

	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("expected lo to be skipped entirely, got %+v", calls)
	}
}

func findGauge(t *testing.T, calls []gaugeCall, series, label string) float64 {
	t.Helper()
	for _, c := range calls {
		if c.series == series && c.label == label {
			return c.v
		}
	}
	t.Fatalf("no Gauge call found for series=%q label=%q in %+v", series, label, calls)
	return 0
}
