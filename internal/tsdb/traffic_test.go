package tsdb_test

import (
	"encoding/json"
	"fmt"
	"strings"
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

	found := findPointAt(t, res, ts)
	if found.Interface != "eth0" {
		t.Fatalf("point Interface = %q, want eth0", found.Interface)
	}
	if found.RxBps == nil || *found.RxBps != 500.0 {
		t.Fatalf("expected rx_bps=500 on the point, got %v", fmtPtr(found.RxBps))
	}
	if found.TxBps == nil || *found.TxBps != 200.0 {
		t.Fatalf("expected tx_bps=200 on the same point, got %v", fmtPtr(found.TxBps))
	}
}

// TestGetHistoryReportsMissingSideAsNull is the regression test for the
// invented zero: rx and tx are two separate series (if.rx_bps / if.tx_bps),
// so a timestamp can have a bucket for one direction and none for the other.
// Filling the missing side with 0 hands the UI a measurement that never
// happened — and a link that is down draws exactly like a link that is idle,
// which is the one mistake the traffic screen exists to avoid. Absence must
// reach the wire as null.
func TestGetHistoryReportsMissingSideAsNull(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	now := time.Now().Unix()
	ts := now - 10

	// Only rx is ever sampled at ts — if.tx_bps has no bucket at all there
	// (asserted against the database below, so this test fails loudly if the
	// premise ever stops holding).
	svc.GaugeForTest("if.rx_bps", "eth0", 500.0, ts)
	svc.GaugeForTest("if.rx_bps", "eth0", 999.0, ts+1) // closes the bucket at ts
	svc.FlushForTest(now)

	txRows, err := db.GetMetricSamples("if.tx_bps", "eth0", 1, now-300, now)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(txRows) != 0 {
		t.Fatalf("premise broken: expected no if.tx_bps buckets stored, got %+v", txRows)
	}

	res, err := svc.GetHistory("eth0", "5m")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}

	p := findPointAt(t, res, ts)
	if p.RxBps == nil || *p.RxBps != 500.0 {
		t.Fatalf("expected the measured side rx_bps=500, got %v", fmtPtr(p.RxBps))
	}
	if p.TxBps != nil {
		t.Fatalf("expected tx_bps to be nil (not measured at this timestamp), got %v — an invented zero makes a dead link look idle", *p.TxBps)
	}

	// The contract that matters is the wire format the chart consumes: it has
	// to be literally null, not 0 and not an omitted field (an omitted field
	// deserializes to 0 in the frontend just the same).
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"tx_bps":null`) {
		t.Fatalf("expected the JSON to carry \"tx_bps\":null, got %s", raw)
	}
	if strings.Contains(string(raw), `"tx_bps":0`) {
		t.Fatalf("JSON reports a measured zero for a direction that was never sampled: %s", raw)
	}
}

// TestGetHistoryKeepsMeasuredZero is the other half of the rule: a real
// measured 0 (an interface up and genuinely idle) must stay 0 and must NOT
// become null — "unknown" and "zero" are different facts and the chart draws
// them differently.
func TestGetHistoryKeepsMeasuredZero(t *testing.T) {
	db := newTestDB(t)
	svc := tsdb.NewService(db)

	now := time.Now().Unix()
	ts := now - 10

	svc.GaugeForTest("if.rx_bps", "eth0", 0.0, ts)
	svc.GaugeForTest("if.tx_bps", "eth0", 0.0, ts)
	svc.GaugeForTest("if.rx_bps", "eth0", 1.0, ts+1)
	svc.GaugeForTest("if.tx_bps", "eth0", 1.0, ts+1)
	svc.FlushForTest(now)

	res, err := svc.GetHistory("eth0", "5m")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}

	p := findPointAt(t, res, ts)
	if p.RxBps == nil || *p.RxBps != 0.0 {
		t.Fatalf("a measured zero must stay 0, got %v", fmtPtr(p.RxBps))
	}
	if p.TxBps == nil || *p.TxBps != 0.0 {
		t.Fatalf("a measured zero must stay 0, got %v", fmtPtr(p.TxBps))
	}
}

func findPointAt(t *testing.T, res *tsdb.HistoryResponse, ts int64) tsdb.HistoryPoint {
	t.Helper()
	for _, p := range res.Points {
		if p.Timestamp == ts {
			return p
		}
	}
	t.Fatalf("expected a point at ts=%d, got points=%+v", ts, res.Points)
	return tsdb.HistoryPoint{}
}

func fmtPtr(v *float64) string {
	if v == nil {
		return "nil"
	}
	return fmt.Sprintf("%v", *v)
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

// sinkFalso registra o que o amostrador entrega à franquia por link.
type sinkFalso struct{ rx, tx map[string]uint64 }

func novoSink() *sinkFalso {
	return &sinkFalso{rx: map[string]uint64{}, tx: map[string]uint64{}}
}

func (s *sinkFalso) AddInterfaceBytes(iface string, rx, tx uint64) {
	s.rx[iface] += rx
	s.tx[iface] += tx
}

func TestUsageSinkRecebeOsMesmosDeltasDaSerie(t *testing.T) {
	sink := novoSink()
	sampler := tsdb.NewTrafficSampler(&fakeRecorder{})
	sampler.SetUsageSink(sink)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "wan1", RxBytes: 1000, TxBytes: 500},
	}, 100)
	// Primeira amostra só semeia o contador anterior: não há delta ainda.
	if sink.rx["wan1"] != 0 {
		t.Errorf("a primeira amostra não pode virar consumo: %d", sink.rx["wan1"])
	}

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "wan1", RxBytes: 3000, TxBytes: 800},
	}, 101)
	if sink.rx["wan1"] != 2000 || sink.tx["wan1"] != 300 {
		t.Errorf("delta entregue: rx=%d tx=%d, queria 2000/300", sink.rx["wan1"], sink.tx["wan1"])
	}
}

func TestUsageSinkNaoRecebeOSaltoFalsoDeUmReset(t *testing.T) {
	// Reboot zera os contadores de /proc. Sem a proteção, a subtração de
	// uint64 daria um número perto de 2^64 e a franquia estouraria sozinha no
	// primeiro reinício da máquina.
	sink := novoSink()
	sampler := tsdb.NewTrafficSampler(&fakeRecorder{})
	sampler.SetUsageSink(sink)

	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "wan1", RxBytes: 9_000_000, TxBytes: 9_000_000},
	}, 100)
	sampler.SampleInterfacesForTest([]system.InterfaceMetrics{
		{Name: "wan1", RxBytes: 10, TxBytes: 10},
	}, 101)

	if sink.rx["wan1"] != 0 || sink.tx["wan1"] != 0 {
		t.Errorf("reset de contador virou consumo: rx=%d tx=%d", sink.rx["wan1"], sink.tx["wan1"])
	}
}

func TestHostStepNuncaPedeUmBaldeQueNaoExiste(t *testing.T) {
	// A série por host é amostrada a cada 10s, então não existe balde de 1s
	// para ela. As janelas curtas resolvem para passo 1 (o nativo das
	// interfaces) e a consulta voltaria vazia — em branco justamente na janela
	// que a tela do aparelho abre por padrão.
	for _, janela := range []string{"5m", "30m"} {
		step, _ := tsdb.HostStepForTest(janela)
		if step < 10 {
			t.Errorf("janela %q resolveu para passo %d; a série por host não tem balde abaixo de 10s", janela, step)
		}
	}
	// As janelas longas continuam usando o rollup que já existe.
	if step, _ := tsdb.HostStepForTest("12h"); step != 60 {
		t.Errorf("12h resolveu para passo %d, queria 60", step)
	}
	if step, _ := tsdb.HostStepForTest("30d"); step != 900 {
		t.Errorf("30d resolveu para passo %d, queria 900", step)
	}
}
