package tsdb

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// TrafficSampler feeds the "if.rx_bps"/"if.tx_bps" series once a second from
// interface byte counters, mirroring what internal/trafficrrd used to do
// directly against the database — the difference is it now calls Gauge()
// instead of writing SQL itself.
type TrafficSampler struct {
	sysCol *system.Collector
	rec    Recorder

	prevCounters map[string]struct {
		ts int64
		rx uint64
		tx uint64
	}
}

// NewTrafficSampler creates a sampler that reports into rec (normally the
// same *Service — pass it as a Recorder).
func NewTrafficSampler(rec Recorder) *TrafficSampler {
	return &TrafficSampler{
		sysCol: system.NewCollector(),
		rec:    rec,
		prevCounters: make(map[string]struct {
			ts int64
			rx uint64
			tx uint64
		}),
	}
}

// SampleOnce reads current interface counters and reports the delta-derived
// rate for each interface. Call once per second.
func (t *TrafficSampler) SampleOnce(now int64) {
	snap, err := t.sysCol.Collect()
	if err != nil {
		return
	}
	t.sampleInterfaces(snap.Interfaces, now)
}

// SampleInterfacesForTest exercises the same delta/rate logic as SampleOnce
// against caller-supplied interface counters instead of a real
// system.Collector.Collect() snapshot, so tests can deterministically drive
// first-call seeding, rate computation, and negative-delta clamping without
// depending on /proc. Test-only — mirrors the *ForTest seam pattern already
// used by Service (FlushForTest, StateForTest, GaugeForTest).
func (t *TrafficSampler) SampleInterfacesForTest(interfaces []system.InterfaceMetrics, now int64) {
	t.sampleInterfaces(interfaces, now)
}

func (t *TrafficSampler) sampleInterfaces(interfaces []system.InterfaceMetrics, now int64) {
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}
		prev, ok := t.prevCounters[iface.Name]
		t.prevCounters[iface.Name] = struct {
			ts int64
			rx uint64
			tx uint64
		}{ts: now, rx: iface.RxBytes, tx: iface.TxBytes}
		if !ok {
			continue
		}
		dt := float64(now - prev.ts)
		if dt <= 0 {
			continue
		}
		// Counters are uint64: on a reset/wrap, current can be < prev, and
		// subtracting unsigned integers in that case underflows to a huge
		// positive number instead of going negative — casting that to
		// float64 before checking the sign would defeat the clamp entirely
		// (a reset would report a bogus multi-exabyte/s spike instead of 0).
		// Comparing before subtracting avoids ever forming the underflowed
		// value.
		var rxDelta, txDelta float64
		if iface.RxBytes >= prev.rx {
			rxDelta = float64(iface.RxBytes - prev.rx)
		}
		if iface.TxBytes >= prev.tx {
			txDelta = float64(iface.TxBytes - prev.tx)
		}
		t.rec.Gauge("if.rx_bps", iface.Name, rxDelta/dt)
		t.rec.Gauge("if.tx_bps", iface.Name, txDelta/dt)
	}
}

// HistoryResponse is returned by the /api/system/traffic-history and
// /api/monitoring/timeline handlers for chart rendering — same shape the
// frontend already consumes from the old trafficrrd.HistoryResponse. Points
// reuses storage.TrafficSample (rather than the generic storage.MetricSample)
// because the frontend (web/src/pages/Interfaces.tsx) reads rx_bps/tx_bps
// directly off each point; this endpoint has always been average-only, so
// there's no min/max to carry here even though tsdb tracks it internally.
type HistoryResponse struct {
	Interface string                  `json:"interface"`
	Range     string                  `json:"range"`
	Step      int                     `json:"step_seconds"`
	Points    []storage.TrafficSample `json:"points"`
}

// GetHistory returns rx/tx history for one interface — drop-in replacement
// for the old trafficrrd.Service.GetHistory. It queries both the if.rx_bps
// and if.tx_bps series and merges them by timestamp so each returned point
// carries both rx_bps and tx_bps, matching the contract the frontend already
// relies on (it reads both fields off the same point).
func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	step, dur := rangeToStepDuration(rangeID)
	toUnix := time.Now().Unix()
	fromUnix := toUnix - int64(dur.Seconds())

	rxSamples, err := s.db.GetMetricSamples("if.rx_bps", iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	txSamples, err := s.db.GetMetricSamples("if.tx_bps", iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}

	rxByTs := make(map[int64]float64, len(rxSamples))
	for _, sample := range rxSamples {
		rxByTs[sample.TsUnix] = sample.VAvg
	}
	txByTs := make(map[int64]float64, len(txSamples))
	for _, sample := range txSamples {
		txByTs[sample.TsUnix] = sample.VAvg
	}

	// Union of timestamps present in either series — an interface can have a
	// bucket for one direction but not the other (e.g. a brief gap), and the
	// frontend still expects one point per distinct timestamp.
	tsSet := make(map[int64]struct{}, len(rxSamples)+len(txSamples))
	for ts := range rxByTs {
		tsSet[ts] = struct{}{}
	}
	for ts := range txByTs {
		tsSet[ts] = struct{}{}
	}
	timestamps := make([]int64, 0, len(tsSet))
	for ts := range tsSet {
		timestamps = append(timestamps, ts)
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	points := make([]storage.TrafficSample, 0, len(timestamps))
	for _, ts := range timestamps {
		points = append(points, storage.TrafficSample{
			Interface:   iface,
			StepSeconds: step,
			Timestamp:   ts,
			RxBps:       rxByTs[ts], // 0 if this timestamp has no rx bucket
			TxBps:       txByTs[ts], // 0 if this timestamp has no tx bucket
		})
	}

	return &HistoryResponse{Interface: iface, Range: rangeID, Step: step, Points: points}, nil
}

func rangeToStepDuration(rangeID string) (int, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(rangeID)) {
	case "5m":
		return 1, 5 * time.Minute
	case "30m":
		return 1, 30 * time.Minute
	case "12h":
		return 60, 12 * time.Hour
	case "30d":
		return 900, 30 * 24 * time.Hour
	case "1y":
		return 3600, 365 * 24 * time.Hour
	case "5y":
		return 3600, 5 * 365 * 24 * time.Hour
	default:
		return 60, 12 * time.Hour
	}
}
