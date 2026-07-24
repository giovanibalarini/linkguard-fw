package tsdb

import (
	"fmt"
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
	for _, iface := range snap.Interfaces {
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
		rxDelta := float64(iface.RxBytes - prev.rx)
		txDelta := float64(iface.TxBytes - prev.tx)
		if rxDelta < 0 {
			rxDelta = 0
		}
		if txDelta < 0 {
			txDelta = 0
		}
		t.rec.Gauge("if.rx_bps", iface.Name, rxDelta/dt)
		t.rec.Gauge("if.tx_bps", iface.Name, txDelta/dt)
	}
}

// HistoryResponse is returned by the /api/system/traffic-history and
// /api/monitoring/timeline handlers for chart rendering — same shape the
// frontend already consumes from the old trafficrrd.HistoryResponse.
type HistoryResponse struct {
	Interface string                 `json:"interface"`
	Range     string                 `json:"range"`
	Step      int                    `json:"step_seconds"`
	Points    []storage.MetricSample `json:"points"`
}

// GetHistory returns rx/tx history for one interface — drop-in replacement
// for the old trafficrrd.Service.GetHistory.
func (s *Service) GetHistory(iface, rangeID string) (*HistoryResponse, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	step, dur := rangeToStepDuration(rangeID)
	toUnix := time.Now().Unix()
	fromUnix := toUnix - int64(dur.Seconds())

	points, err := s.db.GetMetricSamples("if.rx_bps", iface, step, fromUnix, toUnix)
	if err != nil {
		return nil, err
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
