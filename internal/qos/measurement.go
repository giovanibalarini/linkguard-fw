package qos

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
)

const pingTarget = "1.1.1.1"

var (
	pingLossPattern = regexp.MustCompile(`(?m)([0-9]+(?:\.[0-9]+)?)\s*%\s*packet loss`)
	pingRTTPattern  = regexp.MustCompile(`(?m)(?:rtt|round-trip)[^=\n]*=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)(?:/[0-9]+(?:\.[0-9]+)?)?\s*ms`)
)

// Measurement is one parsed ping summary.
type Measurement struct {
	MinMs   float64 `json:"min_ms"`
	AvgMs   float64 `json:"avg_ms"`
	MaxMs   float64 `json:"max_ms"`
	LossPct float64 `json:"loss_pct"`
}

// Comparison contains measurements immediately before and after Apply.
type Comparison struct {
	Before Measurement `json:"before"`
	After  Measurement `json:"after"`
}

// ParsePingSummary extracts packet loss and min/avg/max RTT from common
// iputils, BusyBox, and BSD ping summaries.
func ParsePingSummary(output string) (Measurement, error) {
	lossMatch := pingLossPattern.FindStringSubmatch(output)
	if len(lossMatch) != 2 {
		return Measurement{}, fmt.Errorf("ping output has no packet-loss summary")
	}
	loss, err := strconv.ParseFloat(lossMatch[1], 64)
	if err != nil {
		return Measurement{}, fmt.Errorf("parse ping packet loss: %w", err)
	}

	rttMatch := pingRTTPattern.FindStringSubmatch(output)
	if len(rttMatch) != 4 {
		if loss == 100 {
			return Measurement{LossPct: loss}, nil
		}
		return Measurement{}, fmt.Errorf("ping output has no min/avg/max summary")
	}

	values := make([]float64, 3)
	for i := range values {
		values[i], err = strconv.ParseFloat(rttMatch[i+1], 64)
		if err != nil {
			return Measurement{}, fmt.Errorf("parse ping latency: %w", err)
		}
	}
	return Measurement{
		MinMs:   values[0],
		AvgMs:   values[1],
		MaxMs:   values[2],
		LossPct: loss,
	}, nil
}

// Measure runs a short numeric ping bound to one validated interface.
func (s *Service) Measure(ctx context.Context, iface string) (Measurement, error) {
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return Measurement{}, err
	}
	unlock := s.lockInterface(iface)
	defer unlock()
	return s.measure(ctx, iface)
}

func (s *Service) measure(ctx context.Context, iface string) (Measurement, error) {
	output, execErr := s.exec.ExecuteRead(ctx, "ping",
		"-n", "-I", iface, "-c", "5", "-W", "2", pingTarget)
	measurement, parseErr := ParsePingSummary(output)
	if parseErr == nil {
		return measurement, nil
	}
	if execErr != nil {
		return Measurement{}, fmt.Errorf("ping: %w", execErr)
	}
	return Measurement{}, parseErr
}

// MeasureBeforeAfter measures, applies the requested configuration, and then
// measures again. An apply failure aborts before the second ping.
func (s *Service) MeasureBeforeAfter(ctx context.Context, cfg Config) (Comparison, error) {
	if err := cfg.Validate(); err != nil {
		return Comparison{}, err
	}
	unlock := s.lockInterface(cfg.Interface)
	defer unlock()

	before, err := s.measure(ctx, cfg.Interface)
	if err != nil {
		return Comparison{}, fmt.Errorf("measure before QoS: %w", err)
	}
	if _, err := s.apply(ctx, cfg); err != nil {
		return Comparison{}, fmt.Errorf("apply QoS between measurements: %w", err)
	}
	after, err := s.measure(ctx, cfg.Interface)
	if err != nil {
		return Comparison{}, fmt.Errorf("measure after QoS: %w", err)
	}
	return Comparison{Before: before, After: after}, nil
}
