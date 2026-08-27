package qos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	benchmarkDurationSec = 5
	benchmarkLoadCapMbps = 500
	defaultIperfPort     = 5201

	LimitationServerMissing               = "server_missing"
	LimitationIperfUnavailable            = "iperf_unavailable"
	LimitationIperfFailed                 = "iperf_failed"
	LimitationPingFailed                  = "ping_failed"
	LimitationCPUUnavailable              = "cpu_unavailable"
	LimitationInterfaceMetricsUnavailable = "interface_metrics_unavailable"
	LimitationInsufficientLoad            = "insufficient_load"
	LimitationLoadCapped                  = "load_capped"
	LimitationQoSDisabled                 = "qos_disabled"
	LimitationDryRun                      = "dry_run"
)

var (
	pingLossPattern        = regexp.MustCompile(`(?m)([0-9]+(?:\.[0-9]+)?)\s*%\s*packet loss`)
	pingRTTPattern         = regexp.MustCompile(`(?m)(?:rtt|round-trip)[^=\n]*=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)(?:/[0-9]+(?:\.[0-9]+)?)?\s*ms`)
	benchmarkServerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
)

// BenchmarkRequest identifies an iperf3 server explicitly supplied by the
// operator. An empty server is accepted so the API can return an honest,
// structured limitation without contacting a public default endpoint.
type BenchmarkRequest struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
}

func (r BenchmarkRequest) validate() error {
	if r.Server != "" && net.ParseIP(r.Server) == nil && !benchmarkServerPattern.MatchString(r.Server) {
		return errors.New("invalid iperf3 server")
	}
	if r.Port < 0 || r.Port > 65535 {
		return errors.New("invalid iperf3 port")
	}
	return nil
}

func (r BenchmarkRequest) effectivePort() int {
	if r.Port == 0 {
		return defaultIperfPort
	}
	return r.Port
}

// Measurement is one parsed ping summary captured while load is active.
type Measurement struct {
	MinMs   float64 `json:"min_ms"`
	AvgMs   float64 `json:"avg_ms"`
	MaxMs   float64 `json:"max_ms"`
	LossPct float64 `json:"loss_pct"`
}

// LoadMeasurement contains latency/loss, iperf throughput, interface-counter
// throughput and system CPU for one bounded direction. Missing values remain
// null in JSON and make Valid false.
type LoadMeasurement struct {
	OfferedMbps    int          `json:"offered_mbps"`
	Latency        *Measurement `json:"latency"`
	ThroughputMbps *float64     `json:"throughput_mbps"`
	InterfaceMbps  *float64     `json:"interface_mbps"`
	CPUPercent     *float64     `json:"cpu_percent"`
	Valid          bool         `json:"valid"`
	Limitations    []string     `json:"limitations"`
}

// PhaseMeasurement records identical upload and download loads with either
// the managed CAKE chain absent (Baseline) or configured (Configured).
type PhaseMeasurement struct {
	Upload      LoadMeasurement `json:"upload"`
	Download    LoadMeasurement `json:"download"`
	Valid       bool            `json:"valid"`
	Limitations []string        `json:"limitations"`
}

type BenchmarkConditions struct {
	Server          string `json:"server"`
	Port            int    `json:"port"`
	DurationSec     int    `json:"duration_sec"`
	LoadCapMbps     int    `json:"load_cap_mbps"`
	UploadOffered   int    `json:"upload_offered_mbps"`
	DownloadOffered int    `json:"download_offered_mbps"`
}

// Comparison deliberately contains no improvement verdict. Only complete,
// sufficiently loaded measurements are Valid; the operator can inspect the
// raw baseline/configured values and every explicit limitation.
type Comparison struct {
	Baseline    PhaseMeasurement    `json:"baseline"`
	Configured  PhaseMeasurement    `json:"configured"`
	Conditions  BenchmarkConditions `json:"conditions"`
	Valid       bool                `json:"valid"`
	Restored    bool                `json:"restored"`
	Limitations []string            `json:"limitations"`
}

// ParsePingSummary extracts packet loss and min/avg/max RTT from common
// iputils, BusyBox, and BSD ping summaries.
func ParsePingSummary(output string) (Measurement, error) {
	lossMatch := pingLossPattern.FindStringSubmatch(output)
	if len(lossMatch) != 2 {
		return Measurement{}, errors.New("ping output has no packet-loss summary")
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
		return Measurement{}, errors.New("ping output has no min/avg/max summary")
	}
	values := make([]float64, 3)
	for i := range values {
		values[i], err = strconv.ParseFloat(rttMatch[i+1], 64)
		if err != nil {
			return Measurement{}, fmt.Errorf("parse ping latency: %w", err)
		}
	}
	return Measurement{MinMs: values[0], AvgMs: values[1], MaxMs: values[2], LossPct: loss}, nil
}

// BenchmarkCurrent loads the persisted configuration and runs both phases
// under one per-interface lock. A durable benchmark lease is saved before the
// baseline removes CAKE, so startup can restore Recovery after process death.
func (s *Service) BenchmarkCurrent(
	ctx context.Context,
	iface string,
	request BenchmarkRequest,
	load func() (Config, error),
) (comparison Comparison, retErr error) {
	if err := request.validate(); err != nil {
		return Comparison{}, err
	}
	if err := (Config{Interface: iface}).Validate(); err != nil {
		return Comparison{}, err
	}
	comparison.Conditions = BenchmarkConditions{
		Server: request.Server, Port: request.effectivePort(), DurationSec: benchmarkDurationSec, LoadCapMbps: benchmarkLoadCapMbps,
	}
	unlock, err := s.lockInterface(ctx, iface)
	if err != nil {
		return Comparison{}, err
	}
	defer unlock()
	cfg, err := load()
	if err != nil {
		return Comparison{}, err
	}
	if cfg.Interface != iface {
		return Comparison{}, fmt.Errorf("%w: %q became %q", ErrStaleInterface, iface, cfg.Interface)
	}
	if err := cfg.Validate(); err != nil {
		return Comparison{}, err
	}
	// Preflight limitations below do not mutate the kernel; the persisted
	// configuration is therefore already intact.
	comparison.Restored = true
	if request.Server == "" {
		comparison.Limitations = []string{LimitationServerMissing}
		return comparison, nil
	}
	if s.exec.IsDryRun() {
		comparison.Limitations = []string{LimitationDryRun}
		return comparison, nil
	}
	if _, err := s.exec.ExecuteRead(ctx, "iperf3", "--version"); err != nil {
		comparison.Limitations = []string{LimitationIperfUnavailable}
		return comparison, nil
	}
	if !cfg.Enabled {
		comparison.Limitations = []string{LimitationQoSDisabled}
		return comparison, nil
	}
	uploadOffer, uploadCapped := boundedOffer(cfg.UploadMbps)
	downloadOffer, downloadCapped := boundedOffer(cfg.DownloadMbps)
	comparison.Conditions.UploadOffered = uploadOffer
	comparison.Conditions.DownloadOffered = downloadOffer
	if uploadCapped || downloadCapped {
		comparison.Limitations = addLimitation(comparison.Limitations, LimitationLoadCapped)
	}

	ownership, err := s.inspectOwnership(ctx, iface)
	if err != nil {
		return comparison, err
	}
	if err := validateApplyOwnership(cfg, ownership); err != nil {
		return comparison, err
	}
	operationID, err := s.beginOperation(cfg, cfg, OperationBenchmark, ownership)
	if err != nil {
		return comparison, err
	}
	comparison.Restored = false
	needsRestore := true
	defer func() {
		if !needsRestore {
			return
		}
		repairCtx, cancel := detachedRepairContext(ctx)
		defer cancel()
		if _, restoreErr := s.apply(repairCtx, cfg); restoreErr != nil {
			if retErr == nil {
				retErr = fmt.Errorf("%w: restore QoS after benchmark: %v", ErrCompensationFailed, restoreErr)
			} else {
				retErr = fmt.Errorf("%w: benchmark: %v; restore QoS: %v", ErrCompensationFailed, retErr, restoreErr)
			}
			return
		}
		comparison.Restored = true
		if clearErr := s.clearOperation(operationID, iface); clearErr != nil {
			retErr = fmt.Errorf("%w: clear benchmark recovery lease: %v", ErrCompensationFailed, clearErr)
		}
	}()

	if _, err := s.apply(ctx, Config{Interface: iface}); err != nil {
		return comparison, fmt.Errorf("remove managed CAKE for baseline: %w", err)
	}
	baselineOwnership, err := s.inspectOwnership(ctx, iface)
	if err != nil {
		return comparison, err
	}
	if baselineOwnership.chainOwned || baselineOwnership.egressSignature.kind == "cake" || baselineOwnership.ingressSignature.kind == "cake" {
		return comparison, errors.New("baseline still contains managed CAKE")
	}
	comparison.Baseline = s.measurePhase(ctx, cfg, request, uploadOffer, downloadOffer)
	comparison.Limitations = mergeLimitations(comparison.Limitations, comparison.Baseline.Limitations)

	if _, err := s.apply(ctx, cfg); err != nil {
		return comparison, fmt.Errorf("apply configured CAKE phase: %w", err)
	}
	configuredState, err := s.observe(ctx, iface)
	if err != nil {
		return comparison, err
	}
	if !configuredState.Enabled {
		return comparison, errors.New("configured phase does not have the complete managed CAKE chain")
	}
	comparison.Configured = s.measurePhase(ctx, cfg, request, uploadOffer, downloadOffer)
	comparison.Limitations = mergeLimitations(comparison.Limitations, comparison.Configured.Limitations)
	comparison.Valid = len(comparison.Limitations) == 0 && comparison.Baseline.Valid && comparison.Configured.Valid
	return comparison, nil
}

func boundedOffer(configuredMbps int) (int, bool) {
	offered := (configuredMbps*110 + 99) / 100
	if offered > benchmarkLoadCapMbps {
		return benchmarkLoadCapMbps, true
	}
	return offered, false
}

func (s *Service) measurePhase(ctx context.Context, cfg Config, request BenchmarkRequest, uploadOffer, downloadOffer int) PhaseMeasurement {
	upload := s.measureDirection(ctx, cfg, request, false, uploadOffer, cfg.UploadMbps)
	download := s.measureDirection(ctx, cfg, request, true, downloadOffer, cfg.DownloadMbps)
	limitations := mergeLimitations(upload.Limitations, download.Limitations)
	return PhaseMeasurement{Upload: upload, Download: download, Valid: upload.Valid && download.Valid, Limitations: limitations}
}

func (s *Service) measureDirection(
	ctx context.Context,
	cfg Config,
	request BenchmarkRequest,
	reverse bool,
	offeredMbps, configuredMbps int,
) LoadMeasurement {
	result := LoadMeasurement{OfferedMbps: offeredMbps}
	cpuBefore, cpuBeforeErr := s.readCPU(ctx)
	counterName := "tx_bytes"
	if reverse {
		counterName = "rx_bytes"
	}
	bytesBefore, bytesBeforeErr := s.readInterfaceCounter(ctx, cfg.Interface, counterName)

	var pingOutput, iperfOutput string
	var pingErr, iperfErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pingOutput, pingErr = s.exec.ExecuteRead(ctx, "ping", "-n", "-I", cfg.Interface,
			"-c", "10", "-i", "0.5", "-W", "1", "-w", "7", request.Server)
	}()
	go func() {
		defer wg.Done()
		args := []string{
			"-c", request.Server, "-p", strconv.Itoa(request.effectivePort()), "-J",
			"-t", strconv.Itoa(benchmarkDurationSec), "-P", "1", "-b", strconv.Itoa(offeredMbps) + "M",
			"--connect-timeout", "3000", "--bind-dev", cfg.Interface,
		}
		if reverse {
			args = append(args, "-R")
		}
		iperfOutput, iperfErr = s.exec.Execute(ctx, "iperf3", args...)
	}()
	wg.Wait()

	cpuAfter, cpuAfterErr := s.readCPU(ctx)
	bytesAfter, bytesAfterErr := s.readInterfaceCounter(ctx, cfg.Interface, counterName)
	if latency, err := ParsePingSummary(pingOutput); err == nil {
		result.Latency = &latency
	} else {
		_ = pingErr
		result.Limitations = addLimitation(result.Limitations, LimitationPingFailed)
	}
	if iperfErr != nil {
		result.Limitations = addLimitation(result.Limitations, LimitationIperfFailed)
	} else if throughput, err := parseIperfThroughput(iperfOutput, reverse); err != nil {
		result.Limitations = addLimitation(result.Limitations, LimitationIperfFailed)
	} else {
		result.ThroughputMbps = &throughput
		if throughput < float64(configuredMbps)*0.8 {
			result.Limitations = addLimitation(result.Limitations, LimitationInsufficientLoad)
		}
	}
	if cpuBeforeErr != nil || cpuAfterErr != nil {
		result.Limitations = addLimitation(result.Limitations, LimitationCPUUnavailable)
	} else if cpu, ok := cpuUtilization(cpuBefore, cpuAfter); ok {
		result.CPUPercent = &cpu
	} else {
		result.Limitations = addLimitation(result.Limitations, LimitationCPUUnavailable)
	}
	if bytesBeforeErr != nil || bytesAfterErr != nil || bytesAfter < bytesBefore {
		result.Limitations = addLimitation(result.Limitations, LimitationInterfaceMetricsUnavailable)
	} else {
		mbps := float64(bytesAfter-bytesBefore) * 8 / float64(benchmarkDurationSec) / 1_000_000
		result.InterfaceMbps = &mbps
	}
	result.Valid = len(result.Limitations) == 0 && result.Latency != nil && result.ThroughputMbps != nil &&
		result.InterfaceMbps != nil && result.CPUPercent != nil
	return result
}

func parseIperfThroughput(output string, reverse bool) (float64, error) {
	var payload struct {
		End struct {
			SumSent struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_sent"`
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return 0, err
	}
	bps := payload.End.SumSent.BitsPerSecond
	if reverse {
		bps = payload.End.SumReceived.BitsPerSecond
	}
	if bps <= 0 {
		return 0, errors.New("iperf3 output has no positive throughput")
	}
	return bps / 1_000_000, nil
}

type cpuSample struct {
	idle  uint64
	total uint64
}

func (s *Service) readCPU(ctx context.Context) (cpuSample, error) {
	output, err := s.exec.ExecuteRead(ctx, "cat", "/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	fields := strings.Fields(strings.SplitN(output, "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, errors.New("invalid /proc/stat")
	}
	var sample cpuSample
	for i, field := range fields[1:] {
		if i >= 8 {
			break
		}
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSample{}, err
		}
		sample.total += value
		if i == 3 || i == 4 {
			sample.idle += value
		}
	}
	return sample, nil
}

func cpuUtilization(before, after cpuSample) (float64, bool) {
	if after.total <= before.total || after.idle < before.idle {
		return 0, false
	}
	total := after.total - before.total
	idle := after.idle - before.idle
	if idle > total {
		return 0, false
	}
	return float64(total-idle) * 100 / float64(total), true
}

func (s *Service) readInterfaceCounter(ctx context.Context, iface, counter string) (uint64, error) {
	output, err := s.exec.ExecuteRead(ctx, "cat", "/sys/class/net/"+iface+"/statistics/"+counter)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(output), 10, 64)
}

func addLimitation(values []string, limitation string) []string {
	for _, value := range values {
		if value == limitation {
			return values
		}
	}
	return append(values, limitation)
}

func mergeLimitations(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		for _, limitation := range group {
			out = addLimitation(out, limitation)
		}
	}
	return out
}
