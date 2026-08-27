package qos

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type icmpFilteredExecutor struct {
	*benchmarkExecutor
}

func (e *icmpFilteredExecutor) ExecuteRead(ctx context.Context, command string, args ...string) (string, error) {
	if command == "ping" {
		// Real iputils behaviour: prints the statistics block (no rtt line)
		// and exits 1. RealExecutor.run returns stdout ALONGSIDE the error.
		return "--- iperf.operator.lan ping statistics ---\n10 packets transmitted, 0 received, 100% packet loss, time 4501ms\n",
			errors.New(`command "ping ..." failed: exit status 1`)
	}
	return e.benchmarkExecutor.ExecuteRead(ctx, command, args...)
}

func TestProbeIcmpFilteredStillLooksComplete(t *testing.T) {
	base := newBenchmarkExecutor()
	exec := &icmpFilteredExecutor{benchmarkExecutor: base}
	cfg := benchmarkConfig()
	configureManagedKernelObjects(base.fakeExecutor, cfg.Interface)

	got, err := NewService(exec).BenchmarkCurrent(context.Background(), cfg.Interface,
		BenchmarkRequest{Server: "iperf.operator.lan"}, func() (Config, error) { return cfg, nil })
	if err != nil {
		t.Fatalf("BenchmarkCurrent: %v", err)
	}
	payload, _ := json.MarshalIndent(got, "", "  ")
	t.Logf("comparison.Valid=%v Restored=%v Limitations=%v", got.Valid, got.Restored, got.Limitations)
	t.Logf("baseline.upload.latency=%+v valid=%v lims=%v", got.Baseline.Upload.Latency, got.Baseline.Upload.Valid, got.Baseline.Upload.Limitations)
	t.Logf("JSON:\n%s", payload)
}
