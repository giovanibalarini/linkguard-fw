package qos

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type execResult struct {
	output string
	err    error
}

type pingExecutor struct {
	*fakeExecutor
	pingResults []execResult
}

func newPingExecutor(results ...execResult) *pingExecutor {
	return &pingExecutor{
		fakeExecutor: newFakeExecutor(),
		pingResults:  append([]execResult(nil), results...),
	}
}

func (e *pingExecutor) ExecuteRead(ctx context.Context, command string, args ...string) (string, error) {
	if command != "ping" {
		return e.fakeExecutor.ExecuteRead(ctx, command, args...)
	}
	e.calls = append(e.calls, execCall{Read: true, Command: command, Args: append([]string(nil), args...)})
	if len(e.pingResults) == 0 {
		return "", errors.New("unexpected ping")
	}
	result := e.pingResults[0]
	e.pingResults = e.pingResults[1:]
	return result.output, result.err
}

func TestParsePingSummaryLinux(t *testing.T) {
	output := `PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=8.12 ms

--- 1.1.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4005ms
rtt min/avg/max/mdev = 8.123/9.456/12.789/1.111 ms
`

	got, err := ParsePingSummary(output)
	if err != nil {
		t.Fatalf("ParsePingSummary() error = %v; want nil", err)
	}
	want := Measurement{MinMs: 8.123, AvgMs: 9.456, MaxMs: 12.789, LossPct: 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePingSummary() = %#v; want %#v", got, want)
	}
}

func TestParsePingSummaryBusyBox(t *testing.T) {
	output := `PING 1.1.1.1 (1.1.1.1): 56 data bytes

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 3 packets received, 25% packet loss
round-trip min/avg/max = 10.000/20.500/40.750 ms
`

	got, err := ParsePingSummary(output)
	if err != nil {
		t.Fatalf("ParsePingSummary() error = %v; want nil", err)
	}
	want := Measurement{MinMs: 10, AvgMs: 20.5, MaxMs: 40.75, LossPct: 25}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePingSummary() = %#v; want %#v", got, want)
	}
}

func TestParsePingSummaryBSD(t *testing.T) {
	output := `PING 192.0.2.1 (192.0.2.1): 56 data bytes
64 bytes from 192.0.2.1: icmp_seq=0 ttl=59 time=3.214 ms

--- 192.0.2.1 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 2.100/3.200/5.400/0.900 ms
`

	got, err := ParsePingSummary(output)
	if err != nil {
		t.Fatalf("ParsePingSummary() error = %v; want nil", err)
	}
	want := Measurement{MinMs: 2.1, AvgMs: 3.2, MaxMs: 5.4, LossPct: 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePingSummary() = %#v; want %#v", got, want)
	}
}

func TestParsePingSummaryAcceptsTotalLossWithoutRTTLine(t *testing.T) {
	output := `--- 1.1.1.1 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3068ms
`

	got, err := ParsePingSummary(output)
	if err != nil {
		t.Fatalf("ParsePingSummary() error = %v; want nil", err)
	}
	want := Measurement{LossPct: 100}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePingSummary() = %#v; want %#v", got, want)
	}
}

func TestParsePingSummaryRejectsMissingSummary(t *testing.T) {
	if _, err := ParsePingSummary("ping: unknown host example.invalid"); err == nil {
		t.Fatal("ParsePingSummary() error = nil; want malformed summary error")
	}
}

func TestMeasureBindsPingToValidatedInterfaceWithSeparateArguments(t *testing.T) {
	exec := newPingExecutor(execResult{output: `4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/mdev = 1.000/2.000/3.000/0.200 ms
`})
	service := NewService(exec)

	got, err := service.Measure(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Measure() error = %v; want nil", err)
	}
	want := Measurement{MinMs: 1, AvgMs: 2, MaxMs: 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Measure() = %#v; want %#v", got, want)
	}
	wantCalls := []execCall{{
		Read:    true,
		Command: "ping",
		Args:    []string{"-n", "-I", "wan0", "-c", "5", "-W", "2", "1.1.1.1"},
	}}
	if !reflect.DeepEqual(exec.calls, wantCalls) {
		t.Fatalf("Measure() calls = %#v; want %#v", exec.calls, wantCalls)
	}
}

func TestMeasurePropagatesPingExecutionFailureWithoutValidSummary(t *testing.T) {
	exec := newPingExecutor(execResult{output: "ping: sendmsg: Operation not permitted\n", err: errors.New("exit status 2")})
	service := NewService(exec)

	if _, err := service.Measure(context.Background(), "wan0"); err == nil {
		t.Fatal("Measure() error = nil; want ping execution error")
	}
	if len(exec.calls) != 1 {
		t.Fatalf("Measure() calls = %#v; want one ping", exec.calls)
	}
}

func TestMeasureAcceptsParsedTotalLossDespitePingExitError(t *testing.T) {
	exec := newPingExecutor(execResult{
		output: `4 packets transmitted, 0 received, 100% packet loss, time 3068ms
`,
		err: errors.New("exit status 1"),
	})
	service := NewService(exec)

	got, err := service.Measure(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Measure() error = %v; want parsed loss measurement", err)
	}
	if got.LossPct != 100 {
		t.Fatalf("Measure() loss = %v; want 100", got.LossPct)
	}
}

func TestMeasureRejectsUnsafeInterfaceBeforePing(t *testing.T) {
	exec := newPingExecutor()
	service := NewService(exec)

	if _, err := service.Measure(context.Background(), "wan0;reboot"); err == nil {
		t.Fatal("Measure() error = nil; want validation error")
	}
	if len(exec.calls) != 0 {
		t.Fatalf("Measure() calls after validation error = %#v; want none", exec.calls)
	}
}

func TestMeasureBeforeAfterAppliesQoSBetweenSamples(t *testing.T) {
	exec := newPingExecutor(
		execResult{output: `5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 10.000/20.000/30.000/1.000 ms
`},
		execResult{output: `5 packets transmitted, 4 received, 20% packet loss
rtt min/avg/max/mdev = 5.000/8.000/12.000/1.000 ms
`},
	)
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	got, err := service.MeasureBeforeAfter(context.Background(), cfg)
	if err != nil {
		t.Fatalf("MeasureBeforeAfter() error = %v; want nil", err)
	}
	want := Comparison{
		Before: Measurement{MinMs: 10, AvgMs: 20, MaxMs: 30},
		After:  Measurement{MinMs: 5, AvgMs: 8, MaxMs: 12, LossPct: 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MeasureBeforeAfter() = %#v; want %#v", got, want)
	}
	if len(exec.calls) < 3 || exec.calls[0].Command != "ping" || exec.calls[len(exec.calls)-1].Command != "ping" {
		t.Fatalf("MeasureBeforeAfter() call order = %#v; want ping, apply commands, ping", exec.calls)
	}
	if countCommand(exec.calls[1:len(exec.calls)-1], "tc", "qdisc", "replace") != 2 {
		t.Fatalf("MeasureBeforeAfter() did not apply QoS between samples: %#v", exec.calls)
	}
}

func TestMeasureBeforeAfterStopsWhenApplyFails(t *testing.T) {
	exec := newPingExecutor(
		execResult{output: `5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 10.000/20.000/30.000/1.000 ms
`},
		execResult{output: `5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 5.000/8.000/12.000/1.000 ms
`},
	)
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" {
			return errors.New("apply failed")
		}
		return nil
	}
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.MeasureBeforeAfter(context.Background(), cfg); err == nil {
		t.Fatal("MeasureBeforeAfter() error = nil; want apply failure")
	}
	if got := countCommand(exec.calls, "ping"); got != 1 {
		t.Fatalf("ping count after apply failure = %d; want 1", got)
	}
}

func TestMeasureCurrentBeforeAfterLoadsConfigurationBeforeFirstPing(t *testing.T) {
	exec := newPingExecutor(
		execResult{output: `5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 10.000/20.000/30.000/1.000 ms
`},
		execResult{output: `5 packets transmitted, 5 received, 0% packet loss
rtt min/avg/max/mdev = 5.000/8.000/12.000/1.000 ms
`},
	)
	service := NewService(exec)
	loaded := false
	cfg := validConfig()
	cfg.Interface = "wan0"

	got, err := service.MeasureCurrentBeforeAfter(context.Background(), "wan0", func() (Config, error) {
		loaded = true
		return cfg, nil
	})
	if err != nil {
		t.Fatalf("MeasureCurrentBeforeAfter() error = %v; want nil", err)
	}
	if !loaded {
		t.Fatal("MeasureCurrentBeforeAfter() did not call loader")
	}
	if got.Before.MinMs != 10 || got.After.MinMs != 5 {
		t.Fatalf("MeasureCurrentBeforeAfter() = %#v; want before/after samples", got)
	}
}

func TestMeasureCurrentBeforeAfterRejectsMovedOrDeletedConfigurationBeforePing(t *testing.T) {
	tests := []struct {
		name string
		load func() (Config, error)
	}{
		{
			name: "moved",
			load: func() (Config, error) {
				cfg := validConfig()
				cfg.Interface = "wan1"
				return cfg, nil
			},
		},
		{
			name: "deleted",
			load: func() (Config, error) {
				return Config{}, errors.New("link deleted")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exec := newPingExecutor()
			service := NewService(exec)
			if _, err := service.MeasureCurrentBeforeAfter(context.Background(), "wan0", test.load); err == nil {
				t.Fatal("MeasureCurrentBeforeAfter() error = nil; want loader/lifecycle error")
			}
			if got := countCommand(exec.calls, "ping"); got != 0 {
				t.Fatalf("MeasureCurrentBeforeAfter() ping count = %d; want 0", got)
			}
		})
	}
}
