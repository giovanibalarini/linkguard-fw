package qos

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestParsePingSummaryLinuxAndTotalLoss(t *testing.T) {
	got, err := ParsePingSummary(`5 packets transmitted, 4 received, 20% packet loss
rtt min/avg/max/mdev = 8.123/9.456/12.789/1.111 ms`)
	if err != nil {
		t.Fatalf("ParsePingSummary: %v", err)
	}
	want := Measurement{MinMs: 8.123, AvgMs: 9.456, MaxMs: 12.789, LossPct: 20}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePingSummary = %#v; want %#v", got, want)
	}
	total, err := ParsePingSummary("4 packets transmitted, 0 received, 100% packet loss")
	if err != nil || total.LossPct != 100 {
		t.Fatalf("total-loss summary = %#v, %v", total, err)
	}
}

func TestBenchmarkWithoutOperatorServerIsInvalidAndDoesNotMutateKernel(t *testing.T) {
	exec := newBenchmarkExecutor()
	service := NewService(exec)
	cfg := benchmarkConfig()

	got, err := service.BenchmarkCurrent(context.Background(), cfg.Interface, BenchmarkRequest{}, func() (Config, error) {
		return cfg, nil
	})
	if err != nil {
		t.Fatalf("BenchmarkCurrent error = %v; want structured limitation", err)
	}
	if got.Valid || !containsLimitation(got.Limitations, LimitationServerMissing) {
		t.Fatalf("BenchmarkCurrent = %#v; want invalid server_missing result", got)
	}
	if countBenchmarkCommand(exec.snapshotCalls(), "tc") != 0 || countBenchmarkCommand(exec.snapshotCalls(), "iperf3") != 0 {
		t.Fatalf("missing server touched kernel or ran iperf3: %#v", exec.snapshotCalls())
	}
}

func TestBenchmarkWithoutIperf3IsInvalidAndDoesNotMutateKernel(t *testing.T) {
	exec := newBenchmarkExecutor()
	exec.iperfAvailable = false
	service := NewService(exec)
	cfg := benchmarkConfig()

	got, err := service.BenchmarkCurrent(context.Background(), cfg.Interface, BenchmarkRequest{Server: "iperf.operator.lan"}, func() (Config, error) {
		return cfg, nil
	})
	if err != nil {
		t.Fatalf("BenchmarkCurrent error = %v; want structured limitation", err)
	}
	if got.Valid || !containsLimitation(got.Limitations, LimitationIperfUnavailable) {
		t.Fatalf("BenchmarkCurrent = %#v; want invalid iperf_unavailable result", got)
	}
	if countBenchmarkWrites(exec.snapshotCalls()) != 0 {
		t.Fatalf("missing iperf3 mutated kernel: %#v", exec.snapshotCalls())
	}
}

func TestBenchmarkUsesRealBaselineBoundedIdenticalLoadAndRestoresQoS(t *testing.T) {
	exec := newBenchmarkExecutor()
	cfg := benchmarkConfig()
	configureManagedKernelObjects(exec.fakeExecutor, cfg.Interface)
	service := NewService(exec)

	got, err := service.BenchmarkCurrent(context.Background(), cfg.Interface, BenchmarkRequest{
		Server: "iperf.operator.lan", Port: 5202,
	}, func() (Config, error) { return cfg, nil })
	if err != nil {
		t.Fatalf("BenchmarkCurrent error = %v", err)
	}
	if !got.Valid || !got.Restored || !got.Baseline.Valid || !got.Configured.Valid {
		t.Fatalf("BenchmarkCurrent = %#v; want valid restored comparison", got)
	}
	if got.Baseline.Upload.Latency == nil || got.Baseline.Upload.ThroughputMbps == nil ||
		got.Baseline.Upload.InterfaceMbps == nil || got.Baseline.Upload.CPUPercent == nil {
		t.Fatalf("baseline upload omitted required observability: %#v", got.Baseline.Upload)
	}
	calls := exec.snapshotCalls()
	iperfCalls := benchmarkCalls(calls, "iperf3", false)
	if len(iperfCalls) != 4 {
		t.Fatalf("iperf3 load calls = %#v; want upload/download in both phases", iperfCalls)
	}
	if !reflect.DeepEqual(iperfCalls[0].Args, iperfCalls[2].Args) || !reflect.DeepEqual(iperfCalls[1].Args, iperfCalls[3].Args) {
		t.Fatalf("baseline/configured load conditions differ: %#v", iperfCalls)
	}
	for _, call := range iperfCalls {
		joined := strings.Join(call.Args, " ")
		if !strings.Contains(joined, "-c iperf.operator.lan") || !strings.Contains(joined, "-p 5202") || strings.Contains(joined, "1.1.1.1") {
			t.Fatalf("iperf call uses an undeclared endpoint: %#v", call)
		}
	}
	if !containsArgs(iperfCalls[0].Args, "-b", "55M") || !containsArgs(iperfCalls[1].Args, "-b", "220M") {
		t.Fatalf("load is not the bounded 110%% offer: %#v", iperfCalls)
	}
	firstLoad := indexBenchmarkCommand(calls, "iperf3", false, 0)
	if firstLoad < 0 || !hasWriteBefore(calls, firstLoad, "tc", "qdisc", "del", "dev", cfg.Interface, "root") {
		t.Fatalf("baseline started before managed CAKE was removed: %#v", calls)
	}
	state, err := service.Observe(context.Background(), cfg.Interface)
	if err != nil || !state.Enabled {
		t.Fatalf("QoS after benchmark = %+v, %v; want restored managed chain", state, err)
	}
}

func TestBenchmarkLabelsInsufficientLoadAndUnavailableMetricsWithoutClaimingValidity(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*benchmarkExecutor)
		limitation string
	}{
		{name: "insufficient load", configure: func(e *benchmarkExecutor) { e.throughputMbps = 10 }, limitation: LimitationInsufficientLoad},
		{name: "cpu unavailable", configure: func(e *benchmarkExecutor) { e.cpuAvailable = false }, limitation: LimitationCPUUnavailable},
		{name: "interface metrics unavailable", configure: func(e *benchmarkExecutor) { e.counterAvailable = false }, limitation: LimitationInterfaceMetricsUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := newBenchmarkExecutor()
			tt.configure(exec)
			cfg := benchmarkConfig()
			configureManagedKernelObjects(exec.fakeExecutor, cfg.Interface)
			got, err := NewService(exec).BenchmarkCurrent(context.Background(), cfg.Interface,
				BenchmarkRequest{Server: "iperf.operator.lan"}, func() (Config, error) { return cfg, nil })
			if err != nil {
				t.Fatalf("BenchmarkCurrent: %v", err)
			}
			if got.Valid || !containsLimitation(got.Limitations, tt.limitation) {
				t.Fatalf("limited benchmark = %#v; want %q and valid=false", got, tt.limitation)
			}
		})
	}
}

func TestBenchmarkCapsOfferedLoadAndMarksTheResultLimited(t *testing.T) {
	exec := newBenchmarkExecutor()
	cfg := benchmarkConfig()
	cfg.UploadMbps = 1_000
	cfg.DownloadMbps = 1_000
	configureManagedKernelObjects(exec.fakeExecutor, cfg.Interface)
	got, err := NewService(exec).BenchmarkCurrent(context.Background(), cfg.Interface,
		BenchmarkRequest{Server: "iperf.operator.lan"}, func() (Config, error) { return cfg, nil })
	if err != nil {
		t.Fatalf("BenchmarkCurrent: %v", err)
	}
	if got.Valid || !containsLimitation(got.Limitations, LimitationLoadCapped) {
		t.Fatalf("capped benchmark = %#v; want load_capped invalid result", got)
	}
	for _, call := range benchmarkCalls(exec.snapshotCalls(), "iperf3", false) {
		if !containsArgs(call.Args, "-b", "500M") {
			t.Fatalf("load exceeded safety cap: %#v", call)
		}
	}
}

func TestBenchmarkRestoresQoSAndClearsLeaseWhenLoadFails(t *testing.T) {
	exec := newBenchmarkExecutor()
	exec.iperfRunErr = errors.New("server unreachable")
	cfg := benchmarkConfig()
	configureManagedKernelObjects(exec.fakeExecutor, cfg.Interface)
	store := newRecordingOperationStore(exec.fakeExecutor)
	service := NewService(exec)
	service.SetOperationStore(store)

	got, err := service.BenchmarkCurrent(context.Background(), cfg.Interface,
		BenchmarkRequest{Server: "iperf.operator.lan"}, func() (Config, error) { return cfg, nil })
	if err != nil {
		t.Fatalf("BenchmarkCurrent: %v", err)
	}
	if got.Valid || !got.Restored || !containsLimitation(got.Limitations, LimitationIperfFailed) {
		t.Fatalf("failed-load result = %#v; want limited and restored", got)
	}
	if len(store.leases) != 0 {
		t.Fatalf("benchmark restoration left lease: %#v", store.leases)
	}
	state, observeErr := service.Observe(context.Background(), cfg.Interface)
	if observeErr != nil || !state.Enabled {
		t.Fatalf("QoS after failed load = %+v, %v", state, observeErr)
	}
}

func TestBenchmarkRejectsUnsafeServerBeforeExecutingCommands(t *testing.T) {
	exec := newBenchmarkExecutor()
	_, err := NewService(exec).BenchmarkCurrent(context.Background(), "wan0",
		BenchmarkRequest{Server: "iperf.example; reboot"}, func() (Config, error) { return benchmarkConfig(), nil })
	if err == nil {
		t.Fatal("BenchmarkCurrent accepted unsafe server")
	}
	if len(exec.snapshotCalls()) != 0 {
		t.Fatalf("unsafe server executed commands: %#v", exec.snapshotCalls())
	}
}

func benchmarkConfig() Config {
	return Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
}

type benchmarkExecutor struct {
	*fakeExecutor
	mu               sync.Mutex
	iperfAvailable   bool
	cpuAvailable     bool
	counterAvailable bool
	throughputMbps   float64
	iperfRunErr      error
	cpuReads         int
	counterReads     map[string]int
}

func newBenchmarkExecutor() *benchmarkExecutor {
	return &benchmarkExecutor{
		fakeExecutor: newFakeExecutor(), iperfAvailable: true, cpuAvailable: true,
		counterAvailable: true, counterReads: make(map[string]int),
	}
}

func (e *benchmarkExecutor) Execute(ctx context.Context, command string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if command == "iperf3" {
		e.calls = append(e.calls, execCall{Command: command, Args: append([]string(nil), args...)})
		if e.iperfRunErr != nil {
			return "", e.iperfRunErr
		}
		throughput := e.throughputMbps
		if throughput == 0 {
			bitrate := strings.TrimSuffix(benchmarkTokenAfter(args, "-b"), "M")
			offered, _ := strconv.ParseFloat(bitrate, 64)
			throughput = offered * 0.95
		}
		bps := throughput * 1_000_000
		return fmt.Sprintf(`{"end":{"sum_sent":{"bits_per_second":%.0f},"sum_received":{"bits_per_second":%.0f}}}`, bps, bps), nil
	}
	return e.fakeExecutor.Execute(ctx, command, args...)
}

func (e *benchmarkExecutor) ExecuteRead(ctx context.Context, command string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if command == "iperf3" {
		e.calls = append(e.calls, execCall{Read: true, Command: command, Args: append([]string(nil), args...)})
		if !e.iperfAvailable {
			return "", errors.New("executable file not found")
		}
		return "iperf 3.16", nil
	}
	if command == "ping" {
		e.calls = append(e.calls, execCall{Read: true, Command: command, Args: append([]string(nil), args...)})
		return "8 packets transmitted, 8 received, 0% packet loss\nrtt min/avg/max/mdev = 10.000/20.000/30.000/1.000 ms", nil
	}
	if command == "cat" && len(args) == 1 && args[0] == "/proc/stat" {
		e.calls = append(e.calls, execCall{Read: true, Command: command, Args: append([]string(nil), args...)})
		if !e.cpuAvailable {
			return "", errors.New("proc unavailable")
		}
		e.cpuReads++
		busy := e.cpuReads * 50
		idle := e.cpuReads * 50
		return fmt.Sprintf("cpu %d 0 0 %d 0 0 0 0 0 0\n", busy, idle), nil
	}
	if command == "cat" && len(args) == 1 && strings.HasPrefix(args[0], "/sys/class/net/") {
		e.calls = append(e.calls, execCall{Read: true, Command: command, Args: append([]string(nil), args...)})
		if !e.counterAvailable {
			return "", errors.New("counter unavailable")
		}
		e.counterReads[args[0]]++
		return fmt.Sprintf("%d\n", e.counterReads[args[0]]*100_000_000), nil
	}
	return e.fakeExecutor.ExecuteRead(ctx, command, args...)
}

func (e *benchmarkExecutor) snapshotCalls() []execCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]execCall(nil), e.calls...)
}

func containsLimitation(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func benchmarkCalls(calls []execCall, command string, read bool) []execCall {
	var out []execCall
	for _, call := range calls {
		if call.Command == command && call.Read == read {
			out = append(out, call)
		}
	}
	return out
}

func countBenchmarkCommand(calls []execCall, command string) int {
	count := 0
	for _, call := range calls {
		if call.Command == command {
			count++
		}
	}
	return count
}

func countBenchmarkWrites(calls []execCall) int {
	count := 0
	for _, call := range calls {
		if !call.Read {
			count++
		}
	}
	return count
}

func indexBenchmarkCommand(calls []execCall, command string, read bool, ordinal int) int {
	seen := 0
	for i, call := range calls {
		if call.Command == command && call.Read == read {
			if seen == ordinal {
				return i
			}
			seen++
		}
	}
	return -1
}

func hasWriteBefore(calls []execCall, end int, command string, args ...string) bool {
	for _, call := range calls[:end] {
		if !call.Read && call.Command == command && containsArgs(call.Args, args...) {
			return true
		}
	}
	return false
}

func containsArgs(values []string, sequence ...string) bool {
	for start := 0; start+len(sequence) <= len(values); start++ {
		if reflect.DeepEqual(values[start:start+len(sequence)], sequence) {
			return true
		}
	}
	return false
}

func benchmarkTokenAfter(values []string, token string) string {
	for i, value := range values {
		if value == token && i+1 < len(values) {
			return values[i+1]
		}
	}
	return ""
}
