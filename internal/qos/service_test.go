package qos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

type execCall struct {
	Read    bool
	Command string
	Args    []string
}

type fakeExecutor struct {
	calls    []execCall
	ifbs     map[string]bool
	dryRun   bool
	readErr  error
	failWhen func(execCall) error
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{ifbs: make(map[string]bool)}
}

func (e *fakeExecutor) Execute(_ context.Context, command string, args ...string) (string, error) {
	call := execCall{Command: command, Args: append([]string(nil), args...)}
	e.calls = append(e.calls, call)
	if e.failWhen != nil {
		if err := e.failWhen(call); err != nil {
			return "", err
		}
	}

	if !e.dryRun && command == "ip" && len(args) == 5 && args[0] == "link" && args[1] == "add" && args[3] == "type" && args[4] == "ifb" {
		e.ifbs[args[2]] = true
	}
	if !e.dryRun && command == "ip" && len(args) == 4 && args[0] == "link" && args[1] == "del" && args[2] == "dev" {
		delete(e.ifbs, args[3])
	}
	return "", nil
}

func (e *fakeExecutor) ExecuteRead(_ context.Context, command string, args ...string) (string, error) {
	call := execCall{Read: true, Command: command, Args: append([]string(nil), args...)}
	e.calls = append(e.calls, call)
	if e.failWhen != nil {
		if err := e.failWhen(call); err != nil {
			return "", err
		}
	}
	if e.readErr != nil {
		return "", e.readErr
	}

	if command == "ip" && len(args) == 4 && args[0] == "link" && args[1] == "show" && args[2] == "dev" {
		if e.ifbs[args[3]] {
			return fmt.Sprintf("7: %s: <BROADCAST,UP> mtu 1500", args[3]), nil
		}
		return "", errors.New("device not found")
	}
	return "", nil
}

func (e *fakeExecutor) IsDryRun() bool { return e.dryRun }

func (e *fakeExecutor) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestApplyBuildsEgressIngressAndMatchallCommands(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)
	cfg := Config{
		Interface:    "wan0",
		Enabled:      true,
		UploadMbps:   50,
		DownloadMbps: 500,
	}

	state, err := service.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply() error = %v; want nil", err)
	}

	ifb := IFBName("wan0")
	wantState := State{
		Enabled:   true,
		Interface: "wan0",
		IFB:       ifb,
		Mode:      "besteffort",
	}
	if !reflect.DeepEqual(state, wantState) {
		t.Fatalf("Apply() state = %#v; want %#v", state, wantState)
	}

	wantCalls := []execCall{
		{Command: "tc", Args: []string{"qdisc", "replace", "dev", "wan0", "root", "cake", "bandwidth", "50mbit", "besteffort", "dual-srchost"}},
		{Read: true, Command: "ip", Args: []string{"link", "show", "dev", ifb}},
		{Command: "ip", Args: []string{"link", "add", ifb, "type", "ifb"}},
		{Command: "ip", Args: []string{"link", "set", "dev", ifb, "up"}},
		{Command: "tc", Args: []string{"qdisc", "replace", "dev", ifb, "root", "cake", "bandwidth", "500mbit", "besteffort", "dual-dsthost"}},
		{Command: "tc", Args: []string{"qdisc", "replace", "dev", "wan0", "clsact"}},
		{Command: "tc", Args: []string{"filter", "replace", "dev", "wan0", "ingress", "pref", "49152", "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb}},
	}
	if !reflect.DeepEqual(exec.calls, wantCalls) {
		t.Fatalf("Apply() calls =\n%#v\nwant\n%#v", exec.calls, wantCalls)
	}
}

func TestApplyUsesDiffserv4WhenInteractive(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	state, err := service.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply() error = %v; want nil", err)
	}
	if state.Mode != "diffserv4" {
		t.Fatalf("Apply() state mode = %q; want diffserv4", state.Mode)
	}

	cakeCalls := 0
	for _, call := range exec.calls {
		if call.Command != "tc" || len(call.Args) < 6 || call.Args[0] != "qdisc" || call.Args[5] != "cake" {
			continue
		}
		cakeCalls++
		if !containsToken(call.Args, "diffserv4") || containsToken(call.Args, "besteffort") {
			t.Fatalf("interactive CAKE args = %v; want diffserv4 and no besteffort", call.Args)
		}
	}
	if cakeCalls != 2 {
		t.Fatalf("CAKE call count = %d; want 2", cakeCalls)
	}
}

func TestApplyReusesExistingIFB(t *testing.T) {
	exec := newFakeExecutor()
	exec.ifbs[IFBName("wan0")] = true
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply() error = %v; want nil", err)
	}

	if countCommand(exec.calls, "ip", "link", "add") != 0 {
		t.Fatalf("Apply() created an IFB that already existed: %#v", exec.calls)
	}
	if countCommand(exec.calls, "ip", "link", "set") != 1 {
		t.Fatalf("Apply() did not ensure the existing IFB was up: %#v", exec.calls)
	}
}

func TestRepeatedApplyCreatesIFBOnlyOnce(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("first Apply() error = %v; want nil", err)
	}
	if _, err := service.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("second Apply() error = %v; want nil", err)
	}

	if got := countCommand(exec.calls, "ip", "link", "add"); got != 1 {
		t.Fatalf("IFB add count after repeated Apply() = %d; want 1", got)
	}
	if got := countCommand(exec.calls, "tc", "filter", "replace"); got != 2 {
		t.Fatalf("filter replace count after repeated Apply() = %d; want 2", got)
	}
}

func TestApplyDryRunDoesNotReadKernel(t *testing.T) {
	exec := newFakeExecutor()
	exec.dryRun = true
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	state, err := service.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply() error = %v; want nil", err)
	}
	if !state.DryRun {
		t.Fatalf("Apply() state DryRun = false; want true")
	}
	for _, call := range exec.calls {
		if call.Read {
			t.Fatalf("dry-run performed a kernel read: %#v", call)
		}
		if call.Command == "sh" {
			t.Fatalf("dry-run invoked a shell: %#v", call)
		}
	}
	if got := countCommand(exec.calls, "ip", "link", "add"); got != 1 {
		t.Fatalf("dry-run IFB add count = %d; want 1 recorded command", got)
	}
}

func TestApplyFailureReturnsNoPartialStateAndStops(t *testing.T) {
	exec := newFakeExecutor()
	exec.failWhen = func(call execCall) error {
		if call.Command == "tc" && len(call.Args) > 4 && call.Args[0] == "qdisc" && call.Args[2] == "dev" && call.Args[3] == IFBName("wan0") {
			return errors.New("tc failed")
		}
		return nil
	}
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	state, err := service.Apply(context.Background(), cfg)
	if err == nil {
		t.Fatal("Apply() error = nil; want failure")
	}
	if !reflect.DeepEqual(state, State{}) {
		t.Fatalf("Apply() state = %#v after failure; want zero state", state)
	}
	if countCommand(exec.calls, "tc", "filter", "replace") != 0 {
		t.Fatalf("Apply() continued to the redirect filter after failure: %#v", exec.calls)
	}
}

func TestApplyRejectsInvalidConfigBeforeExecutingCommands(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan;reboot"

	if _, err := service.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply() error = nil; want validation failure")
	}
	if len(exec.calls) != 0 {
		t.Fatalf("Apply() calls after validation failure = %#v; want none", exec.calls)
	}
}

func TestDisableRemovesOnlyManagedFilterQdiscsAndIFB(t *testing.T) {
	exec := newFakeExecutor()
	ifb := IFBName("wan0")
	exec.ifbs[ifb] = true
	service := NewService(exec)

	state, err := service.Disable(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Disable() error = %v; want nil", err)
	}
	wantState := State{Interface: "wan0", IFB: ifb}
	if !reflect.DeepEqual(state, wantState) {
		t.Fatalf("Disable() state = %#v; want %#v", state, wantState)
	}

	wantCalls := []execCall{
		{Command: "tc", Args: []string{"filter", "del", "dev", "wan0", "ingress", "pref", "49152"}},
		{Command: "tc", Args: []string{"qdisc", "del", "dev", "wan0", "root"}},
		{Read: true, Command: "ip", Args: []string{"link", "show", "dev", ifb}},
		{Command: "tc", Args: []string{"qdisc", "del", "dev", ifb, "root"}},
		{Command: "ip", Args: []string{"link", "del", "dev", ifb}},
	}
	if !reflect.DeepEqual(exec.calls, wantCalls) {
		t.Fatalf("Disable() calls =\n%#v\nwant\n%#v", exec.calls, wantCalls)
	}
	for _, call := range exec.calls {
		if containsToken(call.Args, "clsact") {
			t.Fatalf("Disable() removed clsact: %#v", call)
		}
	}
}

func TestApplyDisabledConfigUsesDisablePath(t *testing.T) {
	exec := newFakeExecutor()
	ifb := IFBName("wan0")
	exec.ifbs[ifb] = true
	service := NewService(exec)
	cfg := Config{Interface: "wan0", Enabled: false}

	state, err := service.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Apply(disabled) error = %v; want nil", err)
	}
	if state.Enabled {
		t.Fatalf("Apply(disabled) state Enabled = true; want false")
	}
	if countCommand(exec.calls, "tc", "filter", "del") != 1 {
		t.Fatalf("Apply(disabled) did not remove the managed filter: %#v", exec.calls)
	}
	if countCommand(exec.calls, "ip", "link", "del") != 1 {
		t.Fatalf("Apply(disabled) did not remove the IFB: %#v", exec.calls)
	}
}

func TestDisableSkipsIFBCleanupWhenDeviceIsAlreadyAbsent(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)

	if _, err := service.Disable(context.Background(), "wan0"); err != nil {
		t.Fatalf("Disable() error = %v; want nil", err)
	}
	if countCommand(exec.calls, "tc", "qdisc", "del", "dev", IFBName("wan0")) != 0 {
		t.Fatalf("Disable() tried to remove qdisc from absent IFB: %#v", exec.calls)
	}
	if countCommand(exec.calls, "ip", "link", "del") != 0 {
		t.Fatalf("Disable() tried to remove absent IFB: %#v", exec.calls)
	}
}

func TestDisableDryRunRecordsCleanupWithoutReadingKernel(t *testing.T) {
	exec := newFakeExecutor()
	exec.dryRun = true
	service := NewService(exec)

	state, err := service.Disable(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Disable() error = %v; want nil", err)
	}
	if !state.DryRun {
		t.Fatalf("Disable() state DryRun = false; want true")
	}
	for _, call := range exec.calls {
		if call.Read {
			t.Fatalf("dry-run Disable() performed a kernel read: %#v", call)
		}
	}
	if countCommand(exec.calls, "tc", "qdisc", "del", "dev", IFBName("wan0")) != 1 {
		t.Fatalf("dry-run Disable() did not record IFB qdisc cleanup: %#v", exec.calls)
	}
	if countCommand(exec.calls, "ip", "link", "del") != 1 {
		t.Fatalf("dry-run Disable() did not record IFB deletion: %#v", exec.calls)
	}
}

func TestApplyPropagatesOperationalIFBExistenceError(t *testing.T) {
	exec := newFakeExecutor()
	exec.readErr = errors.New("ip link show: operation not permitted")
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply() error = nil; want IFB existence error")
	}
	if countCommand(exec.calls, "ip", "link", "add") != 0 {
		t.Fatalf("Apply() created IFB after operational existence error: %#v", exec.calls)
	}
}

func TestDisableIsIdempotentForMissingObjects(t *testing.T) {
	exec := newFakeExecutor()
	exec.failWhen = func(call execCall) error {
		if !call.Read && len(call.Args) > 1 && (call.Args[1] == "del") {
			return errors.New("not found")
		}
		return nil
	}
	service := NewService(exec)

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := service.Disable(context.Background(), "wan0"); err != nil {
			t.Fatalf("Disable() attempt %d error = %v; want nil for clean state", attempt, err)
		}
	}
}

func TestDisablePropagatesOperationalDeleteError(t *testing.T) {
	exec := newFakeExecutor()
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && len(call.Args) > 1 && call.Args[0] == "filter" && call.Args[1] == "del" {
			return errors.New("operation not permitted")
		}
		return nil
	}
	service := NewService(exec)

	if _, err := service.Disable(context.Background(), "wan0"); err == nil {
		t.Fatal("Disable() error = nil; want operational delete error")
	}
	if len(exec.calls) != 1 {
		t.Fatalf("Disable() continued after operational delete error: %#v", exec.calls)
	}
}

func TestDisablePropagatesOperationalIFBExistenceError(t *testing.T) {
	exec := newFakeExecutor()
	exec.readErr = errors.New("ip link show: operation not permitted")
	service := NewService(exec)

	if _, err := service.Disable(context.Background(), "wan0"); err == nil {
		t.Fatal("Disable() error = nil; want IFB existence error")
	}
}

func containsToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func countCommand(calls []execCall, command string, prefix ...string) int {
	count := 0
	for _, call := range calls {
		if call.Command != command || len(call.Args) < len(prefix) {
			continue
		}
		if len(prefix) == 0 || reflect.DeepEqual(call.Args[:len(prefix)], prefix) {
			count++
		}
	}
	return count
}
