package qos

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type execCall struct {
	Read       bool
	Command    string
	Args       []string
	ContextErr error
}

type fakeExecutor struct {
	calls     []execCall
	ifbs      map[string]bool
	dryRun    bool
	readErr   error
	readOut   map[string]string
	failWhen  func(execCall) error
	onExecute func(execCall)
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{ifbs: make(map[string]bool)}
}

func configureManagedKernelObjects(exec *fakeExecutor, iface string) {
	ifb := IFBName(iface)
	exec.ifbs[ifb] = true
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", iface):                                             "qdisc cake " + managedEgressHandle + " root refcnt 2 bandwidth 50Mbit besteffort dual-srchost\nqdisc clsact ffff: parent ffff:fff1\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                               "qdisc cake " + managedIngressHandle + " root refcnt 2 bandwidth 500Mbit besteffort dual-dsthost\n",
		executorCallKey("tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
	}
}

func (e *fakeExecutor) Execute(ctx context.Context, command string, args ...string) (string, error) {
	call := execCall{Command: command, Args: append([]string(nil), args...), ContextErr: ctx.Err()}
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
	if !e.dryRun {
		e.applyKernelState(call)
	}
	if e.onExecute != nil {
		e.onExecute(call)
	}
	return "", nil
}

func (e *fakeExecutor) applyKernelState(call execCall) {
	if call.Command != "tc" || len(call.Args) < 2 {
		return
	}
	if e.readOut == nil {
		e.readOut = make(map[string]string)
	}
	if hasPrefix(call.Args, "qdisc", "replace", "dev") && len(call.Args) >= 6 && call.Args[4] == "root" {
		iface := call.Args[3]
		handle := "0:"
		kindIndex := 5
		if len(call.Args) >= 8 && call.Args[5] == "handle" {
			handle = call.Args[6]
			kindIndex = 7
		}
		if kindIndex < len(call.Args) {
			e.setRootOutput(iface, "qdisc "+call.Args[kindIndex]+" "+handle+" root "+strings.Join(call.Args[kindIndex+1:], " ")+"\n")
		}
		return
	}
	if hasPrefix(call.Args, "qdisc", "del", "dev") && len(call.Args) >= 5 && call.Args[4] == "root" {
		e.setRootOutput(call.Args[3], "")
		return
	}
	if hasPrefix(call.Args, "qdisc", "add", "dev") && len(call.Args) >= 5 && call.Args[4] == "clsact" {
		key := executorCallKey("tc", "qdisc", "show", "dev", call.Args[3])
		e.readOut[key] += "qdisc clsact ffff: parent ffff:fff1\n"
		return
	}
	if hasPrefix(call.Args, "qdisc", "del", "dev") && len(call.Args) >= 5 && call.Args[4] == "clsact" {
		key := executorCallKey("tc", "qdisc", "show", "dev", call.Args[3])
		lines := strings.Split(e.readOut[key], "\n")
		kept := lines[:0]
		for _, line := range lines {
			if !strings.HasPrefix(line, "qdisc clsact ") {
				kept = append(kept, line)
			}
		}
		e.readOut[key] = strings.Join(kept, "\n")
		return
	}
	if hasPrefix(call.Args, "filter", "replace", "dev") {
		iface := call.Args[3]
		ifb := call.Args[len(call.Args)-1]
		key := executorCallKey("tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
		e.readOut[key] = "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n"
		return
	}
	if hasPrefix(call.Args, "filter", "del", "dev") {
		iface := call.Args[3]
		key := executorCallKey("tc", "filter", "show", "dev", iface, "ingress", "pref", redirectFilterPriority)
		e.readOut[key] = ""
	}
}

func (e *fakeExecutor) setRootOutput(iface, root string) {
	if e.readOut == nil {
		e.readOut = make(map[string]string)
	}
	key := executorCallKey("tc", "qdisc", "show", "dev", iface)
	var nonRoot []string
	for _, line := range strings.Split(e.readOut[key], "\n") {
		if line != "" && !strings.Contains(line, " root") {
			nonRoot = append(nonRoot, line)
		}
	}
	if root != "" {
		nonRoot = append([]string{strings.TrimSuffix(root, "\n")}, nonRoot...)
	}
	if len(nonRoot) == 0 {
		e.readOut[key] = ""
		return
	}
	e.readOut[key] = strings.Join(nonRoot, "\n") + "\n"
}

func (e *fakeExecutor) ExecuteRead(ctx context.Context, command string, args ...string) (string, error) {
	call := execCall{Read: true, Command: command, Args: append([]string(nil), args...), ContextErr: ctx.Err()}
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
	if output, ok := e.readOut[executorCallKey(command, args...)]; ok {
		return output, nil
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
		{Read: true, Command: "tc", Args: []string{"qdisc", "show", "dev", "wan0"}},
		{Read: true, Command: "tc", Args: []string{"filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority}},
		{Read: true, Command: "ip", Args: []string{"link", "show", "dev", ifb}},
		{Command: "tc", Args: []string{"qdisc", "replace", "dev", "wan0", "root", "handle", managedEgressHandle, "cake", "bandwidth", "50mbit", "besteffort", "dual-srchost"}},
		{Command: "ip", Args: []string{"link", "add", ifb, "type", "ifb"}},
		{Command: "ip", Args: []string{"link", "set", "dev", ifb, "up"}},
		{Command: "tc", Args: []string{"qdisc", "replace", "dev", ifb, "root", "handle", managedIngressHandle, "cake", "bandwidth", "500mbit", "besteffort", "dual-dsthost"}},
		{Command: "tc", Args: []string{"qdisc", "add", "dev", "wan0", "clsact"}},
		{Command: "tc", Args: []string{"filter", "replace", "dev", "wan0", "ingress", "pref", "49152", "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb}},
	}
	if !reflect.DeepEqual(exec.calls, wantCalls) {
		t.Fatalf("Apply() calls =\n%#v\nwant\n%#v", exec.calls, wantCalls)
	}
}

func TestApplyAllowsNormalKernelRootQdiscsWithZeroHandle(t *testing.T) {
	fixtures := map[string]string{
		"multiqueue device": "qdisc mq 0: root\nqdisc fq_codel 8001: parent :1 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms\n",
		"noqueue device":    "qdisc noqueue 0: root refcnt 2\n",
		"default fq_codel":  "qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64\n",
	}

	for name, output := range fixtures {
		t.Run(name, func(t *testing.T) {
			exec := newFakeExecutor()
			exec.readOut = map[string]string{
				executorCallKey("tc", "qdisc", "show", "dev", "wan0"): output,
			}
			cfg := validConfig()
			cfg.Interface = "wan0"

			if _, err := NewService(exec).Apply(context.Background(), cfg); err != nil {
				t.Fatalf("Apply() error = %v; want kernel default root to be replaceable", err)
			}
		})
	}
}

func TestApplyFailureCompensatesSuccessfulKernelMutations(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc mq 0: root\n",
	}
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && len(call.Args) > 1 && call.Args[0] == "filter" && call.Args[1] == "replace" {
			return errors.New("redirect failed")
		}
		return nil
	}
	cfg := validConfig()
	cfg.Interface = "wan0"

	_, err := NewService(exec).Apply(context.Background(), cfg)
	if err == nil {
		t.Fatal("Apply() error = nil; want redirect failure")
	}
	if countCommand(exec.calls, "ip", "link", "del") != 1 {
		t.Fatalf("Apply() did not compensate the created IFB: %#v", exec.calls)
	}
	if countCommand(exec.calls, "tc", "qdisc", "del", "dev", IFBName("wan0"), "root") != 1 {
		t.Fatalf("Apply() did not compensate the ingress qdisc: %#v", exec.calls)
	}
	if !hasQdiscRootRestore(exec.calls, "wan0", "mq") {
		t.Fatalf("Apply() did not restore the kernel default root qdisc: %#v", exec.calls)
	}
}

func TestApplyCompensatesEveryCompletedStageBeforeACommandFailure(t *testing.T) {
	tests := []struct {
		name            string
		fail            func(execCall) bool
		wantIFBDelete   bool
		wantRootRestore bool
	}{
		{
			name: "IFB creation",
			fail: func(call execCall) bool {
				return call.Command == "ip" && hasPrefix(call.Args, "link", "add")
			},
			wantRootRestore: true,
		},
		{
			name: "ingress CAKE",
			fail: func(call execCall) bool {
				return call.Command == "tc" && hasPrefix(call.Args, "qdisc", "replace", "dev", IFBName("wan0"))
			},
			wantIFBDelete:   true,
			wantRootRestore: true,
		},
		{
			name: "clsact",
			fail: func(call execCall) bool {
				return call.Command == "tc" && hasPrefix(call.Args, "qdisc", "add", "dev", "wan0", "clsact")
			},
			wantIFBDelete:   true,
			wantRootRestore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := newFakeExecutor()
			exec.readOut = map[string]string{
				executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc noqueue 0: root refcnt 2\n",
			}
			exec.failWhen = func(call execCall) error {
				if !call.Read && tt.fail(call) {
					return errors.New("injected stage failure")
				}
				return nil
			}
			cfg := validConfig()
			cfg.Interface = "wan0"

			if _, err := NewService(exec).Apply(context.Background(), cfg); err == nil {
				t.Fatal("Apply() error = nil; want injected stage failure")
			}
			if got := countCommand(exec.calls, "ip", "link", "del", "dev", IFBName("wan0")); (got == 1) != tt.wantIFBDelete {
				t.Fatalf("IFB cleanup count = %d, want cleanup=%v; calls=%#v", got, tt.wantIFBDelete, exec.calls)
			}
			got := hasQdiscRootRestore(exec.calls, "wan0", "noqueue")
			if got != tt.wantRootRestore {
				t.Fatalf("egress root restore = %v, want restore=%v; calls=%#v", got, tt.wantRootRestore, exec.calls)
			}
		})
	}
}

func TestApplyFailureReturnsCompensationFailureWhenRepairFails(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc mq 0: root\n",
	}
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && len(call.Args) > 1 && call.Args[0] == "filter" && call.Args[1] == "replace" {
			return errors.New("redirect failed")
		}
		if !call.Read && call.Command == "tc" && hasPrefix(call.Args, "qdisc", "replace", "dev", "wan0", "root", "mq") {
			return errors.New("root restore failed")
		}
		return nil
	}
	cfg := validConfig()
	cfg.Interface = "wan0"

	_, err := NewService(exec).Apply(context.Background(), cfg)
	if !errors.Is(err, ErrCompensationFailed) {
		t.Fatalf("Apply() error = %v; want ErrCompensationFailed", err)
	}
}

func TestDisableFailureCompensatesSuccessfulKernelMutations(t *testing.T) {
	exec := newFakeExecutor()
	configureManagedKernelObjects(exec, "wan0")
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && len(call.Args) >= 4 && call.Args[0] == "qdisc" && call.Args[1] == "del" && call.Args[3] == IFBName("wan0") {
			return errors.New("ingress delete failed")
		}
		return nil
	}

	_, err := NewService(exec).Disable(context.Background(), "wan0")
	if err == nil {
		t.Fatal("Disable() error = nil; want ingress delete failure")
	}
	if !hasManagedFilterRestore(exec.calls, "wan0") || !hasQdiscRootRestore(exec.calls, "wan0", "cake") {
		t.Fatalf("Disable() did not compensate prior deletions: %#v", exec.calls)
	}
}

func TestDisableFailureReturnsCompensationFailureWhenRepairFails(t *testing.T) {
	exec := newFakeExecutor()
	configureManagedKernelObjects(exec, "wan0")
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && len(call.Args) >= 4 && call.Args[0] == "qdisc" && call.Args[1] == "del" && call.Args[3] == IFBName("wan0") {
			return errors.New("ingress delete failed")
		}
		if !call.Read && call.Command == "tc" && len(call.Args) > 1 && call.Args[0] == "filter" && call.Args[1] == "replace" {
			return errors.New("filter restore failed")
		}
		return nil
	}

	_, err := NewService(exec).Disable(context.Background(), "wan0")
	if !errors.Is(err, ErrCompensationFailed) {
		t.Fatalf("Disable() error = %v; want ErrCompensationFailed", err)
	}
}

func TestDisableFailureAtIFBDeleteRestoresAllRemovedManagedObjects(t *testing.T) {
	exec := newFakeExecutor()
	configureManagedKernelObjects(exec, "wan0")
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "ip" && hasPrefix(call.Args, "link", "del", "dev", IFBName("wan0")) {
			return errors.New("IFB delete failed")
		}
		return nil
	}

	_, err := NewService(exec).Disable(context.Background(), "wan0")
	if err == nil {
		t.Fatal("Disable() error = nil; want IFB delete failure")
	}
	if !hasManagedFilterRestore(exec.calls, "wan0") ||
		!hasQdiscRootRestore(exec.calls, "wan0", "cake") ||
		!hasQdiscRootRestore(exec.calls, IFBName("wan0"), "cake") {
		t.Fatalf("Disable() did not restore every managed object after the final delete failed: %#v", exec.calls)
	}
}

func TestApplyCompensationUsesDetachedBoundedContext(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc noqueue 0: root refcnt 2\n",
	}
	exec.failWhen = func(call execCall) error {
		if !call.Read && call.Command == "tc" && hasPrefix(call.Args, "filter", "replace") {
			return errors.New("redirect failed")
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := NewService(exec).Apply(ctx, cfg); err == nil {
		t.Fatal("Apply() error = nil; want redirect failure")
	}
	failureIndex := -1
	for i, call := range exec.calls {
		if !call.Read && call.Command == "tc" && hasPrefix(call.Args, "filter", "replace") {
			failureIndex = i
			break
		}
	}
	if failureIndex == -1 || failureIndex+1 >= len(exec.calls) {
		t.Fatalf("no compensation commands followed the failed mutation: %#v", exec.calls)
	}
	for _, call := range exec.calls[failureIndex+1:] {
		if call.ContextErr != nil {
			t.Fatalf("compensation inherited canceled request context: call=%#v", call)
		}
	}
}

func hasQdiscRootRestore(calls []execCall, iface, kind string) bool {
	for _, call := range calls {
		if call.Read || call.Command != "tc" || len(call.Args) < 5 {
			continue
		}
		if call.Args[0] == "qdisc" && call.Args[1] == "replace" && call.Args[3] == iface && call.Args[4] == "root" && containsToken(call.Args, kind) {
			return true
		}
	}
	return false
}

func hasManagedFilterRestore(calls []execCall, iface string) bool {
	for _, call := range calls {
		if call.Read || call.Command != "tc" || len(call.Args) < 2 {
			continue
		}
		if call.Args[0] == "filter" && call.Args[1] == "replace" && containsToken(call.Args, iface) && containsToken(call.Args, "mirred") {
			return true
		}
	}
	return false
}

func hasPrefix(got []string, want ...string) bool {
	return len(got) >= len(want) && reflect.DeepEqual(got[:len(want)], want)
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
		if call.Read || call.Command != "tc" || len(call.Args) < 2 || call.Args[0] != "qdisc" || !containsToken(call.Args, "cake") {
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

func TestApplyDryRunPerformsReadOnlyOwnershipChecks(t *testing.T) {
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
	configureManagedKernelObjects(exec, "wan0")
	service := NewService(exec)

	state, err := service.Disable(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Disable() error = %v; want nil", err)
	}
	wantState := State{Interface: "wan0", IFB: ifb}
	if !reflect.DeepEqual(state, wantState) {
		t.Fatalf("Disable() state = %#v; want %#v", state, wantState)
	}

	wantWrites := []execCall{
		{Command: "tc", Args: []string{"filter", "del", "dev", "wan0", "ingress", "pref", "49152"}},
		{Command: "tc", Args: []string{"qdisc", "del", "dev", "wan0", "root"}},
		{Command: "tc", Args: []string{"qdisc", "del", "dev", ifb, "root"}},
		{Command: "ip", Args: []string{"link", "del", "dev", ifb}},
	}
	if got := writeCalls(exec.calls); !reflect.DeepEqual(got, wantWrites) {
		t.Fatalf("Disable() writes =\n%#v\nwant\n%#v", got, wantWrites)
	}
	for _, call := range exec.calls {
		if containsToken(call.Args, "clsact") {
			t.Fatalf("Disable() removed clsact: %#v", call)
		}
	}
}

func TestApplyDisabledConfigUsesDisablePath(t *testing.T) {
	exec := newFakeExecutor()
	configureManagedKernelObjects(exec, "wan0")
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

func TestDisableDryRunSkipsUnverifiedCleanup(t *testing.T) {
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
	if countCommand(exec.calls, "tc", "qdisc", "del", "dev", IFBName("wan0")) != 0 {
		t.Fatalf("dry-run Disable() removed an unverified IFB qdisc: %#v", exec.calls)
	}
	if countCommand(exec.calls, "ip", "link", "del") != 0 {
		t.Fatalf("dry-run Disable() removed an unverified IFB: %#v", exec.calls)
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
	configureManagedKernelObjects(exec, "wan0")
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
	writes := writeCalls(exec.calls)
	if len(writes) != 1 || writes[0].Command != "tc" || !hasPrefix(writes[0].Args, "filter", "del") {
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

func TestDisableSkipsForeignRootQdiscsAndIFBCleanup(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.ifbs[ifb] = true
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"):                                             "qdisc fq_codel 1: root refcnt 2 limit 1000\nqdisc clsact ffff: parent ffff:fff1\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                                "qdisc pfifo_fast 1: root refcnt 2 bands 3\n",
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
	}
	service := NewService(exec)

	if _, err := service.Disable(context.Background(), "wan0"); err != nil {
		t.Fatalf("Disable() error = %v; want nil while preserving foreign qdiscs", err)
	}
	for _, call := range exec.calls {
		if call.Command == "ip" && len(call.Args) > 1 && call.Args[1] == "link" && containsToken(call.Args, "del") {
			t.Fatalf("Disable() deleted IFB with foreign root qdiscs: %#v", exec.calls)
		}
		if call.Command == "tc" && len(call.Args) > 1 && call.Args[0] == "qdisc" && call.Args[1] == "del" {
			t.Fatalf("Disable() deleted foreign qdisc: %#v", exec.calls)
		}
	}
}

func TestDisableSkipsForeignMirredFilter(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.ifbs[ifb] = true
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"):                                             "qdisc cake " + managedEgressHandle + " root refcnt 2 bandwidth 50Mbit besteffort dual-srchost\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                                "qdisc cake " + managedIngressHandle + " root refcnt 2 bandwidth 200Mbit besteffort dual-dsthost\n",
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Mirror to device " + ifb + ")\n",
	}
	service := NewService(exec)

	if _, err := service.Disable(context.Background(), "wan0"); err != nil {
		t.Fatalf("Disable() error = %v; want nil while preserving foreign filter", err)
	}
	if countCommand(exec.calls, "tc", "filter", "del") != 0 {
		t.Fatalf("Disable() deleted foreign mirred filter: %#v", exec.calls)
	}
}

func TestApplyRefusesForeignRootQdiscWithoutWriting(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc fq_codel 1: root limit 1000\n",
	}
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.Apply(context.Background(), cfg); !errors.Is(err, ErrOwnershipNotEstablished) {
		t.Fatalf("Apply() error = %v; want ErrOwnershipNotEstablished", err)
	}
	for _, call := range exec.calls {
		if !call.Read {
			t.Fatalf("Apply() wrote while foreign root qdisc was present: %#v", exec.calls)
		}
	}
}

func TestApplyRefusesForeignMirredFilterWithoutWriting(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall action order 1: mirred (Egress Mirror to device " + ifb + ")\n",
	}
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	if _, err := service.Apply(context.Background(), cfg); !errors.Is(err, ErrOwnershipNotEstablished) {
		t.Fatalf("Apply() error = %v; want ErrOwnershipNotEstablished", err)
	}
	for _, call := range exec.calls {
		if !call.Read {
			t.Fatalf("Apply() wrote while foreign mirred filter was present: %#v", exec.calls)
		}
	}
}

func TestApplyNetemRefusesExplicitForeignRootWithoutWriting(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc htb 5: root refcnt 2 r2q 10 default 20 direct_packets_stat 0\n",
	}
	service := NewService(exec)

	err := service.WithInterfaceLock(context.Background(), "wan0", func(ops InterfaceOperations) error {
		return ops.ApplyNetem(context.Background(), 500, 20)
	})
	if !errors.Is(err, ErrOwnershipNotEstablished) {
		t.Fatalf("ApplyNetem() error = %v; want ErrOwnershipNotEstablished", err)
	}
	for _, call := range exec.calls {
		if !call.Read {
			t.Fatalf("ApplyNetem() wrote while a foreign root qdisc was present: %#v", exec.calls)
		}
	}
}

func TestRestoreAfterNetemDeletesOnlyOwnedFaultAndReappliesPersistedQoS(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.ifbs[ifb] = true
	rootKey := executorCallKey("tc", "qdisc", "show", "dev", "wan0")
	exec.readOut = map[string]string{
		rootKey: "qdisc netem " + managedNetemHandle + " root refcnt 2 limit 1000 delay 500ms loss 20%\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                                "qdisc cake " + managedIngressHandle + " root refcnt 2 bandwidth 300Mbit diffserv4 dual-dsthost\n",
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
	}
	exec.onExecute = func(call execCall) {
		if call.Command == "tc" && hasPrefix(call.Args, "qdisc", "del", "dev", "wan0", "root") {
			exec.readOut[rootKey] = "qdisc mq 0: root\nqdisc fq_codel 8001: parent :1 limit 10240p\n"
		}
	}
	cfg := Config{Interface: "wan0", Enabled: true, UploadMbps: 40, DownloadMbps: 300, Interactive: true}
	service := NewService(exec)

	err := service.WithInterfaceLock(context.Background(), "wan0", func(ops InterfaceOperations) error {
		_, err := ops.RestoreAfterNetem(context.Background(), cfg)
		return err
	})
	if err != nil {
		t.Fatalf("RestoreAfterNetem() error = %v; want nil", err)
	}
	if countCommand(exec.calls, "tc", "qdisc", "del", "dev", "wan0", "root") != 1 {
		t.Fatalf("RestoreAfterNetem() did not remove exactly one owned netem root: %#v", exec.calls)
	}
	if !hasQdiscRootRestore(exec.calls, "wan0", "cake") || !containsWriteToken(exec.calls, "40mbit") {
		t.Fatalf("RestoreAfterNetem() did not reapply fresh persisted CAKE: %#v", exec.calls)
	}
}

func TestRestoreAfterNetemPreservesRootThatBecameForeign(t *testing.T) {
	exec := newFakeExecutor()
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"): "qdisc htb 5: root refcnt 2 r2q 10 default 20 direct_packets_stat 0\n",
	}
	service := NewService(exec)

	err := service.WithInterfaceLock(context.Background(), "wan0", func(ops InterfaceOperations) error {
		_, err := ops.RestoreAfterNetem(context.Background(), Config{Interface: "wan0"})
		return err
	})
	if !errors.Is(err, ErrOwnershipNotEstablished) {
		t.Fatalf("RestoreAfterNetem() error = %v; want ErrOwnershipNotEstablished", err)
	}
	for _, call := range exec.calls {
		if !call.Read {
			t.Fatalf("RestoreAfterNetem() mutated a foreign root qdisc: %#v", exec.calls)
		}
	}
}

func containsWriteToken(calls []execCall, want string) bool {
	for _, call := range calls {
		if !call.Read && containsToken(call.Args, want) {
			return true
		}
	}
	return false
}

func TestObserveReturnsManagedKernelStateWithReadOnlySeparatedArguments(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.ifbs[ifb] = true
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"):                              "qdisc cake " + managedEgressHandle + " root refcnt 2 bandwidth 50Mbit diffserv4 dual-srchost\nqdisc clsact ffff: parent ffff:fff1\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                 "qdisc cake " + managedIngressHandle + " root refcnt 2 bandwidth 200Mbit diffserv4 dual-dsthost\n",
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", "49152"): "filter protocol all pref 49152\n\tmatchall action mirred egress redirect to device " + ifb + "\n",
	}
	service := NewService(exec)

	got, err := service.Observe(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Observe() error = %v; want nil", err)
	}
	want := State{Enabled: true, Interface: "wan0", IFB: ifb, Mode: "diffserv4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Observe() state = %#v; want %#v", got, want)
	}
	for _, call := range exec.calls {
		if !call.Read {
			t.Fatalf("Observe() issued a write command: %#v", call)
		}
		if call.Command == "sh" {
			t.Fatalf("Observe() invoked a shell: %#v", call)
		}
	}
	wantCalls := []execCall{
		{Read: true, Command: "ip", Args: []string{"link", "show", "dev", ifb}},
		{Read: true, Command: "tc", Args: []string{"qdisc", "show", "dev", "wan0"}},
		{Read: true, Command: "tc", Args: []string{"qdisc", "show", "dev", ifb}},
		{Read: true, Command: "tc", Args: []string{"filter", "show", "dev", "wan0", "ingress", "pref", "49152"}},
	}
	if !reflect.DeepEqual(exec.calls, wantCalls) {
		t.Fatalf("Observe() calls = %#v; want %#v", exec.calls, wantCalls)
	}
}

func TestObserveDoesNotClaimForeignCakeRootIsManaged(t *testing.T) {
	ifb := IFBName("wan0")
	exec := newFakeExecutor()
	exec.ifbs[ifb] = true
	exec.readOut = map[string]string{
		executorCallKey("tc", "qdisc", "show", "dev", "wan0"):                                             "qdisc cake 8001: root refcnt 2 bandwidth 50Mbit diffserv4 dual-srchost\n",
		executorCallKey("tc", "qdisc", "show", "dev", ifb):                                                "qdisc cake " + managedIngressHandle + " root refcnt 2 bandwidth 200Mbit diffserv4 dual-dsthost\n",
		executorCallKey("tc", "filter", "show", "dev", "wan0", "ingress", "pref", redirectFilterPriority): "filter protocol all pref " + redirectFilterPriority + " matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
	}

	state, err := NewService(exec).Observe(context.Background(), "wan0")
	if err != nil {
		t.Fatalf("Observe() error = %v; want nil", err)
	}
	if state.Enabled {
		t.Fatalf("Observe() claimed foreign egress cake was managed: %#v", state)
	}
}

func TestHasManagedRedirectRecognizesNormalMultilineTopLevelFilterBlock(t *testing.T) {
	ifb := IFBName("wan0")
	output := "filter parent ffff: protocol ip pref 100 flower\n" +
		"\taction order 1: pass\n" +
		"filter parent ffff: protocol all pref 49152\n" +
		"\tmatchall\n" +
		"\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n" +
		"\tindex 1 ref 1 bind 1\n"

	if !hasManagedRedirect(output, ifb) {
		t.Fatalf("hasManagedRedirect() = false for normal multiline tc filter block:\n%s", output)
	}
}

func TestApplyCurrentAndPersistRestoresKernelConfigAfterPersistenceError(t *testing.T) {
	exec := newFakeExecutor()
	service := NewService(exec)
	apply := validConfig()
	apply.Interface = "wan0"
	apply.UploadMbps = 75
	rollback := apply
	rollback.UploadMbps = 50

	_, err := service.ApplyCurrentAndPersist(context.Background(), "wan0", func() (ApplyPlan, error) {
		return ApplyPlan{
			Config:   apply,
			Rollback: rollback,
			Persist:  func() error { return errors.New("database unavailable") },
		}, nil
	})
	if err == nil {
		t.Fatal("ApplyCurrentAndPersist() error = nil; want persistence failure")
	}
	newApply, oldRestore := -1, -1
	for i, call := range exec.calls {
		if call.Command != "tc" || len(call.Args) < 9 || call.Args[0] != "qdisc" || call.Args[1] != "replace" {
			continue
		}
		if containsToken(call.Args, "75mbit") && newApply == -1 {
			newApply = i
		}
		if containsToken(call.Args, "50mbit") && oldRestore == -1 {
			oldRestore = i
		}
	}
	if newApply == -1 || oldRestore <= newApply {
		t.Fatalf("persistence failure did not restore old kernel config: %#v", exec.calls)
	}
}

func TestApplyCurrentAndPersistReturnsDistinctCompensationFailure(t *testing.T) {
	exec := newFakeExecutor()
	exec.failWhen = func(call execCall) error {
		if !call.Read && containsToken(call.Args, "50mbit") {
			return errors.New("rollback unavailable")
		}
		return nil
	}
	service := NewService(exec)
	apply := validConfig()
	apply.Interface = "wan0"
	apply.UploadMbps = 75
	rollback := apply
	rollback.UploadMbps = 50

	_, err := service.ApplyCurrentAndPersist(context.Background(), "wan0", func() (ApplyPlan, error) {
		return ApplyPlan{
			Config:   apply,
			Rollback: rollback,
			Persist:  func() error { return sql.ErrNoRows },
		}, nil
	})
	if !errors.Is(err, ErrCompensationFailed) {
		t.Fatalf("ApplyCurrentAndPersist() error = %v; want ErrCompensationFailed", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("compensation failure retained sql.ErrNoRows mapping: %v", err)
	}
}

func TestPerInterfaceQoSOperationsSerialize(t *testing.T) {
	exec := newBlockingQosExecutor()
	service := NewService(exec)
	cfg := validConfig()
	cfg.Interface = "wan0"

	firstDone := make(chan error, 1)
	go func() {
		_, err := service.MeasureBeforeAfter(context.Background(), cfg)
		firstDone <- err
	}()
	<-exec.firstCall

	secondDone := make(chan error, 1)
	go func() {
		_, err := service.Apply(context.Background(), cfg)
		secondDone <- err
	}()
	select {
	case <-exec.secondCall:
		t.Fatal("Apply entered the executor while MeasureBeforeAfter was still using the interface")
	case <-time.After(50 * time.Millisecond):
	}

	close(exec.release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("MeasureBeforeAfter() error = %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("MeasureBeforeAfter() did not finish after releasing the executor")
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("Apply() error = %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Apply() did not finish after MeasureBeforeAfter() released the interface")
	}
	if exec.overlap {
		t.Fatal("QoS operations used the same interface concurrently")
	}
}

type blockingQosExecutor struct {
	mu         sync.Mutex
	active     int
	calls      int
	overlap    bool
	firstCall  chan struct{}
	secondCall chan struct{}
	release    chan struct{}
}

func newBlockingQosExecutor() *blockingQosExecutor {
	return &blockingQosExecutor{
		firstCall:  make(chan struct{}),
		secondCall: make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (e *blockingQosExecutor) Execute(context.Context, string, ...string) (string, error) {
	e.enter()
	return "", nil
}
func (e *blockingQosExecutor) ExecuteRead(_ context.Context, command string, args ...string) (string, error) {
	if command == "ping" {
		e.enter()
		return "5 packets transmitted, 5 received, 0% packet loss\nrtt min/avg/max/mdev = 10/20/30/1 ms\n", nil
	}
	return "", nil
}

func (e *blockingQosExecutor) enter() {
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.active++
	if e.active > 1 {
		e.overlap = true
	}
	e.mu.Unlock()

	switch call {
	case 1:
		close(e.firstCall)
		<-e.release
	case 2:
		close(e.secondCall)
	}

	e.mu.Lock()
	e.active--
	e.mu.Unlock()
}

func (*blockingQosExecutor) IsDryRun() bool { return true }

func (*blockingQosExecutor) WriteFile(string, []byte, os.FileMode) error { return nil }

func executorCallKey(command string, args ...string) string {
	return strings.Join(append([]string{command}, args...), "\x00")
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

func writeCalls(calls []execCall) []execCall {
	var writes []execCall
	for _, call := range calls {
		if !call.Read {
			writes = append(writes, call)
		}
	}
	return writes
}
