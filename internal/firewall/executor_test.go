package firewall_test

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

func TestDryRunExecutor(t *testing.T) {
	exec := firewall.NewDryRunExecutor()

	if !exec.IsDryRun() {
		t.Error("expected IsDryRun() == true")
	}

	ctx := context.Background()
	out, err := exec.Execute(ctx, "ip", "route", "add", "default", "via", "10.0.0.1")
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty dry-run output")
	}
	if len(exec.Commands) != 1 {
		t.Errorf("expected 1 recorded command, got %d", len(exec.Commands))
	}
	expected := "ip route add default via 10.0.0.1"
	if exec.Commands[0] != expected {
		t.Errorf("expected command %q, got %q", expected, exec.Commands[0])
	}
}

func TestDryRunExecutorMultipleCommands(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	ctx := context.Background()

	cmds := [][]string{
		{"ip", "route", "add", "0.0.0.0/0", "via", "10.0.0.1"},
		{"ip", "rule", "add", "from", "192.168.1.0/24", "table", "100"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"},
	}
	for _, cmd := range cmds {
		if _, err := exec.Execute(ctx, cmd[0], cmd[1:]...); err != nil {
			t.Fatalf("Execute %v: %v", cmd, err)
		}
	}
	if len(exec.Commands) != len(cmds) {
		t.Errorf("expected %d commands, got %d", len(cmds), len(exec.Commands))
	}
}

func TestDryRunExecutorRead(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	ctx := context.Background()

	// ExecuteRead should actually run the command (read-only)
	// Using "echo" which is always available
	out, err := exec.ExecuteRead(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("ExecuteRead returned error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from ExecuteRead")
	}
	// ExecuteRead should NOT record commands (it's a real read)
	if len(exec.Commands) != 0 {
		t.Errorf("expected 0 recorded commands after ExecuteRead, got %d", len(exec.Commands))
	}
}

func TestRealExecutorNotDryRun(t *testing.T) {
	exec := firewall.NewRealExecutor(0)

	if exec.IsDryRun() {
		t.Error("expected IsDryRun() == false for RealExecutor")
	}
}

func TestRealExecutorRunsCommand(t *testing.T) {
	exec := firewall.NewRealExecutor(0)
	ctx := context.Background()

	out, err := exec.Execute(ctx, "echo", "test-output")
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestRealExecutorRead(t *testing.T) {
	exec := firewall.NewRealExecutor(0)
	ctx := context.Background()

	out, err := exec.ExecuteRead(ctx, "echo", "read-output")
	if err != nil {
		t.Fatalf("ExecuteRead returned error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from ExecuteRead")
	}
}

func TestRealExecutorCommandNotFound(t *testing.T) {
	exec := firewall.NewRealExecutor(0)
	ctx := context.Background()

	_, err := exec.Execute(ctx, "definitely-not-a-real-command-12345")
	if err == nil {
		t.Error("expected error for nonexistent command")
	}
}

// TestRealExecutorReadPreservesStdoutOnNonZeroExit guards against a real
// regression: smartctl (and other diagnostic tools) use their exit code as a
// bitmask where several bits mean "ran fine, but the disk/subject is
// unhealthy" rather than "execution failed". Discarding stdout whenever err
// != nil silently throws away the exact JSON payload callers need in that
// case. sh -c is used here only as a test fixture to simulate a real process
// that writes to stdout and then exits non-zero — never use sh -c in
// production code.
func TestRealExecutorReadPreservesStdoutOnNonZeroExit(t *testing.T) {
	exec := firewall.NewRealExecutor(0)
	ctx := context.Background()

	out, err := exec.ExecuteRead(ctx, "sh", "-c", "echo ola; exit 3")
	if err == nil {
		t.Fatal("expected error for non-zero exit code")
	}
	if out != "ola\n" {
		t.Errorf("expected stdout %q to be preserved alongside the error, got %q", "ola\n", out)
	}
}

func TestRealExecutorExecutePreservesStdoutOnNonZeroExit(t *testing.T) {
	exec := firewall.NewRealExecutor(0)
	ctx := context.Background()

	out, err := exec.Execute(ctx, "sh", "-c", "echo ola; exit 3")
	if err == nil {
		t.Fatal("expected error for non-zero exit code")
	}
	if out != "ola\n" {
		t.Errorf("expected stdout %q to be preserved alongside the error, got %q", "ola\n", out)
	}
}

// TestDryRunExecutorReadPreservesStdoutOnNonZeroExit is the DryRunExecutor
// counterpart: ExecuteRead always runs for real (it's read-only), so it must
// preserve stdout on a non-zero exit too.
func TestDryRunExecutorReadPreservesStdoutOnNonZeroExit(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	ctx := context.Background()

	out, err := exec.ExecuteRead(ctx, "sh", "-c", "echo ola; exit 3")
	if err == nil {
		t.Fatal("expected error for non-zero exit code")
	}
	if out != "ola\n" {
		t.Errorf("expected stdout %q to be preserved alongside the error, got %q", "ola\n", out)
	}
}
