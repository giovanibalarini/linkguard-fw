package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Executor abstracts the execution of system commands related to firewall/routing.
// This allows for dry-run mode and easier testing.
type Executor interface {
	// Execute runs a command with the given arguments and returns its output.
	// In dry-run mode, write commands are only logged and not applied.
	Execute(ctx context.Context, cmd string, args ...string) (string, error)
	// ExecuteRead always runs the command even in dry-run mode.
	// Use this for read-only operations (e.g., ip route show, iptables -L).
	ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error)
	// IsDryRun returns true when the executor does not actually apply changes.
	IsDryRun() bool
}

// RealExecutor runs commands against the actual system.
type RealExecutor struct {
	Timeout time.Duration
}

// NewRealExecutor returns an Executor that runs real system commands.
func NewRealExecutor(timeout time.Duration) Executor {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &RealExecutor{Timeout: timeout}
}

// Execute runs the command on the real system.
func (e *RealExecutor) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	return e.run(ctx, cmd, args...)
}

// ExecuteRead runs the command on the real system (same as Execute for RealExecutor).
func (e *RealExecutor) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	return e.run(ctx, cmd, args...)
}

func (e *RealExecutor) run(ctx context.Context, cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	c := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		// Return the captured stdout alongside the error: several diagnostic
		// tools (e.g. smartctl) use their exit code as a bitmask where some
		// bits mean "ran fine, subject is unhealthy" rather than "execution
		// failed", while still writing a complete, valid payload to stdout.
		// When the process never actually ran (e.g. binary not found),
		// stdout.String() is naturally empty, so this is safe either way.
		return stdout.String(), fmt.Errorf("command %q failed: %s", strings.Join(append([]string{cmd}, args...), " "), errMsg)
	}

	return stdout.String(), nil
}

// IsDryRun returns false — this executor really applies changes.
func (e *RealExecutor) IsDryRun() bool { return false }

// DryRunExecutor logs the commands it would run but never executes them.
type DryRunExecutor struct {
	Commands []string
}

// NewDryRunExecutor returns an Executor that only logs commands.
func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

// Execute records the command and returns an informational string (no-op).
func (e *DryRunExecutor) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := strings.Join(append([]string{cmd}, args...), " ")
	e.Commands = append(e.Commands, full)
	return fmt.Sprintf("[dry-run] would execute: %s", full), nil
}

// ExecuteRead always runs the command even in dry-run mode (safe read-only operations).
func (e *DryRunExecutor) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		// See the matching comment in RealExecutor.run: preserve stdout even
		// on a non-zero exit, since some tools encode diagnostic state in
		// the exit code while still writing a useful payload to stdout.
		return stdout.String(), fmt.Errorf("command %q failed: %s", strings.Join(append([]string{cmd}, args...), " "), errMsg)
	}

	return stdout.String(), nil
}

// IsDryRun returns true.
func (e *DryRunExecutor) IsDryRun() bool { return true }
