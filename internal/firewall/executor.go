package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
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
	// WriteFile grava um arquivo de configuração do sistema, respeitando o
	// dry-run pelo TIPO em vez de por disciplina de quem chama.
	//
	// Existe porque o dry-run vazava: cada os.WriteFile espalhado pelo código
	// precisava lembrar de um `if !exec.IsDryRun()` à sua volta, e duas escritas
	// do EnsureResolvConf não lembravam — em --dry-run elas trocavam o
	// /etc/resolv.conf e o dhclient.conf de uma máquina de verdade. É o mesmo
	// buraco que o nftables.Persist documenta ter causado quando a suíte,
	// rodando como root, sobrescreveu o /etc/nftables.conf real.
	//
	// Um os.WriteFile novo esquecido volta a vazar; um exec.WriteFile novo não.
	WriteFile(path string, data []byte, perm os.FileMode) error
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

// WriteFile grava de verdade.
func (e *RealExecutor) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// DryRunExecutor logs the commands it would run but never executes them.
type DryRunExecutor struct {
	Commands []string
	// Writes registra os arquivos que teriam sido gravados, no formato
	// "caminho (perm, N bytes)". É o que permite a um teste afirmar que NADA
	// foi escrito, em vez de torcer para que não tenha sido.
	Writes []string
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

// WriteFile só registra: em dry-run nenhum arquivo é tocado.
func (e *DryRunExecutor) WriteFile(path string, data []byte, perm os.FileMode) error {
	e.Writes = append(e.Writes, fmt.Sprintf("%s (%#o, %d bytes)", path, perm, len(data)))
	return nil
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
