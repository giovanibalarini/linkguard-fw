package routes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// TestEnsureForwardingEnablesAndPersists verifies ip_forward is turned on live
// and a persistent sysctl drop-in is written.
func TestEnsureForwardingEnablesAndPersists(t *testing.T) {
	dir := t.TempDir()
	fwd := filepath.Join(dir, "ip_forward")
	persist := filepath.Join(dir, "99-linkguard-forwarding.conf")
	// Simulate forwarding disabled by the kernel.
	if err := os.WriteFile(fwd, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewRealExecutor(0), fwdPath: fwd, fwdPersistPath: persist}
	s.EnsureForwarding()

	got, err := os.ReadFile(fwd)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Errorf("ip_forward not enabled: got %q, want %q", got, "1\n")
	}
	drop, err := os.ReadFile(persist)
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if !strings.Contains(string(drop), "net.ipv4.ip_forward = 1") {
		t.Errorf("drop-in missing sysctl line: %q", drop)
	}
}

// TestEnsureForwardingDryRunNoWrite ensures dry-run mode never touches the kernel.
func TestEnsureForwardingDryRunNoWrite(t *testing.T) {
	dir := t.TempDir()
	fwd := filepath.Join(dir, "ip_forward")
	if err := os.WriteFile(fwd, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewDryRunExecutor(), fwdPath: fwd, fwdPersistPath: filepath.Join(dir, "drop.conf")}
	s.EnsureForwarding()

	got, _ := os.ReadFile(fwd)
	if string(got) != "0\n" {
		t.Errorf("dry-run modified ip_forward: got %q, want %q", got, "0\n")
	}
}
