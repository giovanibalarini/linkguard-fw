package sysupdates

import (
	"context"
	"os"
	"strings"
	"testing"
)

// fakeExec answers the one command this package runs. Dedicated to this
// package on purpose: a generic fake that returns "" for everything would
// make "no updates" and "apt failed" indistinguishable, which is exactly
// the distinction these tests exist to protect.
type fakeExec struct {
	out     string
	err     error
	lastCmd string
}

func (e *fakeExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.lastCmd = strings.Join(append([]string{cmd}, args...), " ")
	return e.out, e.err
}
func (e *fakeExec) IsDryRun() bool                              { return false }
func (_ *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }

// realProductionSample is the verbatim output captured from the production
// firewall on 2026-08-10, which had a pending kernel SECURITY update. Using
// the real bytes (not an invented string) is deliberate: two separate
// production-only parsing traps were found this way — see the assertions in
// TestCheckForcesCLocaleAndDistUpgrade.
const realProductionSample = `Inst linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
Inst linux-image-amd64 [6.12.94-1] (6.12.101-1 Debian-Security:13/stable-security [amd64])
Conf linux-image-6.12.101+deb13-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
Conf linux-image-amd64 (6.12.101-1 Debian-Security:13/stable-security [amd64])
`

func TestParseAptOutputRealSecurityUpdate(t *testing.T) {
	rep := parseAptOutput(realProductionSample)

	if rep.Total != 2 {
		t.Errorf("Total = %d, want 2 (only the Inst lines, never Conf)", rep.Total)
	}
	if rep.Security != 2 {
		t.Errorf("Security = %d, want 2 (both from Debian-Security)", rep.Security)
	}
	var upgraded *Package
	for i := range rep.Packages {
		if rep.Packages[i].Name == "linux-image-amd64" {
			upgraded = &rep.Packages[i]
		}
	}
	if upgraded == nil {
		t.Fatalf("linux-image-amd64 missing from %+v", rep.Packages)
	}
	if upgraded.CurrentVersion != "6.12.94-1" {
		t.Errorf("CurrentVersion = %q, want %q", upgraded.CurrentVersion, "6.12.94-1")
	}
	if upgraded.NewVersion != "6.12.101-1" {
		t.Errorf("NewVersion = %q, want %q", upgraded.NewVersion, "6.12.101-1")
	}
	if !upgraded.Security {
		t.Errorf("expected Security=true for a Debian-Security origin: %+v", upgraded)
	}
}

// A brand-new package (no [current] bracket) must still parse — that is the
// shape of the kernel's companion package in the real sample above.
func TestParseAptOutputNewPackageHasNoCurrentVersion(t *testing.T) {
	rep := parseAptOutput(realProductionSample)
	for _, p := range rep.Packages {
		if p.Name == "linux-image-6.12.101+deb13-amd64" {
			if p.CurrentVersion != "" {
				t.Errorf("CurrentVersion = %q, want empty for a newly installed package", p.CurrentVersion)
			}
			if p.NewVersion != "6.12.101-1" {
				t.Errorf("NewVersion = %q, want %q", p.NewVersion, "6.12.101-1")
			}
			return
		}
	}
	t.Fatalf("new package missing from %+v", rep.Packages)
}

func TestParseAptOutputNonSecurityUpdate(t *testing.T) {
	sample := "Inst curl [8.14.1-1] (8.14.2-1 Debian:13/stable [amd64])\n"
	rep := parseAptOutput(sample)

	if rep.Total != 1 {
		t.Fatalf("Total = %d, want 1", rep.Total)
	}
	if rep.Security != 0 {
		t.Errorf("Security = %d, want 0 for a plain Debian origin", rep.Security)
	}
	if rep.Packages[0].Security {
		t.Errorf("expected Security=false: %+v", rep.Packages[0])
	}
}

func TestParseAptOutputNothingPending(t *testing.T) {
	rep := parseAptOutput("")

	if rep.Total != 0 || rep.Security != 0 {
		t.Errorf("expected an empty report, got %+v", rep)
	}
	if rep.Packages == nil {
		t.Error("Packages is nil — would marshal as JSON null instead of []")
	}
}

// TestCheckForcesCLocaleAndDistUpgrade guards the two production-only traps
// found while designing this: (1) apt's output is localized — on the real
// box it came back in Portuguese ("atualizável de:"), so the parser must
// force LC_ALL=C; (2) `apt-get --just-print upgrade` reported ZERO for the
// pending kernel security update (kernel upgrades pull in a new package),
// while dist-upgrade reported it correctly. Using the wrong verb would have
// silently under-reported exactly the updates that matter most.
func TestCheckForcesCLocaleAndDistUpgrade(t *testing.T) {
	e := &fakeExec{out: realProductionSample}

	if _, err := Check(context.Background(), e); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(e.lastCmd, "LC_ALL=C") {
		t.Errorf("command must force the C locale, got: %q", e.lastCmd)
	}
	if !strings.Contains(e.lastCmd, "dist-upgrade") {
		t.Errorf("command must use dist-upgrade, got: %q", e.lastCmd)
	}
	if strings.Contains(e.lastCmd, "update") {
		t.Errorf("must never run `apt-get update` from inside the service, got: %q", e.lastCmd)
	}
}

// A failing apt must surface as an error, never as a cheerful "0 updates" —
// no fake data in the panel.
func TestCheckReportsErrorInsteadOfFakingZero(t *testing.T) {
	e := &fakeExec{err: errBoom{}}

	if _, err := Check(context.Background(), e); err == nil {
		t.Fatal("expected an error when apt fails, got nil (would show a false 'up to date')")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
