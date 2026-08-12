package bootstrapdeps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeExec is a firewall.Executor double that models the only two commands
// this package ever runs: `dpkg-query` (read) and `systemd-run -- apt-get`
// (write). It is deliberately stateful — a successful apt-get install flips
// the packages it names to installed — because the whole point of Ensure is
// the transition ("what is missing" -> "install it" -> "what is STILL
// missing"), and a stateless double could never exercise it.
type fakeExec struct {
	dryRun    bool
	installed map[string]bool
	executed  []string

	// installFails makes every apt-get install fail (no network, broken
	// mirror). installFailsUntilUpdate makes it fail only until an
	// `apt-get update` runs — the stale-index case.
	installFails            bool
	installFailsUntilUpdate bool
	updated                 bool

	// installOnly, when non-empty, limits which packages a "successful"
	// install actually provides — used to exercise a partial install.
	installOnly map[string]bool
}

func newFakeExec(installed ...string) *fakeExec {
	e := &fakeExec{installed: map[string]bool{}}
	for _, p := range installed {
		e.installed[p] = true
	}
	return e
}

func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "dpkg-query" && len(args) > 0 {
		pkg := args[len(args)-1]
		if e.installed[pkg] {
			return "install ok installed", nil
		}
		return "", fmt.Errorf("dpkg-query: no packages found matching %s", pkg)
	}
	return "", nil
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := strings.Join(append([]string{cmd}, args...), " ")
	e.executed = append(e.executed, full)

	if strings.Contains(full, "apt-get update") {
		e.updated = true
		return "", nil
	}
	if !strings.Contains(full, "apt-get install") {
		return "", nil
	}
	if e.installFails || (e.installFailsUntilUpdate && !e.updated) {
		return "", errors.New("E: Unable to locate package")
	}
	for _, a := range args {
		// Everything that is not a package name: flags, the `-o Dpkg::...`
		// option values, and the command itself.
		if strings.HasPrefix(a, "-") || strings.Contains(a, "=") ||
			a == "apt-get" || a == "install" || a == "systemd-run" {
			continue
		}
		if e.installOnly != nil && !e.installOnly[a] {
			continue
		}
		e.installed[a] = true
	}
	return "", nil
}

func (e *fakeExec) IsDryRun() bool { return e.dryRun }

func (e *fakeExec) ran(substr string) bool {
	for _, c := range e.executed {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// fakeAlerter records the panel-facing side of Ensure.
type fakeAlerter struct {
	missing []string
	ok      []string
}

func (a *fakeAlerter) BaseDepsMissing(detail string) error {
	a.missing = append(a.missing, detail)
	return nil
}

func (a *fakeAlerter) BaseDepsOK(detail string) error {
	a.ok = append(a.ok, detail)
	return nil
}

func allBase() []string { return append([]string{}, BasePackages...) }

func TestMissingReportsOnlyWhatIsNotInstalled(t *testing.T) {
	exec := newFakeExec("nftables", "iproute2")

	got := Missing(context.Background(), exec, allBase()...)

	want := []string{"iptables", "iputils-ping"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Missing = %v, want %v", got, want)
	}
}

func TestMissingIsEmptyOnAProvisionedBox(t *testing.T) {
	exec := newFakeExec(allBase()...)

	if got := Missing(context.Background(), exec, allBase()...); len(got) != 0 {
		t.Errorf("Missing = %v, want empty on a box that already has everything", got)
	}
}

// A package left in "deinstall ok config-files" (purged binary, config still
// around) is NOT installed — treating it as present would leave the box
// without nft while the panel claimed everything was fine.
func TestMissingTreatsConfigFilesOnlyAsMissing(t *testing.T) {
	exec := &fakeExec{installed: map[string]bool{}}
	exec.installed["iproute2"] = true
	statusExec := &statusFakeExec{fakeExec: exec, status: map[string]string{
		"nftables": "deinstall ok config-files",
	}}

	got := Missing(context.Background(), statusExec, "nftables")
	if len(got) != 1 || got[0] != "nftables" {
		t.Errorf("Missing = %v, want [nftables] for a config-files-only package", got)
	}
}

// statusFakeExec lets a test dictate the raw dpkg status string.
type statusFakeExec struct {
	*fakeExec
	status map[string]string
}

func (e *statusFakeExec) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	if cmd == "dpkg-query" && len(args) > 0 {
		if s, ok := e.status[args[len(args)-1]]; ok {
			return s, nil
		}
	}
	return e.fakeExec.ExecuteRead(ctx, cmd, args...)
}

func TestEnsureDoesNothingWhenEverythingIsPresent(t *testing.T) {
	exec := newFakeExec(allBase()...)
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if len(exec.executed) != 0 {
		t.Errorf("nothing should be executed on a provisioned box, got %v", exec.executed)
	}
	if len(al.missing) != 0 || len(al.ok) != 0 {
		t.Errorf("no alert should be raised, got missing=%v ok=%v", al.missing, al.ok)
	}
}

func TestEnsureInstallsOnlyWhatIsMissing(t *testing.T) {
	exec := newFakeExec("iproute2", "iputils-ping")
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if !exec.ran("apt-get install") || !exec.ran("nftables iptables") {
		t.Errorf("expected a single install of just the missing packages, got %v", exec.executed)
	}
	if exec.ran("iproute2") {
		t.Errorf("must not reinstall what is already there, got %v", exec.executed)
	}
	if len(al.missing) != 0 {
		t.Errorf("a successful install must not raise the critical alert, got %v", al.missing)
	}
	if len(al.ok) != 1 || !strings.Contains(al.ok[0], "nftables") {
		t.Errorf("a successful install must be recorded on the panel, got %v", al.ok)
	}
}

// The stale-index case: a freshly imaged box whose apt lists are empty gets
// "Unable to locate package". Refreshing the index and retrying once is the
// difference between a working appliance and a critical alert.
func TestEnsureRefreshesTheIndexAndRetriesOnce(t *testing.T) {
	exec := newFakeExec()
	exec.installFailsUntilUpdate = true
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if !exec.ran("apt-get update") {
		t.Errorf("expected an apt-get update after the first failure, got %v", exec.executed)
	}
	if len(al.missing) != 0 {
		t.Errorf("the retry succeeded, so no critical alert should be raised: %v", al.missing)
	}
	if len(Missing(context.Background(), exec, allBase()...)) != 0 {
		t.Error("every base package should be installed after the retry")
	}
}

// The honesty requirement: when apt genuinely cannot install (no network,
// dead mirror), the box is left without a packet filter. That must reach the
// panel as a critical alert naming the packages AND what stops working.
func TestEnsureRaisesCriticalAlertWhenAptCannotInstall(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if len(al.missing) != 1 {
		t.Fatalf("expected exactly one critical alert, got %v", al.missing)
	}
	detail := al.missing[0]
	for _, pkg := range BasePackages {
		if !strings.Contains(detail, pkg) {
			t.Errorf("alert detail must name %s, got %q", pkg, detail)
		}
	}
	if !strings.Contains(detail, "firewall") {
		t.Errorf("alert detail must say what stops working, got %q", detail)
	}
	if !strings.Contains(detail, "apt-get install -y") {
		t.Errorf("alert detail must tell the admin how to fix it by hand, got %q", detail)
	}
	if len(al.ok) != 0 {
		t.Errorf("no recovery should be recorded, got %v", al.ok)
	}
}

// A half-done install is the worst case to get wrong: the alert must name
// what is STILL missing after the attempt, not what was missing before it.
func TestEnsureAlertNamesOnlyWhatIsStillMissing(t *testing.T) {
	exec := newFakeExec("iproute2", "iputils-ping")
	exec.installOnly = map[string]bool{"iptables": true}
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if len(al.missing) != 1 {
		t.Fatalf("expected one critical alert, got %v", al.missing)
	}
	if !strings.Contains(al.missing[0], "nftables") {
		t.Errorf("alert must name nftables, got %q", al.missing[0])
	}
	if strings.Contains(al.missing[0], "iptables —") {
		t.Errorf("alert must not name a package that got installed, got %q", al.missing[0])
	}
}

// Dry-run mode never touches the box, so it must not "fail to install" and
// must not scare the operator with a critical alert about it.
func TestEnsureIsANoOpInDryRun(t *testing.T) {
	exec := newFakeExec()
	exec.dryRun = true
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if exec.ran("apt-get") {
		t.Errorf("dry-run must not run apt-get, got %v", exec.executed)
	}
	if len(al.missing) != 0 || len(al.ok) != 0 {
		t.Errorf("dry-run must not alert, got missing=%v ok=%v", al.missing, al.ok)
	}
}

// A nil alerter (no panel wired yet) must not panic — Ensure runs at boot,
// and an error at boot never takes the process down.
func TestEnsureToleratesNilAlerter(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true

	Ensure(context.Background(), exec, nil)
}

func TestInstallPackagesRunsAptOutsideOurOwnSandbox(t *testing.T) {
	exec := newFakeExec()

	if err := InstallPackages(context.Background(), exec, "chrony"); err != nil {
		t.Fatalf("InstallPackages: %v", err)
	}
	want := "systemd-run --pipe --wait --setenv=DEBIAN_FRONTEND=noninteractive " +
		"-- apt-get install -y --no-install-recommends " +
		"-o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef chrony"
	if len(exec.executed) != 1 || exec.executed[0] != want {
		t.Errorf("executed = %v, want [%s]", exec.executed, want)
	}
}

// Nobody is at a terminal when apt runs here: a conffile prompt is not a
// question, it is an aborted transaction ("end of file on stdin at conffile
// prompt") that leaves the package half-configured — which is exactly how the
// nftables install failed on a bare box before these flags existed.
func TestInstallPackagesNeverStopsAtAPrompt(t *testing.T) {
	exec := newFakeExec()

	if err := InstallPackages(context.Background(), exec, "nftables"); err != nil {
		t.Fatalf("InstallPackages: %v", err)
	}
	cmd := exec.executed[0]
	for _, want := range []string{
		"DEBIAN_FRONTEND=noninteractive",
		"--force-confold",
		"--force-confdef",
		"-y",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("apt invocation must carry %q, got %q", want, cmd)
		}
	}
}

func TestInstallPackagesWithNoPackagesRunsNothing(t *testing.T) {
	exec := newFakeExec()

	if err := InstallPackages(context.Background(), exec); err != nil {
		t.Fatalf("InstallPackages: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no command, got %v", exec.executed)
	}
}

// Every base package must carry its own "what stops working" sentence:
// a missing-dependency alert that just lists names tells the operator
// nothing they can act on.
func TestEveryBasePackageHasAConsequence(t *testing.T) {
	for _, pkg := range BasePackages {
		if strings.TrimSpace(consequences[pkg]) == "" {
			t.Errorf("base package %s has no consequence text", pkg)
		}
	}
}
