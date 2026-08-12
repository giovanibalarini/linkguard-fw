package bootstrapdeps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
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

	// unitState é o que `systemctl is-enabled <unidade>` responde. Vazio
	// significa "unidade não existe" (pacote nunca instalado), que é como o
	// systemd responde de verdade: saída vazia e código != 0. O pacote
	// nftables do Debian instala a unidade DESABILITADA, então o estado
	// inicial de uma máquina pelada é "disabled" logo após o apt.
	unitState map[string]string
}

func newFakeExec(installed ...string) *fakeExec {
	e := &fakeExec{installed: map[string]bool{}, unitState: map[string]string{}}
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
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-enabled" {
		state := e.unitState[args[1]]
		if state == "" {
			return "", fmt.Errorf("Failed to get unit file state for %s.service: No such file or directory", args[1])
		}
		if state != "enabled" {
			// `systemctl is-enabled` IMPRIME o estado e sai != 0 quando ele
			// não é "enabled" — a saída é utilizável mesmo com erro.
			return state + "\n", fmt.Errorf("exit status 1")
		}
		return "enabled\n", nil
	}
	return "", nil
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := strings.Join(append([]string{cmd}, args...), " ")
	e.executed = append(e.executed, full)

	if cmd == "systemctl" && len(args) == 2 && args[0] == "enable" {
		if e.unitState[args[1]] == "" {
			return "", fmt.Errorf("Unit %s.service does not exist", args[1])
		}
		if e.unitState[args[1]] == "masked" {
			return "", fmt.Errorf("Unit %s.service is masked", args[1])
		}
		e.unitState[args[1]] = "enabled"
		return "", nil
	}
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
		// O pacote nftables do Debian traz a unidade DESABILITADA — o
		// README.Debian dele diz "you can optionally enable". É o fato que
		// torna a premissa nova (o LinkGuard instala o nftables sozinho)
		// diferente da antiga (o apt trazia e o operador habilitava).
		if a == "nftables" {
			e.unitState["nftables"] = "disabled"
		}
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
	// present conta os fechamentos silenciosos (nada instalado por nós).
	present int
}

func (a *fakeAlerter) BaseDepsPresent() { a.present++ }

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
	want := "systemd-run --collect --pipe --wait --setenv=DEBIAN_FRONTEND=noninteractive " +
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

// ─── EnsureInstalled (on-demand, feature-triggered) ──────────────────────────

// The fast path: turning a feature on over and over must not run apt on a box
// that already has the package. This is on the DHCP/DNS apply path, which runs
// on every save.
func TestEnsureInstalledIsANoOpWhenThePackageIsAlreadyThere(t *testing.T) {
	exec := newFakeExec("kea-dhcp4-server", "unbound")

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server", "unbound")

	if err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	if len(installed) != 0 {
		t.Errorf("nothing was installed, got %v", installed)
	}
	if exec.ran("apt-get") {
		t.Errorf("must not run apt on a box that already has the packages, got %v", exec.executed)
	}
}

// The defect this feature exists to fix: the admin turns DHCP on, the package
// was never installed, and LinkGuard brings it in itself.
func TestEnsureInstalledBringsInWhatIsMissing(t *testing.T) {
	exec := newFakeExec("unbound")

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server", "unbound")

	if err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	if len(installed) != 1 || installed[0] != "kea-dhcp4-server" {
		t.Errorf("installed = %v, want [kea-dhcp4-server] (only what was missing)", installed)
	}
	if !exec.ran("apt-get install") {
		t.Errorf("expected an apt-get install, got %v", exec.executed)
	}
	if exec.ran("unbound") {
		t.Errorf("must not reinstall what is already there, got %v", exec.executed)
	}
}

// Same stale-index case Ensure handles at boot: a box whose apt lists were
// never fetched answers "Unable to locate package" until the index is
// refreshed. One retry is the difference between DHCP working and an error.
func TestEnsureInstalledRefreshesTheIndexAndRetriesOnce(t *testing.T) {
	exec := newFakeExec()
	exec.installFailsUntilUpdate = true

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server")

	if err != nil {
		t.Fatalf("EnsureInstalled after retry: %v", err)
	}
	if !exec.ran("apt-get update") {
		t.Errorf("expected an apt-get update after the first failure, got %v", exec.executed)
	}
	if len(installed) != 1 {
		t.Errorf("installed = %v, want the package the retry brought in", installed)
	}
}

// The honesty requirement (FEATURES.md, "Regra de entrega"): when the package
// cannot be installed, the caller gets a sentence it can put in front of the
// admin — which package, why it failed, what stops working, and how to fix it
// by hand. Never a bare "erro interno do servidor".
func TestEnsureInstalledExplainsItselfWhenAptCannotInstall(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server")

	if err == nil {
		t.Fatal("expected an error when the package could not be installed")
	}
	if len(installed) != 0 {
		t.Errorf("nothing was installed, got %v", installed)
	}
	msg := err.Error()
	for _, want := range []string{
		"kea-dhcp4-server",         // which package
		"Unable to locate package", // why apt failed
		"DHCP",                     // what stops working
		"apt-get install -y",       // how to fix it by hand
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message must mention %q, got %q", want, msg)
		}
	}
}

// A partial install must be reported by what is STILL missing, and must still
// report the package that did make it in (the caller clears its alert with it).
func TestEnsureInstalledReportsWhatIsStillMissingAfterAPartialInstall(t *testing.T) {
	exec := newFakeExec()
	exec.installOnly = map[string]bool{"unbound": true}

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server", "unbound")

	if err == nil {
		t.Fatal("expected an error: kea-dhcp4-server is still missing")
	}
	if !strings.Contains(err.Error(), "kea-dhcp4-server") {
		t.Errorf("error must name what is still missing, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "unbound —") {
		t.Errorf("error must not name the package that got installed, got %q", err.Error())
	}
	if len(installed) != 1 || installed[0] != "unbound" {
		t.Errorf("installed = %v, want [unbound]", installed)
	}
}

// Dry-run never touches the box: it must not apt-install, and it must not
// report a failure the admin cannot act on either.
func TestEnsureInstalledIsANoOpInDryRun(t *testing.T) {
	exec := newFakeExec()
	exec.dryRun = true

	installed, err := EnsureInstalled(context.Background(), exec, "kea-dhcp4-server")

	if err != nil {
		t.Fatalf("dry-run must not fail: %v", err)
	}
	if len(installed) != 0 {
		t.Errorf("dry-run installed nothing, got %v", installed)
	}
	if exec.ran("apt-get") {
		t.Errorf("dry-run must not run apt-get, got %v", exec.executed)
	}
}

// Same contract as TestEveryBasePackageHasAConsequence, for the packages
// installed on demand: naming a package without saying what its absence
// breaks leaves the admin guessing.
func TestEveryOnDemandPackageHasAConsequence(t *testing.T) {
	for _, pkg := range []string{"kea-dhcp4-server", "unbound", "dns-root-data", "chrony"} {
		if strings.TrimSpace(consequences[pkg]) == "" {
			t.Errorf("on-demand package %s has no consequence text", pkg)
		}
	}
}

// lockingFakeExec models what dpkg actually does: only one apt-get may hold
// /var/lib/dpkg/lock-frontend at a time, and a second one fails outright
// ("Could not get lock ... is another process using it?") instead of waiting.
type lockingFakeExec struct {
	mu        sync.Mutex
	inFlight  int
	installs  int
	clashes   int
	installed map[string]bool
}

func (e *lockingFakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "dpkg-query" && len(args) > 0 {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.installed[args[len(args)-1]] {
			return "install ok installed", nil
		}
		return "", errors.New("dpkg-query: no packages found")
	}
	return "", nil
}

func (e *lockingFakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if !strings.Contains(strings.Join(args, " "), "apt-get") {
		return "", nil
	}
	e.mu.Lock()
	e.inFlight++
	clash := e.inFlight > 1
	if clash {
		e.clashes++
	}
	e.installs++
	e.mu.Unlock()

	time.Sleep(20 * time.Millisecond) // apt is not instantaneous

	e.mu.Lock()
	defer e.mu.Unlock()
	e.inFlight--
	if clash {
		return "", errors.New("E: Could not get lock /var/lib/dpkg/lock-frontend")
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") || strings.Contains(a, "=") ||
			a == "apt-get" || a == "install" || a == "systemd-run" {
			continue
		}
		e.installed[a] = true
	}
	return "", nil
}

func (e *lockingFakeExec) IsDryRun() bool { return false }

// Found on the test VM, not in theory: saving the DHCP config arms the
// debounced auto-apply, the admin also presses "Aplicar agora", and both
// reach EnsureInstalled at once. Two apt-get runs collided on the dpkg
// frontend lock, the second died with "Could not get lock", and it burned
// the single retry that exists for the stale-index case. Only one apt may be
// in flight at a time, and whoever waits must re-check instead of installing
// what the other one already brought in.
func TestEnsureInstalledSerializesConcurrentInstalls(t *testing.T) {
	exec := &lockingFakeExec{installed: map[string]bool{}}

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = EnsureInstalled(context.Background(), exec, "kea-dhcp4-server", "unbound")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("chamada concorrente %d falhou: %v", i, err)
		}
	}
	if exec.clashes != 0 {
		t.Errorf("%d apt-get simultâneos: o lock do dpkg não perdoa", exec.clashes)
	}
	if exec.installs != 1 {
		t.Errorf("apt rodou %d vezes, quero 1 (quem esperou tem que reconferir, não reinstalar)", exec.installs)
	}
}

// The raw failure from apt is not a message, it is a transcript: on the test
// VM a single unreachable mirror produced eleven "E: Failed to fetch" lines
// plus systemd-run's own banner (invocation ID, runtime, CPU time, memory
// peak) — over two thousand characters, all of it destined for a red banner
// on the DHCP page. The admin needs the reason, not the transcript; the
// transcript stays in the journal, which is where a transcript belongs.
func TestInstallFailureMessageKeepsTheReasonAndDropsTheTranscript(t *testing.T) {
	raw := errors.New(`command "systemd-run --pipe --wait -- apt-get install -y kea-dhcp4-server" failed: ` +
		"Running as unit: run-p1494-i1794.service; invocation ID: bb438f09288648c59fc87afcf67e3651\n" +
		"E: Failed to fetch http://mirror/pool/main/i/isc-kea/kea-common_2.6.3-1_amd64.deb  Unable to connect\n" +
		"E: Failed to fetch http://mirror/pool/main/i/isc-kea/kea-dhcp4-server_2.6.3-1_amd64.deb  Unable to connect\n" +
		"E: Failed to fetch http://mirror/pool/main/libe/libevent/libevent-2.1-7t64_2.1.12_amd64.deb  Unable to connect\n" +
		"E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n" +
		"Finished with result: exit-code\nMain processes terminated with: code=exited, status=100/n/a\n" +
		"Service runtime: 7.694s\nCPU time consumed: 685ms\nMemory peak: 22.8M (swap: 0B)")

	msg := installFailureMessage([]string{"kea-dhcp4-server"}, raw)

	if !strings.Contains(msg, "Unable to connect") {
		t.Errorf("o motivo real tem que sobreviver, obtive %q", msg)
	}
	for _, noise := range []string{"invocation ID", "Memory peak", "CPU time consumed", "Service runtime"} {
		if strings.Contains(msg, noise) {
			t.Errorf("o ruído do systemd-run não pode ir para o painel (%q): %q", noise, msg)
		}
	}
	if n := strings.Count(msg, "Failed to fetch"); n > 2 {
		t.Errorf("%d linhas de fetch na mensagem; o admin não lê transcrição: %q", n, msg)
	}
	if len(msg) > 700 {
		t.Errorf("mensagem com %d caracteres é banner de painel, não log: %q", len(msg), msg)
	}
	// O que o admin precisa continua lá.
	for _, want := range []string{"kea-dhcp4-server", "DHCP", "apt-get install -y"} {
		if !strings.Contains(msg, want) {
			t.Errorf("a mensagem tem que citar %q, obtive %q", want, msg)
		}
	}
}

// Toda tentativa abortada (timeout, espelho que sumiu) deixava um
// `run-*.service` em estado failed para sempre: `systemctl --failed` é a
// primeira coisa que um operador olha, e ele passava a mostrar lixo de uma
// instalação já refeita com sucesso. O --collect faz o systemd recolher a
// unidade transiente mesmo quando ela falha. O `systemctl reset-failed` que
// já existia no keaunbound NÃO cobre isto: ele limpa kea-dhcp4-server e
// unbound, que são unidades nomeadas, não as transientes anônimas.
func TestTodaChamadaDeAptRecolheAUnidadeTransiente(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true

	// install (2x, por causa do retry) + apt-get update
	_, _ = EnsureInstalled(context.Background(), exec, "kea-dhcp4-server")

	if len(exec.executed) == 0 {
		t.Fatal("nenhum comando executado")
	}
	for _, cmd := range exec.executed {
		if !strings.HasPrefix(cmd, "systemd-run --collect ") {
			t.Errorf("chamada de apt sem --collect: %q", cmd)
		}
	}
}

// O veredito do Ensure é o que permite ao chamador tentar de novo. Ele roda
// uma vez por tentativa, e o motivo mais comum de falhar logo depois do boot
// é o apt-daily/unattended-upgrades estar com o lock do dpkg — sem uma
// segunda tentativa, a base nunca era instalada NAQUELE boot.
func TestEnsureDizSeAindaFaltaAlgo(t *testing.T) {
	// Máquina já provisionada: nada a fazer.
	if !Ensure(context.Background(), newFakeExec(BasePackages...), nil) {
		t.Error("numa máquina já provisionada o Ensure tem que dizer que acabou")
	}

	// Máquina pelada com apt funcionando: instalou, acabou.
	ok := newFakeExec()
	if !Ensure(context.Background(), ok, nil) {
		t.Error("depois de instalar com sucesso o Ensure tem que dizer que acabou")
	}

	// apt indisponível (lock do dpkg, espelho morto): NÃO acabou.
	stuck := newFakeExec()
	stuck.installFails = true
	if Ensure(context.Background(), stuck, nil) {
		t.Error("com a base ainda faltando o Ensure não pode dizer que acabou — é o que faz o chamador tentar de novo")
	}

	// Dry-run: não há o que tentar de novo.
	dry := newFakeExec()
	dry.dryRun = true
	if !Ensure(context.Background(), dry, nil) {
		t.Error("em dry-run não existe retentativa que resolva")
	}
}

// A escala começa curta (o lock do dpkg se resolve sozinho em minutos) e
// estabiliza (sem WAN, martelar o apt não compra nada).
func TestRetryDelayComecaCurtoEEstabiliza(t *testing.T) {
	first := RetryDelay(0)
	if first > time.Minute {
		t.Errorf("a primeira retentativa tem que ser rápida, veio %v", first)
	}
	if RetryDelay(1) <= first {
		t.Errorf("a espera tem que crescer: %v depois de %v", RetryDelay(1), first)
	}
	last := RetryDelay(99)
	if last != RetryDelay(1000) {
		t.Errorf("a espera tem que estabilizar, %v != %v", last, RetryDelay(1000))
	}
	if last > 30*time.Minute {
		t.Errorf("um teto de %v deixa a base sem instalar por tempo demais", last)
	}
	if RetryDelay(-1) != first {
		t.Errorf("tentativa negativa tem que se comportar como a primeira")
	}
}

// O caso mais provável de falha do apt não tem linha `E:` nenhuma: o apt
// morto pelo prazo. O fallback ingênuo ("primeira linha do erro") devolvia
// justamente a pior frase possível — o internal/firewall formata os erros
// como `command "<linha de comando inteira>" failed: ...`, então o admin
// recebia 253 caracteres de systemd-run/apt-get terminando em "signal:
// killed", dentro de um banner de ~980 caracteres na tela de DHCP.
func TestAptReasonNaoDevolveALinhaDeComandoCrua(t *testing.T) {
	cmdline := `systemd-run --collect --pipe --wait --setenv=DEBIAN_FRONTEND=noninteractive -- ` +
		`apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold ` +
		`-o Dpkg::Options::=--force-confdef kea-dhcp4-server unbound dns-root-data`
	err := fmt.Errorf("command %q failed: %s", cmdline, "signal: killed")

	reason := aptReason(err)
	if strings.Contains(reason, "systemd-run") || strings.Contains(reason, "Dpkg::Options") {
		t.Errorf("a linha de comando vazou para o painel:\n%s", reason)
	}
	if strings.Contains(reason, "signal: killed") {
		t.Errorf("\"signal: killed\" não diz nada ao admin:\n%s", reason)
	}
	if !strings.Contains(reason, "prazo") {
		t.Errorf("o motivo tem que dizer que o apt foi interrompido por prazo:\n%s", reason)
	}
	if !strings.Contains(reason, "ainda estar em curso") {
		t.Errorf("o apt não morre junto com o cliente; o motivo tem que dizer isso:\n%s", reason)
	}
}

// Um erro comum que não é timeout continua chegando cru, mas sem o eco do
// comando.
func TestAptReasonMantemOMotivoRealSemOEcoDoComando(t *testing.T) {
	err := fmt.Errorf("command %q failed: %s", "systemd-run --collect -- apt-get install -y unbound",
		"Failed to start transient service unit: Access denied")

	reason := aptReason(err)
	if strings.Contains(reason, "systemd-run") {
		t.Errorf("o eco do comando continua no motivo:\n%s", reason)
	}
	if !strings.Contains(reason, "Access denied") {
		t.Errorf("o motivo verdadeiro foi perdido:\n%s", reason)
	}
}

// O corte existe para o banner do painel continuar legível — a transcrição
// inteira já vai para o journal. Sem teste, trocar 300 por 1000000 passava.
func TestAptReasonCortaMotivoLongoDemaisParaOBanner(t *testing.T) {
	long := "E: " + strings.Repeat("Failed to fetch http://deb.debian.org/debian/pool/main/x ", 40)
	reason := aptReason(errors.New(long))

	if len(reason) > maxReasonLen+len("…") {
		t.Errorf("motivo com %d caracteres: não cabe num banner (limite %d)", len(reason), maxReasonLen)
	}
	if !strings.HasSuffix(reason, "…") {
		t.Errorf("um motivo cortado tem que dizer que foi cortado:\n%s", reason)
	}
	if maxReasonLen > 500 {
		t.Errorf("maxReasonLen = %d: um limite deste tamanho não é um limite", maxReasonLen)
	}
}

// E o caminho com linhas `E:` continua valendo: elas são o que o apt tem de
// acionável, e só as duas primeiras vão para a tela.
func TestAptReasonPrefereAsLinhasEDoApt(t *testing.T) {
	err := errors.New("command \"systemd-run ...\" failed: Reading package lists...\n" +
		"E: Failed to fetch http://espelho/a.deb\n" +
		"E: Failed to fetch http://espelho/b.deb\n" +
		"E: Failed to fetch http://espelho/c.deb\n" +
		"E: Unable to fetch some archives")

	reason := aptReason(err)
	if !strings.Contains(reason, "a.deb") || !strings.Contains(reason, "b.deb") {
		t.Errorf("as duas primeiras linhas E: têm que aparecer:\n%s", reason)
	}
	if strings.Contains(reason, "c.deb") {
		t.Errorf("só as duas primeiras vão para a tela:\n%s", reason)
	}
	if !strings.Contains(reason, "erros do apt no log do serviço") {
		t.Errorf("o motivo tem que dizer que sobraram erros no log:\n%s", reason)
	}
}

// O alerta de base ausente era reavaliado SÓ no boot: quem instalasse à mão
// pelo SSH sem reiniciar ficava com um alerta crítico vermelho para sempre, e
// a mensagem não dizia nem para reiniciar. Agora ela diz o que de fato
// acontece — o LinkGuard tenta de novo sozinho.
func TestOAlertaDeBaseAusenteDizComoSaiDele(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true
	al := &fakeAlerter{}

	Ensure(context.Background(), exec, al)

	if len(al.missing) != 1 {
		t.Fatalf("esperava um alerta, obtive %v", al.missing)
	}
	detail := al.missing[0]
	for _, want := range []string{"tenta de novo sozinho", "sem precisar reiniciar o serviço"} {
		if !strings.Contains(detail, want) {
			t.Errorf("o alerta não diz %q:\n%s", want, detail)
		}
	}
}

// E a promessa tem que ser verdade: uma tentativa posterior, no mesmo
// processo, reconhece o que o admin instalou à mão e fecha o alerta.
func TestUmaTentativaPosteriorFechaOAlertaSemReiniciarOServico(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true
	al := &fakeAlerter{}

	if Ensure(context.Background(), exec, al) {
		t.Fatal("pré-condição: a primeira tentativa tem que falhar")
	}
	if len(al.ok) != 0 {
		t.Fatalf("nada foi instalado ainda: %v", al.ok)
	}

	// O admin instalou à mão pelo SSH — sem reiniciar o LinkGuard.
	for _, p := range BasePackages {
		exec.installed[p] = true
	}

	if !Ensure(context.Background(), exec, al) {
		t.Fatal("com a base instalada à mão, a tentativa seguinte tem que dizer que acabou")
	}
	if len(al.missing) != 1 {
		t.Errorf("não pode reabrir o alerta depois de resolvido: %v", al.missing)
	}
	if al.present == 0 {
		t.Error("o alerta crítico continua aberto: quem instalou à mão ficaria com ele para sempre")
	}
	if len(al.ok) != 0 {
		t.Errorf("o LinkGuard não instalou nada; não há recuperação a anunciar: %v", al.ok)
	}
}

// ─── A unidade do nftables ────────────────────────────────────────────────
//
// C-2 da revisão final. Enquanto a base ficava em Depends:, o apt trazia o
// nftables e o operador habilitava a unidade a mão. Na premissa nova — o
// LinkGuard instala o nftables sozinho no primeiro boot — a unidade nasce
// desabilitada (o pacote do Debian a entrega assim) e ninguém a habilita.
// Numa máquina assim:
//
//  1. Persist() reescreve /etc/nftables.conf a cada reconciliação e NADA
//     nunca lê o arquivo;
//  2. em todo reboot a tabela não existe, EnsureTable devolve true e o
//     main.go chama Restore(snapshot), que começa com `flush ruleset` — a
//     regra de ouro do projeto ("o LinkGuard só mexe na tabela dele") passa
//     a ser violada a cada boot, destruindo qualquer tabela de terceiro
//     (docker, libvirt, fail2ban) criada depois do último snapshot;
//  3. se esse Restore falhar, os sets voltam vazios e as linhas de drop
//     continuam na forward: a tela diz "bloqueado" com o tráfego passando.

func TestEnsureHabilitaAUnidadeDoNftablesQueEleMesmoInstalou(t *testing.T) {
	exec := newFakeExec() // máquina pelada: nem pacote, nem unidade
	alerter := &fakeAlerter{}

	if done := Ensure(context.Background(), exec, alerter); !done {
		t.Fatalf("Ensure devia ter concluído, executados=%v", exec.executed)
	}

	if !exec.ran("systemctl enable nftables") {
		t.Errorf("o LinkGuard instalou o nftables e não habilitou a unidade: "+
			"/etc/nftables.conf não seria lido em boot nenhum e todo reboot passaria pelo "+
			"`flush ruleset` do Restore. Executados: %v", exec.executed)
	}
	if got := exec.unitState["nftables"]; got != "enabled" {
		t.Errorf("estado da unidade = %q, esperado \"enabled\"", got)
	}
}

// O caso que o postinst sozinho não cobriria: o pacote já está instalado
// (veio de um apt do operador, ou de uma instalação anterior) e a unidade
// continua desabilitada. O LinkGuard nunca instala nada nesse boot, então
// não basta habilitar "depois do apt" — tem que ser verificado sempre.
func TestEnsureHabilitaAUnidadeMesmoSemInstalarNada(t *testing.T) {
	exec := newFakeExec(allBase()...)
	exec.unitState["nftables"] = "disabled"
	alerter := &fakeAlerter{}

	if done := Ensure(context.Background(), exec, alerter); !done {
		t.Fatal("Ensure devia ter concluído numa máquina com a base completa")
	}

	if !exec.ran("systemctl enable nftables") {
		t.Errorf("pacote instalado e unidade desabilitada: ninguém habilitou. Executados: %v", exec.executed)
	}
	if len(alerter.missing) != 0 {
		t.Errorf("nada faltava; não podia ter alerta: %v", alerter.missing)
	}
}

// Numa máquina já provisionada isto não pode virar ruído: a unidade já está
// habilitada, então não se executa nada.
func TestEnsureNaoMexeNaUnidadeJaHabilitada(t *testing.T) {
	exec := newFakeExec(allBase()...)
	exec.unitState["nftables"] = "enabled"

	Ensure(context.Background(), exec, &fakeAlerter{})

	if exec.ran("systemctl enable") {
		t.Errorf("a unidade já estava habilitada e o LinkGuard executou algo assim mesmo: %v", exec.executed)
	}
}

// Habilitar sim, iniciar NÃO — e isto é uma decisão, não um esquecimento.
// `systemctl start nftables` roda `nft -f /etc/nftables.conf` por cima do
// ruleset que o LinkGuard acabou de montar em memória (o arquivo, nesse
// instante, é no máximo o snapshot do boot anterior). Pior: o unit do Debian
// declara `ExecStop=/usr/sbin/nft flush ruleset`, então deixar a unidade
// ATIVA faz com que qualquer stop/restart posterior — um `apt upgrade` do
// próprio pacote nftables faz exatamente isso — apague o ruleset inteiro da
// máquina, tabelas de terceiros incluídas, sem um reboot para se recuperar.
// A unidade só precisa estar habilitada: quem a executa é o próximo boot,
// onde ela é a única coisa carregando regras e o arquivo é a autoridade.
func TestEnsureNuncaIniciaAUnidadeDoNftables(t *testing.T) {
	exec := newFakeExec()

	Ensure(context.Background(), exec, &fakeAlerter{})

	for _, c := range exec.executed {
		if strings.Contains(c, "systemctl start nftables") ||
			strings.Contains(c, "systemctl restart nftables") ||
			strings.Contains(c, "enable --now") {
			t.Errorf("a unidade do nftables foi INICIADA: %q — isso recarrega "+
				"/etc/nftables.conf por cima do ruleset vivo e deixa um ExecStop=`nft flush "+
				"ruleset` armado. Executados: %v", c, exec.executed)
		}
	}
}

// Dry-run não muda a máquina, e habilitar unidade é mudar a máquina.
func TestEnsureNaoHabilitaNadaEmDryRun(t *testing.T) {
	exec := newFakeExec(allBase()...)
	exec.dryRun = true
	exec.unitState["nftables"] = "disabled"

	Ensure(context.Background(), exec, &fakeAlerter{})

	if exec.ran("systemctl enable") {
		t.Errorf("dry-run habilitou unidade: %v", exec.executed)
	}
}

// Unidade mascarada é decisão explícita de quem administra a máquina (e
// `systemctl enable` numa unidade mascarada falha de qualquer jeito): não se
// insiste, não se executa nada.
func TestEnsureNaoInsisteComUnidadeMascarada(t *testing.T) {
	exec := newFakeExec(allBase()...)
	exec.unitState["nftables"] = "masked"

	Ensure(context.Background(), exec, &fakeAlerter{})

	if exec.ran("systemctl enable") {
		t.Errorf("tentou habilitar uma unidade mascarada: %v", exec.executed)
	}
}

// Sem o pacote não existe unidade para habilitar — tentar só produziria um
// erro no log, no boot em que o admin já está vendo o alerta de base
// ausente.
func TestEnsureNaoTentaHabilitarSemOPacote(t *testing.T) {
	exec := newFakeExec()
	exec.installFails = true

	if done := Ensure(context.Background(), exec, &fakeAlerter{}); done {
		t.Fatal("Ensure devia relatar que a base continua incompleta")
	}
	if exec.ran("systemctl enable") {
		t.Errorf("tentou habilitar a unidade sem o pacote instalado: %v", exec.executed)
	}
}
