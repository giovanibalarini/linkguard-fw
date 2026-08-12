package keaunbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

// recExec records write commands and lets tests control the kea config-test.
type recExec struct {
	writes      []string
	keaTestErr  error  // returned by `kea-dhcp4 -t` if set
	keaTestPath string // records the file path validateKea passed to `-t`

	// unboundEnabled controls the answer to `systemctl is-enabled unbound`,
	// which EnsureResolvConf gates on: unbound is only Recommends: in the
	// package, so on a box without it (or where it failed to start) taking
	// over resolv.conf would knock out the box's own name resolution.
	unboundEnabled bool

	// unboundCheckErr, when set, is returned by `unbound-checkconf <file>`.
	// unboundCheckPath records the file path validateUnbound passed to the
	// checker (empty when the checker was never run — which is how a test
	// tells "skipped because absent" from "ran and passed"). A missing
	// checker is no longer simulated here: it is a property of the binary
	// path the Service holds, not of what the executor answers (I-6).
	unboundCheckErr  error
	unboundCheckPath string

	// missingPkgs is dpkg's view of the box: the packages it reports as NOT
	// installed. Default (nil) is a machine that already has kea and unbound,
	// so every test that is about the apply itself exercises the apply and
	// not the install. A test that wants the bare-machine case names the
	// packages here.
	//
	// installFails makes apt-get unable to resolve anything (no network, dead
	// mirror), which is the honesty path: LinkGuard has to say what is
	// missing instead of failing opaquely.
	missingPkgs  map[string]bool
	installFails bool
}

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	e.writes = append(e.writes, full)
	if strings.Contains(full, "apt-get install") {
		if e.installFails {
			return "", errors.New("E: Unable to locate package")
		}
		for _, a := range args {
			delete(e.missingPkgs, a)
		}
	}
	return "", nil
}
func (e *recExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "dpkg-query" && len(args) > 0 {
		pkg := args[len(args)-1]
		if e.missingPkgs[pkg] {
			return "", fmt.Errorf("dpkg-query: no packages found matching %s", pkg)
		}
		return "install ok installed", nil
	}
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-enabled" && args[1] == "unbound" {
		if e.unboundEnabled {
			return "enabled\n", nil
		}
		// mirrors systemctl's real behaviour: non-zero exit, "disabled" (or
		// a "no such unit" error) on stdout/stderr either way.
		return "disabled\n", fmt.Errorf("unit unbound.service is not enabled")
	}
	if strings.Contains(cmd, "unbound-checkconf") {
		if len(args) > 0 {
			e.unboundCheckPath = args[0]
		}
		if e.unboundCheckErr != nil {
			return "config error", e.unboundCheckErr
		}
		return "ok", nil
	}
	if len(args) >= 2 && args[0] == "-t" { // kea-dhcp4 -t <file>
		e.keaTestPath = args[1]
		if e.keaTestErr != nil {
			return "config error", e.keaTestErr
		}
		return "ok", nil
	}
	return "", nil
}
func (e *recExec) IsDryRun() bool { return false }

func newTestSvc(t *testing.T, e *recExec) *Service {
	t.Helper()
	dir := t.TempDir()
	s := NewService(e)
	s.keaConf = filepath.Join(dir, "kea-dhcp4.conf")
	s.unboundConf = filepath.Join(dir, "unbound.conf")
	// O checker é resolvido no sistema de arquivos antes de rodar (I-6),
	// então um serviço de teste precisa apontar para um arquivo que existe
	// de verdade: "instalado" e "ausente" viraram estados distintos, não
	// mais um palpite sobre o texto do erro. A máquina que roda o teste não
	// precisa ter o unbound instalado.
	s.unboundCheckBin = filepath.Join(dir, "unbound-checkconf")
	if err := os.WriteFile(s.unboundCheckBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("criar checker falso: %v", err)
	}
	return s
}

func TestReloadConfigsValidatesWritesAndReloads(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	// Config files written.
	if _, err := os.Stat(s.keaConf); err != nil {
		t.Error("kea config not written")
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("unbound config not written")
	}
	// Services reloaded via the canonical, systemd-tracked reload-or-restart.
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl reload-or-restart kea-dhcp4-server") {
		t.Errorf("missing kea reload-or-restart; writes:\n%s", joined)
	}
	// unbound gets a real restart here, not the graceful reload: this apply
	// is the first time the LinkGuard drop-in exists, so the running daemon
	// has never had these `interface:` lines — and SIGHUP does not re-open
	// listening sockets (see unboundNeedsRestart).
	if !strings.Contains(joined, "systemctl restart unbound") {
		t.Errorf("missing unbound restart on the first apply; writes:\n%s", joined)
	}
}

// TestValidateKeaWritesTempFileNextToRealConfig is the regression test for a
// real production bug: the validate temp file used to go to os.TempDir()
// (/tmp), but Debian's kea-dhcp4 AppArmor profile only allows reading under
// /etc/kea/ — kea-dhcp4 -t failed with "Unable to open file" on every real
// apply. The fix creates the temp file next to s.keaConf instead.
func TestValidateKeaWritesTempFileNextToRealConfig(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if e.keaTestPath == "" {
		t.Fatal("kea-dhcp4 -t was never called")
	}
	wantDir := filepath.Dir(s.keaConf)
	if gotDir := filepath.Dir(e.keaTestPath); gotDir != wantDir {
		t.Errorf("validate temp file dir = %q, want %q (same dir as the real kea config, readable by kea-dhcp4's AppArmor profile)", gotDir, wantDir)
	}
}

// TestEnsureKeaDirReadableRelaxesRestrictivePermissions is the regression
// test for a real production bug: Debian's kea-dhcp-server package ships
// /etc/kea owned _kea:_kea mode 0750. kea-dhcp4's AppArmor profile grants
// path-based read access under /etc/kea/** but not the dac_override/
// dac_read_search capabilities needed to bypass that Unix DAC restriction —
// so even root (LinkGuard, and kea-dhcp4 itself at its own startup) got
// "Unable to open file" reading a config that both the file permissions
// (0644) and the AppArmor path rule allowed, because the *directory* blocked
// the traversal first. LinkGuard owns this the same way it owns nftables
// bootstrap/ip_forward/conntrack accounting: self-heals on every start
// regardless of what a package reinstall resets it to.
func TestEnsureKeaDirReadableRelaxesRestrictivePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("Chmod setup: %v", err)
	}
	s := NewService(&recExec{})
	s.keaConf = filepath.Join(dir, "kea-dhcp4.conf")

	s.EnsureKeaDirReadable()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("dir mode = %o, want %o", got, 0o755)
	}
}

func TestReloadConfigsAbortsOnInvalidKeaConfig(t *testing.T) {
	e := &recExec{keaTestErr: assertErr2{}}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err == nil {
		t.Fatal("expected error when kea config test fails")
	}
	// No reload, and the production config file must NOT be written.
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("must not reload when config validation fails")
	}
	if _, err := os.Stat(s.keaConf); err == nil {
		t.Error("must not write kea config when validation fails")
	}
}

type assertErr2 struct{}

func (assertErr2) Error() string { return "kea config invalid" }

// ─── Finding 3 (S1): ReloadConfigs must validate the unbound candidate with
// unbound-checkconf before writing it, mirroring validateKea exactly —
// nothing written or reloaded on failure, same temp-file-next-to-the-real-
// config placement, and a missing checker must not block the DHCP/DNS
// apply. Regression tests for .superpowers/sdd/input-validation-audit.md
// finding #3.

// TestReloadConfigsAbortsOnInvalidUnboundConfig is the unbound-side sibling
// of TestReloadConfigsAbortsOnInvalidKeaConfig: an unbound config that fails
// unbound-checkconf must abort the whole reload with NEITHER file written
// and no service reloaded — a broken unbound.conf must never land on disk,
// since it would survive the next reboot and take DNS down (see this
// finding's motivating incident in the task brief).
func TestReloadConfigsAbortsOnInvalidUnboundConfig(t *testing.T) {
	e := &recExec{unboundCheckErr: fmt.Errorf("unbound config invalid")}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err == nil {
		t.Fatal("expected error when unbound config test fails")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("must not reload when unbound config validation fails")
	}
	if _, err := os.Stat(s.unboundConf); err == nil {
		t.Error("must not write unbound config when validation fails")
	}
	if _, err := os.Stat(s.keaConf); err == nil {
		t.Error("must not write kea config either — nothing is applied when any candidate is invalid")
	}
}

// TestValidateUnboundWritesTempFileNextToRealConfig mirrors
// TestValidateKeaWritesTempFileNextToRealConfig: the temp file must live in
// the same directory as the real unbound config, matching validateKea's
// AppArmor-driven placement so both validators behave identically even
// though unbound-checkconf itself has no comparable confinement on Debian.
func TestValidateUnboundWritesTempFileNextToRealConfig(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if e.unboundCheckPath == "" {
		t.Fatal("unbound-checkconf was never called")
	}
	wantDir := filepath.Dir(s.unboundConf)
	if gotDir := filepath.Dir(e.unboundCheckPath); gotDir != wantDir {
		t.Errorf("validate temp file dir = %q, want %q (same dir as the real unbound config)", gotDir, wantDir)
	}
}

// TestReloadConfigsProceedsWhenUnboundCheckconfMissing: unbound-checkconf
// not being installed must not block DHCP/DNS apply — Debian's unbound
// package (and its checker) is a Recommends:, not a Depends:, of this
// project. The absence is now established by resolving the binary (I-6),
// not by reading the error text of a command that did run, so the test
// points the service at a path that does not exist instead of asking the
// fake executor to imitate a "not found" message.
func TestReloadConfigsProceedsWhenUnboundCheckconfMissing(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.unboundCheckBin = filepath.Join(t.TempDir(), "unbound-checkconf") // nunca criado

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs should proceed when unbound-checkconf is missing: %v", err)
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("unbound config should still be written when the checker is merely absent")
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl restart unbound") && !strings.Contains(joined, "systemctl reload-or-restart unbound") {
		t.Errorf("unbound should still be reloaded when the checker is merely absent; writes:\n%s", joined)
	}
}

func TestGenerateKeaConfigValidJSON(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	res := []netsvc.Reservation{{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.3.50", Hostname: "pc-joao"}}
	out := GenerateKeaConfig(cfg, res, "")

	// Strip the leading // comment line, the rest must be valid JSON.
	jsonPart := out[strings.Index(out, "{"):]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("kea config is not valid JSON: %v\n%s", err, out)
	}
	dhcp4, ok := parsed["Dhcp4"].(map[string]any)
	if !ok {
		t.Fatal("missing Dhcp4 root")
	}
	subnets := dhcp4["subnet4"].([]any)
	sn := subnets[0].(map[string]any)
	if sn["subnet"] != "192.168.3.0/24" {
		t.Errorf("wrong subnet: %v", sn["subnet"])
	}
	pool := sn["pools"].([]any)[0].(map[string]any)["pool"]
	if pool != "192.168.3.10 - 192.168.3.100" {
		t.Errorf("wrong pool: %v", pool)
	}
	rs := sn["reservations"].([]any)[0].(map[string]any)
	if rs["hw-address"] != "aa:bb:cc:dd:ee:ff" || rs["ip-address"] != "192.168.3.50" {
		t.Errorf("wrong reservation: %v", rs)
	}
	if dhcp4["valid-lifetime"].(float64) != 43200 { // 12h
		t.Errorf("wrong valid-lifetime: %v", dhcp4["valid-lifetime"])
	}
}

// optionData extracts the option-data list of the first subnet, for
// asserting on individual DHCP options by name.
func optionData(t *testing.T, out string) []map[string]any {
	t.Helper()
	jsonPart := out[strings.Index(out, "{"):]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("kea config is not valid JSON: %v\n%s", err, out)
	}
	dhcp4 := parsed["Dhcp4"].(map[string]any)
	sn := dhcp4["subnet4"].([]any)[0].(map[string]any)
	opts := sn["option-data"].([]any)
	out2 := make([]map[string]any, len(opts))
	for i, o := range opts {
		out2[i] = o.(map[string]any)
	}
	return out2
}

// TestGenerateKeaConfigEmitsNTPServersOptionWhenSet: passing the firewall's
// LAN IP as ntpServer must render DHCP option 42 (ntp-servers) pointing at
// it, alongside the existing routers/domain-name-servers options — spec §5.
func TestGenerateKeaConfigEmitsNTPServersOptionWhenSet(t *testing.T) {
	cfg := netsvc.DefaultConfig() // Gateway: 192.168.3.3
	out := GenerateKeaConfig(cfg, nil, "192.168.3.3")

	found := false
	for _, o := range optionData(t, out) {
		if o["name"] == "ntp-servers" {
			found = true
			if o["data"] != "192.168.3.3" {
				t.Errorf("ntp-servers data = %v, want 192.168.3.3", o["data"])
			}
		}
	}
	if !found {
		t.Errorf("expected an ntp-servers option; got options: %v\n%s", optionData(t, out), out)
	}
}

// TestGenerateKeaConfigOmitsNTPServersOptionWhenEmpty: the empty string is
// "not serving" — no ntp-servers option at all, matching today's behaviour
// exactly (additive feature, off by default).
func TestGenerateKeaConfigOmitsNTPServersOptionWhenEmpty(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	out := GenerateKeaConfig(cfg, nil, "")

	for _, o := range optionData(t, out) {
		if o["name"] == "ntp-servers" {
			t.Errorf("expected no ntp-servers option when ntpServer is empty; got: %v", o)
		}
	}
	// Still valid JSON (same pattern as TestGenerateKeaConfigValidJSON).
	jsonPart := out[strings.Index(out, "{"):]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("kea config is not valid JSON: %v\n%s", err, out)
	}
}

func TestGenerateUnboundConfigRecursiveByDefault(t *testing.T) {
	cfg := netsvc.DefaultConfig() // empty upstreams = recursive
	out, _, _ := GenerateUnboundConfig(cfg, []string{"ads.example.com"})
	wants := []string{
		"server:",
		"interface: 192.168.3.3",
		"interface: 127.0.0.1",
		"access-control: 192.168.3.0/24 allow",
		"num-threads: 2",
		"local-zone: \"ads.example.com.\" always_nxdomain",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("unbound config missing %q\n--- got ---\n%s", w, out)
		}
	}
	if strings.Contains(out, "forward-zone") {
		t.Errorf("default should be recursive (no forward-zone)\n%s", out)
	}
	if strings.Contains(out, "log-queries") {
		t.Errorf("log-queries should be off by default")
	}
}

func TestGenerateUnboundConfigForwarding(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "8.8.8.8"}
	out, _, _ := GenerateUnboundConfig(cfg, nil)
	for _, w := range []string{"forward-zone:", "forward-addr: 1.1.1.1", "forward-addr: 8.8.8.8"} {
		if !strings.Contains(out, w) {
			t.Errorf("forwarding config missing %q\n%s", w, out)
		}
	}
}

// ─── Finding 1 (S1): GenerateUnboundConfig must revalidate every DB-sourced
// value at render time, not trust that the handler-level validator already
// ran (a restored backup, or a row written under an older/laxer rule,
// reaches this function with no handler in between). Regression tests for
// .superpowers/sdd/input-validation-audit.md finding #2/#3 (systemic
// pattern #4).

// TestGenerateUnboundConfigSkipsInjectedBlocklistEntry: a blocklist entry
// carrying a newline plus a directive must never reach unbound.conf — it
// must be dropped (not crash the render, not take down the other, valid
// entries), exactly like nftables.sanitizeNetworks and
// timesync.GenerateChronyConf already do for their own admin-supplied
// lists.
func TestGenerateUnboundConfigSkipsInjectedBlocklistEntry(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	malicious := "evil.com.\"\ninclude: \"/etc/passwd"
	out, _, _ := GenerateUnboundConfig(cfg, []string{"good.example.com", malicious})

	if strings.Contains(out, "include:") {
		t.Errorf("injected directive reached unbound.conf:\n%s", out)
	}
	if strings.Contains(out, malicious) {
		t.Errorf("malicious blocklist entry was rendered verbatim:\n%s", out)
	}
	if !strings.Contains(out, `local-zone: "good.example.com." always_nxdomain`) {
		t.Errorf("valid blocklist entry must still be rendered even though a sibling entry was bad:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidDomainSuffix: domain_suffix is
// concatenated straight into a local-zone directive too — a value with a
// newline must be dropped rather than injected.
func TestGenerateUnboundConfigSkipsInvalidDomainSuffix(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.DomainSuffix = "lan\"\ninclude: \"/etc/passwd"
	out, _, _ := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "include:") {
		t.Errorf("injected directive via domain_suffix reached unbound.conf:\n%s", out)
	}
}

// TestGenerateUnboundConfigRejectsInvalidGateway: Gateway feeds the
// `interface:` directive by string concatenation. The injected value must
// never reach unbound.conf — and, since I-7, it does not get there by the
// directive being quietly dropped (which would leave unbound listening on
// 127.0.0.1 alone, DNS dead for the LAN, apply reporting success) but by
// the render failing outright.
func TestGenerateUnboundConfigRejectsInvalidGateway(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Gateway = "192.168.3.3\ninterface: 0.0.0.0"
	out, _, err := GenerateUnboundConfig(cfg, nil)

	if err == nil {
		t.Fatalf("esperava falha de renderização, obtive:\n%s", out)
	}
	if strings.Contains(out, "interface: 0.0.0.0") {
		t.Errorf("injected interface directive via gateway reached unbound.conf:\n%s", out)
	}
}

// TestGenerateUnboundConfigRejectsInvalidSubnetCIDR: SubnetCIDR feeds the
// `access-control:` directive by string concatenation. Same reasoning as
// the gateway above — dropping it alone would leave the LAN with no
// access-control line at all, i.e. no DNS.
func TestGenerateUnboundConfigRejectsInvalidSubnetCIDR(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.SubnetCIDR = "192.168.3.0/24 allow\naccess-control: 0.0.0.0/0"
	out, _, err := GenerateUnboundConfig(cfg, nil)

	if err == nil {
		t.Fatalf("esperava falha de renderização, obtive:\n%s", out)
	}
	if strings.Contains(out, "access-control: 0.0.0.0/0") {
		t.Errorf("injected access-control directive via subnet_cidr reached unbound.conf:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidUpstream: Upstreams feed
// `forward-addr:` lines by string concatenation.
func TestGenerateUnboundConfigSkipsInvalidUpstream(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "evil\nforward-addr: 6.6.6.6"}
	out, _, _ := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "6.6.6.6") {
		t.Errorf("injected forward-addr via upstreams reached unbound.conf:\n%s", out)
	}
	if !strings.Contains(out, "forward-addr: 1.1.1.1") {
		t.Errorf("valid upstream must still be rendered even though a sibling entry was bad:\n%s", out)
	}
}

// TestEnsureResolvConfLeavesResolverAloneWhenUnboundNotEnabled: unbound is
// only `Recommends:` in the package, never `Depends:` — on a box without it
// installed (or where it failed to start), EnsureResolvConf must not touch
// either file. Seizing resolv.conf would knock out the box's own name
// resolution (updater, Telegram/webhook notifications, the AI digest,
// chrony pool hostnames) with no local resolver to fall back on.
func TestEnsureResolvConfLeavesResolverAloneWhenUnboundNotEnabled(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	resolvSeed := "nameserver 189.40.0.1\nnameserver 189.40.0.2\n"
	if err := os.WriteFile(resolv, []byte(resolvSeed), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}
	dhclient := filepath.Join(dir, "dhclient.conf")
	dhclientSeed := "send host-name = gethostname();\n"
	if err := os.WriteFile(dhclient, []byte(dhclientSeed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}

	s := NewService(&recExec{unboundEnabled: false})
	s.resolvConf = resolv
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	gotResolv, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("ReadFile resolv.conf: %v", err)
	}
	if string(gotResolv) != resolvSeed {
		t.Errorf("resolv.conf was modified with unbound not enabled:\ngot:  %q\nwant: %q", gotResolv, resolvSeed)
	}
	gotDhclient, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile dhclient.conf: %v", err)
	}
	if string(gotDhclient) != dhclientSeed {
		t.Errorf("dhclient.conf was modified with unbound not enabled:\ngot:  %q\nwant: %q", gotDhclient, dhclientSeed)
	}
}

// TestEnsureResolvConfPointsAtLocalUnbound is the regression test for a real
// production finding on 2026-08-10: /etc/resolv.conf pointed at the ISP's
// nameservers instead of the local unbound. Nothing in the codebase managed
// that file at all — the WAN's dhclient rewrites it on every lease renewal —
// so the appliance silently stopped using its own resolver (losing the DNS
// blocklist and query visibility that unbound provides).
func TestEnsureResolvConfPointsAtLocalUnbound(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 189.40.0.1\nnameserver 189.40.0.2\n"), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = resolv
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "nameserver 127.0.0.1") {
		t.Errorf("resolv.conf does not point at the local resolver:\n%s", got)
	}
	if strings.Contains(string(got), "189.40.0.1") {
		t.Errorf("ISP nameserver survived:\n%s", got)
	}
	if !strings.Contains(string(got), "# managed by linkguard") {
		t.Errorf("missing the managed-by header:\n%s", got)
	}
}

// TestEnsureResolvConfSupersedesDhclient: rewriting resolv.conf alone is not
// enough — the next DHCP lease renewal would overwrite it again. The fix has
// to tell dhclient itself to stop proposing the ISP's servers.
func TestEnsureResolvConfSupersedesDhclient(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	if err := os.WriteFile(dhclient, []byte("send host-name = gethostname();\n"), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the supersede directive:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfDoesNotDuplicateSupersede: it runs on every boot, so a
// second run must not keep appending the same line.
func TestEnsureResolvConfDoesNotDuplicateSupersede(t *testing.T) {
	dir := t.TempDir()
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf(context.Background())
	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(s.dhclientConf)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := strings.Count(string(got), "supersede domain-name-servers"); n != 1 {
		t.Errorf("supersede directive appears %d times, want 1:\n%s", n, got)
	}
}

// countActiveSupersedeLines counts lines that actually take effect as a
// `supersede domain-name-servers` dhclient directive: leading whitespace is
// stripped, comment lines (starting with `#`) never count.
func countActiveSupersedeLines(content string) int {
	n := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "supersede" && fields[1] == "domain-name-servers" {
			n++
		}
	}
	return n
}

// TestEnsureResolvConfIgnoresCommentedOutSupersede is the false-positive case
// from the review: a commented-out directive (e.g. left over from a manual
// experiment) must NOT satisfy the idempotency check. A raw substring check
// matches it and returns early believing DNS is pinned, silently reproducing
// the exact production bug this feature exists to fix.
func TestEnsureResolvConfIgnoresCommentedOutSupersede(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\n# supersede domain-name-servers 127.0.0.1;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want 1 (commented line must not count):\n%s", n, got)
	}
	if !strings.Contains(string(got), "# supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("the original comment line must survive untouched:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfReplacesConflictingValue is the false-negative case
// from the review: an active directive for the same option but a different
// value (e.g. left by the ISP's dhclient defaults, or a stale manual edit)
// must be replaced in place, not left alongside a second, conflicting
// `supersede domain-name-servers` statement — dhclient treats two modifier
// statements for one option as at best last-wins, at worst a parse failure
// that breaks DHCP on that WAN at lease renewal.
func TestEnsureResolvConfReplacesConflictingValue(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\nsupersede domain-name-servers 8.8.8.8;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want exactly 1 (no duplicate/conflicting statement):\n%s", n, got)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the correct supersede directive:\n%s", got)
	}
	if strings.Contains(string(got), "8.8.8.8") {
		t.Errorf("conflicting ISP value survived:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfReplacesIrregularSpacing covers the same false-negative
// failure mode as above but triggered by whitespace instead of value: extra
// spaces between tokens still make the line an active
// `supersede domain-name-servers` statement, which a raw literal-string
// check misses.
func TestEnsureResolvConfReplacesIrregularSpacing(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\nsupersede  domain-name-servers   127.0.0.1;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want exactly 1 (no duplicate statement):\n%s", n, got)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the correctly formatted supersede directive:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

func TestParseKeaLeases(t *testing.T) {
	sample := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.3.50,aa:bb:cc:dd:ee:ff,,43200,1782500000,1,0,0,pc-joao,0,,0
192.168.3.61,11:22:33:44:55:66,,43200,1782500100,1,0,0,,0,,0
192.168.3.99,99:99:99:99:99:99,,43200,1782400000,1,0,0,old,1,,0
`
	got := ParseKeaLeases(sample)
	if len(got) != 2 { // the state=1 row is excluded
		t.Fatalf("expected 2 active leases, got %d: %+v", len(got), got)
	}
	if got[0].IP != "192.168.3.50" || got[0].Hostname != "pc-joao" || got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("lease 0 wrong: %+v", got[0])
	}
	if got[1].IP != "192.168.3.61" || got[1].Hostname != "" {
		t.Errorf("lease 1 wrong: %+v", got[1])
	}
}

// ─── I-5: o arquivo temporário de validação não pode cair no glob do unbound ──
//
// O unbound.conf do Debian faz `include-toplevel:
// "/etc/unbound/unbound.conf.d/*.conf"`, e é justamente esse diretório que
// o validador usa (mesmo sistema de arquivos que a config real). Se o
// processo morrer entre o CreateTemp e o Remove adiado, um sufixo .conf
// deixa para trás um segundo fragmento com `interface:`/`local-zone`
// duplicados — o unbound o carrega no próximo start e o DNS morre no boot
// seguinte, sem ninguém ter mexido em nada.
func TestValidateUnboundTempFileIsNotPickedUpByTheIncludeGlob(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if e.unboundCheckPath == "" {
		t.Fatal("unbound-checkconf nunca foi chamado")
	}
	if strings.HasSuffix(e.unboundCheckPath, ".conf") {
		t.Errorf("o temporário de validação não pode casar com o glob *.conf do include-toplevel, obtive %q", e.unboundCheckPath)
	}
}

// ─── I-6: uma rejeição real do checker não pode virar "checker ausente" ──────
//
// firewall.RealExecutor enfia o stderr do comando na string do erro, e
// muita mensagem legítima do unbound-checkconf cita um arquivo que falta
// ("... /var/lib/unbound/root.key: no such file or directory"). Casar essa
// substring em qualquer lugar do erro transformava a rejeição em "o
// checker não existe, siga em frente": fail-open numa validação cujo
// propósito inteiro é fail-closed.
func TestReloadConfigsFailsClosedWhenCheckerRejectsWithAMissingFileMessage(t *testing.T) {
	e := &recExec{unboundCheckErr: fmt.Errorf(`[1234:0] fatal error: /var/lib/unbound/root.key: no such file or directory`)}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err == nil {
		t.Fatal("uma rejeição do unbound-checkconf tem que abortar o apply, mesmo citando arquivo ausente")
	}
	if _, err := os.Stat(s.unboundConf); err == nil {
		t.Error("nada pode ser escrito quando a validação reprova")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("nada pode ser recarregado quando a validação reprova")
	}
}

// O outro lado da mesma moeda: com o checker de fato ausente (o pacote
// unbound é Recommends:, não Depends:), a validação é pulada e o apply
// segue — e o checker nem chega a ser executado.
func TestReloadConfigsSkipsValidationWhenCheckerIsReallyAbsent(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.unboundCheckBin = filepath.Join(t.TempDir(), "nao-existe", "unbound-checkconf")

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("checker ausente não pode bloquear o apply: %v", err)
	}
	if e.unboundCheckPath != "" {
		t.Errorf("um checker inexistente não devia nem ser executado, mas recebeu %q", e.unboundCheckPath)
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("a config devia ser escrita mesmo sem validação possível")
	}
}

// ─── I-7: campo singular inválido derruba o apply; entradas de lista contam ──
//
// Descartar o Gateway deixa o unbound ouvindo só em 127.0.0.1 e descartar
// a SubnetCIDR deixa a LAN sem access-control: nos dois casos sai uma
// config VÁLIDA (o unbound-checkconf aprova) que mata o DNS do escritório
// em silêncio, enquanto o apply reporta sucesso e o painel segue exibindo
// os valores configurados. "Pular e logar" só é a estratégia certa para
// entrada de lista, onde uma entrada ruim não pode afundar as boas.
func TestGenerateUnboundConfigFailsOnInvalidGateway(t *testing.T) {
	c := netsvc.DefaultConfig()
	c.Gateway = "192.168.3.3; evil"
	if _, _, err := GenerateUnboundConfig(c, nil); err == nil {
		t.Fatal("um gateway inválido tem que derrubar o apply, não sair do unbound.conf em silêncio")
	}
}

func TestGenerateUnboundConfigFailsOnInvalidSubnetCIDR(t *testing.T) {
	c := netsvc.DefaultConfig()
	c.SubnetCIDR = "não é cidr"
	if _, _, err := GenerateUnboundConfig(c, nil); err == nil {
		t.Fatal("uma sub-rede inválida tem que derrubar o apply: sem access-control a LAN inteira perde o DNS")
	}
}

func TestReloadConfigsAbortsWhenASingularUnboundFieldIsInvalid(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	c.Gateway = "192.168.3.3; evil"

	if _, err := s.ReloadConfigs(context.Background(), c, nil, nil, ""); err == nil {
		t.Fatal("ReloadConfigs tinha que falhar com um campo singular inválido")
	}
	if _, err := os.Stat(s.unboundConf); err == nil {
		t.Error("nada pode ser escrito quando a renderização reprova")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("nada pode ser recarregado quando a renderização reprova")
	}
}

// Entradas de lista continuam sendo puladas — mas contadas, e a contagem
// sai do apply para o painel poder mostrar. Sem isso, a blocklist encolhia
// em silêncio e o apply dizia "ok".
func TestReloadConfigsReportsSkippedListEntries(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	c.Upstreams = []string{"1.1.1.1", "não-é-ip"}

	res, err := s.ReloadConfigs(context.Background(), c, nil, []string{"ads.example.com", "domínio inválido!"}, "")
	if err != nil {
		t.Fatalf("uma entrada de lista ruim não pode afundar as boas: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("as entradas descartadas têm que sair no resultado do apply, não só no journal")
	}
	joined := strings.Join(res.Warnings, " | ")
	if !strings.Contains(joined, "1") {
		t.Errorf("o aviso tem que trazer a contagem das descartadas, obtive %q", joined)
	}
	content, rErr := os.ReadFile(s.unboundConf)
	if rErr != nil {
		t.Fatalf("a config devia ter sido escrita: %v", rErr)
	}
	if !strings.Contains(string(content), "forward-addr: 1.1.1.1") || !strings.Contains(string(content), "ads.example.com") {
		t.Errorf("as entradas válidas têm que continuar sendo renderizadas:\n%s", content)
	}
}

// ─── Instalação sob demanda (kea-dhcp4-server / unbound) ─────────────────────

// O defeito que originou esta funcionalidade: numa máquina onde o
// kea-dhcp4-server nunca foi instalado, ligar o DHCP pelo painel morria em
// `open /etc/kea/kea-validate-*.conf: no such file or directory` — o
// diretório só existia se algum humano tivesse rodado apt antes. A premissa
// do produto (FEATURES.md) é o contrário: instalar o LinkGuard é entregar a
// máquina a ele, e o pacote opcional entra quando o admin liga a
// funcionalidade.
func TestReloadConfigsInstallsMissingPackagesOnDemand(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{keaPackage: true}}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, "")
	if err != nil {
		t.Fatalf("ReloadConfigs numa máquina sem o kea: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "apt-get install") || !strings.Contains(joined, keaPackage) {
		t.Errorf("o pacote ausente tinha que ser instalado; comandos:\n%s", joined)
	}
	if len(res.Installed) != 1 || res.Installed[0] != keaPackage {
		t.Errorf("Installed = %v, quero [%s] (para o painel poder registrar a transição)", res.Installed, keaPackage)
	}
	if _, sErr := os.Stat(s.keaConf); sErr != nil {
		t.Errorf("depois de instalar, a config tinha que ser aplicada na mesma execução: %v", sErr)
	}
}

// O caminho normal — todo save de DHCP/DNS passa por aqui. Numa máquina já
// provisionada isso não pode custar um apt: só um dpkg-query por pacote.
func TestReloadConfigsDoesNotRunAptWhenThePackagesAreThere(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, "")
	if err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "apt-get") {
		t.Errorf("nada de apt numa máquina que já tem os pacotes: %v", e.writes)
	}
	if len(res.Installed) != 0 {
		t.Errorf("Installed = %v, quero vazio", res.Installed)
	}
}

// A regra do "não finge": se o pacote não está lá e não dá para instalar
// (sem rede, espelho fora do ar), a resposta tem que dizer o que falta, por
// quê, o que deixa de funcionar e como resolver na mão — e nada pode ser
// escrito nem recarregado.
func TestReloadConfigsExplainsAPackageItCouldNotInstall(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{keaPackage: true}, installFails: true}
	s := newTestSvc(t, e)

	_, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, "")
	if err == nil {
		t.Fatal("aplicar sem o pacote do DHCP tem que falhar, não fingir sucesso")
	}
	var pre *netsvc.PrereqError
	if !errors.As(err, &pre) {
		t.Fatalf("o erro tem que ser um netsvc.PrereqError (para a API não devolver 'erro interno'), obtive %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{keaPackage, "Unable to locate package", "DHCP", "apt-get install -y"} {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(msg, want) {
				t.Errorf("a mensagem tem que citar %q, obtive %q", want, msg)
			}
		})
	}
	if _, sErr := os.Stat(s.keaConf); sErr == nil {
		t.Error("nada pode ser escrito quando o pré-requisito falta")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Errorf("nada pode ser recarregado quando o pré-requisito falta: %v", e.writes)
	}
}

// A armadilha do systemd: ProtectSystem=strict monta o namespace no start do
// serviço, então um diretório que não existia naquele momento fica
// somente-leitura (ou invisível) para o processo em execução mesmo depois de
// o apt criá-lo. O postinst deste pacote cria /etc/kea e
// /etc/unbound/unbound.conf.d justamente para que isso não aconteça — mas se
// acontecer (instalação por `make install`, diretório apagado à mão), o
// admin tem que ler o que fazer, não um erro de escrita cru.
func TestReloadConfigsSaysToRestartWhenTheConfigDirIsOutsideTheSandbox(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.keaConf = filepath.Join(t.TempDir(), "nao-existe", "kea-dhcp4.conf")

	_, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, "")
	if err == nil {
		t.Fatal("escrever num diretório inacessível tem que falhar")
	}
	var pre *netsvc.PrereqError
	if !errors.As(err, &pre) {
		t.Fatalf("erro = %T (%v), quero um netsvc.PrereqError", err, err)
	}
	msg := err.Error()
	for _, want := range []string{filepath.Dir(s.keaConf), "Reinicie o serviço", "systemctl restart linkguard-fw"} {
		if !strings.Contains(msg, want) {
			t.Errorf("a mensagem tem que citar %q, obtive %q", want, msg)
		}
	}
}

// Depois de instalar o kea, o /etc/kea recém-criado pelo pacote vem 0750
// _kea:_kea e o próprio kea-dhcp4 não consegue ler a config lá dentro (bug
// real de produção, ver EnsureKeaDirReadable). Instalar sob demanda tem que
// arrumar isso na hora, não só no próximo boot.
func TestReloadConfigsRelaxesTheKeaDirAfterInstallingIt(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{keaPackage: true}}
	s := newTestSvc(t, e)
	dir := filepath.Dir(s.keaConf)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("modo do %s = %o, quero 0755 (senão o kea-dhcp4 não lê a própria config)", dir, info.Mode().Perm())
	}
}

// Visto na VM: unbound subiu quebrado uma vez (faltava a âncora DNSSEC), o
// systemd esgotou o contador de restart e, DEPOIS de a causa ser corrigida,
// todo apply passou a falhar com "Start request repeated too quickly" — uma
// mensagem que não fala do problema real e que só sai do lugar com um
// `systemctl reset-failed` no SSH. Limpar o estado de falha antes de
// recarregar devolve ao admin o erro verdadeiro (ou o serviço no ar).
func TestReloadConfigsClearsAFailedUnitBeforeReloading(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	for _, svc := range []string{keaService, unboundService} {
		reset := strings.Index(joined, "systemctl reset-failed "+svc)
		act := strings.Index(joined, "systemctl reload-or-restart "+svc)
		if act < 0 {
			act = strings.Index(joined, "systemctl restart "+svc)
		}
		if reset < 0 || act < 0 {
			t.Errorf("faltou o reset-failed ou a ação em %s; comandos:\n%s", svc, joined)
			continue
		}
		if reset > act {
			t.Errorf("o reset-failed de %s tem que vir antes de recarregar/reiniciar; comandos:\n%s", svc, joined)
		}
	}
}

// Medido na VM: o unbound recarregado com SIGHUP (o ExecReload que o pacote
// Debian traz) relê a config mas NÃO reabre os sockets de escuta. Numa
// instalação nova isso é garantido de dar errado: o pacote sobe o unbound
// escutando só em 127.0.0.1, o LinkGuard escreve o drop-in com
// `interface: <IP da LAN>`, recarrega — e o painel diz "aplicado" enquanto a
// LAN inteira fica sem DNS. Quando o endereço de escuta muda, tem que ser
// restart de verdade.
func TestReloadRestartsUnboundWhenTheListenAddressChanges(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	if err := os.WriteFile(s.unboundConf, []byte("server:\n  interface: 10.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("preparar config antiga: %v", err)
	}

	c := netsvc.DefaultConfig()
	c.Gateway = "192.168.3.3"
	if _, err := s.ReloadConfigs(context.Background(), c, nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl restart "+unboundService) {
		t.Errorf("mudou o endereço de escuta: o unbound precisa de restart, não de SIGHUP; comandos:\n%s", joined)
	}
}

// ...e o contrário: mexer só na blocklist não pode derrubar o resolvedor (e
// jogar fora o cache) a cada save. Aí o reload gracioso é o certo.
func TestReloadKeepsGracefulReloadWhenOnlyTheBlocklistChanges(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	if _, err := s.ReloadConfigs(context.Background(), c, nil, nil, ""); err != nil {
		t.Fatalf("primeiro apply: %v", err)
	}

	e.writes = nil
	if _, err := s.ReloadConfigs(context.Background(), c, nil, []string{"ads.example.com"}, ""); err != nil {
		t.Fatalf("segundo apply: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if strings.Contains(joined, "systemctl restart "+unboundService) {
		t.Errorf("nada mudou na escuta: derrubar o unbound (e o cache) por uma blocklist é caro demais;\n%s", joined)
	}
	if !strings.Contains(joined, "reload-or-restart "+unboundService) {
		t.Errorf("faltou o reload gracioso do unbound;\n%s", joined)
	}
}

// Instalação sob demanda: o pacote acabou de subir o unbound com a config
// padrão dele (só 127.0.0.1). Mesmo que o arquivo do LinkGuard já estivesse
// no lugar, o processo em execução não é o que leu esse arquivo.
func TestReloadRestartsUnboundRightAfterInstallingIt(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{unboundPackage: true}}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if !strings.Contains(strings.Join(e.writes, "\n"), "systemctl restart "+unboundService) {
		t.Errorf("o unbound recém-instalado tem que ser reiniciado para valer a config do LinkGuard;\n%s", strings.Join(e.writes, "\n"))
	}
}

// A instalação sob demanda tem que sair pelo executor de pacote, não pelo
// executor de 30s da aplicação. Os dois trabalhos não têm nada em comum: um
// `nft`/`systemctl` que não respondeu em 30s está travado; um apt-get
// baixando kea + unbound + dns-root-data (~10 MB) passa disso num link de
// escritório sem nada estar errado. E quando o prazo estourava, o apt não
// morria junto — a unidade transiente do systemd-run terminava a instalação
// — então o LinkGuard devolvia 503 "não conseguiu instalar" e criava alerta
// crítico enquanto o pacote entrava com sucesso.
func TestInstalacaoSobDemandaUsaOExecutorDePacote(t *testing.T) {
	appExec := &recExec{missingPkgs: map[string]bool{"kea-dhcp4-server": true, "unbound": true, "dns-root-data": true}}
	pkgExec := &recExec{missingPkgs: map[string]bool{"kea-dhcp4-server": true, "unbound": true, "dns-root-data": true}}

	s := newTestSvc(t, appExec)
	s.SetInstallExecutor(pkgExec)

	if _, err := s.ensurePackages(context.Background()); err != nil {
		t.Fatalf("ensurePackages: %v", err)
	}

	if !slices.ContainsFunc(pkgExec.writes, func(c string) bool { return strings.Contains(c, "apt-get install") }) {
		t.Errorf("o apt não saiu pelo executor de pacote; comandos: %v", pkgExec.writes)
	}
	if slices.ContainsFunc(appExec.writes, func(c string) bool { return strings.Contains(c, "apt-get install") }) {
		t.Errorf("o apt saiu pelo executor de 30s da aplicação; comandos: %v", appExec.writes)
	}
}
