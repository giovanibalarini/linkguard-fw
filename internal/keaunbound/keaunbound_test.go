package keaunbound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	// unboundCheckMissing simulates the checker binary not being installed
	// (Debian ships unbound as Recommends:, so unbound-checkconf may be
	// absent even when this project is). unboundCheckPath records the file
	// path validateUnbound passed to the checker.
	unboundCheckErr     error
	unboundCheckMissing bool
	unboundCheckPath    string
}

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.writes = append(e.writes, cmd+" "+strings.Join(args, " "))
	return "", nil
}
func (e *recExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
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
		if e.unboundCheckMissing {
			// Mirrors firewall.RealExecutor's wrapping of a LookPath/fork-exec
			// failure for a binary that doesn't exist — see isMissingBinary.
			return "", fmt.Errorf("command %q failed: exec: %q: executable file not found in $PATH", cmd+" "+strings.Join(args, " "), cmd)
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
	if !strings.Contains(joined, "systemctl reload-or-restart unbound") {
		t.Errorf("missing unbound reload-or-restart; writes:\n%s", joined)
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
// project.
func TestReloadConfigsProceedsWhenUnboundCheckconfMissing(t *testing.T) {
	e := &recExec{unboundCheckMissing: true}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil, ""); err != nil {
		t.Fatalf("ReloadConfigs should proceed when unbound-checkconf is missing: %v", err)
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("unbound config should still be written when the checker is merely absent")
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl reload-or-restart unbound") {
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
	out := GenerateUnboundConfig(cfg, []string{"ads.example.com"})
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
	out := GenerateUnboundConfig(cfg, nil)
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
	out := GenerateUnboundConfig(cfg, []string{"good.example.com", malicious})

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
	out := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "include:") {
		t.Errorf("injected directive via domain_suffix reached unbound.conf:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidGateway: Gateway feeds the
// `interface:` directive by string concatenation.
func TestGenerateUnboundConfigSkipsInvalidGateway(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Gateway = "192.168.3.3\ninterface: 0.0.0.0"
	out := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "interface: 0.0.0.0") {
		t.Errorf("injected interface directive via gateway reached unbound.conf:\n%s", out)
	}
	// The always-present loopback interface line must still be there.
	if !strings.Contains(out, "interface: 127.0.0.1") {
		t.Errorf("loopback interface line missing:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidSubnetCIDR: SubnetCIDR feeds the
// `access-control:` directive by string concatenation.
func TestGenerateUnboundConfigSkipsInvalidSubnetCIDR(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.SubnetCIDR = "192.168.3.0/24 allow\naccess-control: 0.0.0.0/0"
	out := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "access-control: 0.0.0.0/0") {
		t.Errorf("injected access-control directive via subnet_cidr reached unbound.conf:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidUpstream: Upstreams feed
// `forward-addr:` lines by string concatenation.
func TestGenerateUnboundConfigSkipsInvalidUpstream(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "evil\nforward-addr: 6.6.6.6"}
	out := GenerateUnboundConfig(cfg, nil)

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
