package keaunbound

import (
	"context"
	"encoding/json"
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
}

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.writes = append(e.writes, cmd+" "+strings.Join(args, " "))
	return "", nil
}
func (e *recExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
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

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil); err != nil {
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

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil); err != nil {
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

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil, nil); err == nil {
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

func TestGenerateKeaConfigValidJSON(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	res := []netsvc.Reservation{{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.3.50", Hostname: "pc-joao"}}
	out := GenerateKeaConfig(cfg, res)

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
	s := NewService(&recExec{})
	s.resolvConf = resolv
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf()

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
	s := NewService(&recExec{})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf()

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
	s := NewService(&recExec{})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf()
	s.EnsureResolvConf()

	got, err := os.ReadFile(s.dhclientConf)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := strings.Count(string(got), "supersede domain-name-servers"); n != 1 {
		t.Errorf("supersede directive appears %d times, want 1:\n%s", n, got)
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
