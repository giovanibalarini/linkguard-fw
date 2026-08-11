package timesync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeExec is a minimal firewall.Executor test double dedicated to this
// package. Deliberately NOT internal/api/handlers' fakeNftExec — that fake
// returns "" for any non-nft command, which breaks this package's parsers
// (an empty string isn't valid input for "yes"/"no" checks or chronyc
// tracking parsing). This fake returns exactly the text each test
// configures per command.
type fakeExec struct {
	dryRun    bool
	responses map[string]string // "cmd arg1 arg2" -> ExecuteRead output
	execErr   error             // returned by Execute for every call, if set
	readErr   error             // returned by ExecuteRead for every call, if set
	executed  []string          // records every Execute call (not ExecuteRead)
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", e.execErr
}
func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if e.readErr != nil {
		return "", e.readErr
	}
	key := strings.Join(append([]string{cmd}, args...), " ")
	return e.responses[key], nil
}
func (e *fakeExec) IsDryRun() bool { return e.dryRun }

func containsExecuted(executed []string, want string) bool {
	for _, e := range executed {
		if e == want {
			return true
		}
	}
	return false
}

// TestEnsureEnabledCallsSystemctlWhenInstalled and the four tests below it
// pre-date the 2026-08-10 Service addition — carried over unchanged in
// intent (adapted to the new fakeExec's responses/executed shape) because
// EnsureEnabled/IsSynced themselves are explicitly unchanged by this
// feature and must keep their existing coverage.
func TestEnsureEnabledCallsSystemctlWhenInstalled(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"systemctl list-unit-files --no-legend chrony.service": "chrony.service                       enabled         enabled",
	}}
	EnsureEnabled(context.Background(), exec)
	if !containsExecuted(exec.executed, "systemctl enable --now chrony") {
		t.Fatalf("expected systemctl enable --now chrony to be called, got %v", exec.executed)
	}
}

func TestEnsureEnabledSkipsWhenNotInstalled(t *testing.T) {
	exec := &fakeExec{}
	EnsureEnabled(context.Background(), exec)
	if containsExecuted(exec.executed, "systemctl enable --now chrony") {
		t.Fatal("expected systemctl enable NOT to be called when chrony.service is absent")
	}
}

func TestIsSyncedTrue(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl show --property=NTPSynchronized --value": "yes\n",
	}}
	if !IsSynced(context.Background(), exec) {
		t.Fatal("expected IsSynced=true")
	}
}

func TestIsSyncedFalse(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl show --property=NTPSynchronized --value": "no\n",
	}}
	if IsSynced(context.Background(), exec) {
		t.Fatal("expected IsSynced=false")
	}
}

func TestIsSyncedErrorIsFalse(t *testing.T) {
	exec := &fakeExec{readErr: errBoom{}}
	if IsSynced(context.Background(), exec) {
		t.Fatal("expected IsSynced=false on exec error")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

// TestDefaultConfigServersIsEmptySliceNotNil is the regression test for the
// same class of bug already found once this session (internal/netif's
// stable-names GET handler): a nil slice marshals to JSON `null`, which
// crashes a frontend `.join(', ')`/`.map()` call expecting an array.
func TestDefaultConfigServersIsEmptySliceNotNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Servers == nil {
		t.Error("DefaultConfig().Servers is nil — would marshal as JSON null")
	}
}

func TestGenerateChronyConfRendersServersWithHeader(t *testing.T) {
	content := GenerateChronyConf(Config{Servers: []string{"192.36.143.130", "c.ntp.br"}})
	for _, want := range []string{
		"# managed by linkguard",
		"server 192.36.143.130 iburst",
		"server c.ntp.br iburst",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q:\n%s", want, content)
		}
	}
}

// TestGenerateChronyConfEmitsAllowWhenServing is Part 1's core new behavior:
// ServeLAN=true renders one `allow <cidr>` line per admin-chosen network —
// no longer implicitly the DHCP LAN subnet (spec §3.1).
func TestGenerateChronyConfEmitsAllowWhenServing(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}})
	if !strings.Contains(content, "allow 192.168.3.0/24") {
		t.Errorf("expected allow line for the configured CIDR:\n%s", content)
	}
}

// TestGenerateChronyConfEmitsOneAllowLinePerNetwork proves the admin's
// choice of multiple networks (VLAN, Wi-Fi, guest) all get their own allow
// line — the whole point of replacing the single implicit LAN subnet.
func TestGenerateChronyConfEmitsOneAllowLinePerNetwork(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24", "10.20.0.0/24", "192.168.50.0/24"}})
	for _, want := range []string{"allow 192.168.3.0/24", "allow 10.20.0.0/24", "allow 192.168.50.0/24"} {
		if !strings.Contains(content, want) {
			t.Errorf("content missing %q:\n%s", want, content)
		}
	}
}

// TestGenerateChronyConfOmitsAllowWhenNotServing: ServeLAN=false must never
// emit an allow line, even if networks are configured (defense in depth —
// the chrony drop-in must reflect the toggle, not just the list's presence).
func TestGenerateChronyConfOmitsAllowWhenNotServing(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: false, AllowedNetworks: []string{"192.168.3.0/24"}})
	if strings.Contains(content, "allow") {
		t.Errorf("expected no allow line when ServeLAN is false:\n%s", content)
	}
}

// TestGenerateChronyConfOmitsAllowWhenListEmpty: ServeLAN=true but an empty
// AllowedNetworks list is an explicit "nothing allowed" state (spec §3.1),
// never an implicit allow-all.
func TestGenerateChronyConfOmitsAllowWhenListEmpty(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: true})
	if strings.Contains(content, "allow") {
		t.Errorf("expected no allow line when the network list is empty:\n%s", content)
	}
}

// TestGenerateChronyConfRejectsInvalidCIDR: each entry is interpolated into
// a config file consumed by a daemon — an invalid value (e.g. injection
// attempt) must never reach the rendered output, even if other entries in
// the same list are valid.
func TestGenerateChronyConfRejectsInvalidCIDR(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: true, AllowedNetworks: []string{"not a cidr; evil", "192.168.3.0/24"}})
	if strings.Contains(content, "not a cidr") || strings.Contains(content, "evil") {
		t.Errorf("invalid CIDR reached the rendered output:\n%s", content)
	}
	if !strings.Contains(content, "allow 192.168.3.0/24") {
		t.Errorf("expected the valid entry to still be rendered:\n%s", content)
	}
}

// TestGenerateChronyConfRejectsOpenWildcard: 0.0.0.0/0 and ::/0 must never
// reach the rendered drop-in, even if an invalid value slipped past the
// handler-level ValidateAllowedNetworks somehow (defense in depth, spec
// §3.1's "guarda-corpo").
func TestGenerateChronyConfRejectsOpenWildcard(t *testing.T) {
	content := GenerateChronyConf(Config{ServeLAN: true, AllowedNetworks: []string{"0.0.0.0/0", "::/0"}})
	if strings.Contains(content, "allow") {
		t.Errorf("expected no allow line for open wildcards:\n%s", content)
	}
}

func TestReloadConfigWritesDropinWhenServersSet(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	err := s.ReloadConfig(context.Background(), Config{Servers: []string{"c.ntp.br"}})
	if err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "server c.ntp.br iburst") {
		t.Errorf("drop-in missing expected server line:\n%s", got)
	}
	if !containsExecuted(exec.executed, "systemctl reload-or-restart chrony") {
		t.Errorf("expected reload-or-restart chrony, got %v", exec.executed)
	}
}

func TestReloadConfigRemovesDropinWhenServersEmptyAndNotServing(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	if err := os.WriteFile(confPath, []byte("# managed by linkguard\nserver old.example iburst\n"), 0o644); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("expected drop-in removed when Servers is empty and ServeLAN is off, got err=%v", err)
	}
	if !containsExecuted(exec.executed, "systemctl reload-or-restart chrony") {
		t.Errorf("expected reload-or-restart chrony even when removing, got %v", exec.executed)
	}
}

// TestReloadConfigWritesDropinWhenServeLANOnlyNoCustomServers is the
// regression test for the easiest thing to get wrong here: ServeLAN=true
// with an empty (default-pool) Servers list is a very likely real
// combination, and the drop-in must still be written (for the `allow`
// line) instead of being removed as if nothing were configured.
func TestReloadConfigWritesDropinWhenServeLANOnlyNoCustomServers(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("expected drop-in to be written when ServeLAN is on even with no custom servers, got err=%v", err)
	}
	if !strings.Contains(string(got), "allow 192.168.3.0/24") {
		t.Errorf("drop-in missing allow line:\n%s", got)
	}
	if strings.Contains(string(got), "server ") {
		t.Errorf("drop-in should have no server lines (default pool unmanaged):\n%s", got)
	}
}

// TestReloadConfigWritesDropinWhenServeLANOnEvenWithEmptyList: ServeLAN=true
// with an empty AllowedNetworks list is still "something to manage" (an
// explicit nothing-allowed state, spec §3.1) — the drop-in must be written
// (with no allow line), not removed as if serving were fully unmanaged.
func TestReloadConfigWritesDropinWhenServeLANOnEvenWithEmptyList(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{ServeLAN: true}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("expected drop-in to be written when ServeLAN is on, got err=%v", err)
	}
	if strings.Contains(string(got), "allow") {
		t.Errorf("expected no allow line with an empty network list:\n%s", got)
	}
}

func TestReloadConfigRemovingAbsentDropinIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf") // never created
	s := &Service{exec: &fakeExec{}, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{}); err != nil {
		t.Fatalf("ReloadConfig on absent drop-in must be idempotent, got: %v", err)
	}
}

func TestReloadConfigSetsTimezoneWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: filepath.Join(dir, "linkguard.conf")}

	if err := s.ReloadConfig(context.Background(), Config{Timezone: "America/Sao_Paulo"}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if !containsExecuted(exec.executed, "timedatectl set-timezone America/Sao_Paulo") {
		t.Errorf("expected timedatectl set-timezone call, got %v", exec.executed)
	}
}

func TestReloadConfigNoopWriteInDryRun(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "linkguard.conf")
	s := &Service{exec: &fakeExec{dryRun: true}, confPath: confPath}

	if err := s.ReloadConfig(context.Background(), Config{Servers: []string{"c.ntp.br"}}); err != nil {
		t.Fatalf("ReloadConfig in dry-run: %v", err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("expected no file written in dry-run, got err=%v", err)
	}
}

// ─── ValidateAllowedNetworks ────────────────────────────────────────────

func TestValidateAllowedNetworksAcceptsValidCIDRs(t *testing.T) {
	if err := ValidateAllowedNetworks([]string{"192.168.3.0/24", "10.20.0.0/24"}); err != nil {
		t.Errorf("expected valid CIDRs to pass, got %v", err)
	}
}

func TestValidateAllowedNetworksAcceptsEmptyList(t *testing.T) {
	if err := ValidateAllowedNetworks(nil); err != nil {
		t.Errorf("expected an empty list to pass, got %v", err)
	}
}

func TestValidateAllowedNetworksRejectsInvalidCIDR(t *testing.T) {
	if err := ValidateAllowedNetworks([]string{"not-a-cidr"}); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
}

// TestValidateAllowedNetworksRejectsOpenIPv4Wildcard is the spec §3.1
// "guarda-corpo": 0.0.0.0/0 is almost certainly a mistake, not an informed
// choice, and is a known NTP amplification vector.
func TestValidateAllowedNetworksRejectsOpenIPv4Wildcard(t *testing.T) {
	if err := ValidateAllowedNetworks([]string{"0.0.0.0/0"}); err == nil {
		t.Error("expected 0.0.0.0/0 to be rejected")
	}
}

func TestValidateAllowedNetworksRejectsOpenIPv6Wildcard(t *testing.T) {
	if err := ValidateAllowedNetworks([]string{"::/0"}); err == nil {
		t.Error("expected ::/0 to be rejected")
	}
}

// TestValidateAllowedNetworksAcceptsAnyOtherRange proves the guard-rail is
// narrow: any range other than the full-open wildcard is the admin's call,
// including large ones like a /8 — no further paternalism (spec §3.1).
func TestValidateAllowedNetworksAcceptsAnyOtherRange(t *testing.T) {
	if err := ValidateAllowedNetworks([]string{"10.0.0.0/8"}); err != nil {
		t.Errorf("expected a large-but-not-open range to be accepted, got %v", err)
	}
}

// TestParseChronycTrackingRealSample uses a real `chronyc tracking` capture
// taken from production during this session's investigation.
func TestParseChronycTrackingRealSample(t *testing.T) {
	sample := `Reference ID    : C41A61AD (2800:1e0:1080:a::82)
Stratum         : 2
Ref time (UTC)  : Mon Aug 10 13:04:01 2026
System time     : 0.000009313 seconds slow of NTP time
Last offset     : -0.000160444 seconds
RMS offset      : 0.000097272 seconds
Frequency       : 5.836 ppm slow
Residual freq   : -0.003 ppm
Skew            : 0.041 ppm
Root delay      : 0.048532970 seconds
Root dispersion : 0.001106995 seconds
Update interval : 1027.4 seconds
Leap status     : Normal
`
	stratum, offsetSecs, source := ParseChronycTracking(sample)
	if stratum != 2 {
		t.Errorf("stratum = %d, want 2", stratum)
	}
	if !strings.Contains(source, "C41A61AD") {
		t.Errorf("source = %q, want it to contain the reference ID", source)
	}
	wantOffset := -0.000009313
	if diff := offsetSecs - wantOffset; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("offsetSecs = %v, want ~%v", offsetSecs, wantOffset)
	}
}

func TestStatusReportsNotInstalledWhenUnitMissing(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"systemctl list-unit-files --no-legend chrony.service": "",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	st := s.Status(context.Background())
	if st.Installed {
		t.Error("Installed = true, want false when the unit is missing")
	}
	if st.Synced {
		t.Error("Synced = true, want false when not installed")
	}
}

func TestStatusReportsSyncedAndDetailWhenInstalled(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"systemctl list-unit-files --no-legend chrony.service": "chrony.service                        enabled",
		"timedatectl show --property=NTPSynchronized --value":  "yes",
		"chronyc tracking": "Reference ID    : C41A61AD (2800:1e0:1080:a::82)\nStratum         : 2\nSystem time     : 0.000009313 seconds slow of NTP time\n",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	st := s.Status(context.Background())
	if !st.Installed {
		t.Fatal("Installed = false, want true")
	}
	if !st.Synced {
		t.Error("Synced = false, want true")
	}
	if st.Stratum != 2 {
		t.Errorf("Stratum = %d, want 2", st.Stratum)
	}
	if !strings.Contains(st.Source, "C41A61AD") {
		t.Errorf("Source = %q, want it to contain the reference ID", st.Source)
	}
}

func TestListTimezonesParsesNewlineSeparatedOutput(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl list-timezones": "America/Sao_Paulo\nAmerica/New_York\nUTC\n",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	zones, err := s.ListTimezones(context.Background())
	if err != nil {
		t.Fatalf("ListTimezones: %v", err)
	}
	want := []string{"America/Sao_Paulo", "America/New_York", "UTC"}
	if len(zones) != len(want) {
		t.Fatalf("got %d zones, want %d: %v", len(zones), len(want), zones)
	}
	for i, z := range want {
		if zones[i] != z {
			t.Errorf("zones[%d] = %q, want %q", i, zones[i], z)
		}
	}
}

// TestListTimezonesReturnsEmptySliceNotNilOnEmptyOutput is the regression
// test for a real bug caught during this plan's self-review: with zero
// timezone lines, ListTimezones used to leave its result at the nil zero
// value (no error), which the handler's `if err != nil` nil-guard (Task 2)
// does not catch — producing "timezones":null in the API response.
func TestListTimezonesReturnsEmptySliceNotNilOnEmptyOutput(t *testing.T) {
	exec := &fakeExec{responses: map[string]string{
		"timedatectl list-timezones": "",
	}}
	s := &Service{exec: exec, confPath: "/unused"}

	zones, err := s.ListTimezones(context.Background())
	if err != nil {
		t.Fatalf("ListTimezones: %v", err)
	}
	if zones == nil {
		t.Error("zones is nil, want a non-nil empty slice")
	}
	if len(zones) != 0 {
		t.Errorf("zones = %v, want empty", zones)
	}
}

func TestInstallChronyRunsSystemdRun(t *testing.T) {
	exec := &fakeExec{}
	s := &Service{exec: exec, confPath: "/unused"}

	if err := s.InstallChrony(context.Background()); err != nil {
		t.Fatalf("InstallChrony: %v", err)
	}
	want := "systemd-run --pipe --wait -- apt-get install -y --no-install-recommends chrony"
	if !containsExecuted(exec.executed, want) {
		t.Errorf("expected %q, got %v", want, exec.executed)
	}
}
