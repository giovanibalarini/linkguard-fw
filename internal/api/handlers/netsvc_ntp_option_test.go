package handlers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

// capturingNetsvcProvider records the ntpServer argument every call site
// (ReloadConfigs, GenerateConfigs) actually received, so tests can assert on
// the wiring between the NTP toggle and the DHCP config generation without
// depending on keaunbound's real Kea/unbound file I/O.
type capturingNetsvcProvider struct {
	lastNTPServerReload  string
	lastNTPServerPreview string
}

func (*capturingNetsvcProvider) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }
func (p *capturingNetsvcProvider) GenerateConfigs(_ netsvc.Config, _ []netsvc.Reservation, _ []string, ntpServer string) ([]netsvc.ConfigFile, error) {
	p.lastNTPServerPreview = ntpServer
	return nil, nil
}
func (*capturingNetsvcProvider) Apply(context.Context, netsvc.Config, []netsvc.Reservation, []string) (string, error) {
	return "", nil
}
func (p *capturingNetsvcProvider) ReloadConfigs(_ context.Context, _ netsvc.Config, _ []netsvc.Reservation, _ []string, ntpServer string) (netsvc.ApplyResult, error) {
	p.lastNTPServerReload = ntpServer
	return netsvc.ApplyResult{}, nil
}
func (*capturingNetsvcProvider) Leases(context.Context) ([]netsvc.Lease, error) { return nil, nil }

func newTestNetsvcHandlerWithProvider(t *testing.T) (*NetsvcHandler, *capturingNetsvcProvider) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	p := &capturingNetsvcProvider{}
	return NewNetsvcHandler(db, p, nil), p
}

// TestDoReloadOmitsNTPServerOptionByDefault: a fresh install (NTP settings
// never saved) must never advertise an ntp-servers option — additive
// feature, off by default.
func TestDoReloadOmitsNTPServerOptionByDefault(t *testing.T) {
	h, p := newTestNetsvcHandlerWithProvider(t)

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	if p.lastNTPServerReload != "" {
		t.Errorf("ntpServer = %q, want empty when NTP serve_lan was never configured", p.lastNTPServerReload)
	}
}

// TestDoReloadIncludesNTPServerOptionWhenServeLANEnabled is the regression
// test for the cross-package wiring described in spec §5: when
// internal/timesync's persisted config has ServeLAN=true and at least one
// allowed network, the DHCP reload path must pass the firewall's LAN
// gateway IP through to the Kea generator as the ntp-servers option value.
func TestDoReloadIncludesNTPServerOptionWhenServeLANEnabled(t *testing.T) {
	h, p := newTestNetsvcHandlerWithProvider(t)

	ntpCfg := timesync.Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}
	b, err := json.Marshal(ntpCfg)
	if err != nil {
		t.Fatalf("marshal ntp config: %v", err)
	}
	if err := h.db.SetSetting(ntpCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	want := netsvc.DefaultConfig().Gateway
	if p.lastNTPServerReload != want {
		t.Errorf("ntpServer = %q, want %q (the LAN gateway)", p.lastNTPServerReload, want)
	}
}

// TestDoReloadOmitsNTPServerOptionWhenAllowedNetworksIsEmpty is the
// regression test for the review finding: ServeLAN=true with an empty
// AllowedNetworks list is the spec's explicit "serving on, nothing
// allowed" state — chrony's own `allow` directives end up empty, so
// chronyd refuses every client. Advertising option 42 anyway hands DHCP
// clients a dead time source: worse than not advertising, since a client
// that feeds it straight to systemd-timesyncd (or any client that doesn't
// fall back) ends up with exactly one permanently unreachable NTP server
// instead of none.
func TestDoReloadOmitsNTPServerOptionWhenAllowedNetworksIsEmpty(t *testing.T) {
	h, p := newTestNetsvcHandlerWithProvider(t)

	ntpCfg := timesync.Config{ServeLAN: true, AllowedNetworks: []string{}}
	b, err := json.Marshal(ntpCfg)
	if err != nil {
		t.Fatalf("marshal ntp config: %v", err)
	}
	if err := h.db.SetSetting(ntpCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	if p.lastNTPServerReload != "" {
		t.Errorf("ntpServer = %q, want empty — serving is on but no network is actually allowed, so chrony would refuse every client", p.lastNTPServerReload)
	}
}

// TestPreviewIncludesNTPServerOptionWhenServeLANEnabled: the preview path
// (used by the UI before applying) must reflect the same NTP-derived
// option as the actual reload, so what the admin previews matches what
// gets applied.
func TestPreviewIncludesNTPServerOptionWhenServeLANEnabled(t *testing.T) {
	h, p := newTestNetsvcHandlerWithProvider(t)

	ntpCfg := timesync.Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}
	b, _ := json.Marshal(ntpCfg)
	if err := h.db.SetSetting(ntpCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	if _, err := h.provider.GenerateConfigs(h.getConfig(), h.reservationsForProvider(), nil, h.ntpServerOption()); err != nil {
		t.Fatalf("GenerateConfigs: %v", err)
	}
	want := netsvc.DefaultConfig().Gateway
	if p.lastNTPServerPreview != want {
		t.Errorf("ntpServer = %q, want %q (the LAN gateway)", p.lastNTPServerPreview, want)
	}
}
