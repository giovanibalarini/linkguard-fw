package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

// fakeTimesyncExec is a minimal firewall.Executor test double dedicated to
// this file — not internal/api/handlers' fakeNftExec, which returns "" for
// any non-nft command and breaks internal/timesync's parsers (see that
// package's own fakeExec doc comment for the same reasoning).
type fakeTimesyncExec struct{ dryRun bool }

func (e *fakeTimesyncExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeTimesyncExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *fakeTimesyncExec) IsDryRun() bool { return e.dryRun }

func newTestNTPHandler(t *testing.T) *NTPHandler {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	return NewNTPHandler(db, svc, nil, nil)
}

func TestGetNTPReturnsEmptyServersAndTimezonesNotNull(t *testing.T) {
	h := newTestNTPHandler(t)
	r := httptest.NewRequest("GET", "/api/ntp", nil)
	w := httptest.NewRecorder()
	h.GetNTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// Compacting through json.Unmarshal/Marshal (instead of matching the raw
	// body string) avoids brittleness from key ordering while still proving
	// neither field serialized as null.
	var v any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	compact, _ := json.Marshal(v)
	body := string(compact)
	if !strings.Contains(body, `"servers":[]`) {
		t.Errorf("expected servers:[] not null in body: %s", body)
	}
	if !strings.Contains(body, `"timezones":[]`) {
		t.Errorf("expected timezones:[] not null in body: %s", body)
	}
}

func TestUpdateNTPConfigRejectsInvalidServer(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":["evil; rm -rf /"],"timezone":""}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

func TestUpdateNTPConfigPersistsAndRoundTrips(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":["c.ntp.br","192.36.143.130"],"timezone":"America/Sao_Paulo"}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.Servers) != 2 || cfg.Servers[0] != "c.ntp.br" {
		t.Errorf("Servers = %v, want [c.ntp.br 192.36.143.130]", cfg.Servers)
	}
	if cfg.Timezone != "America/Sao_Paulo" {
		t.Errorf("Timezone = %q, want America/Sao_Paulo", cfg.Timezone)
	}
}

// TestUpdateNTPConfigServeLANRoundTrips: the new toggle must persist and
// round-trip through GET/PUT exactly like servers/timezone already do.
func TestUpdateNTPConfigServeLANRoundTrips(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":[],"timezone":"","serve_lan":true}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if !cfg.ServeLAN {
		t.Errorf("ServeLAN = false, want true after PUT")
	}

	rGet := httptest.NewRequest("GET", "/api/ntp", nil)
	wGet := httptest.NewRecorder()
	h.GetNTP(wGet, rGet)
	if !strings.Contains(wGet.Body.String(), `"serve_lan":true`) {
		t.Errorf("GET /api/ntp missing serve_lan:true in body: %s", wGet.Body.String())
	}
}

// ─── allowed_networks: round-trip, validation, default pre-fill ──────────

// TestUpdateNTPConfigAllowedNetworksRoundTrips: the admin's chosen networks
// persist and come back through GET exactly as saved (spec §3.1).
func TestUpdateNTPConfigAllowedNetworksRoundTrips(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":[],"timezone":"","serve_lan":true,"allowed_networks":["192.168.3.0/24","10.20.0.0/24"]}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.AllowedNetworks) != 2 || cfg.AllowedNetworks[0] != "192.168.3.0/24" || cfg.AllowedNetworks[1] != "10.20.0.0/24" {
		t.Errorf("AllowedNetworks = %v, want [192.168.3.0/24 10.20.0.0/24]", cfg.AllowedNetworks)
	}

	rGet := httptest.NewRequest("GET", "/api/ntp", nil)
	wGet := httptest.NewRecorder()
	h.GetNTP(wGet, rGet)
	if !strings.Contains(wGet.Body.String(), `"192.168.3.0/24"`) || !strings.Contains(wGet.Body.String(), `"10.20.0.0/24"`) {
		t.Errorf("GET /api/ntp missing allowed_networks in body: %s", wGet.Body.String())
	}
}

// TestUpdateNTPConfigRejectsInvalidCIDR: server-side validation, not just
// the chrony/nftables layers — a bad CIDR must never even be persisted.
func TestUpdateNTPConfigRejectsInvalidCIDR(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":[],"timezone":"","serve_lan":true,"allowed_networks":["not-a-cidr"]}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

// TestUpdateNTPConfigRejectsOpenWildcard: 0.0.0.0/0 must be rejected with a
// message the UI can show (spec §3.1's "guarda-corpo" and §6).
func TestUpdateNTPConfigRejectsOpenWildcard(t *testing.T) {
	h := newTestNTPHandler(t)
	body := `{"servers":[],"timezone":"","serve_lan":true,"allowed_networks":["0.0.0.0/0"]}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "0.0.0.0/0") {
		t.Errorf("expected the error message to mention the offending CIDR: %s", w.Body.String())
	}
}

// TestUpdateNTPConfigPrefillsFromDHCPSubnetOnFirstEnable is Part 3's
// default-prefill behavior (spec §3.1/§6): turning serve_lan on for the
// first time with the allowed_networks key entirely ABSENT from the body
// (not present-but-empty — see Fix 6 in the tests below) seeds it from the
// DHCP LAN subnet, so a caller that never sends the field still gets the
// common case populated for free.
func TestUpdateNTPConfigPrefillsFromDHCPSubnetOnFirstEnable(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = "192.168.7.0/24"
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	body := `{"servers":[],"timezone":"","serve_lan":true}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.AllowedNetworks) != 1 || cfg.AllowedNetworks[0] != "192.168.7.0/24" {
		t.Errorf("AllowedNetworks = %v, want [192.168.7.0/24] (pre-filled from the DHCP subnet)", cfg.AllowedNetworks)
	}
}

// TestUpdateNTPConfigLeavesListEmptyWhenDHCPSubnetAlsoUnconfigured: the
// pre-fill must never invent a range — if the DHCP subnet is itself unset,
// the list simply stays empty (spec §3.1: "não inventar uma faixa").
func TestUpdateNTPConfigLeavesListEmptyWhenDHCPSubnetAlsoUnconfigured(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = ""
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	body := `{"servers":[],"timezone":"","serve_lan":true}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.AllowedNetworks) != 0 {
		t.Errorf("AllowedNetworks = %v, want empty (no DHCP subnet to pre-fill from)", cfg.AllowedNetworks)
	}
}

// TestUpdateNTPConfigDoesNotPrefillWhenListExplicitlyEmptyOnFirstEnable is
// the regression test for review Fix 6: the client already pre-fills
// "Redes autorizadas" visibly the moment the admin flips the toggle, so by
// the time a save reaches the server the field is either populated or the
// admin cleared it on purpose — either way the request always carries an
// explicit (if empty) allowed_networks array from the real UI, never an
// absent key. Before this fix the server couldn't tell "the client didn't
// send this" from "the client sent an empty list on purpose", so an admin
// who enabled serving, cleared the auto-filled network, and saved got it
// silently restored on this very first save — the field's own help text
// says empty means nothing is allowed, but that state was unreachable.
func TestUpdateNTPConfigDoesNotPrefillWhenListExplicitlyEmptyOnFirstEnable(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = "192.168.7.0/24"
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	body := `{"servers":[],"timezone":"","serve_lan":true,"allowed_networks":[]}`
	r := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.UpdateNTPConfig(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.AllowedNetworks) != 0 {
		t.Errorf("AllowedNetworks = %v, want empty — an explicit [] on first enable must never be silently pre-filled", cfg.AllowedNetworks)
	}
}

// TestUpdateNTPConfigDoesNotReprefillAfterAdminExplicitlyClearsTheList is
// the regression test protecting spec §3.1's "lista vazia com o toggle
// ligado = nada é liberado, estado explícito": the pre-fill only fires when
// the allowed_networks key is entirely absent on the off->on transition,
// never when it is present (even empty). Once serving is already on, an
// admin who explicitly empties the list gets exactly that — not a silent
// re-fill from the DHCP subnet.
func TestUpdateNTPConfigDoesNotReprefillAfterAdminExplicitlyClearsTheList(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = "192.168.7.0/24"
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	// First enable: allowed_networks key absent -> pre-filled.
	firstBody := `{"servers":[],"timezone":"","serve_lan":true}`
	r1 := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(firstBody))
	w1 := httptest.NewRecorder()
	h.UpdateNTPConfig(w1, r1)
	if w1.Code != 200 {
		t.Fatalf("first PUT: status = %d, body = %s", w1.Code, w1.Body.String())
	}
	if got := h.getConfig().AllowedNetworks; len(got) != 1 {
		t.Fatalf("expected the first enable to pre-fill, got %v", got)
	}

	// Admin explicitly clears the list while still serving.
	clearBody := `{"servers":[],"timezone":"","serve_lan":true,"allowed_networks":[]}`
	r2 := httptest.NewRequest("PUT", "/api/ntp/config", strings.NewReader(clearBody))
	w2 := httptest.NewRecorder()
	h.UpdateNTPConfig(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("second PUT: status = %d, body = %s", w2.Code, w2.Body.String())
	}

	cfg := h.getConfig()
	if len(cfg.AllowedNetworks) != 0 {
		t.Errorf("AllowedNetworks = %v, want empty — clearing while already serving must stick, not be re-filled", cfg.AllowedNetworks)
	}
}

// TestGetNTPIncludesSuggestedNetworkFromDHCPConfig: GET must expose the
// suggested default separately from config.allowed_networks, so the UI can
// pre-fill the input on first render before any save happens (spec §6).
func TestGetNTPIncludesSuggestedNetworkFromDHCPConfig(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = "192.168.9.0/24"
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	r := httptest.NewRequest("GET", "/api/ntp", nil)
	w := httptest.NewRecorder()
	h.GetNTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"suggested_network":"192.168.9.0/24"`) {
		t.Errorf("expected suggested_network in body: %s", w.Body.String())
	}
}

func TestGetNTPSuggestedNetworkEmptyWhenDHCPSubnetUnconfigured(t *testing.T) {
	h := newTestNTPHandler(t)
	netCfg := netsvc.DefaultConfig()
	netCfg.SubnetCIDR = ""
	b, err := json.Marshal(netCfg)
	if err != nil {
		t.Fatalf("marshal netsvc config: %v", err)
	}
	if err := h.db.SetSetting(netsvcCfgKey, string(b)); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	r := httptest.NewRequest("GET", "/api/ntp", nil)
	w := httptest.NewRecorder()
	h.GetNTP(w, r)
	if !strings.Contains(w.Body.String(), `"suggested_network":""`) {
		t.Errorf("expected empty suggested_network in body: %s", w.Body.String())
	}
}

func TestApplyRunsReloadAndRecordsStatus(t *testing.T) {
	h := newTestNTPHandler(t)
	if got := h.lastApplyStatus(); got != nil {
		t.Fatalf("expected nil last_apply before any apply, got %+v", got)
	}

	r := httptest.NewRequest("POST", "/api/ntp/apply", nil)
	w := httptest.NewRecorder()
	h.Apply(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	got := h.lastApplyStatus()
	if got == nil || !got.OK {
		t.Fatalf("expected a successful last_apply, got %+v", got)
	}
}

func TestInstallChronyReturns200OnSuccess(t *testing.T) {
	h := newTestNTPHandler(t)
	r := httptest.NewRequest("POST", "/api/ntp/install-chrony", nil)
	w := httptest.NewRecorder()
	h.InstallChrony(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// ─── serve_lan effects: firewall reconcile + DHCP reload wiring ───────────

// TestDoReloadReconcilesFirewallWithServingTrueWhenEnabled is Part 2/3's
// core test: enabling serve_lan and applying must invoke the nftables
// input-chain reconcile with serving=true against the admin's chosen
// AllowedNetworks — reshaped 2026-08-11 (spec §4) from an earlier design
// keyed on the box's enabled WAN links, since the accept/drop pair is now
// keyed on the admin's own choice of networks, not WAN interfaces.
func TestDoReloadReconcilesFirewallWithServingTrueWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	nftExec := &reconcileSpyExec{}
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	h := NewNTPHandler(db, svc, nil, nftables.NewService(nftExec))

	if err := h.saveConfig(timesync.Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}

	found := false
	for _, c := range nftExec.executed {
		if strings.Contains(c, "input") && strings.Contains(c, "192.168.3.0/24") && strings.Contains(c, "accept") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the input chain to be reconciled with an accept rule for 192.168.3.0/24; ran: %v", nftExec.executed)
	}
}

// TestDoReloadReconcilesFirewallWithServingFalseWhenDisabled: the default
// (serve_lan=false) must reconcile the chain empty, never with a drop rule.
func TestDoReloadReconcilesFirewallWithServingFalseWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	nftExec := &reconcileSpyExec{}
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	h := NewNTPHandler(db, svc, nil, nftables.NewService(nftExec))

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}

	for _, c := range nftExec.executed {
		if strings.Contains(c, "drop") {
			t.Errorf("expected no drop rule when serve_lan is off; ran: %v", nftExec.executed)
		}
	}
}

// TestDoReloadTriggersDHCPReloadWhenWired: applying the NTP config must ask
// the wired DHCP/DNS reload callback to run too (spec §5 — toggling
// serve_lan changes the DHCP config's ntp-servers option, and clients only
// get it via a fresh reload).
func TestDoReloadTriggersDHCPReloadWhenWired(t *testing.T) {
	h := newTestNTPHandler(t)
	called := false
	h.SetDHCPReload(func(ctx context.Context) error {
		called = true
		return nil
	})

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	if !called {
		t.Error("expected the wired DHCP reload callback to be invoked")
	}
}

// TestDoReloadWithoutWiringDoesNotPanic: nftSvc/triggerDHCPReload are both
// nil for a handler built without the Part 4 wiring (e.g. an older test
// double) — doReload must degrade gracefully, not panic.
func TestDoReloadWithoutWiringDoesNotPanic(t *testing.T) {
	h := newTestNTPHandler(t)
	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
}

// ─── firewall reconcile outcome must reach the panel (review Fix 2) ──────
//
// Before this fix, reconcileFirewall logged and swallowed every nft
// failure, and GET /api/ntp had no field for the outcome at all — so the
// one state where NTP protection is genuinely absent (the reconcile
// failed) was invisible to the admin, directly violating FEATURES.md's
// delivery rule ("configured ≠ working" must be distinguishable from the
// panel). Follows NetsvcHandler's existing applyStatus/last_apply pattern.

// TestDoReloadRecordsFirewallApplyFailure: an nft failure during
// ReconcileNTPInput must leave a non-OK status behind for the API to
// return, not just a log line.
func TestDoReloadRecordsFirewallApplyFailure(t *testing.T) {
	db := newTestDB(t)
	nftExec := &reconcileSpyExec{execErr: errBoomExec{}}
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	h := NewNTPHandler(db, svc, nil, nftables.NewService(nftExec))

	if err := h.saveConfig(timesync.Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if err := h.doReload(context.Background()); err != nil {
		// reconcileFirewall failures are best-effort and must never turn an
		// otherwise-successful chrony apply into a reported doReload error
		// (same convention as LinksHandler.reconcileNAT) — the failure must
		// surface through firewall_apply instead.
		t.Fatalf("doReload must not itself fail from a firewall reconcile error: %v", err)
	}

	got := h.lastFirewallApplyStatus()
	if got == nil {
		t.Fatal("expected a firewall_apply status to be recorded")
	}
	if got.OK {
		t.Error("expected firewall_apply.ok = false after an nft failure")
	}
	if got.Error == "" {
		t.Error("expected firewall_apply.error to describe the nft failure")
	}

	r := httptest.NewRequest("GET", "/api/ntp", nil)
	w := httptest.NewRecorder()
	h.GetNTP(w, r)
	if !strings.Contains(w.Body.String(), `"firewall_apply"`) {
		t.Errorf("expected GET /api/ntp to include firewall_apply, body: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok":false`) {
		t.Errorf("expected GET /api/ntp firewall_apply to report ok:false, body: %s", w.Body.String())
	}
}

// TestDoReloadRecordsFirewallApplySuccess: the mirror case — a clean
// reconcile must record ok:true, so the panel can positively confirm
// protection is in effect, not just the absence of a failure banner.
func TestDoReloadRecordsFirewallApplySuccess(t *testing.T) {
	db := newTestDB(t)
	nftExec := &reconcileSpyExec{}
	svc := timesync.NewService(&fakeTimesyncExec{dryRun: true})
	h := NewNTPHandler(db, svc, nil, nftables.NewService(nftExec))

	if err := h.saveConfig(timesync.Config{ServeLAN: true, AllowedNetworks: []string{"192.168.3.0/24"}}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}

	got := h.lastFirewallApplyStatus()
	if got == nil || !got.OK {
		t.Fatalf("expected firewall_apply.ok = true, got %+v", got)
	}
}

// TestFirewallApplyStatusNilWhenNftSvcNotWired: a handler built without
// nftSvc (nil-safe, e.g. an older caller) must report "never attempted"
// (nil), not a false "failed" — the same never-vs-failed distinction
// lastApplyStatus already draws for the chrony apply.
func TestFirewallApplyStatusNilWhenNftSvcNotWired(t *testing.T) {
	h := newTestNTPHandler(t)
	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	if got := h.lastFirewallApplyStatus(); got != nil {
		t.Errorf("expected nil firewall_apply when nftSvc isn't wired, got %+v", got)
	}
}

type errBoomExec struct{}

func (errBoomExec) Error() string { return "nft: boom" }
