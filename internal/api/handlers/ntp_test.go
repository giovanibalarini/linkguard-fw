package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
