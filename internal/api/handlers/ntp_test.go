package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
	return NewNTPHandler(db, svc, nil)
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
