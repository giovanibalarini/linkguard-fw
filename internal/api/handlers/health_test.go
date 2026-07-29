package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestHealthReportsRunningVersion is the regression test for a real bug:
// Settings.tsx's "Sobre" tab hardcoded "1.0.0" as the displayed version
// instead of reading the actually running one. /api/health is the one place
// the frontend can read it without needing a GitHub token (unlike
// /api/system/update/check, which exists to compare against the *latest*
// release on a private repo, not report the current one).
func TestHealthReportsRunningVersion(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	h := handlers.NewHealthHandler(db, nil, "9.9.9-test")

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	h.Health(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status    string `json:"status"`
		LinkCount int    `json:"link_count"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Version != "9.9.9-test" {
		t.Errorf("version = %q, want %q", body.Version, "9.9.9-test")
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
}
