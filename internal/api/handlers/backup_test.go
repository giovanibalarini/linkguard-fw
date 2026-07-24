package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestRestoreReportsMissingSecretsToReconfigure(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)

	// Configure github_update_token before Restore so we can prove it is
	// correctly EXCLUDED from secrets_to_reconfigure — the counterpart to the
	// "notifications" case below, which proves an unconfigured secret IS
	// included. Without this case the test would still pass even if the
	// handler ignored Status() entirely and always returned every known
	// secret name.
	if err := sec.Set("github_update_token", "x"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	h := handlers.NewBackupHandler(db, sec, "test-version")

	body, _ := json.Marshal(map[string]interface{}{
		"version":  "test-version",
		"kind":     "linkguard-fw-backup",
		"settings": map[string]string{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/backup/restore", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Restore(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := map[string]bool{"notifications": true}
	got := map[string]bool{}
	for _, k := range resp.SecretsToReconfigure {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("expected %q in secrets_to_reconfigure (never configured on this box), got %v", k, resp.SecretsToReconfigure)
		}
	}
	if got["github_update_token"] {
		t.Fatalf("expected 'github_update_token' NOT in secrets_to_reconfigure (it was configured before Restore), got %v", resp.SecretsToReconfigure)
	}
}
