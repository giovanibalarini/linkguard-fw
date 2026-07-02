package notify

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNotifyRecoveryBypassesMinSeverity(t *testing.T) {
	// A recovery is severity "info". With min_severity=warning it must STILL be
	// eligible to send (bypass), unlike Notify which would drop it.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer srv.Close()

	db := openTestDB(t)
	s := NewService(db)
	_ = s.SaveConfig(Config{
		MinSeverity: "warning",
		Webhook:     WebhookCfg{Enabled: true, URL: srv.URL},
	})

	// SendNow at info severity must reach the webhook (bypass), proving the
	// recovery path ignores the min-severity gate.
	errs := s.SendNow("info", "Recuperado", "voltou")
	for _, e := range errs {
		if e != nil {
			t.Fatalf("send error: %v", e)
		}
	}
	if hits != 1 {
		t.Fatalf("webhook hits = %d, want 1", hits)
	}
}
