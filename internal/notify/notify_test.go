package notify

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

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
	//
	// NotifyRecovery dispatches asynchronously, so delivery is synchronized via
	// a buffered channel signaled from the webhook handler rather than a plain
	// counter (which would race under -race).
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hit <- struct{}{}
	}))
	defer srv.Close()

	db := openTestDB(t)
	s := NewService(db)
	_ = s.SaveConfig(Config{
		MinSeverity: "warning",
		Webhook:     WebhookCfg{Enabled: true, URL: srv.URL},
	})

	s.NotifyRecovery("Recuperado", "voltou")

	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery not delivered")
	}
}

func TestSendNowIsSynchronous(t *testing.T) {
	// SendNow must deliver before returning: by the time it returns, the
	// webhook has already been hit (no channel/wait needed), and it reports a
	// nil-error slice on a 200 response.
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
