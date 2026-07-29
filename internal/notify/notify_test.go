package notify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
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

func newTestSecrets(t *testing.T, db *storage.DB) *secrets.Service {
	t.Helper()
	dir := t.TempDir()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	return secrets.NewService(db, key)
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
	s := NewService(db, newTestSecrets(t, db))
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
	s := NewService(db, newTestSecrets(t, db))
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

func TestBuildMultipartMessageIncludesAttachment(t *testing.T) {
	msg, err := buildMultipartMessage("from@example.com", "to@example.com", "Backup LinkGuard", "Segue em anexo.",
		[]byte("conteudo cifrado de teste"), "linkguard-backup.lgbak")
	if err != nil {
		t.Fatalf("buildMultipartMessage: %v", err)
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(msg)))
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("ReadMIMEHeader: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("expected multipart/mixed, got %q", mediaType)
	}

	mr := multipart.NewReader(tp.R, params["boundary"])
	var sawText, sawAttachment bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		partBody, _ := io.ReadAll(part)
		switch {
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain"):
			sawText = true
			if string(partBody) != "Segue em anexo." {
				t.Fatalf("text part mismatch: %q", partBody)
			}
		case part.Header.Get("Content-Disposition") != "":
			sawAttachment = true
			decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(partBody)))
			if err != nil {
				t.Fatalf("base64 decode attachment: %v", err)
			}
			if string(decoded) != "conteudo cifrado de teste" {
				t.Fatalf("attachment mismatch: %q", decoded)
			}
			if !strings.Contains(part.Header.Get("Content-Disposition"), "linkguard-backup.lgbak") {
				t.Fatalf("filename missing from Content-Disposition: %q", part.Header.Get("Content-Disposition"))
			}
		}
	}
	if !sawText || !sawAttachment {
		t.Fatalf("expected both text and attachment parts, sawText=%v sawAttachment=%v", sawText, sawAttachment)
	}
}

func TestSendEmailAttachmentFailsWhenEmailDisabled(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db, newTestSecrets(t, db))

	if err := s.SendEmailAttachment("assunto", "corpo", []byte("dados"), "arquivo.lgbak"); err == nil {
		t.Fatal("expected error when email channel is not enabled, got nil")
	}
}
