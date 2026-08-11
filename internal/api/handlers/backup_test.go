package handlers_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeEmailSender struct{ err error }

func (f *fakeEmailSender) SendEmailAttachment(subject, body string, attachment []byte, filename string) error {
	return f.err
}

func newBackupTestHandler(t *testing.T) (*handlers.BackupHandler, *secrets.Service) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	alertSvc := alerts.NewService(db)
	sched := backup.NewScheduler(db, sec, &fakeEmailSender{}, alertSvc, "test-version")
	h := handlers.NewBackupHandler(db, sec, "test-version", sched)
	return h, sec
}

func multipartRestoreBody(t *testing.T, encrypted []byte, passphrase string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "linkguard-backup.lgbak")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(encrypted); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := mw.WriteField("passphrase", passphrase); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close multipart writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// ─── Finding 2 (S1): restoring a backup must validate every settings blob it
// recognizes through the same checks the live API applies before an admin's
// edit ever reaches the DB, and must write nothing at all when any of them
// fails — a crafted or corrupted backup must not be able to reach
// unbound.conf/kea-dhcp4.conf with unvalidated content by going around the
// handlers entirely. Regression tests for
// .superpowers/sdd/input-validation-audit.md finding #1.

// encryptBackupData encrypts an arbitrary BackupData under passphrase, the
// same on-disk shape Restore expects — but built directly (not via
// h.Export), so a test can craft settings/blocklist content Export would
// never produce from a clean DB.
func encryptBackupData(t *testing.T, data backup.BackupData, passphrase string) []byte {
	t.Helper()
	plaintext, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal BackupData: %v", err)
	}
	encrypted, err := backupcrypt.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return encrypted
}

// doRestore posts data (encrypted under passphrase) to h.Restore and returns
// the response.
func doRestore(t *testing.T, h *handlers.BackupHandler, data backup.BackupData, passphrase string) *httptest.ResponseRecorder {
	t.Helper()
	encrypted := encryptBackupData(t, data, passphrase)
	body, contentType := multipartRestoreBody(t, encrypted, passphrase)
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	return rw
}

// snapshotDB exports the handler's live DB (via the same h.Export path a
// real download uses) and decrypts it back into a BackupData, so a test can
// assert on exactly what ended up persisted — including "nothing changed"
// after a restore that should have been rejected.
func snapshotDB(t *testing.T, h *handlers.BackupHandler, passphrase string) backup.BackupData {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	data, err := backup.DecryptRestore(w.Body.Bytes(), passphrase)
	if err != nil {
		t.Fatalf("DecryptRestore: %v", err)
	}
	return data
}

const testPassphrase = "senha-de-teste-123456"

// validNetsvcConfigJSON is a clean, fully-valid netsvc_config settings blob
// — the baseline every "rejected restore must write nothing" test restores
// first, so there's known-good state to prove survives untouched.
const validNetsvcConfigJSON = `{"backend":"kea-unbound","interface":"br10","subnet_cidr":"192.168.3.0/24","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3","lease_hours":12,"dns_to_clients":["192.168.3.3"],"upstreams":[],"log_queries":false,"domain_suffix":"lan"}`

func TestRestoreRejectsInvalidCIDRInNetsvcConfigAndWritesNothing(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, testPassphrase); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	baseline := backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup",
		Settings: map[string]string{"netsvc_config": validNetsvcConfigJSON}}
	if rw := doRestore(t, h, baseline, testPassphrase); rw.Code != http.StatusOK {
		t.Fatalf("baseline restore: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	before := snapshotDB(t, h, testPassphrase)

	malicious := baseline
	malicious.Settings = map[string]string{
		"netsvc_config": `{"backend":"kea-unbound","interface":"br10","subnet_cidr":"not-a-cidr","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3"}`,
	}
	rw := doRestore(t, h, malicious, testPassphrase)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid subnet_cidr in a restored backup, got %d: %s", rw.Code, rw.Body.String())
	}

	after := snapshotDB(t, h, testPassphrase)
	if !reflect.DeepEqual(before.Settings, after.Settings) {
		t.Fatalf("settings changed after a restore that should have been rejected:\nbefore=%v\nafter=%v", before.Settings, after.Settings)
	}
}

func TestRestoreRejectsInvalidInterfaceInNetsvcConfigAndWritesNothing(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, testPassphrase); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	baseline := backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup",
		Settings: map[string]string{"netsvc_config": validNetsvcConfigJSON}}
	if rw := doRestore(t, h, baseline, testPassphrase); rw.Code != http.StatusOK {
		t.Fatalf("baseline restore: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	before := snapshotDB(t, h, testPassphrase)

	malicious := baseline
	malicious.Settings = map[string]string{
		// A newline in "interface" would land in kea-dhcp4.conf's
		// interfaces-config by string concatenation elsewhere in the config
		// pipeline; an interface name this long/invalid is also outright
		// rejected by validIface.
		"netsvc_config": `{"backend":"kea-unbound","interface":"this-interface-name-is-way-too-long-for-linux","subnet_cidr":"192.168.3.0/24","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3"}`,
	}
	rw := doRestore(t, h, malicious, testPassphrase)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid interface in a restored backup, got %d: %s", rw.Code, rw.Body.String())
	}

	after := snapshotDB(t, h, testPassphrase)
	if !reflect.DeepEqual(before.Settings, after.Settings) {
		t.Fatalf("settings changed after a restore that should have been rejected:\nbefore=%v\nafter=%v", before.Settings, after.Settings)
	}
}

func TestRestoreRejectsInjectedBlocklistEntryAndWritesNothing(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, testPassphrase); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	baseline := backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup",
		Blocklist: []string{"good.example.com"}}
	if rw := doRestore(t, h, baseline, testPassphrase); rw.Code != http.StatusOK {
		t.Fatalf("baseline restore: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	before := snapshotDB(t, h, testPassphrase)

	malicious := backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup",
		Blocklist: []string{"good.example.com", "evil.com\ninclude: \"/etc/passwd"}}
	rw := doRestore(t, h, malicious, testPassphrase)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an injected blocklist entry in a restored backup, got %d: %s", rw.Code, rw.Body.String())
	}

	after := snapshotDB(t, h, testPassphrase)
	if !reflect.DeepEqual(before.Blocklist, after.Blocklist) {
		t.Fatalf("blocklist changed after a restore that should have been rejected:\nbefore=%v\nafter=%v", before.Blocklist, after.Blocklist)
	}
}

// TestRestoreCleanBackupWithNetsvcConfigRestoresUnchanged proves the new
// validation doesn't reject legitimate content: a fully-valid netsvc_config
// blob and a fully-valid blocklist restore exactly as given.
func TestRestoreCleanBackupWithNetsvcConfigRestoresUnchanged(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, testPassphrase); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	clean := backup.BackupData{
		Version:   "test-version",
		Kind:      "linkguard-fw-backup",
		Settings:  map[string]string{"netsvc_config": validNetsvcConfigJSON},
		Blocklist: []string{"ads.example.com", "tracker.example.net"},
	}
	rw := doRestore(t, h, clean, testPassphrase)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for a clean backup, got %d: %s", rw.Code, rw.Body.String())
	}

	after := snapshotDB(t, h, testPassphrase)
	if after.Settings["netsvc_config"] != validNetsvcConfigJSON {
		t.Errorf("netsvc_config changed on a clean restore:\nwant=%s\ngot=%s", validNetsvcConfigJSON, after.Settings["netsvc_config"])
	}
	if !reflect.DeepEqual(after.Blocklist, clean.Blocklist) {
		t.Errorf("blocklist changed on a clean restore:\nwant=%v\ngot=%v", clean.Blocklist, after.Blocklist)
	}
}

func TestExportRequiresPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a configured passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportThenRestoreRoundTrip(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	encrypted := w.Body.Bytes()
	if len(encrypted) < 4 || string(encrypted[:4]) != "LGB2" {
		t.Fatalf("expected encrypted output starting with LGB2 magic, got %d bytes", len(encrypted))
	}

	body, contentType := multipartRestoreBody(t, encrypted, "senha-de-teste-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusOK {
		t.Fatalf("Restore: expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestRestoreWithWrongPassphraseFails(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	body, contentType := multipartRestoreBody(t, encrypted, "senha-errada-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong passphrase, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestRestoreReportsMissingSecretsToReconfigure(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	// Configure github_update_token before Restore so we can prove it is
	// correctly EXCLUDED from secrets_to_reconfigure — the counterpart to the
	// "notifications" case below, which proves an unconfigured secret IS
	// included.
	if err := sec.Set("github_update_token", "x"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	body, contentType := multipartRestoreBody(t, encrypted, "senha-de-teste-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
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

func TestRestoreLocksOutAfterRepeatedWrongPassphrase(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	var lastCode int
	for i := 0; i < 10; i++ {
		body, contentType := multipartRestoreBody(t, encrypted, "senha-errada-123456")
		rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
		rreq.Header.Set("Content-Type", contentType)
		rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
		rw := httptest.NewRecorder()
		h.Restore(rw, rreq)
		lastCode = rw.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated wrong-passphrase attempts, got %d", lastCode)
	}
}

// TestRestoreConcurrentWrongPassphraseRespectsLockout reproduces the Task 11
// review finding: firing many concurrent restore requests for the *same*
// userID with a wrong passphrase used to let every single one of them race
// past the restoreLockedOut() check before any recorded a failure, because
// the check and the (slow, scrypt) decrypt-then-record step were split
// across separate critical sections. With the fix (a per-user lock held for
// the whole check-decrypt-record sequence), no more than maxRestoreAttempts
// requests should ever reach a real decrypt attempt (400) before the rest
// are rejected by the lockout (429) — regardless of how many requests start
// at the same instant.
func TestRestoreConcurrentWrongPassphraseRespectsLockout(t *testing.T) {
	const maxRestoreAttempts = 5 // must match the unexported constant in backup.go
	const concurrency = 20

	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, concurrency)
	for i := 0; i < concurrency; i++ {
		i := i
		body, contentType := multipartRestoreBody(t, encrypted, "senha-errada-123456")
		rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
		rreq.Header.Set("Content-Type", contentType)
		rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "concurrent-user", Username: "tester"}))
		rw := httptest.NewRecorder()

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all goroutines at (as close to) the same instant as possible
			h.Restore(rw, rreq)
			codes[i] = rw.Code
		}()
	}
	close(start)
	wg.Wait()

	var badRequestCount, tooManyRequestsCount, other int
	for _, code := range codes {
		switch code {
		case http.StatusBadRequest:
			badRequestCount++
		case http.StatusTooManyRequests:
			tooManyRequestsCount++
		default:
			other++
		}
	}

	if other != 0 {
		t.Fatalf("expected every response to be 400 or 429, got %d unexpected codes: %v", other, codes)
	}
	if badRequestCount > maxRestoreAttempts {
		t.Fatalf("lockout race: %d/%d concurrent requests reached a real decrypt attempt (400), "+
			"want at most maxRestoreAttempts=%d — the rest should have been rejected by the "+
			"lockout (429) instead; got codes=%v", badRequestCount, concurrency, maxRestoreAttempts, codes)
	}
	if badRequestCount+tooManyRequestsCount != concurrency {
		t.Fatalf("expected %d total responses, got %d 400s + %d 429s", concurrency, badRequestCount, tooManyRequestsCount)
	}
	// Sanity: the lockout must actually have kicked in for at least one
	// request, otherwise this test would trivially pass with an
	// unserialized handler that just happens to be slow enough in CI.
	if tooManyRequestsCount == 0 {
		t.Fatalf("expected at least one 429 among %d concurrent requests, got none — codes=%v", concurrency, codes)
	}
}

func TestRestoreRejectsOversizedBody(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	oversized := make([]byte, 33<<20) // 33MB, over the 32MB cap
	body, contentType := multipartRestoreBody(t, oversized, "senha-certa-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized upload, got %d", rw.Code)
	}
}

func TestPassphraseSetRejectsShortPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"passphrase": "curta"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/passphrase", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PassphraseSet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPassphraseSetThenStatusReportsConfigured(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"passphrase": "senha-valida-123456"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/passphrase", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PassphraseSet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PassphraseSet: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	sreq := httptest.NewRequest(http.MethodGet, "/api/backup/passphrase/status", nil)
	sw := httptest.NewRecorder()
	h.PassphraseStatus(sw, sreq)
	var resp struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(sw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Configured {
		t.Fatal("expected configured=true after PassphraseSet")
	}
}

func TestScheduleSetRejectsEnablingWithoutPassphrase(t *testing.T) {
	h, _ := newBackupTestHandler(t)
	body, _ := json.Marshal(map[string]string{"schedule": "daily"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/schedule", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ScheduleSet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 enabling schedule without passphrase, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScheduleSetThenGetRoundTrip(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"schedule": "weekly"})
	req := httptest.NewRequest(http.MethodPut, "/api/backup/schedule", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ScheduleSet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ScheduleSet: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	greq := httptest.NewRequest(http.MethodGet, "/api/backup/schedule", nil)
	gw := httptest.NewRecorder()
	h.ScheduleGet(gw, greq)
	var resp struct {
		Schedule string `json:"schedule"`
	}
	if err := json.Unmarshal(gw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Schedule != "weekly" {
		t.Fatalf("Schedule = %q, want weekly", resp.Schedule)
	}
}

func TestSendNowUsesScheduler(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/backup/send-now", nil)
	w := httptest.NewRecorder()
	h.SendNow(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
