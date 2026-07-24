package secrets_test

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestSvc(t *testing.T) *secrets.Service {
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
	return secrets.NewService(db, key)
}

func TestSetThenGetRoundTrips(t *testing.T) {
	svc := newTestSvc(t)

	if err := svc.Set("github_update_token", "ghp_realvalue"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := svc.Get("github_update_token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "ghp_realvalue" {
		t.Fatalf("expected round-trip value, got %q", got)
	}
}

func TestGetUnsetReturnsEmpty(t *testing.T) {
	svc := newTestSvc(t)

	got, err := svc.Get("never_set")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string for unset secret, got %q", got)
	}
}

func TestStatusReflectsConfiguredAndHint(t *testing.T) {
	svc := newTestSvc(t)

	configured, hint := svc.Status("ai_api_token")
	if configured {
		t.Fatal("expected not configured before Set")
	}
	if hint != "" {
		t.Fatalf("expected empty hint before Set, got %q", hint)
	}

	if err := svc.Set("ai_api_token", "sk-ant-abcd1234wxyz7f2a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	configured, hint = svc.Status("ai_api_token")
	if !configured {
		t.Fatal("expected configured after Set")
	}
	if hint != "sk-ant-…7f2a" {
		t.Fatalf("expected hint to show only a suffix, got %q", hint)
	}
}

func TestDeleteRemovesSecret(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("notifications", `{"webhook":{"url":"https://x"}}`)
	if err := svc.Delete("notifications"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	configured, _ := svc.Status("notifications")
	if configured {
		t.Fatal("expected not configured after Delete")
	}
}

func TestEachSetUsesAFreshNonce(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("k", "value-one")
	nonce1 := svc.NonceForTest("k")
	_ = svc.Set("k", "value-two")
	nonce2 := svc.NonceForTest("k")

	if string(nonce1) == string(nonce2) {
		t.Fatal("expected a fresh nonce on every Set — reusing a GCM nonce breaks its authentication guarantee")
	}
}

func TestTamperedCiphertextFailsToDecrypt(t *testing.T) {
	svc := newTestSvc(t)

	_ = svc.Set("k", "original")
	svc.CorruptCiphertextForTest("k")

	if _, err := svc.Get("k"); err == nil {
		t.Fatal("expected Get to fail on tampered ciphertext, not silently return corrupted data")
	}
}
