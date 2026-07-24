package secrets_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestLoadOrGenerateKeyCreatesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	key1, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadOrGenerateKeyReturnsExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	key1, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("first LoadOrGenerateKey: %v", err)
	}
	key2, err := secrets.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("second LoadOrGenerateKey: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("expected the second call to return the same key, not regenerate")
	}
}

func TestLoadOrGenerateKeyRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatalf("seed bad key file: %v", err)
	}

	if _, err := secrets.LoadOrGenerateKey(path); err == nil {
		t.Fatal("expected an error for a key file of the wrong size")
	}
}

func TestCheckNotOrphanedAllowsGenuineFirstBoot(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	path := filepath.Join(dir, "secret.key") // never created
	if err := secrets.CheckNotOrphaned(path, db); err != nil {
		t.Fatalf("expected nil for empty secrets table + missing key file (genuine first boot), got %v", err)
	}
}

func TestCheckNotOrphanedRejectsLostKeyWithExistingSecrets(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// Seed a row directly into the secrets table, bypassing the vault --
	// same shape as TestSecretsTableExists in internal/storage.
	if _, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)`, "totp_user-1", []byte("012345678901"), []byte("ciphertext"), time.Now()); err != nil {
		t.Fatalf("seed secrets row: %v", err)
	}

	path := filepath.Join(dir, "secret.key") // missing: "lost the key"
	err = secrets.CheckNotOrphaned(path, db)
	if err == nil {
		t.Fatal("expected an error: key file missing but secrets table already has rows")
	}
}

func TestCheckNotOrphanedAllowsExistingKeyFile(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	path := filepath.Join(dir, "secret.key")
	if _, err := secrets.LoadOrGenerateKey(path); err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)`, "totp_user-1", []byte("012345678901"), []byte("ciphertext"), time.Now()); err != nil {
		t.Fatalf("seed secrets row: %v", err)
	}

	if err := secrets.CheckNotOrphaned(path, db); err != nil {
		t.Fatalf("expected nil when the key file exists (regardless of secrets table contents), got %v", err)
	}
}
