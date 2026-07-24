package secrets_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
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
