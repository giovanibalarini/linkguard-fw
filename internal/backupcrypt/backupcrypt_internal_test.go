package backupcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Whitebox tests (package backupcrypt, not backupcrypt_test) — they need
// direct access to saltSize and to build a legacy LGB1 file by hand using
// the same fixed N the pre-fix Encrypt used to write, to prove format
// versioning didn't strand backups issued before this change.

func TestEncryptUsesLGB2WithStrongerN(t *testing.T) {
	ciphertext, err := Encrypt([]byte("dado"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ciphertext[:4]) != "LGB2" {
		t.Fatalf("expected new files to use LGB2 magic, got %q", ciphertext[:4])
	}
}

func TestDecryptStillOpensLegacyLGB1Files(t *testing.T) {
	// Hand-build an LGB1 file (old format: magic + salt + nonce + ciphertext,
	// fixed N=32768) the way the pre-fix Encrypt used to, to prove old backups
	// already sent/downloaded before this change still restore correctly.
	passphrase := "senha-antiga-123456"
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keySize)
	if err != nil {
		t.Fatalf("scrypt.Key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	plaintext := []byte("backup antigo")
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	legacyFile := append([]byte("LGB1"), salt...)
	legacyFile = append(legacyFile, nonce...)
	legacyFile = append(legacyFile, ciphertext...)

	got, err := Decrypt(legacyFile, passphrase)
	if err != nil {
		t.Fatalf("Decrypt of a legacy LGB1 file failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted content mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptRejectsExcessiveScryptN(t *testing.T) {
	// Hand-build an LGB2 file whose embedded N is above maxScryptN. Asserting
	// on the specific sentinel error (not just "any error") matters: without
	// the cap, Decrypt would still return *an* error eventually (GCM auth
	// failure on the bogus nonce/ciphertext below), but only after actually
	// running scrypt.Key with N=1<<21 — several seconds and ~2GB of memory
	// for this test's N, and unboundedly worse for a hostile N near the
	// uint32 max. Checking for ErrScryptCostTooHigh specifically, combined
	// with a wall-clock budget, proves the reject happens before scrypt runs
	// at all.
	passphrase := "senha-123456789012"
	salt := make([]byte, saltSize)
	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nBytes, uint32(1<<21)) // above maxScryptN (1<<20)

	file := append([]byte("LGB2"), nBytes...)
	file = append(file, salt...)
	// No valid nonce/ciphertext needed — Decrypt must reject on N before
	// getting anywhere near GCM.
	file = append(file, make([]byte, 32)...)

	done := make(chan struct{})
	var err error
	go func() {
		_, err = Decrypt(file, passphrase)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Decrypt did not return within 2s — looks like it ran scrypt.Key with the untrusted N instead of rejecting it upfront")
	}
	if !errors.Is(err, ErrScryptCostTooHigh) {
		t.Fatalf("expected ErrScryptCostTooHigh, got %v", err)
	}
}

func TestEncryptDecryptRoundTripStillWorksLGB2(t *testing.T) {
	plaintext := []byte(`{"kind":"linkguard-fw-backup"}`)
	ciphertext, err := Encrypt(plaintext, "senha-nova-123456789")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ciphertext, "senha-nova-123456789")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}
