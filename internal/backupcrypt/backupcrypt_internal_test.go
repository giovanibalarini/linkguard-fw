package backupcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

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
