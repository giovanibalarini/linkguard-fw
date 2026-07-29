package backupcrypt_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte(`{"kind":"linkguard-fw-backup","settings":{}}`)
	ciphertext, err := backupcrypt.Encrypt(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := backupcrypt.Decrypt(ciphertext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertextEachTime(t *testing.T) {
	// Salt+nonce are random per call, so encrypting the same plaintext twice
	// must never produce identical bytes — a fixed salt/nonce would leak
	// whether two backups share content.
	a, err := backupcrypt.Encrypt([]byte("mesmo conteudo"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := backupcrypt.Encrypt([]byte("mesmo conteudo"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("expected different ciphertext across calls (salt/nonce must be random per call)")
	}
}

func TestDecryptWrongPassphraseFails(t *testing.T) {
	ciphertext, err := backupcrypt.Encrypt([]byte("segredo"), "senha-certa-123456")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := backupcrypt.Decrypt(ciphertext, "senha-errada-123456"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase, got nil")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	ciphertext, err := backupcrypt.Encrypt([]byte("dado importante"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF // flip a byte inside the GCM ciphertext/tag
	if _, err := backupcrypt.Decrypt(tampered, "senha-123456789012"); err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestDecryptUnknownMagicFails(t *testing.T) {
	garbage := []byte("not a linkguard backup file at all, just garbage bytes here")
	if _, err := backupcrypt.Decrypt(garbage, "qualquer-senha-1234"); err != backupcrypt.ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestDecryptTruncatedFileFails(t *testing.T) {
	if _, err := backupcrypt.Decrypt([]byte("LGB1x"), "qualquer-senha-1234"); err != backupcrypt.ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat for truncated file, got %v", err)
	}
}
