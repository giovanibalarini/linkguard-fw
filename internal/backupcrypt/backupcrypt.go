// Package backupcrypt encrypts and decrypts the LinkGuard FW backup file.
// AES-256-GCM with a key derived from a user passphrase via scrypt — pure
// algorithm, no knowledge of HTTP, storage, or what BackupData looks like.
package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// magic identifies a LinkGuard backup file and its format version. Bumping
// the version (a new magic value) lets a future format change coexist with
// files written by this version — Decrypt rejects unknown magic outright
// instead of trying to decrypt garbage.
var magic = []byte("LGB1")

const (
	saltSize = 16
	scryptN  = 32768
	scryptR  = 8
	scryptP  = 1
	keySize  = 32 // AES-256
)

// ErrInvalidFormat means data is not a recognizable LinkGuard backup file
// (wrong magic, or too short to contain one) — distinct from a wrong
// passphrase, which fails inside GCM's authentication check instead.
var ErrInvalidFormat = errors.New("backupcrypt: not a valid LinkGuard backup file")

// Encrypt derives a key from passphrase via scrypt (fresh random salt every
// call) and seals plaintext with AES-256-GCM (fresh random nonce every call).
// The returned bytes are self-contained: magic + salt + nonce + ciphertext.
func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("gerar salt: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("gerar nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(magic)+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt. A wrong passphrase or a tampered file both fail
// (GCM is authenticated) — never decrypts silently into garbage.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < len(magic)+saltSize {
		return nil, ErrInvalidFormat
	}
	if !bytes.Equal(data[:len(magic)], magic) {
		return nil, ErrInvalidFormat
	}
	offset := len(magic)
	salt := data[offset : offset+saltSize]
	offset += saltSize

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < offset+nonceSize {
		return nil, ErrInvalidFormat
	}
	nonce := data[offset : offset+nonceSize]
	offset += nonceSize
	ciphertext := data[offset:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("senha incorreta ou arquivo inválido: %w", err)
	}
	return plaintext, nil
}
