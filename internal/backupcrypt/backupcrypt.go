// Package backupcrypt encrypts and decrypts the LinkGuard FW backup file.
// AES-256-GCM with a key derived from a user passphrase via scrypt — pure
// algorithm, no knowledge of HTTP, storage, or what BackupData looks like.
package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// magicLegacy (LGB1) is the original fixed-cost format: magic + salt + nonce +
// ciphertext, always N=legacyScryptN. magicCurrent (LGB2) is written by every
// new Encrypt call and embeds N explicitly (4 bytes, big-endian) right after
// the magic, so a future cost bump doesn't strand already-issued files again —
// Decrypt reads whichever N the file says to use instead of assuming a fixed
// constant.
var (
	magicLegacy  = []byte("LGB1")
	magicCurrent = []byte("LGB2")
)

const (
	saltSize = 16
	// legacyScryptN is the fixed N used by every LGB1 file ever written
	// (before this format version existed) — never change this constant, it
	// exists only to keep decrypting old files correct.
	legacyScryptN = 32768
	// scryptN is what Encrypt uses today — RFC 7914's guidance for a
	// long-lived, offline-attackable file (not just an interactive login) is
	// closer to 2^20; 2^17 is a deliberate middle ground that stays under ~1s
	// on modest hardware while raising the offline-bruteforce cost well above
	// the previous 2^15.
	scryptN = 131072
	scryptR = 8
	scryptP = 1
	keySize = 32 // AES-256

	// maxScryptN caps the N a .lgbak file is allowed to request before
	// Decrypt will even attempt scrypt.Key. LGB2 files carry N in the file
	// itself so a future cost bump doesn't strand old backups (see the
	// comment above), but that also means an attacker- or corruption-supplied
	// N is untrusted input: scrypt.Key's memory use is ~128*N*r bytes, so an
	// N near the uint32 max (as read straight off the wire) would try to
	// allocate terabytes and OOM/hang the process before the passphrase is
	// even checked. 1<<20 (2^20) is 8x today's scryptN (2^17) — plenty of
	// headroom for future cost bumps like the 2^15→2^17 one this format
	// already survived — while keeping worst-case memory in the ~1GB range.
	maxScryptN = 1 << 20
)

// ErrInvalidFormat means data is not a recognizable LinkGuard backup file
// (wrong magic, or too short to contain one) — distinct from a wrong
// passphrase, which fails inside GCM's authentication check instead.
var ErrInvalidFormat = errors.New("backupcrypt: not a valid LinkGuard backup file")

// ErrScryptCostTooHigh means the file's embedded scrypt N exceeds
// maxScryptN. Returned before scrypt.Key is ever called, so a malicious or
// corrupted file can't force a huge memory allocation / CPU stall just by
// claiming an absurd cost parameter.
var ErrScryptCostTooHigh = errors.New("backupcrypt: scrypt cost parameter exceeds allowed maximum")

// Encrypt derives a key from passphrase via scrypt (fresh random salt every
// call) and seals plaintext with AES-256-GCM (fresh random nonce every call).
// Always writes the current format (LGB2): magic + N (4 bytes) + salt + nonce
// + ciphertext.
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

	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nBytes, uint32(scryptN))

	out := make([]byte, 0, len(magicCurrent)+len(nBytes)+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, magicCurrent...)
	out = append(out, nBytes...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt for either format: LGB1 (fixed legacyScryptN) or
// LGB2 (N embedded in the file). A wrong passphrase or a tampered file both
// fail (GCM is authenticated) — never decrypts silently into garbage.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 4 {
		return nil, ErrInvalidFormat
	}
	var n int
	var offset int
	switch {
	case bytes.Equal(data[:4], magicLegacy):
		n = legacyScryptN
		offset = 4
	case bytes.Equal(data[:4], magicCurrent):
		if len(data) < 8 {
			return nil, ErrInvalidFormat
		}
		n = int(binary.BigEndian.Uint32(data[4:8]))
		offset = 8
	default:
		return nil, ErrInvalidFormat
	}
	// Applied to both formats: legacyScryptN is a fixed code constant well
	// under the cap, so this is a no-op there; for LGB2 it's the load-bearing
	// check that stops a file-supplied N from reaching scrypt.Key uncapped.
	if n <= 0 || n > maxScryptN {
		return nil, ErrScryptCostTooHigh
	}
	if len(data) < offset+saltSize {
		return nil, ErrInvalidFormat
	}
	salt := data[offset : offset+saltSize]
	offset += saltSize

	key, err := scrypt.Key([]byte(passphrase), salt, n, scryptR, scryptP, keySize)
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
