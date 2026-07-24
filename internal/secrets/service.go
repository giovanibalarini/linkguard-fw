package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Secrets is the only way credentials enter or leave storage. There is
// deliberately no "list all" or "export" method — callers must know the exact
// name they want, which keeps a future accidental dump structurally hard.
type Secrets interface {
	Set(name, plaintext string) error
	Get(name string) (string, error)
	Status(name string) (configured bool, hint string)
	Delete(name string) error
}

// Service is the AES-256-GCM-backed implementation, storing ciphertext in the
// secrets table.
type Service struct {
	db  *storage.DB
	gcm cipher.AEAD
}

// NewService creates a secrets Service. key must be exactly 32 bytes (see
// LoadOrGenerateKey).
func NewService(db *storage.DB, key []byte) *Service {
	block, err := aes.NewCipher(key)
	if err != nil {
		// key is always 32 bytes from LoadOrGenerateKey; a bad key here is a
		// programming error, not a runtime condition to recover from.
		panic(fmt.Sprintf("secrets: invalid key: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("secrets: create GCM: %v", err))
	}
	return &Service{db: db, gcm: gcm}
}

// Set encrypts plaintext with a fresh random nonce and upserts it.
func (s *Service) Set(name, plaintext string) error {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := s.gcm.Seal(nil, nonce, []byte(plaintext), nil)

	_, err := s.db.Conn().Exec(`
		INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at`,
		name, nonce, ciphertext, time.Now())
	return err
}

// Get decrypts and returns the plaintext, or "" if name was never set. A
// tampered or corrupted ciphertext returns an error rather than garbage —
// GCM is authenticated, so decryption failure is detectable, and this
// function never masks that as "not configured".
func (s *Service) Get(name string) (string, error) {
	var nonce, ciphertext []byte
	err := s.db.Conn().QueryRow(`SELECT nonce, ciphertext FROM secrets WHERE name = ?`, name).
		Scan(&nonce, &ciphertext)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	return string(plaintext), nil
}

// Status reports whether name is configured and, if so, a display hint. Many
// API tokens use a multi-segment prefix (e.g. "sk-ant-"), so the hint keeps
// everything up to and including the *last* "-" found within the first 12
// characters — not just the first "-", which would truncate "sk-ant-" down
// to "sk-" — replaces the middle with "…", and shows the last 4 characters.
// That's enough for the admin to recognize which token it is without ever
// seeing the value.
func (s *Service) Status(name string) (configured bool, hint string) {
	val, err := s.Get(name)
	if err != nil || val == "" {
		return false, ""
	}
	window := val
	if len(window) > 12 {
		window = window[:12]
	}
	prefix := ""
	if idx := strings.LastIndex(window, "-"); idx > 0 {
		prefix = val[:idx+1]
	}
	suffix := val
	if len(val) > 4 {
		suffix = val[len(val)-4:]
	}
	return true, prefix + "…" + suffix
}

// Delete removes a secret. No-op if it was never set.
func (s *Service) Delete(name string) error {
	_, err := s.db.Conn().Exec(`DELETE FROM secrets WHERE name = ?`, name)
	return err
}

// NonceForTest exposes the stored nonce for a name, for testing nonce
// uniqueness across Set calls. Test-only.
func (s *Service) NonceForTest(name string) []byte {
	var nonce []byte
	_ = s.db.Conn().QueryRow(`SELECT nonce FROM secrets WHERE name = ?`, name).Scan(&nonce)
	return nonce
}

// CorruptCiphertextForTest flips a byte of the stored ciphertext, simulating
// tampering or disk corruption, so tests can verify Get fails loudly instead
// of returning garbage. Test-only.
func (s *Service) CorruptCiphertextForTest(name string) {
	var ciphertext []byte
	_ = s.db.Conn().QueryRow(`SELECT ciphertext FROM secrets WHERE name = ?`, name).Scan(&ciphertext)
	if len(ciphertext) == 0 {
		return
	}
	ciphertext[0] ^= 0xFF
	_, _ = s.db.Conn().Exec(`UPDATE secrets SET ciphertext = ? WHERE name = ?`, ciphertext, name)
}
