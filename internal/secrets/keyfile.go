// Package secrets stores credentials separately from configuration. The
// separation is the guarantee: internal/storage's ExportSettings() only ever
// reads the settings table, so a value stored here structurally cannot leak
// through a backup export, no matter what future feature adds a new secret.
//
// This does not protect against root on the machine — the service runs as
// root and can read both the key file and the database. It protects against
// the real vectors for this installation: a shared backup file, a copied
// .db, a decommissioned disk.
package secrets

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const keySize = 32 // AES-256

// LoadOrGenerateKey reads the encryption key from path, generating and
// writing a new random one on first run. The key is never derived from any
// other secret (e.g. jwt_secret) — rotating one must never invalidate the
// other. A key file that exists but is unreadable or the wrong size is a
// fatal error: the service must not start and silently treat every secret as
// "not configured".
func LoadOrGenerateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != keySize {
			return nil, fmt.Errorf("secret key file %s is %d bytes, expected %d", path, len(data), keySize)
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secret key file %s: %w", path, err)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create secret key directory: %w", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("write secret key file %s: %w", path, err)
	}
	return key, nil
}
