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

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
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

// CheckNotOrphaned returns an error if path does not exist but db already has
// rows in the secrets table — meaning a key was lost after secrets were
// encrypted under it, not that this is a genuine first boot. Call this
// before LoadOrGenerateKey so a missing key with no prior secrets still takes
// the normal first-boot generate path, while a missing key with existing
// secrets fails loudly instead of silently orphaning them (which would
// otherwise, e.g., make every user's 2FA silently stop being checked, since
// getTwoFA swallows a decrypt error and treats it as "2FA not enabled").
//
// A stat error other than "not exist" is left for LoadOrGenerateKey's own
// os.ReadFile call to report — that call already turns it into a clear,
// specific error (e.g. permission denied), so this function does not
// duplicate that path; it treats "can't tell if it exists" as "not our
// problem to report" and returns nil, deferring to the caller's next step.
func CheckNotOrphaned(path string, db *storage.DB) error {
	_, err := os.Stat(path)
	if err == nil {
		// Key file exists: nothing to check here, LoadOrGenerateKey will
		// validate its size/readability itself.
		return nil
	}
	if !os.IsNotExist(err) {
		// Some other stat failure (e.g. permission denied on a parent
		// directory). Not our call to make — LoadOrGenerateKey's own
		// os.ReadFile will hit the same condition and report it.
		return nil
	}

	var count int
	if qErr := db.Conn().QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&count); qErr != nil {
		return fmt.Errorf("check for orphaned secrets: %w", qErr)
	}
	if count > 0 {
		return fmt.Errorf(
			"secret key file %s is missing but the secrets table already has %d row(s): "+
				"this looks like the encryption key was lost, NOT a first boot — starting now "+
				"would generate a new key and silently make every existing secret (including "+
				"2FA) undecryptable; restore the original %s or, if the loss is confirmed and "+
				"accepted, clear the secrets table before restarting",
			path, count, path)
	}
	return nil
}
