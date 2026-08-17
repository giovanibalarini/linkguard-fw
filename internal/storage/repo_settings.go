package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// ─── Settings repository ─────────────────────────────────────────────────────

// GetSetting retrieves a setting value by key.
func (db *DB) GetSetting(key string) (string, error) {
	var value string
	err := db.conn.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSetting upserts a setting value.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.conn.Exec(`
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now())
	return err
}

// ExportSettings returns every key/value in the settings table (for backups).
// Secrets are never in this table — see internal/secrets — so no filtering is
// needed here; the guarantee is structural, not a maintained exclusion list.
func (db *DB) ExportSettings() (map[string]string, error) {
	rows, err := db.conn.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SecretsSetter is the minimal write surface MigrateSettingsToSecrets needs.
// Defined here (not imported from internal/secrets) so internal/storage never
// depends on internal/secrets — the dependency runs the other way (secrets
// depends on storage.DB), and this keeps it that way.
type SecretsSetter interface {
	Set(name, plaintext string) error
}

// MigrateSettingsToSecrets moves the legacy secret-shaped settings rows
// (github_update_token, notifications, wireguard, and every totp_<userID>)
// into sec, then deletes them from settings. Idempotent: a key already absent
// from settings (already migrated on a prior boot) is silently skipped.
func MigrateSettingsToSecrets(db *DB, sec SecretsSetter) error {
	exact := []string{"github_update_token", "notifications", "wireguard"}
	for _, key := range exact {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}

	// GLOB (not LIKE) here: SQLite's LIKE treats "_" itself as a
	// single-character wildcard, so `LIKE 'totp_%'` would also match keys
	// like "totpXanything" that merely start with "totp" + any one
	// character — not just the literal "totp_" prefix. GLOB uses shell-style
	// wildcards where "_" has no special meaning, so `GLOB 'totp_*'` matches
	// exactly the intended "totp_<userID>" keys.
	rows, err := db.conn.Query(`SELECT key FROM settings WHERE key GLOB 'totp_*'`)
	if err != nil {
		return err
	}
	var totpKeys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		totpKeys = append(totpKeys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range totpKeys {
		if err := migrateOneSetting(db, sec, key); err != nil {
			return err
		}
	}
	return nil
}

// migrateOneSetting moves a single settings row into sec, then deletes it
// from settings. If sec.Set fails, the settings row is left untouched (no
// delete happens), so a retry of MigrateSettingsToSecrets will re-attempt
// this exact key from the plaintext still sitting in settings rather than
// silently losing the value.
func migrateOneSetting(db *DB, sec SecretsSetter, key string) error {
	value, err := db.GetSetting(key)
	if err != nil {
		return err
	}
	if value == "" {
		return nil // never set, or already migrated
	}
	if err := sec.Set(key, value); err != nil {
		return fmt.Errorf("migrate secret %q: %w", key, err)
	}
	_, err = db.conn.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}
