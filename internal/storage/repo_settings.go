package storage

import (
	"database/sql"
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

// DeleteSetting removes a setting row. No-op if the key was never set.
func (db *DB) DeleteSetting(key string) error {
	_, err := db.conn.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}

// SettingKeys returns every key in the settings table, without the values.
// Used by the boot-time migration in internal/secrets to find the
// totp_<userID> rows: which keys are secrets is that package's policy, so
// this one only answers "what keys exist".
func (db *DB) SettingKeys() ([]string, error) {
	rows, err := db.conn.Query(`SELECT key FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
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
