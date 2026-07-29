// Package backup owns the LinkGuard FW configuration snapshot: what goes into
// a backup, and how it's encrypted/decrypted. Kept separate from
// internal/api/handlers so both the HTTP handler and the Scheduler (which
// runs with no HTTP request in sight) can share the exact same logic without
// an import cycle.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// PassphraseSecretName is the internal/secrets entry holding the backup
// encryption passphrase.
const PassphraseSecretName = "backup_passphrase"

// BackupData is the portable snapshot of the panel's configuration. Settings
// carry the bulk of it (balancer, port forwards, VPN, notifications, DHCP/DNS,
// 2FA), plus the LAN-facing reservation/blocklist lists. Links are exported for
// reference but not auto-restored (they tie into live routing/table IDs).
type BackupData struct {
	Version      string                    `json:"version"`
	Kind         string                    `json:"kind"`
	Settings     map[string]string         `json:"settings"`
	Links        []storage.Link            `json:"links"`
	Reservations []storage.DHCPReservation `json:"dhcp_reservations"`
	Blocklist    []string                  `json:"dns_blocklist"`
}

// ErrPassphraseNotConfigured means EncryptSnapshot was called before a backup
// passphrase was ever set — there's nothing to encrypt with.
var ErrPassphraseNotConfigured = errors.New("nenhuma senha de backup configurada")

// Snapshot builds the current BackupData from the database.
func Snapshot(db *storage.DB, version string) (BackupData, error) {
	settings, err := db.ExportSettings()
	if err != nil {
		return BackupData{}, err
	}
	links, err := db.GetLinks()
	if err != nil {
		return BackupData{}, err
	}
	res, err := db.ListDHCPReservations()
	if err != nil {
		return BackupData{}, err
	}
	block, err := db.ListDNSBlocklist()
	if err != nil {
		return BackupData{}, err
	}
	if block == nil {
		block = []string{}
	}
	return BackupData{
		Version:      version,
		Kind:         "linkguard-fw-backup",
		Settings:     settings,
		Links:        links,
		Reservations: res,
		Blocklist:    block,
	}, nil
}

// EncryptSnapshot builds the current snapshot, serializes it to JSON, and
// encrypts it with the configured backup passphrase.
func EncryptSnapshot(db *storage.DB, sec secrets.Secrets, version string) ([]byte, error) {
	passphrase, err := sec.Get(PassphraseSecretName)
	if err != nil {
		return nil, fmt.Errorf("ler senha de backup: %w", err)
	}
	if passphrase == "" {
		return nil, ErrPassphraseNotConfigured
	}
	data, err := Snapshot(db, version)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serializar backup: %w", err)
	}
	return backupcrypt.Encrypt(plaintext, passphrase)
}

// DecryptRestore decrypts ciphertext with passphrase and parses it back into
// BackupData, verifying it really is a LinkGuard backup (not just any file
// that happens to decrypt without error under this passphrase).
func DecryptRestore(ciphertext []byte, passphrase string) (BackupData, error) {
	plaintext, err := backupcrypt.Decrypt(ciphertext, passphrase)
	if err != nil {
		return BackupData{}, err
	}
	var data BackupData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return BackupData{}, fmt.Errorf("backup decifrado não é um JSON válido: %w", err)
	}
	if data.Kind != "linkguard-fw-backup" {
		return BackupData{}, errors.New("isto não parece um backup do LinkGuard FW")
	}
	return data, nil
}
