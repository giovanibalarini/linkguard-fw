package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

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

// BackupHandler exports and restores the configuration.
type BackupHandler struct {
	db      *storage.DB
	sec     secrets.Secrets
	version string
}

// NewBackupHandler creates a BackupHandler.
func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string) *BackupHandler {
	return &BackupHandler{db: db, sec: sec, version: version}
}

// Export downloads the full configuration as a JSON attachment.
func (h *BackupHandler) Export(w http.ResponseWriter, r *http.Request) {
	data, err := h.snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "export", "backup", "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="linkguard-backup.json"`)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *BackupHandler) snapshot() (BackupData, error) {
	settings, err := h.db.ExportSettings()
	if err != nil {
		return BackupData{}, err
	}
	links, err := h.db.GetLinks()
	if err != nil {
		return BackupData{}, err
	}
	res, err := h.db.ListDHCPReservations()
	if err != nil {
		return BackupData{}, err
	}
	block, err := h.db.ListDNSBlocklist()
	if err != nil {
		return BackupData{}, err
	}
	if block == nil {
		block = []string{}
	}
	return BackupData{
		Version:      h.version,
		Kind:         "linkguard-fw-backup",
		Settings:     settings,
		Links:        links,
		Reservations: res,
		Blocklist:    block,
	}, nil
}

// restoreResult reports what the restore applied.
type restoreResult struct {
	Settings             int      `json:"settings"`
	Reservations         int      `json:"reservations"`
	Blocklist            int      `json:"blocklist"`
	SecretsToReconfigure []string `json:"secrets_to_reconfigure"`
}

// Restore applies settings, DHCP reservations and the DNS blocklist from an
// uploaded backup. It does not restart services (the operator re-applies DHCP/
// DNS/firewall afterwards) and does not touch users/roles or WAN links, so it
// can never lock the operator out or disturb live routing.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	var data BackupData
	if err := decodeJSON(r, &data); err != nil {
		writeError(w, http.StatusBadRequest, "arquivo de backup inválido")
		return
	}
	if data.Kind != "linkguard-fw-backup" {
		writeError(w, http.StatusBadRequest, "isto não parece um backup do LinkGuard FW")
		return
	}

	var res restoreResult
	for k, v := range data.Settings {
		if err := h.db.SetSetting(k, v); err == nil {
			res.Settings++
		}
	}
	for _, rsv := range data.Reservations {
		if err := h.db.UpsertDHCPReservation(rsv.MAC, rsv.IP, rsv.Hostname); err == nil {
			res.Reservations++
		}
	}
	for _, d := range data.Blocklist {
		if err := h.db.AddDNSBlocklist(d); err == nil {
			res.Blocklist++
		}
	}

	// Secrets are never in the backup file (they live in a separate table
	// ExportSettings never touches), so a restored device must be told which
	// ones it still needs configured by hand. totp_* is deliberately excluded:
	// 2FA is per-user state, not a single "is it configured" toggle, so it
	// can't be represented as one entry in this list.
	knownSecrets := []string{"github_update_token", "notifications"}
	missing := []string{}
	for _, name := range knownSecrets {
		if configured, _ := h.sec.Status(name); !configured {
			missing = append(missing, name)
		}
	}
	res.SecretsToReconfigure = missing

	auditAction(h.db, r, "restore", "backup", "")
	writeJSON(w, http.StatusOK, res)
}
