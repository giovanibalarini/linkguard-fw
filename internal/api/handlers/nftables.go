package handlers

import (
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NftablesHandler exposes the native nftables ruleset and its backups. This
// replaces the legacy iptables handler — the firewall is managed via nft now.
type NftablesHandler struct {
	svc *nftables.Service
	db  *storage.DB
}

// NewNftablesHandler creates an NftablesHandler.
func NewNftablesHandler(svc *nftables.Service, db *storage.DB) *NftablesHandler {
	return &NftablesHandler{svc: svc, db: db}
}

// Ruleset returns the full live nftables ruleset.
func (h *NftablesHandler) Ruleset(w http.ResponseWriter, r *http.Request) {
	rs, err := h.svc.Ruleset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": rs})
}

// Backup snapshots the current nftables ruleset into the database.
func (h *NftablesHandler) Backup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = decodeJSON(r, &body)
	if body.Label == "" {
		body.Label = "nft-" + time.Now().Format("2006-01-02T15:04:05")
	}
	rs, err := h.svc.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read nft ruleset: "+err.Error())
		return
	}
	backup := &storage.IptablesBackup{Label: body.Label, Rules: rs}
	if err := h.db.CreateIptablesBackup(backup); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store backup: "+err.Error())
		return
	}
	auditAction(h.db, r, "nft.backup", "ruleset", body.Label)
	writeJSON(w, http.StatusCreated, backup)
}

// ListBackups returns stored ruleset backups.
func (h *NftablesHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := h.db.GetIptablesBackups(20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if backups == nil {
		backups = []storage.IptablesBackup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// Rollback restores a stored ruleset snapshot via nft.
func (h *NftablesHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BackupID string `json:"backup_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	backups, err := h.db.GetIptablesBackups(100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var target *storage.IptablesBackup
	for i := range backups {
		if backups[i].ID == body.BackupID {
			target = &backups[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	out, err := h.svc.Restore(r.Context(), target.Rules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rollback failed: "+err.Error())
		return
	}
	auditAction(h.db, r, "nft.rollback", "ruleset", target.Label)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "rollback completed", "output": out})
}
