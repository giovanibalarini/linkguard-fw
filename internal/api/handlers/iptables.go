package handlers

import (
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// IptablesHandler handles iptables-related requests.
type IptablesHandler struct {
	svc *iptables.Service
	db  *storage.DB
}

// NewIptablesHandler creates an IptablesHandler.
func NewIptablesHandler(svc *iptables.Service, db *storage.DB) *IptablesHandler {
	return &IptablesHandler{svc: svc, db: db}
}

// ListAll returns all iptables tables.
func (h *IptablesHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	tables, err := h.svc.ListAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tables)
}

// ListFilter returns the filter table.
func (h *IptablesHandler) ListFilter(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "filter")
}

// ListNat returns the nat table.
func (h *IptablesHandler) ListNat(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "nat")
}

// ListMangle returns the mangle table.
func (h *IptablesHandler) ListMangle(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "mangle")
}

func (h *IptablesHandler) listTable(w http.ResponseWriter, r *http.Request, table string) {
	t, err := h.svc.ListTable(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// Preview returns the commands that would be applied without executing them.
func (h *IptablesHandler) Preview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Commands []string `json:"commands"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"preview":  true,
		"commands": body.Commands,
		"message":  "Dry-run preview — no changes applied",
	})
}

// Backup saves current iptables rules to the database.
func (h *IptablesHandler) Backup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = decodeJSON(r, &body)
	if body.Label == "" {
		body.Label = "manual-" + time.Now().Format("2006-01-02T15:04:05")
	}

	rules, err := h.svc.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save iptables rules: "+err.Error())
		return
	}

	backup := &storage.IptablesBackup{Label: body.Label, Rules: rules}
	if err := h.db.CreateIptablesBackup(backup); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store backup: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, backup)
}

// ListBackups returns iptables rule backups.
func (h *IptablesHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
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

// Rollback restores iptables rules from a backup.
func (h *IptablesHandler) Rollback(w http.ResponseWriter, r *http.Request) {
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "rollback completed",
		"output":  out,
		"backup":  target,
	})
}
