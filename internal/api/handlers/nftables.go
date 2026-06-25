package handlers

import (
	"net"
	"net/http"
	"strings"
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

// Managed returns the editable element-level view (host_wan map + sets).
func (h *NftablesHandler) Managed(w http.ResponseWriter, r *http.Request) {
	m, err := h.svc.Managed(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// WanHost adds (POST) or removes (DELETE) a host IP in the host_wan map.
func (h *NftablesHandler) WanHost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Mark string `json:"mark"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := strings.TrimSpace(body.IP)
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelWanHost(r.Context(), ip)
		auditAction(h.db, r, "nft.wan-host.del", "host_wan:"+ip, "")
	} else {
		_, err = h.svc.AddWanHost(r.Context(), ip, strings.TrimSpace(body.Mark))
		auditAction(h.db, r, "nft.wan-host.add", "host_wan:"+ip, body.Mark)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Blocklist adds (POST) or removes (DELETE) a destination CIDR/IP in the set.
func (h *NftablesHandler) Blocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cidr := strings.TrimSpace(body.CIDR)
	if !validCIDRorIP(cidr) {
		writeError(w, http.StatusBadRequest, "invalid CIDR or IP")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.del", cidr, "")
	} else {
		_, err = h.svc.AddBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.add", cidr, "")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validCIDRorIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
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
