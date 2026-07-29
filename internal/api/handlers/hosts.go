package handlers

import (
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// HostsHandler handles the LAN host inventory.
type HostsHandler struct {
	svc *hosts.Service
	db  *storage.DB
}

// NewHostsHandler creates a HostsHandler.
func NewHostsHandler(svc *hosts.Service, db *storage.DB) *HostsHandler {
	return &HostsHandler{svc: svc, db: db}
}

// List returns the current host inventory.
func (h *HostsHandler) List(w http.ResponseWriter, r *http.Request) {
	hs, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if hs == nil {
		hs = []hosts.Host{}
	}
	writeJSON(w, http.StatusOK, hs)
}

// SetAlias sets a friendly name for a host (by MAC).
func (h *HostsHandler) SetAlias(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC   string `json:"mac"`
		Alias string `json:"alias"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.MAC = strings.TrimSpace(strings.ToLower(body.MAC))
	if body.MAC == "" {
		writeError(w, http.StatusBadRequest, "mac is required")
		return
	}
	if err := h.svc.SetAlias(body.MAC, strings.TrimSpace(body.Alias)); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetBlocked blocks or unblocks a host (by MAC).
func (h *HostsHandler) SetBlocked(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MAC     string `json:"mac"`
		Blocked bool   `json:"blocked"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.MAC = strings.TrimSpace(strings.ToLower(body.MAC))
	if body.MAC == "" {
		writeError(w, http.StatusBadRequest, "mac is required")
		return
	}
	if err := h.svc.SetBlocked(r.Context(), body.MAC, body.Blocked); err != nil {
		writeInternalError(w, err)
		return
	}
	action := "host.unblock"
	if body.Blocked {
		action = "host.block"
	}
	auditAction(h.db, r, action, "host:"+body.MAC, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
