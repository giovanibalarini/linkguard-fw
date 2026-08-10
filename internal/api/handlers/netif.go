package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NetifHandler handles the read-only interface inventory (Phase 1).
type NetifHandler struct {
	svc *netif.Service
	db  *storage.DB
}

// NewNetifHandler creates a NetifHandler.
func NewNetifHandler(svc *netif.Service, db *storage.DB) *NetifHandler {
	return &NetifHandler{svc: svc, db: db}
}

// List returns every interface the kernel currently knows about.
func (h *NetifHandler) List(w http.ResponseWriter, r *http.Request) {
	views, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if views == nil {
		views = []netif.IfaceView{}
	}
	writeJSON(w, http.StatusOK, views)
}

// Drift is a Phase 1 stub — real drift detection ships in Phase 4 (spec
// §14). Always returns an empty list: the frontend must not render this as
// "confirmed no drift", only as "this feature isn't built yet" (no UI
// surface in Phase 1 reads this endpoint — it exists so the route is stable
// once Phase 4 lands).
func (h *NetifHandler) Drift(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []struct{}{})
}

// Identify blinks a physical port's LED (`ethtool -p`) so an admin at the
// rack can find it. Rejects VLAN/bridge names — identification only makes
// sense for a real physical port.
func (h *NetifHandler) Identify(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "interface name is required")
		return
	}

	views, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var found *netif.IfaceView
	for i := range views {
		if views[i].Name == name {
			found = &views[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "interface not found")
		return
	}
	if found.Kind != netif.KindPhysical {
		writeError(w, http.StatusBadRequest, "only physical interfaces can be identified")
		return
	}

	if err := h.svc.Identify(r.Context(), name, 10); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "interface.identify", "interface:"+name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Preview shows what would change for an edit, without applying it.
func (h *NetifHandler) Preview(w http.ResponseWriter, r *http.Request) {
	var edit netif.IfaceEdit
	if err := decodeJSON(r, &edit); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	result, err := h.svc.Preview(r.Context(), edit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Apply writes the new config and starts the confirm-or-rollback window.
func (h *NetifHandler) Apply(w http.ResponseWriter, r *http.Request) {
	var edit netif.IfaceEdit
	if err := decodeJSON(r, &edit); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	pending, err := h.svc.ApplyChange(r.Context(), edit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.apply", "interface:"+edit.Name, "")
	writeJSON(w, http.StatusOK, pending)
}

// Confirm accepts a pending change.
func (h *NetifHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if err := h.svc.Confirm(r.Context(), body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.confirm", "interface:"+body.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Rollback immediately reverts a pending change.
func (h *NetifHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	if err := h.svc.Rollback(r.Context(), body.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "interface.rollback", "interface:"+body.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Pending lists every in-flight unconfirmed change.
func (h *NetifHandler) Pending(w http.ResponseWriter, r *http.Request) {
	pending, err := h.svc.ListPending(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pending)
}

// StableNames previews the persistent MAC-matched names Fase A would
// assign to configured WAN interfaces — see
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
func (h *NetifHandler) StableNames(w http.ResponseWriter, r *http.Request) {
	entries, err := h.svc.StableNames(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if entries == nil {
		entries = []netif.StableNameEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// ApplyStableNames writes the .link files. This never takes effect until
// the next reboot (see WriteLinkFile) — requires_reboot=true in the
// response tells the frontend to say so explicitly instead of implying it
// already happened.
func (h *NetifHandler) ApplyStableNames(w http.ResponseWriter, r *http.Request) {
	entries, err := h.svc.ApplyStableNames(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if entries == nil {
		entries = []netif.StableNameEntry{}
	}
	auditAction(h.db, r, "apply", "interfaces/stable-names", fmt.Sprintf("%d", len(entries)))
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":         entries,
		"requires_reboot": true,
	})
}
