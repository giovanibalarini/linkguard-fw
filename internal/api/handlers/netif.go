package handlers

import (
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
		writeError(w, http.StatusInternalServerError, err.Error())
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
		writeError(w, http.StatusInternalServerError, err.Error())
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
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(h.db, r, "interface.identify", "interface:"+name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
