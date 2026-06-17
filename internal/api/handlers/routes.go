package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/routes"
)

// RoutesHandler handles routing table requests.
type RoutesHandler struct {
	svc *routes.Service
}

// NewRoutesHandler creates a RoutesHandler.
func NewRoutesHandler(svc *routes.Service) *RoutesHandler {
	return &RoutesHandler{svc: svc}
}

// List returns the main routing table.
func (h *RoutesHandler) List(w http.ResponseWriter, r *http.Request) {
	rs, err := h.svc.ListRoutes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rs == nil {
		rs = []routes.Route{}
	}
	writeJSON(w, http.StatusOK, rs)
}

// ListRules returns ip rules.
func (h *RoutesHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.svc.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []routes.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}
