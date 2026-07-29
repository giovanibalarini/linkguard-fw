package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// AlertsHandler handles alert-related requests.
type AlertsHandler struct {
	svc *alerts.Service
}

// NewAlertsHandler creates an AlertsHandler.
func NewAlertsHandler(svc *alerts.Service) *AlertsHandler {
	return &AlertsHandler{svc: svc}
}

// List returns recent alerts.
func (h *AlertsHandler) List(w http.ResponseWriter, r *http.Request) {
	unresolvedOnly := r.URL.Query().Get("unresolved") == "true"
	ls, err := h.svc.List(unresolvedOnly, 100)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if ls == nil {
		ls = []storage.Alert{}
	}
	writeJSON(w, http.StatusOK, ls)
}

// Resolve marks an alert as resolved.
func (h *AlertsHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Resolve(id); err != nil {
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
