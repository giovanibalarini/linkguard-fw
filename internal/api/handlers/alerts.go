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
	db  *storage.DB
}

// NewAlertsHandler creates an AlertsHandler. It takes the DB because resolving
// an alert is an audited mutation, like every other mutation in the API.
func NewAlertsHandler(svc *alerts.Service, db *storage.DB) *AlertsHandler {
	return &AlertsHandler{svc: svc, db: db}
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

// Resolve marks an alert as resolved. Resolver um alerta é apagar da tela o
// aviso de WAN caída, disco com setor realocado ou divergência do firewall —
// por isso exige monitoring.write e fica registrado na auditoria, como qualquer
// outra mutação. Antes o gate era monitoring.read e não havia registro nenhum.
func (h *AlertsHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.Resolve(id); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "alert.resolve", "alert:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}
