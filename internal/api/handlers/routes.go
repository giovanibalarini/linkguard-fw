package handlers

import (
	"net/http"
	"strings"

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

// AddRoute creates a route entry.
func (h *RoutesHandler) AddRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Destination string `json:"destination"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"interface"`
		Table       string `json:"table"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.Destination) == "" {
		writeError(w, http.StatusBadRequest, "destination is required")
		return
	}
	out, err := h.svc.AddRoute(r.Context(), body.Destination, body.Gateway, body.Interface, body.Table)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "route added", "output": out})
}

// DeleteRoute removes a route entry.
func (h *RoutesHandler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Destination string `json:"destination"`
		Table       string `json:"table"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.Destination) == "" {
		writeError(w, http.StatusBadRequest, "destination is required")
		return
	}
	out, err := h.svc.DelRoute(r.Context(), body.Destination, body.Table)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "route deleted", "output": out})
}

// UpdateRoute replaces a route by deleting old and adding new.
func (h *RoutesHandler) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldDestination string `json:"old_destination"`
		OldTable       string `json:"old_table"`
		Destination    string `json:"destination"`
		Gateway        string `json:"gateway"`
		Interface      string `json:"interface"`
		Table          string `json:"table"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.OldDestination) == "" || strings.TrimSpace(body.Destination) == "" {
		writeError(w, http.StatusBadRequest, "old_destination and destination are required")
		return
	}
	if _, err := h.svc.DelRoute(r.Context(), body.OldDestination, body.OldTable); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.AddRoute(r.Context(), body.Destination, body.Gateway, body.Interface, body.Table)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "route updated", "output": out})
}

// AddRule creates an ip rule entry.
func (h *RoutesHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		From     string `json:"from"`
		Table    string `json:"table"`
		Priority int    `json:"priority"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.Table) == "" {
		writeError(w, http.StatusBadRequest, "table is required")
		return
	}
	out, err := h.svc.AddRule(r.Context(), body.From, body.Table, body.Priority)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "rule added", "output": out})
}

// DeleteRule removes an ip rule entry.
func (h *RoutesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		From     string `json:"from"`
		Table    string `json:"table"`
		Priority int    `json:"priority"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	out, err := h.svc.DelRule(r.Context(), body.From, body.Table, body.Priority)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "rule deleted", "output": out})
}

// UpdateRule replaces an ip rule by deleting old and adding new.
func (h *RoutesHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldFrom     string `json:"old_from"`
		OldTable    string `json:"old_table"`
		OldPriority int    `json:"old_priority"`
		From        string `json:"from"`
		Table       string `json:"table"`
		Priority    int    `json:"priority"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(body.Table) == "" {
		writeError(w, http.StatusBadRequest, "table is required")
		return
	}
	if _, err := h.svc.DelRule(r.Context(), body.OldFrom, body.OldTable, body.OldPriority); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.AddRule(r.Context(), body.From, body.Table, body.Priority)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "rule updated", "output": out})
}
