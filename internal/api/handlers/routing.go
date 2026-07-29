package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/balancer"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// RoutingHandler exposes multi-WAN balancing (weighted multipath default route
// + scheduled rebalancing) with a safe apply/auto-rollback flow.
type RoutingHandler struct {
	svc *balancer.Service
	db  *storage.DB
}

// NewRoutingHandler creates a RoutingHandler.
func NewRoutingHandler(svc *balancer.Service, db *storage.DB) *RoutingHandler {
	return &RoutingHandler{svc: svc, db: db}
}

// statusResponse bundles the live plan with the persisted config for the UI.
type statusResponse struct {
	Config balancer.Config `json:"config"`
	Plan   balancer.Plan   `json:"plan"`
}

// Status returns the current balancing config + computed plan.
func (h *RoutingHandler) Status(w http.ResponseWriter, r *http.Request) {
	plan, err := h.svc.Plan(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Config: h.svc.LoadConfig(), Plan: plan})
}

// UpdateConfig updates mode/table/arm window and the schedule list.
func (h *RoutingHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg balancer.Config
	if err := decodeJSON(r, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	prev := h.svc.LoadConfig()
	if err := h.svc.SaveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "update", "routing/balance",
		"mode="+cfg.Mode+" schedules="+strconv.Itoa(len(cfg.Schedules)))

	// Switching INTO balance mode applies the route immediately (armed so a bad
	// change rolls back on its own). Leaving balance mode does not touch routes.
	if prev.Mode != balancer.ModeBalance && cfg.Mode == balancer.ModeBalance {
		if _, err := h.svc.Apply(r.Context(), true); err != nil {
			// Persisted, but apply failed — surface it without 500ing the save.
			writeJSON(w, http.StatusOK, map[string]any{"saved": true, "apply_error": err.Error()})
			return
		}
	}
	h.Status(w, r)
}

// Apply installs the multipath route now, arming auto-rollback unless arm=false.
func (h *RoutingHandler) Apply(w http.ResponseWriter, r *http.Request) {
	arm := true
	if r.URL.Query().Get("arm") == "false" {
		arm = false
	}
	plan, err := h.svc.Apply(r.Context(), arm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "apply", "routing/balance", strings.Join(commandSummary(plan), "; "))
	writeJSON(w, http.StatusOK, plan)
}

// Confirm keeps the last applied route (cancels the pending auto-rollback).
func (h *RoutingHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	ok := h.svc.Confirm()
	auditAction(h.db, r, "confirm", "routing/balance", "")
	writeJSON(w, http.StatusOK, map[string]bool{"confirmed": ok})
}

// Rollback restores the previous default route immediately.
func (h *RoutingHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Rollback(r.Context()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "rollback", "routing/balance", "")
	h.Status(w, r)
}

func commandSummary(p balancer.Plan) []string {
	out := make([]string, 0, len(p.Nexthops))
	for _, n := range p.Nexthops {
		out = append(out, n.Name+"(w="+strconv.Itoa(n.Weight)+")")
	}
	return out
}
