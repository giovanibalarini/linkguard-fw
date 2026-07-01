package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/stresstest"
)

// StressTestHandler drives on-demand link fault-injection tests.
type StressTestHandler struct {
	svc *stresstest.Service
	db  *storage.DB
}

// NewStressTestHandler creates a StressTestHandler.
func NewStressTestHandler(svc *stresstest.Service, db *storage.DB) *StressTestHandler {
	return &StressTestHandler{svc: svc, db: db}
}

// Start launches a test (one at a time).
func (h *StressTestHandler) Start(w http.ResponseWriter, r *http.Request) {
	var p stresstest.StartParams
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	t, err := h.svc.Start(p)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "start", "stresstest", string(p.Mode)+" "+t.LinkName)
	writeJSON(w, http.StatusOK, t)
}

// Status returns the current or last test.
func (h *StressTestHandler) Status(w http.ResponseWriter, r *http.Request) {
	t := h.svc.Status()
	if t == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "idle"})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// Stop aborts a running test (it restores the link).
func (h *StressTestHandler) Stop(w http.ResponseWriter, r *http.Request) {
	h.svc.Stop()
	auditAction(h.db, r, "stop", "stresstest", "")
	writeJSON(w, http.StatusOK, map[string]bool{"stopped": true})
}
