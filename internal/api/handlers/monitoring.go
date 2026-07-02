package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// MonitoringHandler exposes the health snapshot and monitoring config.
type MonitoringHandler struct {
	col *monitoring.Collector
	db  *storage.DB
}

func NewMonitoringHandler(col *monitoring.Collector, db *storage.DB) *MonitoringHandler {
	return &MonitoringHandler{col: col, db: db}
}

// Health returns the current health of services, links and resources.
func (h *MonitoringHandler) Health(w http.ResponseWriter, r *http.Request) {
	items := h.col.Snapshot()
	if items == nil {
		items = []monitoring.HealthItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

// GetConfig returns the monitoring config (zero-config defaults if unset).
func (h *MonitoringHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, monitoring.LoadConfig(h.db))
}

// SetConfig persists the monitoring config.
func (h *MonitoringHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	var in monitoring.Config
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := monitoring.SaveConfig(h.db, in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, monitoring.LoadConfig(h.db))
}
