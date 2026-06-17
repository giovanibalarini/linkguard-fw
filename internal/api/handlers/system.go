package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// SystemHandler handles system status requests.
type SystemHandler struct {
	sysCol *system.Collector
}

// NewSystemHandler creates a SystemHandler.
func NewSystemHandler(sysCol *system.Collector) *SystemHandler {
	return &SystemHandler{sysCol: sysCol}
}

// Status returns current system resource metrics.
func (h *SystemHandler) Status(w http.ResponseWriter, r *http.Request) {
	m, err := h.sysCol.Collect()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to collect system metrics")
		return
	}

	type response struct {
		*system.Metrics
		UptimeStr string `json:"uptime_str"`
	}

	writeJSON(w, http.StatusOK, response{
		Metrics:   m,
		UptimeStr: system.UptimeString(m.UptimeSeconds),
	})
}
