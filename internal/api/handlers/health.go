package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// HealthHandler handles health check requests.
type HealthHandler struct {
	db     *storage.DB
	sysCol *system.Collector
}

// NewHealthHandler creates a HealthHandler.
func NewHealthHandler(db *storage.DB, sysCol *system.Collector) *HealthHandler {
	return &HealthHandler{db: db, sysCol: sysCol}
}

// Health returns a simple health status.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	n, err := h.db.CountLinks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"link_count": n,
	})
}
