package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// HealthHandler handles health check requests.
type HealthHandler struct {
	db      *storage.DB
	sysCol  *system.Collector
	version string
}

// NewHealthHandler creates a HealthHandler.
func NewHealthHandler(db *storage.DB, sysCol *system.Collector, version string) *HealthHandler {
	return &HealthHandler{db: db, sysCol: sysCol, version: version}
}

// Health returns a simple health status, including the running version —
// the one place the frontend can read it without hitting GitHub (unlike
// /api/system/update/check, which needs a token for the private repo and
// exists to compare against the *latest* release, not report the current one).
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	n, err := h.db.CountLinks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"link_count": n,
		"version":    h.version,
	})
}
