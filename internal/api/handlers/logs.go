package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// LogsHandler handles audit log requests.
type LogsHandler struct {
	db *storage.DB
}

// NewLogsHandler creates a LogsHandler.
func NewLogsHandler(db *storage.DB) *LogsHandler {
	return &LogsHandler{db: db}
}

// List returns recent audit logs.
func (h *LogsHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := clampLimit(r.URL.Query().Get("limit"), 100, 1000)

	filter := r.URL.Query().Get("filter")
	logs, err := h.db.SearchAuditLogs(filter, limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if logs == nil {
		logs = []storage.AuditLog{}
	}
	writeJSON(w, http.StatusOK, logs)
}
