package handlers

import (
	"net/http"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// FailoverHandler handles failover event requests.
type FailoverHandler struct {
	svc *failover.Service
}

// NewFailoverHandler creates a FailoverHandler.
func NewFailoverHandler(svc *failover.Service) *FailoverHandler {
	return &FailoverHandler{svc: svc}
}

// ListEvents returns recent failover events.
func (h *FailoverHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	events, err := h.svc.GetEvents(limit)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if events == nil {
		events = []storage.FailoverEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}
