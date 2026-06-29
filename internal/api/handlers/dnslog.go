package handlers

import (
	"net/http"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/dnslog"
)

// DNSLogHandler exposes recent DNS queries parsed from the unbound journal.
type DNSLogHandler struct {
	svc *dnslog.Service
}

// NewDNSLogHandler creates a DNSLogHandler.
func NewDNSLogHandler(svc *dnslog.Service) *DNSLogHandler {
	return &DNSLogHandler{svc: svc}
}

// Recent returns recent DNS queries (most recent first). Query params: limit, q.
func (h *DNSLogHandler) Recent(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	q, err := h.svc.Recent(r.Context(), limit, r.URL.Query().Get("q"))
	if err != nil {
		// Journal unavailable or logging disabled — return an empty list so the
		// UI can show a friendly "enable logging" state rather than an error.
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	if q == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, q)
}
