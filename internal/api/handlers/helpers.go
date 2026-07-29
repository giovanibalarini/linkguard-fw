package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeInternalError logs the real error server-side (traceable via journalctl)
// and returns a generic message to the client — a raw err.Error() can embed
// exec stderr, SQLite driver detail, or file paths that shouldn't be visible
// to a lower-privileged authenticated role in a multi-admin RBAC setup.
func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "erro interno do servidor")
}

func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// clampLimit parses a "limit" query-string value, falling back to def when
// absent/invalid/non-positive, and never returning more than max — an
// unbounded limit lets a single authenticated request force the server to
// load and serialize an unbounded number of rows.
func clampLimit(raw string, def, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// auditAction records who performed a mutating action, for the audit log.
func auditAction(db *storage.DB, r *http.Request, action, resource, details string) {
	user := "unknown"
	if c := auth.ClaimsFromContext(r.Context()); c != nil {
		user = c.Username
	}
	_ = db.CreateAuditLog(&storage.AuditLog{
		User:     user,
		Action:   action,
		Resource: resource,
		Details:  details,
		IP:       r.RemoteAddr,
	})
}
