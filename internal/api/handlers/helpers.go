package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type domainRoutingReconciler interface {
	Reconcile(context.Context) error
}

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

// saveNftSnapshot persists the live nftables ruleset (host_wan, blocklist,
// user rules, port forwards — everything `table inet linkguard` currently
// holds) so a from-scratch install can restore it automatically instead of
// coming back with an empty firewall (see nftables.EnsureTable /
// LiveSnapshotSettingKey). Called after every mutation that changes the live
// ruleset. Best-effort: a failed snapshot must never fail the mutation that
// triggered it — the live change already applied, this is just backup.
func saveNftSnapshot(ctx context.Context, db *storage.DB, nft *nftables.Service) {
	rs, err := nft.PersistentRuleset(ctx)
	if err != nil {
		slog.Warn("could not read nftables ruleset to persist it", "err", err)
		return
	}
	if err := db.SetSetting(nftables.LiveSnapshotSettingKey, rs); err != nil {
		slog.Warn("could not persist nftables ruleset snapshot", "err", err)
	}
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

// enabledWANInterfaces returns the interface names of every enabled link —
// the shared "what does this box call its WANs" derivation used by both the
// masquerade rule (LinksHandler.reconcileNAT) and the NTP-protection input
// chain (NTPHandler's firewall reconcile), so the two never drift from
// independently-written queries against the same links table.
func enabledWANInterfaces(db *storage.DB) ([]string, error) {
	ls, err := db.GetLinks()
	if err != nil {
		return nil, err
	}
	ifaces := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			ifaces = append(ifaces, l.Interface)
		}
	}
	return ifaces, nil
}

// auditAction records who performed a mutating action, for the audit log.
func auditAction(db *storage.DB, r *http.Request, action, resource, details string) {
	_ = db.CreateAuditLog(&storage.AuditLog{
		User:     actingUser(r),
		Action:   action,
		Resource: resource,
		Details:  details,
		IP:       r.RemoteAddr,
	})
}

// actingUser is shared audit metadata. "unknown" is only reachable from
// unauthenticated tests; every production mutation is behind auth middleware.
func actingUser(r *http.Request) string {
	if c := auth.ClaimsFromContext(r.Context()); c != nil {
		return c.Username
	}
	return "unknown"
}
