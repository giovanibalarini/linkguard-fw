package handlers

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NftablesHandler exposes the native nftables ruleset and its backups. This
// replaces the legacy iptables handler — the firewall is managed via nft now.
type NftablesHandler struct {
	svc *nftables.Service
	db  *storage.DB
	fr  *firewallrules.Service
}

// NewNftablesHandler creates an NftablesHandler.
func NewNftablesHandler(svc *nftables.Service, db *storage.DB, fr *firewallrules.Service) *NftablesHandler {
	return &NftablesHandler{svc: svc, db: db, fr: fr}
}

// Ruleset returns the full live nftables ruleset.
func (h *NftablesHandler) Ruleset(w http.ResponseWriter, r *http.Request) {
	rs, err := h.svc.Ruleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": rs})
}

// Overview returns every chain of `table inet linkguard` and its rules —
// handle, raw expression, counters (when present), and origin
// classification (managed vs. the admin's own, plus which control owns a
// managed rule) — the structured view behind the unified Firewall overview
// page (design spec §3). Read-only.
//
// The user_rules chain gets one extra step beyond a plain read of nft
// (Phase B, design spec §4.1): a disabled rule lives only in the DB, never
// in nft, so a bare ListRuleset would silently omit it. MergeUserRules
// interleaves the DB's full rule list (in position order) with the live
// chain so a disabled rule still shows up — with no handle and no counter,
// honestly marked, never hidden ("mostrar tudo, mentir sobre nada").
func (h *NftablesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	chains, err := h.svc.ListRuleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if chains == nil {
		chains = []nftables.ChainInfo{}
	}

	dbRules, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	stored := firewallrules.ToStoredRules(dbRules)
	for i := range chains {
		if chains[i].Name == nftables.UserChain {
			chains[i] = nftables.MergeUserRules(stored, chains[i])
		}
	}

	writeJSON(w, http.StatusOK, chains)
}

// Managed returns the editable element-level view (host_wan map + sets).
func (h *NftablesHandler) Managed(w http.ResponseWriter, r *http.Request) {
	m, err := h.svc.Managed(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// WanHost adds (POST) or removes (DELETE) a host IP in the host_wan map.
func (h *NftablesHandler) WanHost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Mark string `json:"mark"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := strings.TrimSpace(body.IP)
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelWanHost(r.Context(), ip)
		auditAction(h.db, r, "nft.wan-host.del", "host_wan:"+ip, "")
	} else {
		_, err = h.svc.AddWanHost(r.Context(), ip, strings.TrimSpace(body.Mark))
		auditAction(h.db, r, "nft.wan-host.add", "host_wan:"+ip, body.Mark)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Blocklist adds (POST) or removes (DELETE) a destination CIDR/IP in the set.
func (h *NftablesHandler) Blocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cidr := strings.TrimSpace(body.CIDR)
	if !validCIDRorIP(cidr) {
		writeError(w, http.StatusBadRequest, "invalid CIDR or IP")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.del", cidr, "")
	} else {
		_, err = h.svc.AddBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.add", cidr, "")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── The admin's own rules (Phase B, design spec §4.1) ───────────────────
//
// These rules live in the DB now, identified by a stable id — not nft's
// handle, which changes every time the chain is rebuilt. Every mutation
// below writes the DB first, then calls reconcile() so the live user_rules
// chain is re-rendered immediately: the panel must never show a state the
// firewall isn't actually in.

// maxRuleDescriptionLen bounds the free-text "why this rule exists" field —
// generous enough for a real explanation, small enough that a request body
// can't be used to stuff an unbounded blob into the DB on every save.
const maxRuleDescriptionLen = 500

// ListRules returns the admin's rules, ordered by position.
func (h *NftablesHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if rules == nil {
		rules = []storage.FirewallRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

type firewallRuleBody struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Iif         string `json:"iif"`
	Oif         string `json:"oif"`
	Saddr       string `json:"saddr"`
	Daddr       string `json:"daddr"`
	Proto       string `json:"proto"`
	Dport       string `json:"dport"`
	Description string `json:"description"`
}

func (b firewallRuleBody) fields() nftables.RuleFields {
	return nftables.RuleFields{
		Action: strings.TrimSpace(b.Action), Iif: strings.TrimSpace(b.Iif), Oif: strings.TrimSpace(b.Oif),
		Saddr: strings.TrimSpace(b.Saddr), Daddr: strings.TrimSpace(b.Daddr),
		Proto: strings.TrimSpace(b.Proto), Dport: strings.TrimSpace(b.Dport),
	}
}

// validateFirewallRuleBody reuses nftables.ValidateRuleFields — the exact
// check ReconcileUserRules/AddUserRule already apply before a field reaches
// the nft argv — instead of the old handler-local check that only looked at
// saddr/daddr and let a malformed interface or port through to be rejected
// later (or worse, silently dropped by the reconcile's own skip-and-log).
func validateFirewallRuleBody(b firewallRuleBody) string {
	if err := nftables.ValidateRuleFields(b.fields()); err != nil {
		return err.Error()
	}
	if len(b.Description) > maxRuleDescriptionLen {
		return fmt.Sprintf("descrição muito longa (máx. %d caracteres)", maxRuleDescriptionLen)
	}
	return ""
}

// reconcileRules re-renders user_rules from the DB and refreshes the live
// snapshot, shared by every mutation below so nft never lags what the
// panel/DB show. A reconcile failure is surfaced to the caller as an error
// (the DB write already landed; only a subsequent successful reconcile —
// the next mutation, or the next boot — will pick it up), rather than
// silently reporting success while nft has fallen out of sync.
func (h *NftablesHandler) reconcileRules(w http.ResponseWriter, r *http.Request) bool {
	if err := h.fr.Reconcile(r.Context()); err != nil {
		writeInternalError(w, err)
		return false
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	return true
}

// CreateRule adds a new rule, always appended after every existing one.
func (h *NftablesHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var b firewallRuleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if msg := validateFirewallRuleBody(b); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	row := &storage.FirewallRule{
		Action: b.fields().Action, Iif: b.fields().Iif, Oif: b.fields().Oif,
		Saddr: b.fields().Saddr, Daddr: b.fields().Daddr, Proto: b.fields().Proto, Dport: b.fields().Dport,
		Description: strings.TrimSpace(b.Description),
	}
	if err := h.db.CreateFirewallRule(row); err != nil {
		writeInternalError(w, err)
		return
	}
	if !h.reconcileRules(w, r) {
		return
	}
	auditAction(h.db, r, "nft.rule.add", "user_rules:"+row.ID, b.Action)
	writeJSON(w, http.StatusOK, row)
}

// UpdateRule edits a rule's content in place, by id — its position and
// enabled state are untouched (see ReorderRules/ToggleRule for those).
func (h *NftablesHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	var b firewallRuleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if msg := validateFirewallRuleBody(b); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	f := b.fields()
	row := &storage.FirewallRule{
		ID: b.ID, Action: f.Action, Iif: f.Iif, Oif: f.Oif,
		Saddr: f.Saddr, Daddr: f.Daddr, Proto: f.Proto, Dport: f.Dport,
		Description: strings.TrimSpace(b.Description),
	}
	if err := h.db.UpdateFirewallRule(row); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.reconcileRules(w, r) {
		return
	}
	auditAction(h.db, r, "nft.rule.update", "user_rules:"+b.ID, b.Action)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteRule removes a rule permanently, by id.
func (h *NftablesHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := h.db.DeleteFirewallRule(b.ID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.reconcileRules(w, r) {
		return
	}
	auditAction(h.db, r, "nft.rule.del", "user_rules:"+b.ID, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ToggleRule enables or disables a rule without deleting it — the
// appliance-style capability the whole DB-backed model exists for (design
// spec §4.1). A disabled rule keeps every field intact; it simply stops
// being rendered into nft until re-enabled.
func (h *NftablesHandler) ToggleRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(b.ID) == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := h.db.SetFirewallRuleEnabled(b.ID, b.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.reconcileRules(w, r) {
		return
	}
	action := "nft.rule.disable"
	if b.Enabled {
		action = "nft.rule.enable"
	}
	auditAction(h.db, r, action, "user_rules:"+b.ID, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ReorderRules sets the evaluation order for every one of the admin's rules
// in a single request. ids must be exactly the current set of rule ids —
// neither more nor fewer: a partial list would silently strand the missing
// rules at their old positions (possibly colliding with the new ones), and
// an id LinkGuard doesn't recognise is rejected outright rather than
// ignored, so a stale client can never quietly corrupt the order.
func (h *NftablesHandler) ReorderRules(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	current, err := h.db.ListFirewallRules()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if len(b.IDs) != len(current) {
		writeError(w, http.StatusBadRequest, "a lista de reordenação precisa conter exatamente as regras atuais, sem faltar nem sobrar nenhuma")
		return
	}
	currentSet := make(map[string]bool, len(current))
	for _, row := range current {
		currentSet[row.ID] = true
	}
	seen := make(map[string]bool, len(b.IDs))
	for _, id := range b.IDs {
		if !currentSet[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("regra %q não encontrada", id))
			return
		}
		if seen[id] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("id %q repetido na lista de reordenação", id))
			return
		}
		seen[id] = true
	}
	if err := h.db.ReorderFirewallRules(b.IDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.reconcileRules(w, r) {
		return
	}
	auditAction(h.db, r, "nft.rule.reorder", "user_rules", fmt.Sprintf("%d regras", len(b.IDs)))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validCIDRorIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// Backup snapshots the current nftables ruleset into the database.
func (h *NftablesHandler) Backup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	_ = decodeJSON(r, &body)
	if body.Label == "" {
		body.Label = "nft-" + time.Now().Format("2006-01-02T15:04:05")
	}
	rs, err := h.svc.Save(r.Context())
	if err != nil {
		writeInternalError(w, fmt.Errorf("failed to read nft ruleset: %w", err))
		return
	}
	backup := &storage.IptablesBackup{Label: body.Label, Rules: rs}
	if err := h.db.CreateIptablesBackup(backup); err != nil {
		writeInternalError(w, fmt.Errorf("failed to store backup: %w", err))
		return
	}
	auditAction(h.db, r, "nft.backup", "ruleset", body.Label)
	writeJSON(w, http.StatusCreated, backup)
}

// ListBackups returns stored ruleset backups.
func (h *NftablesHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := h.db.GetIptablesBackups(20)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if backups == nil {
		backups = []storage.IptablesBackup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// Rollback restores a stored ruleset snapshot via nft.
func (h *NftablesHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BackupID string `json:"backup_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	backups, err := h.db.GetIptablesBackups(100)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var target *storage.IptablesBackup
	for i := range backups {
		if backups[i].ID == body.BackupID {
			target = &backups[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "backup not found")
		return
	}
	out, err := h.svc.Restore(r.Context(), target.Rules)
	if err != nil {
		writeInternalError(w, fmt.Errorf("rollback failed: %w", err))
		return
	}
	auditAction(h.db, r, "nft.rollback", "ruleset", target.Label)
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "rollback completed", "output": out})
}
