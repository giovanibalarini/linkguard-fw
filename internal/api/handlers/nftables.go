package handlers

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// NftablesHandler exposes the native nftables ruleset and its backups. This
// replaces the legacy iptables handler — the firewall is managed via nft now.
type NftablesHandler struct {
	svc *nftables.Service
	db  *storage.DB
}

// NewNftablesHandler creates an NftablesHandler.
func NewNftablesHandler(svc *nftables.Service, db *storage.DB) *NftablesHandler {
	return &NftablesHandler{svc: svc, db: db}
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
func (h *NftablesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	chains, err := h.svc.ListRuleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if chains == nil {
		chains = []nftables.ChainInfo{}
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

// ListUserRules returns the custom rules (ordered, with handles + fields).
func (h *NftablesHandler) ListUserRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.svc.ListUserRules(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if rules == nil {
		rules = []nftables.UserRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

type ruleBody struct {
	Handle       int    `json:"handle"`
	BeforeHandle int    `json:"before_handle"`
	Action       string `json:"action"`
	Iif          string `json:"iif"`
	Oif          string `json:"oif"`
	Saddr        string `json:"saddr"`
	Daddr        string `json:"daddr"`
	Proto        string `json:"proto"`
	Dport        string `json:"dport"`
}

func (b ruleBody) fields() nftables.RuleFields {
	return nftables.RuleFields{
		Action: strings.TrimSpace(b.Action), Iif: strings.TrimSpace(b.Iif), Oif: strings.TrimSpace(b.Oif),
		Saddr: strings.TrimSpace(b.Saddr), Daddr: strings.TrimSpace(b.Daddr),
		Proto: strings.TrimSpace(b.Proto), Dport: strings.TrimSpace(b.Dport),
	}
}

func validateRuleFields(f nftables.RuleFields) string {
	if f.Saddr != "" && !validCIDRorIP(f.Saddr) {
		return "Origem inválida (use IP ou CIDR)"
	}
	if f.Daddr != "" && !validCIDRorIP(f.Daddr) {
		return "Destino inválido (use IP ou CIDR)"
	}
	return ""
}

// CreateUserRule adds a custom rule (optionally before another, for ordering).
func (h *NftablesHandler) CreateUserRule(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if msg := validateRuleFields(b.fields()); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if _, err := h.svc.AddUserRule(r.Context(), b.fields(), b.BeforeHandle); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "nft.rule.add", "user_rules", b.Action)
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// UpdateUserRule edits a custom rule in place (keeps its position).
func (h *NftablesHandler) UpdateUserRule(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.Handle <= 0 {
		writeError(w, http.StatusBadRequest, "handle is required")
		return
	}
	if msg := validateRuleFields(b.fields()); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if _, err := h.svc.UpdateUserRule(r.Context(), b.Handle, b.fields()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "nft.rule.update", "user_rules", strconv.Itoa(b.Handle))
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteUserRule removes a custom rule by handle.
func (h *NftablesHandler) DeleteUserRule(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.Handle <= 0 {
		writeError(w, http.StatusBadRequest, "handle is required")
		return
	}
	if _, err := h.svc.DeleteUserRule(r.Context(), b.Handle); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "nft.rule.del", "user_rules", strconv.Itoa(b.Handle))
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// MoveUserRule reorders a custom rule up or down.
func (h *NftablesHandler) MoveUserRule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Handle int    `json:"handle"`
		Dir    string `json:"dir"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.MoveUserRule(r.Context(), b.Handle, b.Dir); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
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
