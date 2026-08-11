// Package firewallrules bridges the admin's rules living in the database
// (internal/storage) with the nftables reconcile that renders them
// (internal/nftables) — the same shape as internal/hosts (exec + db + nft
// combined into one small service), used here because internal/nftables
// must not import internal/storage (see nftables.StoredRule's doc comment).
package firewallrules

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ImportedSettingKey guards the one-time import of pre-existing user_rules
// (design spec §4.1: "na primeira execução, as regras hoje existentes no
// nft são importadas para o banco"). Deliberately a settings flag — "has
// this ever run" — rather than "is firewall_rules empty": the latter would
// resurrect every rule from nft on the next boot after an admin
// legitimately deleted them all, which is exactly the false confidence this
// whole DB-backed model exists to eliminate. See ImportOnce's doc comment.
const ImportedSettingKey = "firewall_rules_imported"

// Service combines the DB (source of truth for the admin's rules) and the
// nftables service (renders them into the live user_rules chain).
type Service struct {
	db  *storage.DB
	nft *nftables.Service
}

// NewService creates a firewallrules Service.
func NewService(db *storage.DB, nft *nftables.Service) *Service {
	return &Service{db: db, nft: nft}
}

// ImportOnce migrates a box upgrading from Phase A: its admin rules exist
// only inside nft's user_rules chain, identified by a volatile handle, and
// this brings them into the DB exactly once, preserving their evaluation
// order, then reconciles so nft is re-rendered from the DB (idempotent — the
// same rules, now DB-backed).
//
// Guarded by ImportedSettingKey, not by "is firewall_rules empty": an admin
// who deliberately deletes every rule after the import has already run must
// see an empty list stay empty on the next boot, not have nft's (by-then
// also empty, once ReconcileUserRules has flushed it) or stale live chain
// repopulate the table. Checking the flag first, before ever reading nft,
// is what makes that guarantee hold regardless of what nft currently
// contains.
//
// If parsing an individual nft rule's fields fails — ValidateRuleFields
// rejects the best-effort RuleFields ListUserRules produced for it — that
// one rule is skipped and logged loudly; the rest of the import still
// proceeds. The guard is set (import considered "done") even when there was
// nothing to import, or everything failed to parse: a box with zero
// pre-existing rules must not re-attempt this on every subsequent boot.
//
// C-2 (round-trip check): ValidateRuleFields alone only proves the
// best-effort RuleFields are syntactically safe — it says nothing about
// whether they still mean what the live rule actually said. parseRuleFields
// ignores any token it doesn't recognise, so a rule richer than the 7-field
// model best-effort-parses into whatever survived, not "unparsable": `ct
// state established,related counter accept` collapses to {Action: accept},
// which then re-renders as "accept everything"; `tcp flags syn /
// fin,syn,rst,ack counter drop` collapses to {Proto: tcp, Action: drop},
// which re-renders as "drop all TCP". Importing either as-is (then
// reconciled into nft on the very next line) would silently change what the
// rule does, breaking spec §4.1's "nada é perdido" promise in the one
// direction that matters most — silently, not with an error anyone would
// see. Every candidate is therefore re-rendered with buildRuleTokens (via
// nftables.ExpressionMatches) and compared word-for-word against the live
// rule's own normalised text before it is trusted: a match imports as
// today, an enabled row; a mismatch imports DISABLED, with the original nft
// text preserved in Description instead of the fields that couldn't
// reproduce it, so the admin sees exactly what could not be modelled and
// can re-author it deliberately, rather than the firewall changing meaning
// underneath them.
func (s *Service) ImportOnce(ctx context.Context) error {
	flag, err := s.db.GetSetting(ImportedSettingKey)
	if err != nil {
		return err
	}
	if flag != "" {
		return nil // already imported (or confirmed nothing to import) on a prior boot
	}

	existing, err := s.nft.ListUserRules(ctx)
	if err != nil {
		return err
	}

	var rows []storage.FirewallRule
	imported, skippedInvalid, importedDisabled := 0, 0, 0
	for _, r := range existing {
		if verr := nftables.ValidateRuleFields(r.RuleFields); verr != nil {
			skippedInvalid++
			slog.Warn("regra existente do user_rules não pôde ser importada e foi ignorada",
				"handle", r.Handle, "raw", r.Raw, "err", verr)
			continue
		}
		row := storage.FirewallRule{
			Enabled: true,
			Action:  r.RuleFields.Action,
			Iif:     r.RuleFields.Iif,
			Oif:     r.RuleFields.Oif,
			Saddr:   r.RuleFields.Saddr,
			Daddr:   r.RuleFields.Daddr,
			Proto:   r.RuleFields.Proto,
			Dport:   r.RuleFields.Dport,
		}
		if !nftables.ExpressionMatches(r.RuleFields, r.Raw) {
			row.Enabled = false
			row.Description = r.Raw
			importedDisabled++
			slog.Warn("regra existente não pôde ser fielmente representada pelos campos estruturados (informação seria perdida ao re-renderizar); importada DESATIVADA, com o texto original preservado na descrição para revisão manual",
				"handle", r.Handle, "raw", r.Raw, "campos_interpretados", r.RuleFields)
		}
		rows = append(rows, row)
		imported++
	}

	// I-5 (already fixed, reused here): a single transaction inserts every
	// row and flips the guard together, so a crash or DB error partway
	// through can never leave the guard set with only some rules landed, or
	// vice versa. Enabled is honoured exactly as set on each row above —
	// unlike CreateFirewallRule, which always forces it true — which is
	// exactly what lets an unmodellable rule import disabled instead of
	// enabled-then-immediately-wrong.
	if err := s.db.ImportFirewallRules(rows, ImportedSettingKey, "true"); err != nil {
		return err
	}

	slog.Info("importação única das regras existentes de user_rules para o banco concluída",
		"importadas", imported, "puladas_invalidas", skippedInvalid,
		"importadas_desativadas_nao_modeladas", importedDisabled, "total_no_nft", len(existing))

	return s.Reconcile(ctx)
}

// CheckPending validates, with a parse-only `nft -c` dry run
// (nftables.Service.CheckUserRules), the user_rules chain that candidate —
// the DB rows exactly as they would read immediately after the mutation the
// caller is about to make — would render, before that mutation's DB write
// happens (C-1, design spec §4.1/§8). candidate must reflect every rule
// that would end up enabled in the DB, not just the one being changed:
// `nft -c` validates the whole resulting chain, the same one Reconcile
// renders immediately after the DB write actually lands. On failure the
// caller must not write anything to the DB — the error carries nft's own
// rejection message, so field-level validation (ValidateRuleFields) not
// catching something doesn't mean nothing ever will.
func (s *Service) CheckPending(ctx context.Context, candidate []storage.FirewallRule) error {
	return s.nft.CheckUserRules(ctx, ToStoredRules(candidate))
}

// ApplyStatusKey persists the outcome of the most recent user_rules
// reconcile (design spec §4.1, C-3). Reconcile is called from two places
// that never share an HTTP response — the API handlers (CreateRule,
// UpdateRule, ..., Rollback) and the unconditional boot-time call in
// cmd/linkguard-fw/main.go — and the boot case in particular has no status
// code or client to surface a failure to at all. Persisting here, inside
// Reconcile itself, means both call sites get this for free instead of each
// needing its own copy of the same bookkeeping, and a boot-time reconcile
// failure is no longer invisible: it is exactly as discoverable as any
// other mutation's, the next time anyone opens the panel.
const ApplyStatusKey = "firewall_rules_apply"

// ApplyStatus is ApplyStatusKey's persisted shape — deliberately the same
// {ok, error, at} contract as internal/api/handlers.applyStatus (NTP,
// DHCP/DNS), a proven pattern for exactly this "was the last apply actually
// applied" question, kept here as an independent, exported type: this
// package must not import internal/api/handlers (the dependency runs the
// other way), so the type can't be shared directly, only its json shape.
type ApplyStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	At    int64  `json:"at"` // unix seconds
}

// Reconcile loads every stored rule (enabled or not, in position order) and
// re-renders user_rules from it — the DB is the source of truth, nft is the
// rendered result (design spec §4.1). Safe and cheap to call on every boot
// and after every mutation, exactly like the other reconciles in this
// project. The outcome — success or failure, with nft's own error message —
// is always persisted under ApplyStatusKey (see LastApplyStatus), even when
// this is called from a boot path with nobody watching synchronously.
func (s *Service) Reconcile(ctx context.Context) error {
	rows, err := s.db.ListFirewallRules()
	if err != nil {
		return err
	}
	applyErr := s.nft.ReconcileUserRules(ctx, ToStoredRules(rows))
	s.recordApplyStatus(applyErr)
	return applyErr
}

func (s *Service) recordApplyStatus(applyErr error) {
	st := ApplyStatus{OK: applyErr == nil, At: time.Now().Unix()}
	if applyErr != nil {
		st.Error = applyErr.Error()
	}
	b, err := json.Marshal(st)
	if err != nil {
		return // never happens for this fixed shape; nothing sane to do if it did
	}
	if err := s.db.SetSetting(ApplyStatusKey, string(b)); err != nil {
		slog.Warn("não foi possível persistir o status da última aplicação de user_rules", "err", err)
	}
}

// LastApplyStatus returns the persisted result of the most recent
// user_rules reconcile, or nil if Reconcile has never run yet — the same
// "never attempted" vs "attempted and failed" distinction as
// internal/api/handlers.lastApplyStatus/lastFirewallApplyStatus, so a
// caller (the rules API handler) can tell "nothing to worry about yet" from
// "actively broken" instead of defaulting one into looking like the other.
func (s *Service) LastApplyStatus() *ApplyStatus {
	raw, _ := s.db.GetSetting(ApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st ApplyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

// ToStoredRules converts the DB rows into nftables' own StoredRule shape —
// internal/nftables cannot import internal/storage (see StoredRule's doc
// comment), so this conversion always happens on the caller's side.
func ToStoredRules(rows []storage.FirewallRule) []nftables.StoredRule {
	out := make([]nftables.StoredRule, len(rows))
	for i, r := range rows {
		out[i] = nftables.StoredRule{
			ID:       r.ID,
			Position: r.Position,
			Enabled:  r.Enabled,
			Fields: nftables.RuleFields{
				Action: r.Action, Iif: r.Iif, Oif: r.Oif,
				Saddr: r.Saddr, Daddr: r.Daddr, Proto: r.Proto, Dport: r.Dport,
			},
			Description: r.Description,
		}
	}
	return out
}
