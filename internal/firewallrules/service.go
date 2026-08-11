// Package firewallrules bridges the admin's rules living in the database
// (internal/storage) with the nftables reconcile that renders them
// (internal/nftables) — the same shape as internal/hosts (exec + db + nft
// combined into one small service), used here because internal/nftables
// must not import internal/storage (see nftables.StoredRule's doc comment).
package firewallrules

import (
	"context"
	"log/slog"

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

	imported, skipped := 0, 0
	for _, r := range existing {
		if verr := nftables.ValidateRuleFields(r.RuleFields); verr != nil {
			skipped++
			slog.Warn("regra existente do user_rules não pôde ser importada e foi ignorada",
				"handle", r.Handle, "raw", r.Raw, "err", verr)
			continue
		}
		row := &storage.FirewallRule{
			Action: r.RuleFields.Action,
			Iif:    r.RuleFields.Iif,
			Oif:    r.RuleFields.Oif,
			Saddr:  r.RuleFields.Saddr,
			Daddr:  r.RuleFields.Daddr,
			Proto:  r.RuleFields.Proto,
			Dport:  r.RuleFields.Dport,
		}
		if err := s.db.CreateFirewallRule(row); err != nil {
			skipped++
			slog.Warn("falha ao gravar regra importada no banco; regra foi ignorada",
				"handle", r.Handle, "raw", r.Raw, "err", err)
			continue
		}
		imported++
	}

	slog.Info("importação única das regras existentes de user_rules para o banco concluída",
		"importadas", imported, "puladas", skipped, "total_no_nft", len(existing))

	if err := s.db.SetSetting(ImportedSettingKey, "true"); err != nil {
		return err
	}

	return s.Reconcile(ctx)
}

// Reconcile loads every stored rule (enabled or not, in position order) and
// re-renders user_rules from it — the DB is the source of truth, nft is the
// rendered result (design spec §4.1). Safe and cheap to call on every boot
// and after every mutation, exactly like the other reconciles in this
// project.
func (s *Service) Reconcile(ctx context.Context) error {
	rows, err := s.db.ListFirewallRules()
	if err != nil {
		return err
	}
	return s.nft.ReconcileUserRules(ctx, toStoredRules(rows))
}

// toStoredRules converts the DB rows into nftables' own StoredRule shape —
// internal/nftables cannot import internal/storage (see StoredRule's doc
// comment), so this conversion always happens on the caller's side.
func toStoredRules(rows []storage.FirewallRule) []nftables.StoredRule {
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
