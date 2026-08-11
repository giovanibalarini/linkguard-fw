package nftables

import (
	"context"
	"log/slog"
	"sort"
	"strings"
)

// StoredRule is this package's own view of one of the admin's rules, kept
// deliberately independent of internal/storage.FirewallRule: internal/nftables
// must not import internal/storage (a cycle — storage already sits below the
// service layer), so the caller (internal/firewallrules, and the API
// handlers) converts its DB rows into this shape before calling
// ReconcileUserRules or MergeUserRules. See the design spec §4.1.
type StoredRule struct {
	ID          string
	Position    int
	Enabled     bool
	Fields      RuleFields
	Description string
}

// ValidateRuleFields reports whether f is safe and well-formed enough to
// reach an nft argv, without actually building or applying anything. It is
// the exact validation buildRuleTokens already performs for AddUserRule,
// exported so both the reorder/create/update API handlers and the one-time
// import of pre-existing rules (internal/firewallrules) reuse a single
// source of truth instead of re-implementing (and risking under-validating)
// it.
func ValidateRuleFields(f RuleFields) error {
	_, err := buildRuleTokens(f)
	return err
}

// ReconcileUserRules rebuilds the user_rules chain from the admin's stored
// rules, in position order — the DB is the source of truth now (design spec
// §4.1) and nft is the rendered result, mirroring
// ReconcileStructuralChains/ReconcileMasquerade's safety properties exactly:
// it flushes only this chain (never the table or the ruleset), the result is
// idempotent for the same input, it's a no-op in dry-run, and it persists
// afterward.
//
// Disabled rules are simply not rendered — nftables has no notion of a
// disabled rule, so "disable without deleting" can only mean "exists in the
// DB, absent from nft" (see MergeUserRules for how the overview still shows
// it honestly). Every enabled rule is validated with ValidateRuleFields
// before it reaches the nft argv, exactly like the old AddUserRule path; one
// invalid entry is skipped and logged loudly rather than aborting the whole
// reconcile — the same "one bad entry doesn't sink the good ones" contract
// already used for WAN interfaces and NTP-allowed networks elsewhere in this
// package. In practice this should never trigger (the API layer validates on
// create/update with the very same function), but a stale or hand-edited DB
// row must not be able to take down every other rule's enforcement.
func (s *Service) ReconcileUserRules(ctx context.Context, rules []StoredRule) error {
	if s.exec.IsDryRun() {
		return nil
	}

	sorted := make([]StoredRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	var tokenSets [][]string
	skipped := 0
	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		tokens, err := buildRuleTokens(r.Fields)
		if err != nil {
			skipped++
			slog.Warn("regra do usuário ignorada ao reconciliar user_rules: campos inválidos",
				"id", r.ID, "err", err)
			continue
		}
		tokenSets = append(tokenSets, tokens)
	}

	if err := s.rebuildChain(ctx, UserChain, tokenSets); err != nil {
		return err
	}

	slog.Info("chain user_rules reconciliada a partir do banco",
		"total", len(rules), "aplicadas", len(tokenSets), "puladas", skipped)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain user_rules reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// MergeUserRules produces the honest, unified view of the user_rules chain
// for the Firewall overview (design spec §3, §4.1): every stored rule, in
// position order, whether or not it made it into nft. It assumes
// ReconcileUserRules has already run against the same dbRules — so
// nftChain.Rules is exactly the enabled subset, in the same relative order —
// and walks both lists in lockstep: an enabled rule consumes the next live
// nft rule (carrying its real handle and counters), a disabled rule gets a
// synthetic entry with no handle and HasCounter=false ("not measured", never
// a fake zero — it was never sent to nft at all, see ChainRule's doc
// comment). Any live rules left over past the last DB rule (should not
// happen if the reconcile ran, but never silently dropped) are appended
// as-is, marked enabled.
func MergeUserRules(dbRules []StoredRule, nftChain ChainInfo) ChainInfo {
	sorted := make([]StoredRule, len(dbRules))
	copy(sorted, dbRules)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	merged := ChainInfo{
		Name: nftChain.Name, Type: nftChain.Type, Hook: nftChain.Hook,
		Priority: nftChain.Priority, Policy: nftChain.Policy, Rules: []ChainRule{},
	}

	live := nftChain.Rules
	li := 0
	trueVal, falseVal := true, false

	for _, r := range sorted {
		if r.Enabled {
			var rule ChainRule
			if li < len(live) {
				rule = live[li]
				li++
			} else {
				// Defensive fallback: nft has fewer rules than expected (a
				// reconcile hasn't run yet, or failed partway). Render what we
				// know from the DB rather than dropping the row silently.
				rule = syntheticUserRule(r)
			}
			rule.ID = r.ID
			rule.Enabled = &trueVal
			merged.Rules = append(merged.Rules, rule)
			continue
		}

		rule := syntheticUserRule(r)
		rule.ID = r.ID
		rule.Enabled = &falseVal
		merged.Rules = append(merged.Rules, rule)
	}

	for ; li < len(live); li++ {
		rule := live[li]
		rule.Enabled = &trueVal
		merged.Rules = append(merged.Rules, rule)
	}

	return merged
}

// syntheticUserRule renders a stored rule's fields into a display-only
// ChainRule — used for a disabled rule (never sent to nft, so it has no
// handle or counter to report) and as the defensive fallback above. It
// deliberately does not carry a handle or counter: HasCounter stays false,
// meaning "not measured", the correct honest state for something nft has
// never seen (design spec §3.1).
func syntheticUserRule(r StoredRule) ChainRule {
	expr := r.Description
	if tokens, err := buildRuleTokens(r.Fields); err == nil {
		expr = strings.Join(tokens, " ")
	}
	return ChainRule{
		Chain:       UserChain,
		Expression:  expr,
		Managed:     false,
		Owner:       RuleOwner{},
		Description: describeUserRuleExpression(expr),
	}
}
