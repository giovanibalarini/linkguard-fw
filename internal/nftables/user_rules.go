package nftables

import (
	"context"
	"fmt"
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

	tokenSets, skipped := renderEnabledUserRules(rules)

	// Idempotently ensure the chain exists before flushing it — mirrors
	// ReconcileNTPInput's own guard for the input chain. user_rules is
	// normally created once at EnsureTable/bootstrap and never deleted, but
	// a box that reaches this reconcile before that (or one recovering from
	// an operator error) must not fail here with "no such chain" instead of
	// self-healing. `nft add chain` with no body is a no-op when a chain by
	// this name already exists, regardless of its declaration.
	if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, UserChain); err != nil {
		return fmt.Errorf("garantir a existência da chain %s: %w", UserChain, err)
	}

	rebuildErr := s.rebuildChain(ctx, UserChain, tokenSets)

	// "tentadas" (not "aplicadas"): rebuildChain may have rejected some of
	// these at nft time (C-1) — rebuildErr, logged by rebuildChain itself
	// per rejected rule, is the source of truth for how many actually
	// landed.
	slog.Info("chain user_rules reconciliada a partir do banco",
		"total", len(rules), "tentadas", len(tokenSets), "puladas_por_campo_invalido", skipped, "erro_ao_aplicar", rebuildErr != nil)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain user_rules reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return rebuildErr
}

// CheckUserRules validates, with a parse-only `nft -c` dry run (CheckChain),
// the exact user_rules chain ReconcileUserRules would render for rules —
// same sorting, same enabled-only filter, same buildRuleTokens rendering —
// so a rule that passes this check is guaranteed to render into exactly the
// commands the real reconcile issues afterwards. This is C-1's second
// layer, meant to run before a DB write commits (see
// internal/firewallrules.Service.CheckPending): field-level validation
// alone (ValidateRuleFields) cannot catch everything nft itself would
// reject, and reconciling straight into the live chain on a rule nft
// rejects used to truncate every rule after it, permanently.
func (s *Service) CheckUserRules(ctx context.Context, rules []StoredRule) error {
	tokenSets, _ := renderEnabledUserRules(rules)
	return s.CheckChain(ctx, UserChain, tokenSets)
}

// renderEnabledUserRules sorts rules by position and renders every enabled
// one into nft tokens, skipping (and counting) any with invalid fields —
// shared by ReconcileUserRules and CheckUserRules so they can never render
// the "resulting chain" differently from one another. In practice a
// skipped entry should never happen (the API layer validates with the same
// ValidateRuleFields on create/update), but a stale or hand-edited DB row
// must not be able to take down every other rule's enforcement or check.
func renderEnabledUserRules(rules []StoredRule) (tokenSets [][]string, skipped int) {
	sorted := make([]StoredRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		tokens, err := buildRuleTokens(r.Fields)
		if err != nil {
			skipped++
			slog.Warn("regra do usuário ignorada ao reconciliar/validar user_rules: campos inválidos",
				"id", r.ID, "err", err)
			continue
		}
		tokenSets = append(tokenSets, tokens)
	}
	return tokenSets, skipped
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
