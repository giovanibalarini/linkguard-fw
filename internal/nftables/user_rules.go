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
		"total", len(rules), "tentadas", len(tokenSets), "puladas_por_campo_invalido", len(skipped), "erro_ao_aplicar", rebuildErr != nil)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain user_rules reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	if rebuildErr != nil {
		// nft's own rejection is the more urgent message and already names
		// the rules it refused; the skipped ones ride along in the log line
		// above.
		return rebuildErr
	}
	if len(skipped) > 0 {
		// I-8: the rebuild itself succeeded, but a rule the admin has
		// ENABLED is not in the firewall. Returning nil here (what this did
		// before) made recordApplyStatus write ok:true, and the panel said
		// "applied" about a chain that is missing a configured rule — a
		// state nobody could have found out about except by reading the
		// journal. An unrenderable rule is a state that cannot be reported
		// as ok, only as "these ones are out".
		return &SkippedRulesError{IDs: skipped}
	}
	return nil
}

// SkippedRulesError reports that the user_rules chain was rebuilt
// successfully but one or more ENABLED stored rules never made it into it,
// because their fields don't render (a stale or hand-edited DB row —
// create/update validate with the same ValidateRuleFields, so this should
// not be reachable through the panel). It carries the rules' ids so the
// apply status can name them instead of just admitting that something,
// somewhere, is missing.
type SkippedRulesError struct{ IDs []string }

func (e *SkippedRulesError) Error() string {
	return fmt.Sprintf("%d regra(s) ativada(s) não puderam ser aplicadas por campos inválidos e estão fora do firewall: %s",
		len(e.IDs), strings.Join(e.IDs, ", "))
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
//
// skipped returns the ids, not a count: whoever reports this to the admin
// has to be able to say WHICH rule is not in effect (I-8) — "one of your
// rules isn't applied" is barely better than saying nothing.
func renderEnabledUserRules(rules []StoredRule) (tokenSets [][]string, skipped []string) {
	sorted := make([]StoredRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		tokens, err := buildRuleTokens(r.Fields)
		if err != nil {
			skipped = append(skipped, r.ID)
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
// and walks both lists in lockstep: an enabled rule claims the next live
// nft rule (carrying its real handle and counters) ONLY when that live
// rule's expression actually matches what this DB row would render
// (ExpressionMatches, I-4); anything else — a disabled rule, or an enabled
// one with no matching live counterpart — gets a synthetic entry with no
// handle, HasCounter=false ("not measured", never a fake zero — see
// ChainRule's doc comment) and Applied=false (C-3: "configured but not
// actually in effect", never confused with Enabled=true meaning "in
// effect"). Any live rules left over past the last DB rule (should not
// happen if the reconcile ran, but never silently dropped) are appended
// as-is, marked enabled and applied.
//
// I-4: before this fix, an enabled DB rule always consumed the next live
// entry by position alone, with no check that the two actually agreed on
// what the rule says. The moment the two lists diverged even slightly (a
// reconcile that failed partway — the exact scenario C-1 used to cause — or
// any other transient mismatch), every DB row from that point on was paired
// with the wrong live rule: a handle and counters attributed to a rule that
// doesn't own them, and the overview's click-through editing a different
// rule than the one shown. Comparing the rendered expression before
// consuming a live entry, and falling back to "not applied" on a mismatch
// (without advancing past that live entry, so a later DB row still gets a
// chance to match it), makes a wrong attribution impossible: a rule is only
// ever shown as applied when it demonstrably is.
func MergeUserRules(dbRules []StoredRule, nftChain ChainInfo) ChainInfo {
	sorted := make([]StoredRule, len(dbRules))
	copy(sorted, dbRules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

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
			if li < len(live) && ExpressionMatches(r.Fields, live[li].Expression) {
				rule = live[li]
				rule.Applied = true
				li++
			} else {
				// No live entry left, or the next one belongs to some other
				// rule entirely (a divergence between the DB and the live
				// chain) — render what we know from the DB instead of
				// misattributing a handle/counters that aren't this rule's.
				// li is deliberately NOT advanced: that live entry stays
				// available for a later DB row to match.
				rule = syntheticUserRule(r, merged.Name)
			}
			rule.ID = r.ID
			rule.Enabled = &trueVal
			merged.Rules = append(merged.Rules, rule)
			continue
		}

		rule := syntheticUserRule(r, merged.Name)
		rule.ID = r.ID
		rule.Enabled = &falseVal
		merged.Rules = append(merged.Rules, rule)
	}

	for ; li < len(live); li++ {
		rule := live[li]
		rule.Enabled = &trueVal
		rule.Applied = true
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
//
// C-1: chain is the chain that actually CONTAINS this rule, threaded in from
// the ChainInfo being merged — never a constant. Since the Fase C1 migration
// the admin's rules live inside their group's chain (grp_…) and the legacy
// user_rules chain was deleted from the ruleset altogether; stamping
// "user_rules" here made every disabled rule claim, in both endpoints the
// panel reads, to live in a chain that exists nowhere in the firewall.
func syntheticUserRule(r StoredRule, chain string) ChainRule {
	expr := r.Description
	if tokens, err := buildRuleTokens(r.Fields); err == nil {
		expr = strings.Join(tokens, " ")
	}
	return ChainRule{
		Chain:       chain,
		Expression:  expr,
		Managed:     false,
		Owner:       RuleOwner{},
		Description: describeUserRuleExpression(expr),
		Desc:        userRuleDesc(expr),
	}
}
