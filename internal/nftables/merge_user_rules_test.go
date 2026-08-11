package nftables

import "testing"

// ─── MergeUserRules ─────────────────────────────────────────────────────────
//
// The unified overview (design spec §3) must show a disabled rule honestly
// instead of hiding it: it exists in the DB but never reaches nft (§4.1), so
// ReconcileUserRules never renders it and ListRuleset's live chain has no
// trace of it at all. MergeUserRules walks the DB rules (the full picture,
// in position order) alongside the live nft chain (exactly the enabled
// subset, in the same order, once ReconcileUserRules has run) so both an
// enabled rule (with its real handle/counters) and a disabled one (with
// none — it was never sent to nft) show up in the same ordered list.

func TestMergeUserRulesInterleavesDisabledAmongEnabled(t *testing.T) {
	db := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
		{ID: "b", Position: 1, Enabled: false, Fields: RuleFields{Action: "drop", Saddr: "10.0.0.2"}},
		{ID: "c", Position: 2, Enabled: true, Fields: RuleFields{Action: "reject", Saddr: "10.0.0.3"}},
	}
	// Expression is written the way parseChainRuleLine actually produces it
	// (the whole "counter packets N bytes M" clause stripped, keyword
	// included — see expressionTokens' doc comment), not with a literal
	// "counter" word, so this fixture matches what MergeUserRules really
	// receives in production.
	live := ChainInfo{
		Name: UserChain,
		Rules: []ChainRule{
			{Chain: UserChain, Handle: 11, Expression: `ip saddr 10.0.0.1 accept`, HasCounter: true, Packets: 5, Bytes: 500},
			{Chain: UserChain, Handle: 12, Expression: `ip saddr 10.0.0.3 reject`, HasCounter: true, Packets: 0, Bytes: 0},
		},
	}

	merged := MergeUserRules(db, live)

	if len(merged.Rules) != 3 {
		t.Fatalf("expected 3 rules (2 enabled + 1 disabled), got %d: %+v", len(merged.Rules), merged.Rules)
	}

	if merged.Rules[0].ID != "a" || merged.Rules[0].Enabled == nil || !*merged.Rules[0].Enabled {
		t.Errorf("rule 0 expected enabled=true id=a, got %+v", merged.Rules[0])
	}
	if merged.Rules[0].Handle != 11 {
		t.Errorf("rule 0 expected to carry its real nft handle 11, got %d", merged.Rules[0].Handle)
	}

	disabled := merged.Rules[1]
	if disabled.ID != "b" {
		t.Errorf("rule 1 expected id=b, got %+v", disabled)
	}
	if disabled.Enabled == nil || *disabled.Enabled {
		t.Errorf("rule 1 expected enabled=false, got %+v", disabled)
	}
	if disabled.HasCounter {
		t.Errorf("a disabled rule was never in nft — it must never claim a counter, got %+v", disabled)
	}
	if disabled.Handle != 0 {
		t.Errorf("a disabled rule has no real nft handle, got %d", disabled.Handle)
	}
	if disabled.Managed {
		t.Errorf("a disabled admin rule is still the admin's own, not LinkGuard-managed, got %+v", disabled)
	}

	if merged.Rules[2].ID != "c" || merged.Rules[2].Handle != 12 {
		t.Errorf("rule 2 expected id=c handle=12, got %+v", merged.Rules[2])
	}
}

func TestMergeUserRulesAllDisabledYieldsNoLiveHandles(t *testing.T) {
	db := []StoredRule{
		{ID: "x", Position: 0, Enabled: false, Fields: RuleFields{Action: "drop"}},
	}
	live := ChainInfo{Name: UserChain, Rules: []ChainRule{}}

	merged := MergeUserRules(db, live)
	if len(merged.Rules) != 1 {
		t.Fatalf("expected the disabled rule to still show up, got %+v", merged.Rules)
	}
	if merged.Rules[0].Enabled == nil || *merged.Rules[0].Enabled {
		t.Errorf("expected enabled=false, got %+v", merged.Rules[0])
	}
}

func TestMergeUserRulesEmptyDBYieldsEmptyChain(t *testing.T) {
	merged := MergeUserRules(nil, ChainInfo{Name: UserChain, Rules: []ChainRule{}})
	if len(merged.Rules) != 0 {
		t.Errorf("expected no rules, got %+v", merged.Rules)
	}
}

// ─── I-4: pairing must be by identity, not by position ─────────────────────
//
// Before this fix, an enabled DB rule always consumed live[li] and advanced
// li, regardless of whether the two actually matched. Any divergence
// between the DB and the live chain (a reconcile that failed partway, C-1's
// old truncation, a race) attributed a later rule's handle and counters to
// an earlier, unrelated DB row — and the overview's click-through then
// edited the wrong rule entirely.

func TestMergeUserRulesEnabledButNotYetLiveShowsNotApplied(t *testing.T) {
	db := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
	}
	// The live chain has nothing for it — as if a reconcile hasn't run yet,
	// or C-1's rebuildChain skipped it after an nft rejection.
	live := ChainInfo{Name: UserChain, Rules: []ChainRule{}}

	merged := MergeUserRules(db, live)
	if len(merged.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", merged.Rules)
	}
	got := merged.Rules[0]
	if got.Enabled == nil || !*got.Enabled {
		t.Errorf("expected Enabled=true (the DB says so), got %+v", got)
	}
	if got.Applied {
		t.Errorf("expected Applied=false — nft has no counterpart for this rule, got %+v", got)
	}
	if got.HasCounter {
		t.Errorf("a rule with no live counterpart must never claim a counter, got %+v", got)
	}
}

func TestMergeUserRulesSkipsAMismatchedLiveEntryInsteadOfConsumingIt(t *testing.T) {
	// DB says: rule "a" (saddr 10.0.0.1). Live chain's first entry is
	// completely unrelated (as if nft still holds a stale/leftover rule at
	// that position). Position-based pairing would wrongly attribute
	// handle 99 and its counters to rule "a"; identity-based pairing must
	// not.
	db := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
	}
	live := ChainInfo{
		Name: UserChain,
		Rules: []ChainRule{
			{Chain: UserChain, Handle: 99, Expression: "ip saddr 203.0.113.9 drop", HasCounter: true, Packets: 42, Bytes: 4242},
		},
	}

	merged := MergeUserRules(db, live)
	if len(merged.Rules) != 2 {
		t.Fatalf("expected the DB rule (not applied) plus the leftover live rule, got %+v", merged.Rules)
	}
	a := merged.Rules[0]
	if a.ID != "a" {
		t.Fatalf("expected rule 0 to be DB rule 'a', got %+v", a)
	}
	if a.Applied {
		t.Errorf("rule 'a' must not claim the mismatched live entry's handle/counters, got %+v", a)
	}
	if a.Handle == 99 {
		t.Errorf("rule 'a' must never be attributed handle 99 (that belongs to an unrelated live rule), got %+v", a)
	}
}

func TestMergeUserRulesMatchedLiveEntryIsApplied(t *testing.T) {
	db := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
	}
	live := ChainInfo{
		Name: UserChain,
		Rules: []ChainRule{
			{Chain: UserChain, Handle: 11, Expression: "ip saddr 10.0.0.1 accept", HasCounter: true, Packets: 5, Bytes: 500},
		},
	}
	merged := MergeUserRules(db, live)
	if len(merged.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", merged.Rules)
	}
	got := merged.Rules[0]
	if !got.Applied {
		t.Errorf("expected Applied=true for a rule whose expression matches the live entry, got %+v", got)
	}
	if got.Handle != 11 || !got.HasCounter {
		t.Errorf("expected the matched live rule's handle/counter carried through, got %+v", got)
	}
}
