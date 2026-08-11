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
	live := ChainInfo{
		Name: UserChain,
		Rules: []ChainRule{
			{Chain: UserChain, Handle: 11, Expression: `ip saddr 10.0.0.1 counter accept`, HasCounter: true, Packets: 5, Bytes: 500},
			{Chain: UserChain, Handle: 12, Expression: `ip saddr 10.0.0.3 counter reject`, HasCounter: true, Packets: 0, Bytes: 0},
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
