package nftables

import "testing"

// ─── ExpressionMatches (shared building block behind C-2's round-trip check
// and I-4's live-rule identity check) ───────────────────────────────────────
//
// Both ask the same question: "does this structured RuleFields really mean
// what this raw nft text says?" buildRuleTokens always appends the literal
// "counter" keyword, which ListUserRules/ListRuleset strip out entirely
// (along with the runtime packet/byte counts) when producing the live text
// this is compared against — so the comparison must normalize the same way
// or every real rule would spuriously "mismatch".

func TestExpressionMatchesIgnoresTheCounterKeyword(t *testing.T) {
	f := RuleFields{Action: "accept", Saddr: "10.0.0.1"}
	live := "ip saddr 10.0.0.1 accept" // what ListUserRules/ListRuleset produce: no "counter" at all
	if !ExpressionMatches(f, live) {
		t.Errorf("expected a faithful round-trip to match despite the counter keyword, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesDetectsADivergentRule(t *testing.T) {
	// The C-2 production example: `ct state established,related counter
	// accept` best-effort-parses into just {Action: accept} — which then
	// renders as "accept everything", not what the live rule actually says.
	f := RuleFields{Action: "accept"}
	live := "ct state established,related accept"
	if ExpressionMatches(f, live) {
		t.Errorf("expected a mismatch: fields=%+v cannot faithfully reproduce live=%q", f, live)
	}
}

func TestExpressionMatchesFullFieldsRoundTrip(t *testing.T) {
	f := RuleFields{Action: "drop", Iif: "eth0", Proto: "tcp", Dport: "22"}
	live := "iifname eth0 tcp dport 22 drop"
	if !ExpressionMatches(f, live) {
		t.Errorf("expected a full field set to round-trip, fields=%+v live=%q", f, live)
	}
}

func TestExpressionMatchesInvalidFieldsNeverMatch(t *testing.T) {
	f := RuleFields{Action: "bogus"}
	if ExpressionMatches(f, "accept") {
		t.Error("expected invalid fields (which don't even build) to never match")
	}
}
