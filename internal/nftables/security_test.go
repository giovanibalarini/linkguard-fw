package nftables

import "testing"

func TestValidMarkRejectsInjection(t *testing.T) {
	ok := []string{"0x12c", "0x1", "300", "0xABCDEF"}
	for _, m := range ok {
		if !ValidMark(m) {
			t.Errorf("mark %q should be valid", m)
		}
	}
	// nft-injection payloads must be rejected.
	bad := []string{
		"0x1 }; flush ruleset; add element inet linkguard host_wan { 1.1.1.1 : 0x1",
		"0x1; drop",
		"300 }",
		"0xzz",
		"", "0x", "; flush ruleset",
	}
	for _, m := range bad {
		if ValidMark(m) {
			t.Errorf("mark %q must be rejected (injection)", m)
		}
	}
}

func TestBuildRuleTokensRejectsInjection(t *testing.T) {
	// Malicious interface / port must not produce tokens.
	cases := []RuleFields{
		{Action: "drop", Iif: "eth0; flush ruleset"},
		{Action: "drop", Oif: "eth0 }; drop"},
		{Action: "accept", Proto: "tcp", Dport: "80; flush ruleset"},
		{Action: "accept", Saddr: "1.2.3.4; drop"},
		{Action: "accept", Proto: "tcp", Dport: "80 drop"},
	}
	for _, f := range cases {
		if _, err := buildRuleTokens(f); err == nil {
			t.Errorf("buildRuleTokens(%+v) should reject the injection", f)
		}
	}

	// A legitimate rule still builds.
	tok, err := buildRuleTokens(RuleFields{Action: "accept", Iif: "enp5s0", Proto: "tcp", Dport: "443", Saddr: "192.168.3.0/24"})
	if err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if len(tok) == 0 {
		t.Error("expected tokens for a valid rule")
	}
}
