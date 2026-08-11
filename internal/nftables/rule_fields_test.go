package nftables

import "testing"

// ─── C-1 layer 1: field validation must reject what nft itself would reject
// for the IPv4-only `ip saddr`/`ip daddr` rendering, before a rule ever
// reaches an nft argv (or the DB). Reachable with ordinary typing: an admin
// pastes an IPv6 literal/CIDR into the source/destination field, or a port
// number/range outside what TCP/UDP actually supports.

func TestValidateRuleFieldsRejectsIPv6Saddr(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Saddr: "2001:db8::1"})
	if err == nil {
		t.Fatal("expected an error for an IPv6 source address (rendered as IPv4-only `ip saddr`)")
	}
}

func TestValidateRuleFieldsRejectsIPv6Daddr(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Daddr: "2001:db8::/32"})
	if err == nil {
		t.Fatal("expected an error for an IPv6 destination CIDR (rendered as IPv4-only `ip daddr`)")
	}
}

func TestValidateRuleFieldsAcceptsIPv4CIDR(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "drop", Saddr: "192.168.3.0/24", Daddr: "10.0.0.1"})
	if err != nil {
		t.Fatalf("expected a well-formed IPv4 saddr/daddr to pass, got: %v", err)
	}
}

func TestValidateRuleFieldsRejectsPortAbove65535(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Proto: "tcp", Dport: "99999"})
	if err == nil {
		t.Fatal("expected an error for a port above 65535")
	}
}

func TestValidateRuleFieldsRejectsPortZero(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Proto: "tcp", Dport: "0"})
	if err == nil {
		t.Fatal("expected an error for port 0 (not a valid TCP/UDP port)")
	}
}

func TestValidateRuleFieldsRejectsInvertedPortRange(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Proto: "tcp", Dport: "8080-80"})
	if err == nil {
		t.Fatal("expected an error for an inverted port range (start > end)")
	}
}

func TestValidateRuleFieldsAcceptsWellFormedPortRange(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Proto: "udp", Dport: "1000-2000"})
	if err != nil {
		t.Fatalf("expected a well-formed port range to pass, got: %v", err)
	}
}

func TestValidateRuleFieldsRejectsRangeEndAbove65535(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Proto: "tcp", Dport: "60000-70000"})
	if err == nil {
		t.Fatal("expected an error when the range's end exceeds 65535")
	}
}
