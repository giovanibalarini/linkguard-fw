// internal/iptables/validate_test.go
package iptables

import "testing"

func TestValidateRuleSpecAcceptsWizardShape(t *testing.T) {
	specs := []string{
		"-s 192.168.1.0/24 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.50 -j MARK --set-mark 0x1",
		"-s 192.168.1.0/24 -m conntrack --ctstate NEW -j MARK --set-mark 0x2",
	}
	for _, spec := range specs {
		if err := validateRuleSpec(spec); err != nil {
			t.Errorf("expected wizard-shaped spec to be valid, got error for %q: %v", spec, err)
		}
	}
}

func TestValidateRuleSpecRejectsExtraTarget(t *testing.T) {
	spec := "-s 192.168.1.0/24 -j TEE --gateway 1.2.3.4"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for -j TEE (not in allowlist), got nil")
	}
}

func TestValidateRuleSpecRejectsInvalidCIDR(t *testing.T) {
	spec := "-s not-a-cidr -m conntrack --ctstate NEW -j MARK --set-mark 0x1"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for malformed -s CIDR, got nil")
	}
}

func TestValidateRuleSpecRejectsUnknownFlag(t *testing.T) {
	spec := "-s 192.168.1.0/24 -j ACCEPT --random-unknown-flag foo"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for unrecognized flag, got nil")
	}
}

func TestValidateTableChainAcceptsMangleprerouting(t *testing.T) {
	if err := validateTableChain("mangle", "PREROUTING"); err != nil {
		t.Fatalf("expected mangle/PREROUTING to be accepted, got: %v", err)
	}
}

func TestValidateTableChainRejectsUnknownCombination(t *testing.T) {
	if err := validateTableChain("nat", "POSTROUTING"); err == nil {
		t.Fatal("expected error for table/chain outside the allowlist, got nil")
	}
}
