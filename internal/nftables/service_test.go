package nftables

import "testing"

func TestDnatRuleRejectsMalformedInterface(t *testing.T) {
	f := PortForward{
		Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80,
		Interface: `wan" ; add rule inet fw forward accept #`,
	}
	if _, err := dnatRule(f); err == nil {
		t.Fatal("expected error for interface with embedded quote/semicolon, got nil")
	}
}

func TestDnatRuleAcceptsValidInterface(t *testing.T) {
	f := PortForward{
		Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80,
		Interface: "enp3s0",
	}
	if _, err := dnatRule(f); err != nil {
		t.Fatalf("expected valid interface name to be accepted, got: %v", err)
	}
}

func TestDnatRuleAcceptsEmptyInterface(t *testing.T) {
	f := PortForward{Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80}
	if _, err := dnatRule(f); err != nil {
		t.Fatalf("expected empty interface (any) to be accepted, got: %v", err)
	}
}
