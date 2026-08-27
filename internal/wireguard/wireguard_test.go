package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKeypairProducesWireGuardKeys(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	for name, key := range map[string]string{"private": priv, "public": pub} {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key = %q, decoded=%d err=%v", name, key, len(decoded), err)
		}
	}
	if priv == pub {
		t.Fatal("private and public key must differ")
	}
}

func TestValidateConfigRejectsEveryRenderedInjectionSlot(t *testing.T) {
	valid := DefaultConfig()
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"address newline", func(c *Config) { c.Address = "10.7.0.1/24\nPostUp = touch /tmp/pwn" }},
		{"invalid port", func(c *Config) { c.ListenPort = 70000 }},
		{"endpoint newline", func(c *Config) { c.EndpointHost = "vpn.example\nAllowedIPs = 0.0.0.0/0" }},
		{"link id newline", func(c *Config) { c.EndpointLinkID = "wan\n1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.edit(&c)
			if err := ValidateConfig(c); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRenderServerConfigRevalidatesPersistedValuesAtSink(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.Address = "10.7.0.1/24\nPostUp = touch /tmp/pwn"
	_, err := RenderServerConfig(c, strings.Repeat("A", 43)+"=", nil)
	if err == nil {
		t.Fatal("sink accepted an injected address")
	}
}

func TestRenderServerAndClientConfigsKeepPrivateKeysSeparated(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	serverPriv, serverPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, clientPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana", PublicKey: clientPub, Address: "10.7.0.2/32"}
	server, err := RenderServerConfig(c, serverPriv, []Peer{peer})
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	if strings.Contains(server, clientPriv) || !strings.Contains(server, clientPub) {
		t.Fatal("server config must contain only the client's public key")
	}
	client, err := RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net")
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if !strings.Contains(client, clientPriv) || strings.Contains(client, serverPriv) {
		t.Fatal("client config did not keep private keys separated")
	}
	if !strings.Contains(client, "DNS = 10.7.0.1") || !strings.Contains(client, "Endpoint = vpn.example.net:51820") {
		t.Fatalf("client config lacks tunnel DNS/endpoint:\n%s", client)
	}
}

func TestNextAddressKeepsExistingPeerAndAllocatesNextFreeHost(t *testing.T) {
	c := DefaultConfig()
	got, err := NextAddress(c, []Peer{{Address: "10.7.0.2/32"}, {Address: "10.7.0.4/32"}})
	if err != nil {
		t.Fatalf("NextAddress: %v", err)
	}
	if got != "10.7.0.3/32" {
		t.Fatalf("NextAddress = %q, want 10.7.0.3/32", got)
	}
}
