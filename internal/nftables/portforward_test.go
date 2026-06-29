package nftables

import (
	"strings"
	"testing"
)

func TestDNATRule(t *testing.T) {
	tests := []struct {
		name    string
		f       PortForward
		want    string
		wantErr bool
	}{
		{
			name: "tcp with interface",
			f:    PortForward{Proto: "tcp", Interface: "enp5s0", ExtPort: 8080, DestIP: "192.168.3.50", DestPort: 80},
			want: `iifname "enp5s0" tcp dport 8080 dnat ip to 192.168.3.50:80`,
		},
		{
			name: "udp any interface",
			f:    PortForward{Proto: "udp", ExtPort: 51820, DestIP: "192.168.3.10", DestPort: 51820},
			want: `udp dport 51820 dnat ip to 192.168.3.10:51820`,
		},
		{
			name:    "bad proto",
			f:       PortForward{Proto: "icmp", ExtPort: 80, DestIP: "192.168.3.1", DestPort: 80},
			wantErr: true,
		},
		{
			name:    "port out of range",
			f:       PortForward{Proto: "tcp", ExtPort: 70000, DestIP: "192.168.3.1", DestPort: 80},
			wantErr: true,
		},
		{
			name:    "bad dest ip",
			f:       PortForward{Proto: "tcp", ExtPort: 80, DestIP: "not-an-ip", DestPort: 80},
			wantErr: true,
		},
		{
			name:    "ipv6 dest rejected (inet dnat ip to is v4)",
			f:       PortForward{Proto: "tcp", ExtPort: 80, DestIP: "fd00::1", DestPort: 80},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dnatRule(tt.f)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got rule %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDNATRuleProtoCaseInsensitive(t *testing.T) {
	got, err := dnatRule(PortForward{Proto: "TCP", ExtPort: 22, DestIP: "10.0.0.2", DestPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "tcp dport 22") {
		t.Errorf("expected lowercased proto, got %q", got)
	}
}
