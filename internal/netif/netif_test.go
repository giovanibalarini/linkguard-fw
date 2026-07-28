package netif

import "testing"

func TestIsSystemInterface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"lo", true},
		{"docker0", true},
		{"br-0293233c552c", true}, // docker's hash-named bridges — real name captured on this dev machine
		{"veth3f8a21b", true},
		{"tun0", true},
		{"tap0", true},
		{"wg0", true},
		{"eth0", false},
		{"wlp2s0", false},
		{"br10", false}, // LAN bridge the admin created — NOT a docker br-<hex>
		{"vlan100", false},
	}
	for _, c := range cases {
		if got := isSystemInterface(c.name); got != c.want {
			t.Errorf("isSystemInterface(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
