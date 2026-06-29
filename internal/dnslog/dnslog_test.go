package dnslog

import "testing"

func TestParseQueryLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantOK     bool
		wantClient string
		wantName   string
		wantType   string
	}{
		{
			name:       "typical A query",
			line:       "2026-06-29T10:00:00-0300 firewall unbound[1234]: info: 192.168.3.35 google.com. A IN",
			wantOK:     true,
			wantClient: "192.168.3.35",
			wantName:   "google.com",
			wantType:   "A",
		},
		{
			name:       "unbound own-timestamp prefix",
			line:       "2026-06-29T10:00:01-0300 firewall unbound[1234]: [1719660000] unbound[1234:0] info: 192.168.3.61 github.com. AAAA IN",
			wantOK:     true,
			wantClient: "192.168.3.61",
			wantName:   "github.com",
			wantType:   "AAAA",
		},
		{
			name:   "non-query info line ignored",
			line:   "2026-06-29T10:00:02-0300 firewall unbound[1234]: info: service stopped (unbound 1.17.0).",
			wantOK: false,
		},
		{
			name:   "no info marker",
			line:   "2026-06-29T10:00:03-0300 firewall unbound[1234]: notice: init module 0: validator",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, ok := parseQueryLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (line: %q)", ok, tt.wantOK, tt.line)
			}
			if !tt.wantOK {
				return
			}
			if q.Client != tt.wantClient || q.Name != tt.wantName || q.Type != tt.wantType {
				t.Errorf("got {%s %s %s}, want {%s %s %s}",
					q.Client, q.Name, q.Type, tt.wantClient, tt.wantName, tt.wantType)
			}
		})
	}
}
