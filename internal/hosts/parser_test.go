package hosts

import "testing"

// Real sample captured from `ip neigh show` on the production firewall.
const sampleNeigh = `192.168.3.19 dev br10 FAILED
192.168.3.93 dev br10 lladdr 3c:7c:3f:0d:15:9a STALE
192.168.3.14 dev br10 lladdr 7c:63:05:db:2b:1c REACHABLE
192.168.15.1 dev enp5s0 lladdr f4:54:20:30:a4:77 REACHABLE
fe80::1 dev enp3s0 lladdr b0:16:56:f8:9c:aa router STALE

`

func TestParseNeighbors(t *testing.T) {
	got := parseNeighbors(sampleNeigh)
	if len(got) != 5 {
		t.Fatalf("expected 5 neighbours, got %d: %+v", len(got), got)
	}

	// FAILED entry without lladdr: MAC must be empty, state preserved.
	if got[0].IP != "192.168.3.19" || got[0].MAC != "" || got[0].State != "FAILED" || got[0].Interface != "br10" {
		t.Errorf("failed-entry parsed wrong: %+v", got[0])
	}

	// Normal reachable entry with MAC.
	if got[2].IP != "192.168.3.14" || got[2].MAC != "7c:63:05:db:2b:1c" ||
		got[2].State != "REACHABLE" || got[2].Interface != "br10" {
		t.Errorf("reachable entry parsed wrong: %+v", got[2])
	}

	// IPv6 entry with the extra "router" flag before the state.
	v6 := got[4]
	if v6.IP != "fe80::1" || v6.MAC != "b0:16:56:f8:9c:aa" || v6.State != "STALE" || v6.Interface != "enp3s0" {
		t.Errorf("ipv6 router entry parsed wrong: %+v", v6)
	}
}

func TestParseNeighborsSkipsGarbage(t *testing.T) {
	got := parseNeighbors("\n  \nnonsense line\n192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n")
	if len(got) != 1 {
		t.Fatalf("expected 1 valid neighbour, got %d: %+v", len(got), got)
	}
	if got[0].IP != "192.168.1.5" {
		t.Errorf("unexpected: %+v", got[0])
	}
}
