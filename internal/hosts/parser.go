// Package hosts builds an inventory of LAN hosts seen by the firewall, starting
// from the kernel neighbour (ARP/NDP) table. Per-host traffic accounting (via
// conntrack) is a later addition and requires enabling nf_conntrack_acct on the
// host.
package hosts

import "strings"

// Neighbor is one entry from `ip neigh show` (the kernel ARP/NDP table).
type Neighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	State     string `json:"state"`
}

// neighStates is the set of NUD (neighbour unreachability detection) states the
// kernel reports as the trailing token of an `ip neigh` line.
var neighStates = map[string]bool{
	"PERMANENT": true, "NOARP": true, "REACHABLE": true, "STALE": true,
	"NONE": true, "INCOMPLETE": true, "DELAY": true, "PROBE": true, "FAILED": true,
}

// parseNeighbors parses the output of `ip neigh show`. Each line looks like:
//
//	192.168.3.14 dev br10 lladdr 7c:63:05:db:2b:1c REACHABLE
//	192.168.3.19 dev br10 FAILED
//	fe80::1 dev enp3s0 lladdr b0:16:56:f8:9c:aa router STALE
//
// Lines without an IP+interface are skipped. A missing lladdr yields an empty
// MAC (common for FAILED/INCOMPLETE entries).
func parseNeighbors(output string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		n := Neighbor{IP: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					n.Interface = fields[i+1]
					i++
				}
			case "lladdr":
				if i+1 < len(fields) {
					n.MAC = fields[i+1]
					i++
				}
			default:
				if neighStates[fields[i]] {
					n.State = fields[i]
				}
			}
		}
		if n.IP == "" || n.Interface == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}
