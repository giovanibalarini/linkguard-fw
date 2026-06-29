// Package hosttraffic computes per-host bandwidth from the conntrack table
// (requires net.netfilter.nf_conntrack_acct=1). It answers "who is using the
// link right now" — the top talkers — by aggregating the bytes of every active
// flow to/from each LAN host.
package hosttraffic

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// ConntrackPath is the kernel's live flow table (with byte counters when
// nf_conntrack_acct is enabled).
const ConntrackPath = "/proc/net/nf_conntrack"

// HostTraffic is the aggregated active-flow byte counters for one LAN host.
type HostTraffic struct {
	IP      string `json:"ip"`
	RxBytes uint64 `json:"rx_bytes"` // download (reply direction)
	TxBytes uint64 `json:"tx_bytes"` // upload (orig direction)
}

// Service reads conntrack and aggregates per-host traffic.
type Service struct {
	exec firewall.Executor
}

// NewService creates a hosttraffic Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// TopTalkers returns LAN hosts ranked by active-flow bytes (descending).
func (s *Service) TopTalkers(ctx context.Context, subnetCIDR string) ([]HostTraffic, error) {
	out, err := s.exec.ExecuteRead(ctx, "cat", ConntrackPath)
	if err != nil {
		return nil, err
	}
	return parseConntrack(out, subnetCIDR), nil
}

// parseConntrack aggregates per-host bytes from a conntrack dump. The LAN host
// is the original source; its upload is the orig direction's bytes and its
// download is the reply direction's bytes (which under NAT is addressed to the
// WAN IP, so we key on the orig source rather than the reply destination).
func parseConntrack(content, subnetCIDR string) []HostTraffic {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(subnetCIDR))
	if err != nil {
		return []HostTraffic{}
	}
	agg := map[string]*HostTraffic{}
	for _, line := range strings.Split(content, "\n") {
		var srcs, byteVals []string
		for _, f := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(f, "src="):
				srcs = append(srcs, f[4:])
			case strings.HasPrefix(f, "bytes="):
				byteVals = append(byteVals, f[6:])
			}
		}
		if len(srcs) == 0 {
			continue
		}
		host := srcs[0] // original source = the host that initiated the flow
		ip := net.ParseIP(host)
		if ip == nil || !ipnet.Contains(ip) {
			continue
		}
		h := agg[host]
		if h == nil {
			h = &HostTraffic{IP: host}
			agg[host] = h
		}
		if len(byteVals) >= 1 {
			v, _ := strconv.ParseUint(byteVals[0], 10, 64)
			h.TxBytes += v
		}
		if len(byteVals) >= 2 {
			v, _ := strconv.ParseUint(byteVals[1], 10, 64)
			h.RxBytes += v
		}
	}
	out := make([]HostTraffic, 0, len(agg))
	for _, h := range agg {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RxBytes+out[i].TxBytes > out[j].RxBytes+out[j].TxBytes
	})
	return out
}
