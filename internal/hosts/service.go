package hosts

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Host is one LAN host in the inventory: live neighbour data merged with stored
// metadata (alias, blocked flag, first/last seen).
type Host struct {
	IP        string     `json:"ip"`
	MAC       string     `json:"mac"`
	Interface string     `json:"interface"`
	State     string     `json:"state"`
	Online    bool       `json:"online"`
	Hostname  string     `json:"hostname,omitempty"`
	Alias     string     `json:"alias,omitempty"`
	Blocked   bool       `json:"blocked"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// reachableStates are NUD states that mean the host is currently present.
var reachableStates = map[string]bool{
	"REACHABLE": true, "STALE": true, "DELAY": true, "PROBE": true, "PERMANENT": true,
}

// Service builds the host inventory from the kernel neighbour table and the
// stored host metadata.
type Service struct {
	exec firewall.Executor
	db   *storage.DB
	nft  *nftables.Service
	net  netsvc.Provider
}

// NewService creates a hosts Service.
func NewService(exec firewall.Executor, db *storage.DB, nft *nftables.Service, net netsvc.Provider) *Service {
	return &Service{exec: exec, db: db, nft: nft, net: net}
}

// List returns the current host inventory. It records a sighting for every host
// with a MAC (so the inventory persists across reboots/STALE states) and merges
// in stored metadata. Hosts known from storage but not currently in the
// neighbour table are included as offline.
func (s *Service) List(ctx context.Context) ([]Host, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "neigh", "show")
	if err != nil {
		return nil, err
	}
	neighbors := parseNeighbors(out)

	metaList, err := s.db.ListHostMetadata()
	if err != nil {
		return nil, err
	}
	meta := make(map[string]storage.HostMetadata, len(metaList))
	for _, m := range metaList {
		meta[m.MAC] = m
	}

	// Collect sightings and persist them in one transaction at the end (one
	// write per host on every List was extremely slow without WAL).
	sightings := make(map[string]string)
	seen := make(map[string]bool)
	var hosts []Host
	for _, n := range neighbors {
		if n.MAC == "" {
			continue // can't track a host without a stable identifier
		}
		seen[n.MAC] = true
		sightings[n.MAC] = n.IP

		h := Host{
			IP:        n.IP,
			MAC:       n.MAC,
			Interface: n.Interface,
			State:     n.State,
			Online:    reachableStates[n.State],
		}
		if m, ok := meta[n.MAC]; ok {
			h.Hostname = m.Hostname
			h.Alias = m.Alias
			h.Blocked = m.Blocked
			h.FirstSeen = &m.FirstSeen
		}
		hosts = append(hosts, h)
	}

	// Persist all sightings at once; best-effort (don't fail listing on write error).
	_ = s.db.UpsertHostSightings(sightings)

	// Add known-but-currently-absent hosts as offline entries.
	for _, m := range metaList {
		if seen[m.MAC] {
			continue
		}
		first, last := m.FirstSeen, m.LastSeen
		hosts = append(hosts, Host{
			IP:        m.IP,
			MAC:       m.MAC,
			State:     "OFFLINE",
			Online:    false,
			Hostname:  m.Hostname,
			Alias:     m.Alias,
			Blocked:   m.Blocked,
			FirstSeen: &first,
			LastSeen:  &last,
		})
	}

	// Enrich with hostnames from DHCP leases (by MAC) — best-effort.
	if leases, err := s.net.Leases(ctx); err == nil {
		byMAC := make(map[string]string, len(leases))
		for _, l := range leases {
			if l.Hostname != "" {
				byMAC[strings.ToLower(l.MAC)] = l.Hostname
			}
		}
		for i := range hosts {
			if hosts[i].Hostname == "" {
				if hn, ok := byMAC[strings.ToLower(hosts[i].MAC)]; ok {
					hosts[i].Hostname = hn
				}
			}
		}
	}

	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Online != hosts[j].Online {
			return hosts[i].Online // online first
		}
		return hosts[i].IP < hosts[j].IP
	})
	return hosts, nil
}

// SetAlias assigns a friendly name to a host.
func (s *Service) SetAlias(mac, alias string) error {
	return s.db.SetHostAlias(mac, alias)
}

// SetBlocked blocks/unblocks a host: it persists the flag AND enforces it on the
// live firewall by adding/removing the host's current IP in the nft
// `blocked_hosts` set (the FORWARD chain drops traffic to/from that set).
func (s *Service) SetBlocked(ctx context.Context, mac string, blocked bool) error {
	if err := s.db.SetHostBlocked(mac, blocked); err != nil {
		return err
	}
	ip := s.ipForMAC(mac)
	if ip == "" {
		return nil // host IP unknown yet; flag persisted, enforced on next sighting
	}
	// Best-effort enforcement: a duplicate add or missing-element delete is not
	// a hard failure (the persisted flag is the source of truth).
	if blocked {
		_, _ = s.nft.BlockHost(ctx, ip)
	} else {
		_, _ = s.nft.UnblockHost(ctx, ip)
	}
	return nil
}

func (s *Service) ipForMAC(mac string) string {
	metas, err := s.db.ListHostMetadata()
	if err != nil {
		return ""
	}
	for _, m := range metas {
		if m.MAC == mac {
			return m.IP
		}
	}
	return ""
}
