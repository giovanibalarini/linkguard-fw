package hosts

import (
	"context"
	"sort"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
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
}

// NewService creates a hosts Service.
func NewService(exec firewall.Executor, db *storage.DB) *Service {
	return &Service{exec: exec, db: db}
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

// SetBlocked records the intent to block/unblock a host.
//
// NOTE: this persists the flag only. Actual enforcement (a FORWARD drop rule)
// is applied by the firewall ruleset generator, which is the component that
// touches the live firewall — wired in a later step. The UI reflects the flag
// so intent is visible before enforcement is connected.
func (s *Service) SetBlocked(mac string, blocked bool) error {
	return s.db.SetHostBlocked(mac, blocked)
}
