// Package nftables manages the firewall via the native nft tooling. It replaces
// the legacy iptables path: the system now runs a single `table inet linkguard`
// ruleset, and all management (read, backup/restore, host blocking) goes through
// nft rather than iptables.
package nftables

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Family/table the application owns.
const (
	Family = "inet"
	Table  = "linkguard"
	// BlockedSet holds individual host IPs whose forwarded traffic is dropped.
	BlockedSet = "blocked_hosts"
	// HostWanMap maps a host IP to the fwmark that steers it to a given WAN.
	HostWanMap = "host_wan"
)

// Service wraps nft operations.
type Service struct {
	exec firewall.Executor
}

// NewService creates an nftables Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// Ruleset returns the full live nftables ruleset (`nft list ruleset`).
func (s *Service) Ruleset(ctx context.Context) (string, error) {
	return s.exec.ExecuteRead(ctx, "nft", "list", "ruleset")
}

// Save returns the current ruleset for storage as a backup (same as Ruleset).
func (s *Service) Save(ctx context.Context) (string, error) {
	return s.Ruleset(ctx)
}

// Restore atomically reloads a previously saved ruleset via `nft -f`.
func (s *Service) Restore(ctx context.Context, ruleset string) (string, error) {
	f, err := os.CreateTemp("", "linkguard-nft-*.conf")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	// Ensure a clean load: flush before applying the snapshot.
	body := "flush ruleset\n" + ruleset
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return "", fmt.Errorf("write ruleset: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return s.exec.Execute(ctx, "nft", "-f", f.Name())
}

// BlockHost drops a host's forwarded traffic by adding its IP to the blocked set.
func (s *Service) BlockHost(ctx context.Context, ip string) (string, error) {
	if strings.TrimSpace(ip) == "" {
		return "", fmt.Errorf("ip is required")
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// UnblockHost removes a host's IP from the blocked set.
func (s *Service) UnblockHost(ctx context.Context, ip string) (string, error) {
	if strings.TrimSpace(ip) == "" {
		return "", fmt.Errorf("ip is required")
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, BlockedSet, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// ─── Managed view & editing (sets / map elements) ────────────────────────────

// ConfPath is the persisted ruleset loaded by nftables.service at boot.
const ConfPath = "/etc/nftables.conf"

// DefaultWanMark steers a host to the secondary WAN (sumicity).
const DefaultWanMark = "0x12c"

// WanHost is one entry of the host_wan map (a host steered to a WAN by fwmark).
type WanHost struct {
	IP   string `json:"ip"`
	Mark string `json:"mark"`
}

// Managed is the editable, element-level view of the linkguard ruleset.
type Managed struct {
	WanHosts     []WanHost `json:"wan_hosts"`
	Blocklist    []string  `json:"blocklist"`
	BlockedHosts []string  `json:"blocked_hosts"`
}

// Managed returns the current elements of the host_wan map and the sets.
func (s *Service) Managed(ctx context.Context) (*Managed, error) {
	m := &Managed{WanHosts: []WanHost{}, Blocklist: []string{}, BlockedHosts: []string{}}

	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "map", Family, Table, HostWanMap); err == nil {
		for _, e := range parseElements(out) {
			parts := strings.SplitN(e, ":", 2)
			h := WanHost{IP: strings.TrimSpace(parts[0])}
			if len(parts) == 2 {
				h.Mark = strings.TrimSpace(parts[1])
			}
			m.WanHosts = append(m.WanHosts, h)
		}
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, "blocklist"); err == nil {
		m.Blocklist = parseElements(out)
	}
	if out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, BlockedSet); err == nil {
		m.BlockedHosts = parseElements(out)
	}
	return m, nil
}

// AddWanHost steers a host IP to a WAN by adding it to the host_wan map.
func (s *Service) AddWanHost(ctx context.Context, ip, mark string) (string, error) {
	if mark == "" {
		mark = DefaultWanMark
	}
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, HostWanMap, "{", ip, ":", mark, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelWanHost removes a host from the host_wan map (reverts it to the primary WAN).
func (s *Service) DelWanHost(ctx context.Context, ip string) (string, error) {
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, HostWanMap, "{", ip, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// AddBlocklist blocks a destination CIDR by adding it to the blocklist set.
func (s *Service) AddBlocklist(ctx context.Context, cidr string) (string, error) {
	out, err := s.exec.Execute(ctx, "nft", "add", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// DelBlocklist removes a destination CIDR from the blocklist set.
func (s *Service) DelBlocklist(ctx context.Context, cidr string) (string, error) {
	out, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, "blocklist", "{", cidr, "}")
	if err != nil {
		return out, err
	}
	return out, s.Persist(ctx)
}

// Persist writes the live ruleset to ConfPath so element edits survive a reboot
// (nftables.service reloads ConfPath at boot). Skipped in dry-run.
func (s *Service) Persist(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	rs, err := s.Ruleset(ctx)
	if err != nil {
		return err
	}
	body := "#!/usr/sbin/nft -f\n\nflush ruleset\n\n" + rs + "\n"
	return os.WriteFile(ConfPath, []byte(body), 0o644)
}

// parseElements extracts the comma-separated tokens inside an `elements = { ... }`
// block from `nft list set/map` output (the block may span multiple lines).
func parseElements(out string) []string {
	res := []string{}
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return res
	}
	rest := out[i+len("elements = {"):]
	j := strings.Index(rest, "}")
	if j < 0 {
		return res
	}
	for _, tok := range strings.Split(rest[:j], ",") {
		t := strings.Join(strings.Fields(tok), " ")
		if t != "" {
			res = append(res, t)
		}
	}
	return res
}
