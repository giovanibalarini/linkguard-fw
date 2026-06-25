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
	return s.exec.Execute(ctx, "nft", "add", "element", Family, Table, BlockedSet, "{", ip, "}")
}

// UnblockHost removes a host's IP from the blocked set.
func (s *Service) UnblockHost(ctx context.Context, ip string) (string, error) {
	if strings.TrimSpace(ip) == "" {
		return "", fmt.Errorf("ip is required")
	}
	return s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, BlockedSet, "{", ip, "}")
}
