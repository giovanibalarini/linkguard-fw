package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// masqueradeChain is the chain whose sole content is the WAN masquerade
// rule (verified against the live production ruleset: nothing else is ever
// written there — port forwards live in prerouting_dnat, filtering in
// forward/user_rules). That is what makes flush-then-rewrite safe here.
const masqueradeChain = "postrouting"

// ReconcileMasquerade re-derives the WAN masquerade (NAT) rule from the
// currently configured WAN interfaces, on every boot and on every link
// mutation — not just once at bootstrap.
//
// Why this exists: EnsureTable only creates `table inet linkguard` when it
// is missing, so on an already-provisioned box it is a no-op and the
// masquerade rule keeps whatever interface names it was born with. In
// production on 2026-08-10 a NIC was renamed by a PCI reshuffle
// (enp4s0 -> enp5s0) and the stale rule silently stopped matching, taking
// WAN1's NAT down until an operator added an iptables rule by hand.
//
// It flushes the chain before writing because `nft -f` (and `nft add`)
// ACCUMULATE rules rather than replacing them — the same production ruleset
// ended up with two masquerade lines, one of them referencing an interface
// that no longer existed. Flushing only this chain (never the table or the
// ruleset) keeps host_wan / blocklist / blocked_hosts / user_rules /
// prerouting_dnat untouched.
//
// Idempotent by construction: the same WAN set always yields the same two
// commands and the same final chain contents. A no-op in dry-run mode, same
// convention as the rest of the package.
func (s *Service) ReconcileMasquerade(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)

	if len(ifaces) == 0 {
		// No configured WANs (all disabled, last one deleted, or a box using
		// LinkGuard for firewall/hosts but no links): refuse to touch the
		// chain at all. Flushing here would take down whatever masquerade
		// rule is currently live and working, and since Persist is skipped
		// in this branch too, /etc/nftables.conf would silently diverge
		// from the (now empty) live chain. Acting on an empty source of
		// truth is strictly less safe than doing nothing, so we do nothing.
		slog.Warn("nenhuma interface WAN válida configurada; regra de NAT existente foi mantida intacta", "requested", wanInterfaces)
		return nil
	}

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, masqueradeChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", masqueradeChain, err)
	}

	quoted := make([]string, len(ifaces))
	for i, iface := range ifaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	set := fmt.Sprintf("{ %s }", strings.Join(quoted, ", "))
	if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, masqueradeChain,
		"oifname", set, "masquerade"); err != nil {
		return fmt.Errorf("aplicar regra de masquerade: %w", err)
	}

	slog.Info("regra de NAT reconciliada a partir das WANs configuradas", "interfaces", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("regra de NAT reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// InputChain is the first `hook input` chain this project has ever created
// (added 2026-08-11 for "serve NTP to the LAN" — see
// docs/superpowers/specs/2026-08-11-ntp-server-for-lan-design.md §2). Before
// it, nothing filtered traffic destined for the firewall itself (SSH, the
// web panel, DNS, DHCP) — the table only had prerouting/forward/postrouting
// hooks.
//
// Non-negotiable: this chain is declared, created and reconciled with
// `policy accept` and must never become `policy drop`. A drop policy would
// cut SSH and the panel the instant it applied, on a firewall that may have
// no other admin access. Protection here is via a specific deny rule, not a
// restrictive default policy — hardening the policy is a separate project
// with its own port inventory and maintenance window (spec §8).
const InputChain = "input"

// ReconcileNTPInput rebuilds the input chain's NTP-protection rule from the
// current WAN interfaces and the serve-NTP-to-LAN toggle, mirroring
// ReconcileMasquerade's structure and safety properties: it flushes only
// this chain (never the table or the ruleset), sanitizes interface names
// before they reach nft, is a no-op in dry-run, and persists afterward.
//
// Unlike the masquerade chain (always present since bootstrap), the input
// chain may not exist yet on a box provisioned before this feature — so it
// is created first via an idempotent `nft add chain ... { type filter hook
// input priority filter; policy accept; }`, which nft treats as a no-op
// when a base chain with the same declaration already exists (the same
// convention already in production for DNATChain, see ApplyPortForwards).
//
// When serving is true, the chain ends up with exactly one rule: drop
// udp/123 arriving on the WAN interfaces (defense in depth alongside
// chrony's own `allow` directive — see spec §4, "why this matters even with
// chrony's allow"). The LAN is never named in a rule; it is covered by the
// chain's own policy accept, which would be redundant and misleading to
// restate explicitly. When serving is false, the chain is flushed and left
// empty — not deleted — so its state is always explicit and idempotent.
func (s *Service) ReconcileNTPInput(ctx context.Context, wanInterfaces []string, serving bool) error {
	if s.exec.IsDryRun() {
		return nil
	}

	if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, InputChain,
		"{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", "accept", ";", "}"); err != nil {
		return fmt.Errorf("criar chain %s: %w", InputChain, err)
	}

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, InputChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", InputChain, err)
	}

	ifaces := sanitizeInterfaces(wanInterfaces)
	if serving {
		if len(ifaces) == 0 {
			slog.Warn("servir NTP para a LAN está ligado, mas nenhuma interface WAN válida está configurada; chain de proteção ficou vazia", "requested", wanInterfaces)
		} else {
			quoted := make([]string, len(ifaces))
			for i, iface := range ifaces {
				quoted[i] = fmt.Sprintf("%q", iface)
			}
			set := fmt.Sprintf("{ %s }", strings.Join(quoted, ", "))
			if _, err := s.exec.Execute(ctx, "nft", "add", "rule", Family, Table, InputChain,
				"iifname", set, "udp", "dport", "123", "drop"); err != nil {
				return fmt.Errorf("aplicar regra de proteção do NTP: %w", err)
			}
		}
	}

	slog.Info("chain de proteção do NTP (input) reconciliada", "serving", serving, "wan_interfaces", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("chain de input reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}
