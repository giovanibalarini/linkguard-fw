package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// LiveSnapshotSettingKey is the settings row holding the last-known-good
// `nft list ruleset` text, refreshed on every mutation (host_wan, blocklist,
// user rules, host blocks, port forwards) — see saveLiveSnapshot callers in
// internal/api/handlers and internal/hosts. It's what EnsureTable's caller
// restores on a fresh bootstrap so those elements survive a from-scratch
// install, not just the bare table structure.
const LiveSnapshotSettingKey = "nft_live_snapshot"

// EnsureTable creates the base `table inet linkguard` (chains, sets, maps) if
// it does not already exist, deriving the postrouting masquerade interfaces
// from the given WAN links. LinkGuard owns this bootstrap the same way it
// owns ip_forward/conntrack accounting/WAN steering (mirrors
// routes.EnsureForwarding / hosttraffic.EnsureAccounting): on a machine that
// already has the table (every install to date), this is a no-op; on a fresh
// install it recreates exactly the structure `internal/nftables/service.go`'s
// other methods assume exists. Best-effort — logs and returns on failure
// instead of blocking startup. Requires root (the daemon runs as root).
//
// Returns true only when it actually had to create the table — the caller
// uses this to decide whether to also restore the saved element-level state
// (LiveSnapshotSettingKey) via Restore: doing that on every boot would risk
// clobbering a running firewall with a stale snapshot, but doing it right
// after a from-scratch bootstrap is exactly the disaster-recovery case this
// exists for.
func (s *Service) EnsureTable(ctx context.Context, wanInterfaces []string) bool {
	if _, err := s.exec.ExecuteRead(ctx, "nft", "list", "table", Family, Table); err == nil {
		return false // already exists — nothing to do
	}

	ruleset := buildBootstrapRuleset(wanInterfaces)
	f, err := os.CreateTemp("", "linkguard-bootstrap-*.conf")
	if err != nil {
		slog.Warn("could not create nftables bootstrap file; firewall table was not created", "err", err)
		return false
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(ruleset); err != nil {
		f.Close()
		slog.Warn("could not write nftables bootstrap file; firewall table was not created", "err", err)
		return false
	}
	if err := f.Close(); err != nil {
		slog.Warn("could not close nftables bootstrap file; firewall table was not created", "err", err)
		return false
	}

	if out, err := s.exec.Execute(ctx, "nft", "-f", f.Name()); err != nil {
		slog.Warn("could not bootstrap the linkguard nftables table", "err", err, "output", out)
		return false
	}
	slog.Info("bootstrapped nftables table inet linkguard", "wan_interfaces", wanInterfaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("bootstrapped nftables table but could not persist it across reboots", "err", err)
	}
	return true
}

// buildBootstrapRuleset renders the base linkguard table — the same
// structure that was originally hand-created on the production box in
// June 2026 (see `nft list ruleset` there) — as an `nft -f` script. Invalid
// interface names are dropped rather than interpolated raw: this text is fed
// straight to `nft -f`, so an unvalidated name could inject extra nft
// commands (mirrors the reIface guard used elsewhere in this package).
func buildBootstrapRuleset(wanInterfaces []string) string {
	var b strings.Builder
	b.WriteString("table inet linkguard {\n")
	b.WriteString("\tmap host_wan {\n\t\ttype ipv4_addr : mark\n\t}\n\n")
	b.WriteString("\tset blocklist {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n\n")
	b.WriteString("\tset blocked_hosts {\n\t\ttype ipv4_addr\n\t}\n\n")
	b.WriteString("\tchain user_rules {\n\t}\n\n")
	// mark_hosts/forward's rules carry `counter` from the very first boot —
	// each is reconciled on every subsequent boot from its own canonical
	// definition (mark_hosts by ReconcileStructuralChains, forward by
	// ReconcileGroups since rule groups, Phase C1), and a fresh install must
	// never diverge from an upgraded box's post-reconcile state, the same
	// "fresh box == upgraded box" invariant already applied to the input
	// chain above.
	//
	// The `counter jump user_rules` line below is the one exception, and it
	// is deliberate: it is what the production box has had since June 2026,
	// so a fresh install starts from the same ruleset an upgraded one does.
	// The first ReconcileGroups is what replaces it with the group jumps —
	// the admin's own rules migrate into a group ("Minhas regras"), so a
	// forward reaching user_rules is pre-Phase-C1 state, never a target.
	b.WriteString("\tchain mark_hosts {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString("\t\tcounter meta mark set ip saddr map @host_wan\n")
	b.WriteString("\t}\n\n")
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	b.WriteString("\t\tcounter jump user_rules\n")
	b.WriteString("\t\tip saddr @blocked_hosts counter drop\n")
	b.WriteString("\t\tip daddr @blocked_hosts counter drop\n")
	b.WriteString("\t\tip daddr @blocklist counter drop\n")
	b.WriteString("\t\tip saddr @blocklist counter drop\n")
	b.WriteString("\t}\n\n")
	// The first `hook input` chain in the project (2026-08-11, "serve NTP to
	// the LAN"). Empty and policy accept on a fresh install, exactly like an
	// upgraded box's chain after ReconcileNTPInput with serving=false — a
	// fresh box and an upgraded box must never diverge. NEVER policy drop:
	// see ReconcileNTPInput's doc comment (internal/nftables/reconcile.go)
	// for why.
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	b.WriteString("\t}\n\n")
	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	if ifaces := sanitizeInterfaces(wanInterfaces); len(ifaces) > 0 {
		quoted := make([]string, len(ifaces))
		for i, iface := range ifaces {
			quoted[i] = fmt.Sprintf("%q", iface)
		}
		fmt.Fprintf(&b, "\t\toifname { %s } masquerade\n", strings.Join(quoted, ", "))
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// sanitizeInterfaces drops empty/invalid/duplicate names, preserving order.
func sanitizeInterfaces(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, iface := range in {
		iface = strings.TrimSpace(iface)
		if iface == "" || seen[iface] || !reIface.MatchString(iface) {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	return out
}
