package nftables

import (
	"context"
	"strings"
	"testing"
)

// fakeReconcileExec records every command so the test can assert the exact
// nft invocations. Dedicated to this file: the package's other fakes answer
// different command shapes, and reusing a generic one would hide which nft
// subcommand actually ran — the whole point of these assertions.
type fakeReconcileExec struct {
	dryRun   bool
	executed []string
	execErr  error
}

func (e *fakeReconcileExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, strings.Join(append([]string{cmd}, args...), " "))
	return "", e.execErr
}
func (e *fakeReconcileExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "", nil
}
func (e *fakeReconcileExec) IsDryRun() bool { return e.dryRun }

func ranCommand(executed []string, want string) bool {
	for _, c := range executed {
		if c == want {
			return true
		}
	}
	return false
}

// TestReconcileMasqueradeFlushesBeforeAdding is the regression test for the
// real production bug this feature exists to fix: `nft -f` on the persisted
// ruleset ADDS rules instead of replacing them, so a stale masquerade line
// referencing a renamed interface (enp4s0 after the NIC became enp5s0)
// survived alongside the new one. Reconciliation must flush the chain first
// so the result is exactly one masquerade rule matching current reality.
func TestReconcileMasqueradeFlushesBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "enp5s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard postrouting"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	wantAdd := `nft add rule inet linkguard postrouting oifname { "enp2s0", "enp5s0" } masquerade`
	if !ranCommand(exec.executed, wantAdd) {
		t.Errorf("missing %q; ran: %v", wantAdd, exec.executed)
	}
	// Order matters: flushing after adding would wipe the new rule.
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if c == wantAdd {
			addIdx = i
		}
	}
	if flushIdx > addIdx {
		t.Errorf("flush ran after add (would erase the new rule); ran: %v", exec.executed)
	}
}

// TestReconcileMasqueradeNeverFlushesTheWholeTable guards the elements that
// live in the same table but must survive: host_wan, blocklist,
// blocked_hosts, user_rules and prerouting_dnat.
func TestReconcileMasqueradeNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset (would drop host_wan/blocklist/user_rules), ran: %q", c)
		}
	}
}

func TestReconcileMasqueradeIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
}

// TestReconcileMasqueradeSanitizesInterfaces: an invalid name must never be
// interpolated into text handed to `nft` (command injection guard, same
// rule the bootstrap path already applies).
func TestReconcileMasqueradeSanitizesInterfaces(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "evil; rm -rf /"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "evil") || strings.Contains(c, "rm -rf") {
			t.Errorf("invalid interface reached the nft command: %q", c)
		}
	}
}

// TestReconcileMasqueradeWithNoWANsLeavesTheChainAlone: with zero configured
// WANs (all disabled, last one deleted, or a box using LinkGuard for
// firewall/hosts but no links) there is nothing legitimate to masquerade on
// — but there may well be a live, working NAT rule already in the chain
// (e.g. written by a previous reconcile, or the DB read racing a link
// delete). Flushing on an empty source of truth would take a healthy box's
// NAT down and, since Persist is also skipped in this branch, leave
// /etc/nftables.conf out of sync with whatever the live chain ends up as.
// Refusing to act — no flush, no add — is strictly safer than acting on
// nothing, and it stays idempotent.
func TestReconcileMasqueradeWithNoWANsLeavesTheChainAlone(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), nil); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands at all with zero WANs (chain must be left alone), ran: %v", exec.executed)
	}
}

func TestReconcileMasqueradeNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// ─── ReconcileNTPInput ────────────────────────────────────────────────────
//
// Reshaped 2026-08-11 per the revised spec (§4): the chain no longer denies
// NTP by WAN interface. It now accepts udp/123 from the admin-chosen
// AllowedNetworks (internal/timesync.Config.AllowedNetworks, spec §3.1) and
// drops udp/123 from everywhere else — more precise than the old
// per-interface deny, since it also covers a VLAN or guest network that
// exists on the box but that the admin did NOT authorize (a case the old
// WAN-only rule let straight through).

// TestReconcileNTPInputPolicyIsAcceptNeverDrop is the single most important
// test in this suite (see the spec, §2): the input chain this feature
// creates must declare `policy accept`. A `policy drop` chain would cut
// SSH and the web panel the instant it applied to a production firewall.
func TestReconcileNTPInputPolicyIsAcceptNeverDrop(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	joined := strings.Join(exec.executed, "\n")
	if !strings.Contains(joined, "policy accept") {
		t.Fatalf("expected the input chain definition to declare policy accept; ran: %v", exec.executed)
	}
	if strings.Contains(joined, "policy drop") {
		t.Fatalf("input chain must NEVER declare policy drop (would lock SSH/panel out); ran: %v", exec.executed)
	}
}

// TestReconcileNTPInputCreatesChainIdempotently: a box provisioned before
// this feature has no input chain at all; creating it must never fail just
// because a later reconcile finds it already there.
func TestReconcileNTPInputCreatesChainIdempotently(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("second (chain already exists): %v", err)
	}
}

// TestReconcileNTPInputServingAcceptsAllowedNetworksThenDropsRest is the
// core new behavior: an accept rule scoped to the admin-chosen networks,
// followed by a catch-all drop — both matching only udp/123.
func TestReconcileNTPInputServingAcceptsAllowedNetworksThenDropsRest(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24", "10.20.0.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	wantAccept := `nft add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24, 10.20.0.0/24 } accept`
	if !ranCommand(exec.executed, wantAccept) {
		t.Errorf("missing %q; ran: %v", wantAccept, exec.executed)
	}
	wantDrop := "nft add rule inet linkguard input udp dport 123 drop"
	if !ranCommand(exec.executed, wantDrop) {
		t.Errorf("missing %q; ran: %v", wantDrop, exec.executed)
	}
}

// TestReconcileNTPInputAcceptRulePrecedesDropRule: nft evaluates rules in
// order, so the accept rule for authorized networks must be added before
// the catch-all drop — reversed, the drop would shadow it and nothing
// would ever be accepted.
func TestReconcileNTPInputAcceptRulePrecedesDropRule(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	acceptIdx, dropIdx := -1, -1
	for i, c := range exec.executed {
		// strings.HasSuffix(..., "accept") deliberately excludes the
		// chain-creation command, whose declaration also ends in "policy
		// accept ; }" — matching that too would let this test pass even if
		// the actual accept *rule* vanished, since the chain-creation
		// command always runs before the flush regardless.
		if strings.HasSuffix(c, "ip saddr { 192.168.3.0/24 } accept") {
			acceptIdx = i
		}
		if strings.HasSuffix(c, "udp dport 123 drop") {
			dropIdx = i
		}
	}
	if acceptIdx == -1 || dropIdx == -1 {
		t.Fatalf("expected both an accept and a drop rule; ran: %v", exec.executed)
	}
	if acceptIdx > dropIdx {
		t.Errorf("accept rule ran after drop rule (would be shadowed); ran: %v", exec.executed)
	}
}

// TestReconcileNTPInputRulesMatchOnlyPort123: nothing else destined to the
// firewall (SSH 22, the panel 9997, DNS 53, DHCP 67) may ever be touched by
// this chain.
func TestReconcileNTPInputRulesMatchOnlyPort123(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if !strings.HasPrefix(c, "nft add rule") {
			continue
		}
		if !strings.Contains(c, "udp dport 123") {
			t.Errorf("rule does not match udp dport 123: %q", c)
		}
		for _, forbidden := range []string{"dport 22", "dport 9997", "dport 53", "dport 67"} {
			if strings.Contains(c, forbidden) {
				t.Errorf("rule touches a port other than 123 (%s): %q", forbidden, c)
			}
		}
	}
}

// TestReconcileNTPInputNotServingLeavesChainEmpty: toggle off => chain is
// flushed and left with no accept/drop rules (not deleted — always
// explicit state).
func TestReconcileNTPInputNotServingLeavesChainEmpty(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, false); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	wantFlush := "nft flush chain inet linkguard input"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("expected the chain to be flushed; ran: %v", exec.executed)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule") {
			t.Errorf("expected no rules when serving=false; ran: %v", exec.executed)
		}
	}
}

// TestReconcileNTPInputEmptyNetworksLeavesChainEmpty: serving=true but an
// empty AllowedNetworks list is the explicit "nothing allowed" state (spec
// §3.1) — neither the accept nor the drop rule is added (no-op, matching
// the toggle-off case exactly, since there is nothing to protect).
func TestReconcileNTPInputEmptyNetworksLeavesChainEmpty(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), nil, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule") {
			t.Errorf("expected no rules with an empty allowed-networks list; ran: %v", exec.executed)
		}
	}
}

// TestReconcileNTPInputNeverFlushesTheWholeTable mirrors the masquerade
// safety test: only this chain may ever be flushed.
func TestReconcileNTPInputNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset, ran: %q", c)
		}
	}
}

// TestReconcileNTPInputSanitizesInvalidCIDR: an invalid CIDR — an injection
// attempt, or plain garbage — must never be interpolated into a command
// handed to nft. It is dropped from the set; other valid entries still get
// their accept rule.
func TestReconcileNTPInputSanitizesInvalidCIDR(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24", "evil; rm -rf /"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "evil") || strings.Contains(c, "rm -rf") {
			t.Errorf("invalid CIDR reached the nft command: %q", c)
		}
	}
	wantAccept := "nft add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24 } accept"
	if !ranCommand(exec.executed, wantAccept) {
		t.Errorf("expected the valid CIDR to still be accepted; ran: %v", exec.executed)
	}
}

// TestReconcileNTPInputRejectsOpenWildcard: 0.0.0.0/0 (or ::/0) reaching
// this function would defeat the entire point of the accept/drop pair —
// rejected here too, independent of the handler-level
// timesync.ValidateAllowedNetworks that is the primary gate.
func TestReconcileNTPInputRejectsOpenWildcard(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"0.0.0.0/0", "::/0"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule") {
			t.Errorf("expected no accept/drop rules for an open wildcard; ran: %v", exec.executed)
		}
	}
}

func TestReconcileNTPInputNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// TestReconcileNTPInputSkipsIPv6EntriesButStillProtectsIPv4Ones is the
// regression test for the highest-impact review finding: `ip saddr { … }`
// only ever matches IPv4 in the `inet` family, so an IPv6 CIDR reaching this
// function must be dropped (defense in depth — the primary gate is
// timesync.ValidateAllowedNetworks at the API boundary, which now rejects
// IPv6 outright), and — critically — the valid IPv4 entries in the same
// list must still get their accept/drop protection. Before this fix an
// IPv6 entry made the `nft add rule ... accept` command itself fail, which
// returned early with the chain already flushed and no drop rule added:
// an empty, unprotected chain, not a partially-correct one.
func TestReconcileNTPInputSkipsIPv6EntriesButStillProtectsIPv4Ones(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24", "fd00::/64"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "fd00") {
			t.Errorf("IPv6 entry reached the nft command: %q", c)
		}
	}
	wantAccept := "nft add rule inet linkguard input udp dport 123 ip saddr { 192.168.3.0/24 } accept"
	if !ranCommand(exec.executed, wantAccept) {
		t.Errorf("expected the valid IPv4 entry to still be accepted; ran: %v", exec.executed)
	}
	wantDrop := "nft add rule inet linkguard input udp dport 123 drop"
	if !ranCommand(exec.executed, wantDrop) {
		t.Errorf("expected the catch-all drop rule to still be present (chain must not end up empty); ran: %v", exec.executed)
	}
}

func TestReconcileNTPInputIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileNTPInput(context.Background(), []string{"192.168.3.0/24"}, true); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
}
