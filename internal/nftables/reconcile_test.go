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

// TestReconcileNTPInputPolicyIsAcceptNeverDrop is the single most important
// test in this suite (see the spec, §2): the input chain this feature
// creates must declare `policy accept`. A `policy drop` chain would cut
// SSH and the web panel the instant it applied to a production firewall.
func TestReconcileNTPInputPolicyIsAcceptNeverDrop(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
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

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("second (chain already exists): %v", err)
	}
}

// TestReconcileNTPInputServingDropsUDP123OnWANs: exactly one rule, dropping
// NTP arriving on the WAN interfaces — never on the LAN (no rule at all for
// the LAN; the chain's own policy-accept covers it).
func TestReconcileNTPInputServingDropsUDP123OnWANs(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0", "enp5s0"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	wantRule := `nft add rule inet linkguard input iifname { "enp2s0", "enp5s0" } udp dport 123 drop`
	if !ranCommand(exec.executed, wantRule) {
		t.Errorf("missing %q; ran: %v", wantRule, exec.executed)
	}
}

// TestReconcileNTPInputNotServingLeavesChainEmpty: toggle off => chain is
// flushed and left with no drop rule (not deleted — always explicit state).
func TestReconcileNTPInputNotServingLeavesChainEmpty(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, false); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	wantFlush := "nft flush chain inet linkguard input"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("expected the chain to be flushed; ran: %v", exec.executed)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "drop") {
			t.Errorf("expected no drop rule when serving=false; ran: %v", exec.executed)
		}
	}
}

// TestReconcileNTPInputNeverFlushesTheWholeTable mirrors the masquerade
// safety test: only this chain may ever be flushed.
func TestReconcileNTPInputNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset, ran: %q", c)
		}
	}
}

// TestReconcileNTPInputSanitizesInterfaces: an invalid interface name must
// never be interpolated into a command handed to nft.
func TestReconcileNTPInputSanitizesInterfaces(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0", "evil; rm -rf /"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "evil") || strings.Contains(c, "rm -rf") {
			t.Errorf("invalid interface reached the nft command: %q", c)
		}
	}
}

func TestReconcileNTPInputNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("ReconcileNTPInput in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

func TestReconcileNTPInputIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileNTPInput(context.Background(), []string{"enp2s0"}, true); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
}
