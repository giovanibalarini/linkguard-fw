package nftables

import (
	"context"
	"strings"
	"testing"
)

// ─── ReconcileStructuralChains (forward, mark_hosts) ─────────────────────
//
// Regression coverage for §1/§6 of the design spec: forward and mark_hosts
// were, until now, only ever created once at EnsureTable/bootstrap and
// never reconciled — the exact gap that let a double-load of the ruleset
// (2026-08-10 incident) leave every rule in both chains permanently
// duplicated, because nothing ever flushed and rewrote them again. These
// tests mirror TestReconcileMasquerade*'s safety properties exactly.

func TestReconcileStructuralChainsFlushesForwardBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard forward"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	flushIdx, lastAddIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard forward") {
			lastAddIdx = i
		}
	}
	if flushIdx == -1 || lastAddIdx == -1 || flushIdx > lastAddIdx {
		t.Errorf("forward chain must be flushed before any rule is added; ran: %v", exec.executed)
	}
}

func TestReconcileStructuralChainsFlushesMarkHostsBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard mark_hosts"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard mark_hosts") {
			addIdx = i
		}
	}
	if flushIdx == -1 || addIdx == -1 || flushIdx > addIdx {
		t.Errorf("mark_hosts chain must be flushed before its rule is added; ran: %v", exec.executed)
	}
}

// TestReconcileStructuralChainsNeverFlushesTheWholeTable guards every other
// piece of live state in the table: host_wan, blocklist, blocked_hosts,
// user_rules, postrouting, input, prerouting_dnat.
func TestReconcileStructuralChainsNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset, ran: %q", c)
		}
		if strings.Contains(c, "flush chain") && !strings.Contains(c, "forward") && !strings.Contains(c, "mark_hosts") {
			t.Errorf("must only ever flush forward/mark_hosts, ran: %q", c)
		}
	}
}

func TestReconcileStructuralChainsIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
	for i := range first {
		if first[i] != exec.executed[i] {
			t.Errorf("command %d differs between runs:\nfirst=%q\nsecond=%q", i, first[i], exec.executed[i])
		}
	}
}

func TestReconcileStructuralChainsNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// TestReconcileStructuralChainsEveryRuleCarriesCounter is the regression
// test for the spec's explicit caution (§6): production's forward-chain
// drop rules were hand-created in June 2026 WITH `counter`, and reconciling
// to a counter-less definition would silently reset that data to zero on
// every boot. Every `add rule` this reconcile issues, in both chains, must
// include `counter`.
func TestReconcileStructuralChainsEveryRuleCarriesCounter(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	found := 0
	for _, c := range exec.executed {
		if !strings.HasPrefix(c, "nft add rule") {
			continue
		}
		found++
		if !strings.Contains(c, "counter") {
			t.Errorf("rule was added without a counter: %q", c)
		}
	}
	if found != 6 {
		t.Errorf("expected 6 add-rule commands (1 jump + 4 drops in forward, 1 in mark_hosts), got %d: %v", found, exec.executed)
	}
}

// TestReconcileStructuralChainsForwardRuleOrder: nft evaluates top to
// bottom, so the admin's own rules (reached via jump) must run before the
// managed blocklist/host-block drops — an admin's explicit accept must
// never be shadowed by a managed drop that ran first.
func TestReconcileStructuralChainsForwardRuleOrder(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	var forwardAdds []string
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard forward") {
			forwardAdds = append(forwardAdds, c)
		}
	}
	if len(forwardAdds) != 5 {
		t.Fatalf("expected 5 rules added to forward, got %d: %v", len(forwardAdds), forwardAdds)
	}
	if !strings.Contains(forwardAdds[0], "jump "+UserChain) {
		t.Errorf("first forward rule must be the jump to user_rules, got %q", forwardAdds[0])
	}
	for i, want := range []string{"@blocked_hosts", "@blocked_hosts", "@blocklist", "@blocklist"} {
		if !strings.Contains(forwardAdds[i+1], want) {
			t.Errorf("forward rule %d = %q, want it to contain %q", i+1, forwardAdds[i+1], want)
		}
	}
}

func TestReconcileStructuralChainsMarkHostsRule(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileStructuralChains(context.Background()); err != nil {
		t.Fatalf("ReconcileStructuralChains: %v", err)
	}
	wantSubstr := "meta mark set ip saddr map @" + HostWanMap
	found := false
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard mark_hosts") && strings.Contains(c, wantSubstr) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a mark_hosts rule containing %q; ran: %v", wantSubstr, exec.executed)
	}
}

// TestReconcileStructuralChainsResultParsesBackCleanly proves the canonical
// definition, once round-tripped through the same parser used for the
// panel (parseTableRuleset/classifyRule/describeRule), still classifies
// exactly as expected — i.e. the reconcile and the overview agree on what
// these chains contain.
func TestReconcileStructuralChainsResultParsesBackCleanly(t *testing.T) {
	rendered := `table inet linkguard {
	chain forward {
		type filter hook forward priority filter; policy accept;
		counter packets 1 bytes 2 jump user_rules
		ip saddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocked_hosts counter packets 0 bytes 0 drop
		ip daddr @blocklist counter packets 0 bytes 0 drop
		ip saddr @blocklist counter packets 0 bytes 0 drop
	}
	chain mark_hosts {
		type filter hook prerouting priority mangle; policy accept;
		counter packets 3 bytes 4 meta mark set ip saddr map @host_wan
	}
}
`
	chains := parseTableRuleset(rendered)
	fwd := chainByName(chains, "forward")
	if fwd == nil || len(fwd.Rules) != 5 {
		t.Fatalf("expected 5 rules in forward, got %+v", fwd)
	}
	for _, r := range fwd.Rules {
		if !r.HasCounter {
			t.Errorf("forward rule must report HasCounter=true after the fix, got false: %+v", r)
		}
		if !r.Managed {
			t.Errorf("forward rule must be managed: %+v", r)
		}
	}
	mh := chainByName(chains, "mark_hosts")
	if mh == nil || len(mh.Rules) != 1 || !mh.Rules[0].HasCounter {
		t.Fatalf("mark_hosts rule must have a counter after the fix: %+v", mh)
	}
	if mh.Rules[0].Owner.Key != "wan_steering" {
		t.Errorf("mark_hosts rule owner = %+v, want wan_steering", mh.Rules[0].Owner)
	}
}
