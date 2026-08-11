package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ─── ReconcileUserRules (Phase B: the admin's rules live in the DB) ────────
//
// Mirrors ReconcileStructuralChains/ReconcileMasquerade's safety properties
// exactly (see reconcile_structural_test.go's doc comment): flush only this
// chain, never the table or the ruleset; idempotent; a no-op in dry-run;
// every rendered rule carries `counter`.

func TestReconcileUserRulesFlushesBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "drop", Daddr: "203.0.113.0/24"}},
	}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard user_rules"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard user_rules") {
			addIdx = i
		}
	}
	if flushIdx == -1 || addIdx == -1 || flushIdx > addIdx {
		t.Errorf("user_rules must be flushed before any rule is added; ran: %v", exec.executed)
	}
}

func TestReconcileUserRulesNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept"}}}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset, ran: %q", c)
		}
		if strings.Contains(c, "flush chain") && !strings.Contains(c, "user_rules") {
			t.Errorf("must only ever flush user_rules, ran: %q", c)
		}
	}
}

func TestReconcileUserRulesSkipsDisabledRules(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "192.168.3.10"}},
		{ID: "b", Position: 1, Enabled: false, Fields: RuleFields{Action: "drop", Saddr: "192.168.3.99"}},
	}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "192.168.3.99") {
			t.Errorf("disabled rule must never be rendered into nft, ran: %q", c)
		}
	}
	adds := 0
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard user_rules") {
			adds++
		}
	}
	if adds != 1 {
		t.Errorf("expected exactly 1 add-rule command (the enabled one), got %d: %v", adds, exec.executed)
	}
}

func TestReconcileUserRulesOrdersByPositionNotSliceOrder(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	// Deliberately out of order in the input slice — position must decide.
	rules := []StoredRule{
		{ID: "b", Position: 1, Enabled: true, Fields: RuleFields{Action: "drop", Saddr: "10.0.0.2"}},
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
	}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
	}
	var adds []string
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard user_rules") {
			adds = append(adds, c)
		}
	}
	if len(adds) != 2 {
		t.Fatalf("expected 2 add-rule commands, got %d: %v", len(adds), adds)
	}
	if !strings.Contains(adds[0], "10.0.0.1") || !strings.Contains(adds[1], "10.0.0.2") {
		t.Errorf("expected rules rendered in position order (10.0.0.1 then 10.0.0.2), got: %v", adds)
	}
}

func TestReconcileUserRulesEveryRuleCarriesCounter(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept"}},
		{ID: "b", Position: 1, Enabled: true, Fields: RuleFields{Action: "drop"}},
	}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
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
	if found != 2 {
		t.Errorf("expected 2 add-rule commands, got %d: %v", found, exec.executed)
	}
}

func TestReconcileUserRulesSkipsInvalidFieldsButKeepsTheRest(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{
		// Invalid: bad interface name (would inject extra nft tokens if unvalidated).
		{ID: "bad", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Iif: `eth0" ; flush ruleset #`}},
		{ID: "good", Position: 1, Enabled: true, Fields: RuleFields{Action: "drop", Saddr: "10.0.0.5"}},
	}
	// I-8: a regra ruim não pode derrubar a boa (ela continua sendo
	// aplicada), mas o resultado também não pode ser "tudo certo": há uma
	// regra ativada, configurada, que não está no firewall. O erro tipado
	// carrega a contagem e a identificação para virar estado de apply
	// não-ok lá em cima.
	err := s.ReconcileUserRules(context.Background(), rules)
	var skipped *SkippedRulesError
	if !errors.As(err, &skipped) {
		t.Fatalf("esperava um SkippedRulesError identificando a regra não aplicada, obtive %v", err)
	}
	if len(skipped.IDs) != 1 || skipped.IDs[0] != "bad" {
		t.Errorf("o erro tem que identificar exatamente a regra pulada, obtive %+v", skipped.IDs)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush ruleset") && !strings.HasSuffix(c, "flush chain inet linkguard user_rules") {
			// crude guard: the injected text must never appear verbatim as a
			// second command
		}
		if strings.Contains(c, `eth0"`) {
			t.Errorf("invalid rule must never reach the nft argv, ran: %q", c)
		}
	}
	adds := 0
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard user_rules") {
			adds++
		}
	}
	if adds != 1 {
		t.Errorf("expected the valid rule to still be applied despite the bad one, got %d add-rule commands: %v", adds, exec.executed)
	}
}

func TestReconcileUserRulesIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	rules := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
	}

	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Fatalf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
	for i := range first {
		if first[i] != exec.executed[i] {
			t.Errorf("command %d differs between runs:\nfirst=%q\nsecond=%q", i, first[i], exec.executed[i])
		}
	}
}

func TestReconcileUserRulesNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}
	rules := []StoredRule{{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept"}}}

	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// ─── C-1 layer 3: a per-rule nft failure must not truncate the chain ───────
//
// Before this fix, rebuildChain returned on the very first `nft add rule`
// error, leaving the chain flushed but only partially rebuilt: every rule
// after the failing one silently vanished from the live firewall, on this
// request and on every subsequent boot (the same bad DB row re-renders and
// re-fails every time). A rule nft rejects for a reason field-level
// validation cannot catch must not be able to take the rest of the chain
// down with it.

func TestReconcileUserRulesSurvivesAPerRuleNftFailure(t *testing.T) {
	exec := &fakeReconcileExec{
		failOn: func(cmd string) error {
			if strings.Contains(cmd, "203.0.113.99") {
				return errors.New("nft: Error: could not process rule")
			}
			return nil
		},
	}
	s := &Service{exec: exec}

	rules := []StoredRule{
		{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
		{ID: "bad", Position: 1, Enabled: true, Fields: RuleFields{Action: "drop", Saddr: "203.0.113.99"}},
		{ID: "c", Position: 2, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.3"}},
	}
	err := s.ReconcileUserRules(context.Background(), rules)
	if err == nil {
		t.Fatal("expected an aggregate error surfaced to the caller when a rule fails at nft time")
	}

	var sawA, sawBad, sawC bool
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.1") {
			sawA = true
		}
		if strings.Contains(c, "203.0.113.99") {
			sawBad = true
		}
		if strings.Contains(c, "10.0.0.3") {
			sawC = true
		}
	}
	if !sawA || !sawC {
		t.Errorf("the other rules must still be applied despite one nft failure, ran: %v", exec.executed)
	}
	_ = sawBad // the failing add-rule command is still attempted (and recorded); it's the *result* that must not abort the rest
}

func TestReconcileUserRulesEnsuresChainExistsBeforeFlushing(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept"}}}
	if err := s.ReconcileUserRules(context.Background(), rules); err != nil {
		t.Fatalf("ReconcileUserRules: %v", err)
	}

	wantEnsure := "nft add chain inet linkguard user_rules"
	wantFlush := "nft flush chain inet linkguard user_rules"
	ensureIdx, flushIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantEnsure {
			ensureIdx = i
		}
		if c == wantFlush {
			flushIdx = i
		}
	}
	if ensureIdx == -1 {
		t.Errorf("expected the chain to be idempotently ensured before flushing, ran: %v", exec.executed)
	}
	if flushIdx == -1 || ensureIdx > flushIdx {
		t.Errorf("chain must be ensured before it is flushed; ran: %v", exec.executed)
	}
}

func TestReconcileUserRulesEmptyLeavesChainEmpty(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileUserRules(context.Background(), nil); err != nil {
		t.Fatalf("ReconcileUserRules with no rules: %v", err)
	}
	wantFlush := "nft flush chain inet linkguard user_rules"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("expected the chain to still be flushed, ran: %v", exec.executed)
	}
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule") {
			t.Errorf("expected no add-rule commands with an empty rule set, ran: %q", c)
		}
	}
}

// ─── ValidateRuleFields (exported so the API layer and the import path can
// reuse the exact same validation AddUserRule already applies) ─────────────

func TestValidateRuleFieldsRejectsBadInterface(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "accept", Iif: `eth0" ; flush ruleset #`})
	if err == nil {
		t.Fatal("expected an error for a malicious interface name")
	}
}

func TestValidateRuleFieldsAcceptsWellFormedFields(t *testing.T) {
	err := ValidateRuleFields(RuleFields{Action: "drop", Saddr: "192.168.3.0/24", Proto: "tcp", Dport: "443"})
	if err != nil {
		t.Fatalf("expected valid fields to pass, got: %v", err)
	}
}
