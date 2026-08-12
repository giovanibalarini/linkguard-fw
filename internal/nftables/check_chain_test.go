package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ─── CheckChain / CheckUserRules (C-1 layer 2: pre-flight `nft -c`) ────────
//
// Before this fix, only nft's own reconcile ever saw whether a rule was
// really acceptable — and by the time it did, the chain had already been
// flushed. CheckChain lets a caller (the API handler, before any DB write —
// see internal/firewallrules.Service.CheckPending) ask nft up front,
// without touching the live ruleset: a parse-only `nft -c -f` dry run.

func TestCheckChainRunsNftDashCWithATempFile(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.CheckChain(context.Background(), UserChain, [][]string{{"ip", "saddr", "10.0.0.1", "counter", "accept"}}); err != nil {
		t.Fatalf("CheckChain: %v", err)
	}
	if len(exec.reads) != 1 {
		t.Fatalf("expected exactly 1 read (the -c invocation), got %d: %v", len(exec.reads), exec.reads)
	}
	got := exec.reads[0]
	if !strings.HasPrefix(got, "nft -c -f ") {
		t.Errorf("expected `nft -c -f <file>`, got %q", got)
	}
	// Never a mutating command — this must change nothing live.
	if len(exec.executed) != 0 {
		t.Errorf("CheckChain must never issue a mutating command, ran: %v", exec.executed)
	}
}

func TestCheckChainSurfacesNftsOwnRejection(t *testing.T) {
	exec := &fakeReconcileExec{readErr: errors.New(`nft: Error: invalid port range: end before start`)}
	s := &Service{exec: exec}

	err := s.CheckChain(context.Background(), UserChain, [][]string{{"tcp", "dport", "8080-80", "counter", "accept"}})
	if err == nil {
		t.Fatal("expected the pre-flight to surface nft's own rejection")
	}
	if !strings.Contains(err.Error(), "invalid port range") {
		t.Errorf("expected nft's own message in the error, got %q", err.Error())
	}
}

func TestCheckChainNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.CheckChain(context.Background(), UserChain, [][]string{{"counter", "accept"}}); err != nil {
		t.Fatalf("CheckChain in dry-run: %v", err)
	}
	if len(exec.reads) != 0 {
		t.Errorf("expected no reads in dry-run, ran: %v", exec.reads)
	}
}

func TestCheckUserRulesRendersTheSameChainReconcileWould(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	rules := []StoredRule{
		{ID: "a", Position: 1, Enabled: true, Fields: RuleFields{Action: "drop", Saddr: "10.0.0.2"}},
		{ID: "b", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}},
		{ID: "c", Position: 2, Enabled: false, Fields: RuleFields{Action: "drop", Saddr: "10.0.0.3"}},
	}
	if err := s.CheckUserRules(context.Background(), rules); err != nil {
		t.Fatalf("CheckUserRules: %v", err)
	}
	if len(exec.reads) != 1 {
		t.Fatalf("expected exactly 1 read, got %d: %v", len(exec.reads), exec.reads)
	}
	// O script de verdade, não o caminho do arquivo temporário: até a Fase C1
	// este teste olhava exec.reads[0] ("nft -c -f /tmp/..."), onde nenhuma das
	// duas asserções abaixo poderia falhar — passava sem provar nada.
	if len(exec.checkScripts) != 1 {
		t.Fatalf("expected exactly 1 checked script, got %d", len(exec.checkScripts))
	}
	script := exec.checkScripts[0]
	// The disabled rule must never appear, and order must follow Position
	// (10.0.0.1 before 10.0.0.2), exactly like ReconcileUserRules.
	if strings.Contains(script, "10.0.0.3") {
		t.Errorf("disabled rule leaked into the checked script: %s", script)
	}
	if strings.Index(script, "10.0.0.1") > strings.Index(script, "10.0.0.2") {
		t.Errorf("expected position order preserved in the checked script: %s", script)
	}
}

func TestCheckUserRulesRejectsWhatNftWouldReject(t *testing.T) {
	exec := &fakeReconcileExec{readErr: errors.New("nft: Error: could not process rule")}
	s := &Service{exec: exec}

	rules := []StoredRule{{ID: "a", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Saddr: "10.0.0.1"}}}
	if err := s.CheckUserRules(context.Background(), rules); err == nil {
		t.Fatal("expected CheckUserRules to surface nft's rejection")
	}
}
