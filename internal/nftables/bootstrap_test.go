package nftables

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// recordExec is a controllable firewall.Executor fake for bootstrap tests: it
// simulates whether `nft list table ...` finds the table, captures the
// content of any `-f` script passed to `nft`, and never touches the real
// system.
type recordExec struct {
	listTableErr error
	execErr      error
	rulesetOut   string
	tableOut     string // response to `nft list table <family> <table>`; defaults below if empty
	dryRun       bool

	calls        []string
	bootstrapSrc string
}

func (r *recordExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	r.calls = append(r.calls, cmd+" "+strings.Join(args, " "))
	if cmd == "nft" && len(args) >= 2 && args[0] == "-f" {
		if r.execErr != nil {
			return "", r.execErr
		}
		b, _ := os.ReadFile(args[1])
		r.bootstrapSrc = string(b)
		return "", nil
	}
	return "", nil
}

func (r *recordExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	r.calls = append(r.calls, "read:"+cmd+" "+strings.Join(args, " "))
	if cmd == "nft" && len(args) >= 2 && args[0] == "list" && args[1] == "table" {
		if r.listTableErr != nil {
			return "", r.listTableErr
		}
		if r.tableOut != "" {
			return r.tableOut, nil
		}
		return "table inet linkguard {\n}\n", nil
	}
	if cmd == "nft" && len(args) >= 2 && args[0] == "list" && args[1] == "ruleset" {
		return r.rulesetOut, nil
	}
	return "", nil
}

func (r *recordExec) IsDryRun() bool { return r.dryRun }

func TestEnsureTableNoOpWhenTableAlreadyExists(t *testing.T) {
	exec := &recordExec{}
	s := NewService(exec)
	created := s.EnsureTable(context.Background(), []string{"enp5s0"})

	if created {
		t.Error("expected EnsureTable to report created=false when the table already exists")
	}
	for _, c := range exec.calls {
		if strings.Contains(c, "-f") {
			t.Fatalf("expected no table creation when table already exists, got calls: %v", exec.calls)
		}
	}
}

func TestEnsureTableCreatesWhenMissing(t *testing.T) {
	exec := &recordExec{
		listTableErr: fmt.Errorf("Error: No such file or directory"),
		rulesetOut:   "table inet linkguard {\n}\n",
	}
	s := NewService(exec)
	created := s.EnsureTable(context.Background(), []string{"enp5s0", "enp3s0"})

	if !created {
		t.Error("expected EnsureTable to report created=true when it had to bootstrap the table")
	}
	if exec.bootstrapSrc == "" {
		t.Fatalf("expected `nft -f` to be called with a bootstrap ruleset; calls: %v", exec.calls)
	}
	if !strings.Contains(exec.bootstrapSrc, "table inet linkguard") {
		t.Errorf("bootstrap ruleset missing table declaration:\n%s", exec.bootstrapSrc)
	}
	if !strings.Contains(exec.bootstrapSrc, `"enp5s0"`) || !strings.Contains(exec.bootstrapSrc, `"enp3s0"`) {
		t.Errorf("bootstrap ruleset missing WAN interfaces:\n%s", exec.bootstrapSrc)
	}
}

func TestEnsureTableSurvivesCreateFailure(t *testing.T) {
	exec := &recordExec{
		listTableErr: fmt.Errorf("no such table"),
		execErr:      fmt.Errorf("nft: parse error"),
	}
	s := NewService(exec)
	// Must not panic and must not attempt to persist a ruleset that never applied.
	created := s.EnsureTable(context.Background(), []string{"enp5s0"})
	if created {
		t.Error("expected created=false when the bootstrap nft -f itself failed")
	}
	for _, c := range exec.calls {
		if strings.Contains(c, "read:nft list ruleset") {
			t.Errorf("did not expect Persist() to run after a failed bootstrap; calls: %v", exec.calls)
		}
	}
}

func TestEnsureTableRunsCheckEvenInDryRun(t *testing.T) {
	// ExecuteRead always runs for real (per the Executor contract), so the
	// existence check must still happen in dry-run mode. Whether creation
	// actually applies is left to the Executor implementation (DryRunExecutor
	// no-ops Execute), not to EnsureTable itself.
	exec := &recordExec{listTableErr: fmt.Errorf("no such table"), dryRun: true}
	s := NewService(exec)
	s.EnsureTable(context.Background(), []string{"enp5s0"})

	found := false
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "read:nft list table") {
			found = true
		}
	}
	if !found {
		t.Error("expected the table-existence check to run even in dry-run")
	}
}

// TestBootstrapThenRestoreAppliesSavedState mirrors exactly what main.go does
// on a from-scratch install: EnsureTable creates the bare skeleton (reports
// created=true), and the caller then restores the saved live snapshot on top
// — this is how host_wan/blocklist/user rules/port forwards survive a
// reinstall even though EnsureTable's own skeleton is empty.
func TestBootstrapThenRestoreAppliesSavedState(t *testing.T) {
	exec := &recordExec{listTableErr: fmt.Errorf("no such table")}
	s := NewService(exec)

	created := s.EnsureTable(context.Background(), []string{"enp5s0"})
	if !created {
		t.Fatal("expected created=true on a missing table")
	}

	saved := "table inet linkguard {\n\tmap host_wan {\n\t\telements = { 10.0.0.9 : 0x12c }\n\t}\n}\n"
	if _, err := s.Restore(context.Background(), saved); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	found := false
	for _, c := range exec.calls {
		if strings.HasPrefix(c, "nft -f ") {
			found = true
		}
	}
	if !found {
		t.Error("expected Restore to invoke `nft -f` with the saved ruleset")
	}
}

func TestBuildBootstrapRulesetContainsCoreStructure(t *testing.T) {
	rs := buildBootstrapRuleset([]string{"enp5s0"})
	for _, want := range []string{
		"table inet linkguard {",
		"map host_wan {",
		"set blocklist {",
		"set blocked_hosts {",
		"chain user_rules {",
		"chain mark_hosts {",
		"type filter hook prerouting priority mangle",
		"chain forward {",
		"type filter hook forward priority filter",
		"jump user_rules",
		"ip saddr @blocked_hosts",
		"ip daddr @blocklist",
		"chain input {",
		"type filter hook input priority filter",
		"chain postrouting {",
		"type nat hook postrouting priority srcnat",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("bootstrap ruleset missing %q:\n%s", want, rs)
		}
	}
}

// TestBuildBootstrapRulesetInputChainPolicyIsAccept: a fresh install must
// never come up with a `policy drop` input chain — same non-negotiable as
// ReconcileNTPInput (see its doc comment / spec §2). A fresh box and an
// upgraded box must converge on the exact same chain.
func TestBuildBootstrapRulesetInputChainPolicyIsAccept(t *testing.T) {
	rs := buildBootstrapRuleset([]string{"enp5s0"})
	i := strings.Index(rs, "chain input {")
	if i < 0 {
		t.Fatal("bootstrap ruleset missing chain input")
	}
	end := strings.Index(rs[i:], "}")
	if end < 0 {
		t.Fatal("could not find end of chain input block")
	}
	block := rs[i : i+end]
	if !strings.Contains(block, "policy accept") {
		t.Errorf("input chain must declare policy accept:\n%s", block)
	}
	if strings.Contains(block, "policy drop") {
		t.Errorf("input chain must NEVER declare policy drop:\n%s", block)
	}
}

func TestBuildBootstrapRulesetSanitizesInterfaces(t *testing.T) {
	rs := buildBootstrapRuleset([]string{"enp5s0", `evil"; flush ruleset; #`, "enp5s0"})
	if strings.Contains(rs, "evil") || strings.Contains(rs, "flush ruleset;") {
		t.Errorf("invalid interface name leaked into generated ruleset:\n%s", rs)
	}
	if strings.Count(rs, `"enp5s0"`) != 1 {
		t.Errorf("expected deduplicated single occurrence of enp5s0, got:\n%s", rs)
	}
}

func TestBuildBootstrapRulesetEmptyInterfacesOmitsMasquerade(t *testing.T) {
	rs := buildBootstrapRuleset(nil)
	if strings.Contains(rs, "masquerade") {
		t.Errorf("expected no masquerade rule with zero WAN interfaces:\n%s", rs)
	}
	if !strings.Contains(rs, "chain postrouting {") {
		t.Errorf("expected postrouting chain to still be declared:\n%s", rs)
	}
}
