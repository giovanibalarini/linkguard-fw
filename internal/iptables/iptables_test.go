package iptables_test

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
)

// mockExecutor simulates read output for testing.
type mockExecutor struct {
	readOutput string
	commands   []string
}

func (m *mockExecutor) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd
	for _, a := range args {
		full += " " + a
	}
	m.commands = append(m.commands, full)
	return "[dry-run] " + full, nil
}

func (m *mockExecutor) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return m.readOutput, nil
}

func (m *mockExecutor) IsDryRun() bool { return true }

const sampleFilterOutput = `Chain INPUT (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source               destination
1       10  1024 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
2        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:23

Chain FORWARD (policy DROP)
num   pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source               destination
1        5   500 ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0
`

func TestListTable(t *testing.T) {
	mock := &mockExecutor{readOutput: sampleFilterOutput}
	svc := iptables.NewService(mock)

	table, err := svc.ListTable(context.Background(), "filter")
	if err != nil {
		t.Fatalf("ListTable: %v", err)
	}
	if table.Name != "filter" {
		t.Errorf("expected Name=filter, got %s", table.Name)
	}
	if len(table.Chains) != 3 {
		t.Errorf("expected 3 chains, got %d", len(table.Chains))
	}
}

func TestListTableChainPolicies(t *testing.T) {
	mock := &mockExecutor{readOutput: sampleFilterOutput}
	svc := iptables.NewService(mock)

	table, err := svc.ListTable(context.Background(), "filter")
	if err != nil {
		t.Fatalf("ListTable: %v", err)
	}

	policies := map[string]string{}
	for _, c := range table.Chains {
		policies[c.Name] = c.Policy
	}

	if policies["INPUT"] != "ACCEPT" {
		t.Errorf("expected INPUT policy=ACCEPT, got %s", policies["INPUT"])
	}
	if policies["FORWARD"] != "DROP" {
		t.Errorf("expected FORWARD policy=DROP, got %s", policies["FORWARD"])
	}
	if policies["OUTPUT"] != "ACCEPT" {
		t.Errorf("expected OUTPUT policy=ACCEPT, got %s", policies["OUTPUT"])
	}
}

func TestListTableRuleParsing(t *testing.T) {
	mock := &mockExecutor{readOutput: sampleFilterOutput}
	svc := iptables.NewService(mock)

	table, err := svc.ListTable(context.Background(), "filter")
	if err != nil {
		t.Fatalf("ListTable: %v", err)
	}

	var inputChain *iptables.Chain
	for i, c := range table.Chains {
		if c.Name == "INPUT" {
			inputChain = &table.Chains[i]
			break
		}
	}
	if inputChain == nil {
		t.Fatal("INPUT chain not found")
	}
	if len(inputChain.Rules) != 2 {
		t.Errorf("expected 2 INPUT rules, got %d", len(inputChain.Rules))
	}
	if inputChain.Rules[0].Num != "1" {
		t.Errorf("expected first rule num=1, got %s", inputChain.Rules[0].Num)
	}
	if inputChain.Rules[0].Target != "ACCEPT" {
		t.Errorf("expected first rule target=ACCEPT, got %s", inputChain.Rules[0].Target)
	}
	if inputChain.Rules[1].Target != "DROP" {
		t.Errorf("expected second rule target=DROP, got %s", inputChain.Rules[1].Target)
	}
}

func TestListTableEmptyOutput(t *testing.T) {
	mock := &mockExecutor{readOutput: ""}
	svc := iptables.NewService(mock)

	table, err := svc.ListTable(context.Background(), "nat")
	if err != nil {
		t.Fatalf("ListTable: %v", err)
	}
	if len(table.Chains) != 0 {
		t.Errorf("expected 0 chains for empty output, got %d", len(table.Chains))
	}
}

func TestListAllTables(t *testing.T) {
	mock := &mockExecutor{readOutput: sampleFilterOutput}
	svc := iptables.NewService(mock)

	tables, err := svc.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(tables) == 0 {
		t.Error("expected non-empty tables list")
	}
}

func TestDryRunExecuteNotRead(t *testing.T) {
	// Verify that Execute (write) in dry-run mode does not actually call the system
	exec := firewall.NewDryRunExecutor()
	svc := iptables.NewService(exec)

	// Save calls ExecuteRead internally
	// We can test that a real Execute (write) call is captured as dry-run
	ctx := context.Background()
	_, err := exec.Execute(ctx, "iptables", "-F")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(exec.Commands) != 1 {
		t.Errorf("expected 1 dry-run command, got %d", len(exec.Commands))
	}
	_ = svc // just verify the service compiles and works
}

func TestDeleteRuleDryRun(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	svc := iptables.NewService(exec)

	if _, err := svc.DeleteRule(context.Background(), "filter", "INPUT", 1); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if len(exec.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(exec.Commands))
	}
	if exec.Commands[0] != "iptables -t filter -D INPUT 1" {
		t.Fatalf("unexpected command: %s", exec.Commands[0])
	}
}

func TestReplaceRuleDryRun(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	svc := iptables.NewService(exec)

	if _, err := svc.ReplaceRule(context.Background(), "filter", "INPUT", 2, "-s 10.0.0.0/24 -j ACCEPT"); err != nil {
		t.Fatalf("ReplaceRule: %v", err)
	}
	if len(exec.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(exec.Commands))
	}
	if exec.Commands[0] != "iptables -t filter -R INPUT 2 -s 10.0.0.0/24 -j ACCEPT" {
		t.Fatalf("unexpected command: %s", exec.Commands[0])
	}
}
