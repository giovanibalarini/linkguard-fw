package routes_test

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
)

// mockExec simulates ip output for testing.
type mockExec struct {
	output string
}

func (m *mockExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "[dry-run]", nil
}
func (m *mockExec) ExecuteRead(_ context.Context, _ string, _ ...string) (string, error) {
	return m.output, nil
}
func (m *mockExec) IsDryRun() bool { return true }

const sampleRoutes = `default via 10.1.0.1 dev eth0 proto dhcp
10.1.0.0/24 dev eth0 proto kernel scope link
192.168.100.0/24 via 10.1.0.1 dev eth0 metric 100
`

const sampleRules = `0:	from all lookup local
100:	from 192.168.10.0/24 lookup 100
200:	from 192.168.20.0/24 lookup 200
32766:	from all lookup main
32767:	from all lookup default
`

func TestListRoutes(t *testing.T) {
	svc := routes.NewService(&mockExec{output: sampleRoutes})

	rs, err := svc.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(rs) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(rs))
	}

	// Default route
	if rs[0].Destination != "default" {
		t.Errorf("expected destination=default, got %s", rs[0].Destination)
	}
	if rs[0].Gateway != "10.1.0.1" {
		t.Errorf("expected gateway=10.1.0.1, got %s", rs[0].Gateway)
	}
	if rs[0].Interface != "eth0" {
		t.Errorf("expected interface=eth0, got %s", rs[0].Interface)
	}

	// Second route
	if rs[1].Destination != "10.1.0.0/24" {
		t.Errorf("expected destination=10.1.0.0/24, got %s", rs[1].Destination)
	}

	// Third route with metric
	if rs[2].Metric != "100" {
		t.Errorf("expected metric=100, got %s", rs[2].Metric)
	}
}

func TestListRules(t *testing.T) {
	svc := routes.NewService(&mockExec{output: sampleRules})

	rules, err := svc.ListRules(context.Background())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}
}

func TestListRulesPriorities(t *testing.T) {
	svc := routes.NewService(&mockExec{output: sampleRules})

	rules, err := svc.ListRules(context.Background())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}

	if rules[0].Priority != "0" {
		t.Errorf("expected priority=0, got %s", rules[0].Priority)
	}
	if rules[1].Priority != "100" {
		t.Errorf("expected priority=100, got %s", rules[1].Priority)
	}
	if rules[4].Priority != "32767" {
		t.Errorf("expected priority=32767, got %s", rules[4].Priority)
	}
}

func TestListRulesSelectors(t *testing.T) {
	svc := routes.NewService(&mockExec{output: sampleRules})

	rules, err := svc.ListRules(context.Background())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}

	// Rule 1: "from 192.168.10.0/24 lookup 100"
	if rules[1].Selector != "from 192.168.10.0/24" {
		t.Errorf("expected selector 'from 192.168.10.0/24', got %q", rules[1].Selector)
	}
	if rules[1].Table != "100" {
		t.Errorf("expected table=100, got %s", rules[1].Table)
	}
}

func TestListRoutesEmpty(t *testing.T) {
	svc := routes.NewService(&mockExec{output: ""})

	rs, err := svc.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(rs) != 0 {
		t.Errorf("expected 0 routes for empty output, got %d", len(rs))
	}
}

func TestDryRunExecutorCaptures(t *testing.T) {
	exec := firewall.NewDryRunExecutor()
	svc := routes.NewService(exec)
	ctx := context.Background()

	if _, err := svc.AddRoute(ctx, "10.0.0.0/8", "10.0.0.1", "eth0", ""); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if _, err := svc.DelRoute(ctx, "10.0.0.0/8", ""); err != nil {
		t.Fatalf("DelRoute: %v", err)
	}

	if len(exec.Commands) != 2 {
		t.Errorf("expected 2 recorded commands, got %d: %v", len(exec.Commands), exec.Commands)
	}
}
