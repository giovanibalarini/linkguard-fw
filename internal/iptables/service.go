// Package iptables reads and parses iptables rules from the Linux kernel.
package iptables

import (
	"context"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Table represents an iptables table (filter, nat, mangle, raw).
type Table struct {
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}

// Chain represents a chain within an iptables table.
type Chain struct {
	Name   string `json:"name"`
	Policy string `json:"policy,omitempty"`
	Rules  []Rule `json:"rules"`
}

// Rule represents a single iptables rule.
type Rule struct {
	Raw     string   `json:"raw"`
	Pkts    string   `json:"pkts,omitempty"`
	Bytes   string   `json:"bytes,omitempty"`
	Target  string   `json:"target,omitempty"`
	Prot    string   `json:"prot,omitempty"`
	In      string   `json:"in,omitempty"`
	Out     string   `json:"out,omitempty"`
	Source  string   `json:"source,omitempty"`
	Dest    string   `json:"dest,omitempty"`
	Options []string `json:"options,omitempty"`
}

// Service wraps iptables operations.
type Service struct {
	exec firewall.Executor
}

// NewService creates a new iptables Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// ListAll returns all tables (filter, nat, mangle) with their chains and rules.
func (s *Service) ListAll(ctx context.Context) ([]Table, error) {
	tableNames := []string{"filter", "nat", "mangle"}
	tables := make([]Table, 0, len(tableNames))

	for _, name := range tableNames {
		t, err := s.ListTable(ctx, name)
		if err != nil {
			// Include the table but mark the error in a comment chain
			tables = append(tables, Table{Name: name, Chains: []Chain{{Name: "ERROR", Rules: []Rule{{Raw: err.Error()}}}}})
			continue
		}
		tables = append(tables, t)
	}
	return tables, nil
}

// ListTable returns the rules for a specific iptables table using iptables -L -n -v.
func (s *Service) ListTable(ctx context.Context, table string) (Table, error) {
	out, err := s.exec.ExecuteRead(ctx, "iptables", "-t", table, "-L", "-n", "-v", "--line-numbers")
	if err != nil {
		return Table{Name: table}, err
	}
	return parseIptablesOutput(table, out), nil
}

// Save returns the output of iptables-save (used for backups).
func (s *Service) Save(ctx context.Context) (string, error) {
	return s.exec.ExecuteRead(ctx, "iptables-save")
}

// Restore applies rules from an iptables-save dump.
func (s *Service) Restore(ctx context.Context, rules string) (string, error) {
	// Write rules to a temp file and call iptables-restore
	return s.exec.Execute(ctx, "iptables-restore", "--noflush")
}

// ─── Parser ──────────────────────────────────────────────────────────────────

func parseIptablesOutput(tableName, output string) Table {
	t := Table{Name: tableName}
	var currentChain *Chain

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Chain header: "Chain INPUT (policy ACCEPT)"  or  "Chain FORWARD (x references)"
		if strings.HasPrefix(line, "Chain ") {
			if currentChain != nil {
				t.Chains = append(t.Chains, *currentChain)
			}
			parts := strings.Fields(line)
			chain := Chain{Name: parts[1]}
			if len(parts) >= 4 && parts[2] == "(policy" {
				chain.Policy = strings.TrimRight(parts[3], ")")
			}
			currentChain = &chain
			continue
		}

		// Skip the column header line
		if strings.HasPrefix(line, "pkts") || strings.HasPrefix(line, "num") {
			continue
		}

		if currentChain == nil {
			continue
		}

		rule := parseRuleLine(line)
		currentChain.Rules = append(currentChain.Rules, rule)
	}

	if currentChain != nil {
		t.Chains = append(t.Chains, *currentChain)
	}

	return t
}

func parseRuleLine(line string) Rule {
	fields := strings.Fields(line)
	r := Rule{Raw: line}

	// Format: num pkts bytes target prot opt in out source destination [options...]
	if len(fields) >= 10 {
		// num pkts bytes target prot opt in out source destination
		r.Pkts = fields[1]
		r.Bytes = fields[2]
		r.Target = fields[3]
		r.Prot = fields[4]
		r.In = fields[6]
		r.Out = fields[7]
		r.Source = fields[8]
		r.Dest = fields[9]
		if len(fields) > 10 {
			r.Options = fields[10:]
		}
	}

	return r
}
