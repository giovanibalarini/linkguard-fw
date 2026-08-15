// Package iptables reads and parses iptables rules from the Linux kernel.
package iptables

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
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
	Num     string   `json:"num,omitempty"`
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

// Restore FOI REMOVIDO (2026-08-13, antes do deploy em produção). Ele rodava
// `iptables-restore <arquivo>`, e o único chamador era o rollback legado
// (POST /api/firewall/rollback), removido junto — nenhuma tela o chamava.
//
// Por que não fica "só por precaução": `iptables-restore` SEM `-n` dá flush em
// `ip filter/nat/mangle` antes de carregar, e essas são justamente as chains do
// Docker numa máquina de produção. O texto que ele receberia vinha da tabela
// `iptables_backups`, que hoje guarda dump do `nft` — ou seja, um caminho que
// só não destruía nada por acidente (o parse falha na linha 1). Deixar a função
// viva é deixar a arma carregada esperando o próximo chamador distraído. O que
// restaura firewall neste produto é nftables.Service.Restore, escopado à tabela
// `inet linkguard` e com pré-voo `nft -c -f`.

// CreateRule inserts/appends a rule in the specified table and chain.
// ruleSpec should contain only rule arguments (e.g. "-s 10.0.0.0/24 -j ACCEPT").
func (s *Service) CreateRule(ctx context.Context, table, chain, ruleSpec string, line int) (string, error) {
	if err := validateTableChain(table, chain); err != nil {
		return "", err
	}
	if err := validateRuleSpec(ruleSpec); err != nil {
		return "", err
	}
	parts := strings.Fields(strings.TrimSpace(ruleSpec))
	if len(parts) == 0 {
		return "", fmt.Errorf("rule_spec is required")
	}

	args := []string{"-t", table}
	if line > 0 {
		args = append(args, "-I", chain, fmt.Sprintf("%d", line))
	} else {
		args = append(args, "-A", chain)
	}
	args = append(args, parts...)
	return s.exec.Execute(ctx, "iptables", args...)
}

// DeleteRule e ReplaceRule foram removidos. O DeleteRule era o único caminho de
// escrita restante que não passava por validateTableChain: aceitava qualquer
// table/chain e apagava regra viva de outro programa (as chains do Docker, por
// exemplo). Nenhum dos dois tinha chamador — o único uso vivo do pacote é o
// CreateRule do assistente de balanceamento WAN, restrito a mangle/PREROUTING.

var (
	allowedModules = map[string]bool{"conntrack": true, "statistic": true}
	allowedCtstate = map[string]bool{"NEW": true, "ESTABLISHED": true, "RELATED": true, "INVALID": true}
	allowedMode    = map[string]bool{"random": true, "nth": true}
	allowedTarget  = map[string]bool{"ACCEPT": true, "DROP": true, "REJECT": true, "RETURN": true, "MARK": true}
	setMarkRe      = regexp.MustCompile(`^0x[0-9a-fA-F]{1,8}$`)
)

// validateRuleSpec accepts only the exact rule shape the WAN-balance wizard
// (the sole caller of this legacy endpoint) needs to build:
//
//	-s <CIDR> -m conntrack --ctstate <states> [-m statistic --mode <mode> --probability <p>] -j <target> [--set-mark <hex>]
//
// Every token must be recognized; anything else — including match/target
// extensions not in this allowlist — rejects the whole spec. This replaces a
// denylist that only blocked rule-management flags (-A/-I/-F/...) but let
// arbitrary -j targets and unvalidated -s/-d values through as extra argv
// tokens on the real `iptables` invocation.
func validateRuleSpec(ruleSpec string) error {
	parts := strings.Fields(strings.TrimSpace(ruleSpec))
	if len(parts) == 0 {
		return fmt.Errorf("rule_spec is required")
	}
	i := 0
	next := func() (string, bool) {
		if i >= len(parts) {
			return "", false
		}
		v := parts[i]
		i++
		return v, true
	}
	for i < len(parts) {
		flag, _ := next()
		switch flag {
		case "-s", "-d":
			val, ok := next()
			if !ok {
				return fmt.Errorf("%s requires a value", flag)
			}
			if net.ParseIP(val) == nil {
				if _, _, err := net.ParseCIDR(val); err != nil {
					return fmt.Errorf("%s: endereço/CIDR inválido: %q", flag, val)
				}
			}
		case "-m":
			val, ok := next()
			if !ok || !allowedModules[val] {
				return fmt.Errorf("módulo -m não permitido: %q", val)
			}
		case "--ctstate":
			val, ok := next()
			if !ok {
				return fmt.Errorf("--ctstate requires a value")
			}
			for _, state := range strings.Split(val, ",") {
				if !allowedCtstate[state] {
					return fmt.Errorf("--ctstate não permitido: %q", state)
				}
			}
		case "--mode":
			val, ok := next()
			if !ok || !allowedMode[val] {
				return fmt.Errorf("--mode não permitido: %q", val)
			}
		case "--probability":
			val, ok := next()
			if !ok {
				return fmt.Errorf("--probability requires a value")
			}
			p, err := strconv.ParseFloat(val, 64)
			if err != nil || p < 0 || p > 1 {
				return fmt.Errorf("--probability inválida: %q", val)
			}
		case "-j":
			val, ok := next()
			if !ok || !allowedTarget[val] {
				return fmt.Errorf("alvo -j não permitido: %q", val)
			}
		case "--set-mark":
			val, ok := next()
			if !ok || !setMarkRe.MatchString(val) {
				return fmt.Errorf("--set-mark inválido: %q", val)
			}
		default:
			return fmt.Errorf("flag não reconhecida: %q", flag)
		}
	}
	return nil
}

// validateTableChain restricts table/chain to the one combination the WAN-
// balance wizard (the sole caller of this legacy endpoint) actually uses.
// Extending this list is a deliberate, explicit decision for a future real
// use case — not something any caller can widen by just passing a new string.
func validateTableChain(table, chain string) error {
	if table == "mangle" && chain == "PREROUTING" {
		return nil
	}
	return fmt.Errorf("table/chain não suportados: %s/%s", table, chain)
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
		r.Num = fields[0]
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
