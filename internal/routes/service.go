// Package routes manages Linux routing tables using ip route and ip rule.
package routes

import (
	"context"
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Route represents an entry from the kernel routing table.
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      string `json:"metric,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Raw         string `json:"raw"`
}

// Rule represents an ip rule entry.
type Rule struct {
	Priority string `json:"priority"`
	Selector string `json:"selector"`
	Action   string `json:"action"`
	Table    string `json:"table,omitempty"`
	FWMark   string `json:"fwmark,omitempty"`
	Raw      string `json:"raw"`
}

// Service wraps ip route / ip rule operations.
type Service struct {
	exec firewall.Executor
}

// NewService creates a new routes Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{exec: exec}
}

// ListRoutes returns the main routing table entries.
func (s *Service) ListRoutes(ctx context.Context) ([]Route, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show")
	if err != nil {
		return nil, err
	}
	return parseRoutes(out), nil
}

// ListAllRoutes returns routes from all tables.
func (s *Service) ListAllRoutes(ctx context.Context) ([]Route, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	return parseRoutes(out), nil
}

// ListRules returns the ip rules.
func (s *Service) ListRules(ctx context.Context) ([]Rule, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "rule", "list")
	if err != nil {
		return nil, err
	}
	return parseRules(out), nil
}

// AddRoute adds a route (dry-run safe).
func (s *Service) AddRoute(ctx context.Context, dest, gw, iface, table string) (string, error) {
	args := []string{"route", "add", dest}
	if gw != "" {
		args = append(args, "via", gw)
	}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	if table != "" {
		args = append(args, "table", table)
	}
	return s.exec.Execute(ctx, "ip", args...)
}

// DelRoute removes a route (dry-run safe).
func (s *Service) DelRoute(ctx context.Context, dest, table string) (string, error) {
	args := []string{"route", "del", dest}
	if table != "" {
		args = append(args, "table", table)
	}
	return s.exec.Execute(ctx, "ip", args...)
}

// AddRule adds an ip rule (dry-run safe).
func (s *Service) AddRule(ctx context.Context, from, fwmark, table string, priority int) (string, error) {
	args := []string{"rule", "add"}
	if from != "" {
		args = append(args, "from", from)
	}
	if fwmark != "" {
		args = append(args, "fwmark", fwmark)
	}
	args = append(args, "lookup", table)
	if priority > 0 {
		args = append(args, "priority", fmt.Sprintf("%d", priority))
	}
	return s.exec.Execute(ctx, "ip", args...)
}

// DelRule removes an ip rule (dry-run safe).
func (s *Service) DelRule(ctx context.Context, from, fwmark, table string, priority int) (string, error) {
	args := []string{"rule", "del"}
	if from != "" {
		args = append(args, "from", from)
	}
	if fwmark != "" {
		args = append(args, "fwmark", fwmark)
	}
	if table != "" {
		args = append(args, "lookup", table)
	}
	if priority > 0 {
		args = append(args, "priority", fmt.Sprintf("%d", priority))
	}
	return s.exec.Execute(ctx, "ip", args...)
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

func parseRoutes(output string) []Route {
	var routes []Route
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		routes = append(routes, parseRouteLine(line))
	}
	return routes
}

func parseRouteLine(line string) Route {
	r := Route{Raw: line}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return r
	}

	r.Destination = fields[0]

	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				r.Gateway = fields[i+1]
				i++
			}
		case "dev":
			if i+1 < len(fields) {
				r.Interface = fields[i+1]
				i++
			}
		case "metric":
			if i+1 < len(fields) {
				r.Metric = fields[i+1]
				i++
			}
		case "proto":
			if i+1 < len(fields) {
				r.Protocol = fields[i+1]
				i++
			}
		case "scope":
			if i+1 < len(fields) {
				r.Scope = fields[i+1]
				i++
			}
		}
	}
	return r
}

func parseRules(output string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rules = append(rules, parseRuleLine(line))
	}
	return rules
}

func parseRuleLine(line string) Rule {
	r := Rule{Raw: line}
	// Format: "0:	from all lookup local"
	colonIdx := strings.Index(line, ":")
	if colonIdx >= 0 {
		r.Priority = strings.TrimSpace(line[:colonIdx])
		rest := strings.TrimSpace(line[colonIdx+1:])
		fields := strings.Fields(rest)
		for i, f := range fields {
			switch f {
			case "lookup":
				if i+1 < len(fields) {
					r.Table = fields[i+1]
					r.Action = "lookup"
				}
			case "from":
				if i+1 < len(fields) {
					r.Selector = "from " + fields[i+1]
				}
			case "fwmark":
				if i+1 < len(fields) {
					r.FWMark = fields[i+1]
				}
			}
		}
		if r.Selector == "" {
			r.Selector = rest
		}
	}
	return r
}
