// Package dnslog reads recent DNS queries from the unbound journal. Query
// logging is opt-in (the DNS "log_queries" setting toggles unbound's
// log-queries), so this returns nothing until an admin enables it — keeping the
// I/O cost off by default on busy resolvers.
package dnslog

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Query is one resolved DNS request parsed from the unbound log.
type Query struct {
	Time   string `json:"time"`
	Client string `json:"client"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

// Service reads the unbound journal.
type Service struct {
	exec firewall.Executor
}

// NewService creates a dnslog Service.
func NewService(exec firewall.Executor) *Service { return &Service{exec: exec} }

// Recent returns up to limit recent queries (most recent first), optionally
// filtered by a case-insensitive substring of the client IP or domain.
func (s *Service) Recent(ctx context.Context, limit int, filter string) ([]Query, error) {
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	// Pull extra lines because the journal interleaves non-query info lines.
	scan := strconv.Itoa(limit * 5)
	out, err := s.exec.ExecuteRead(ctx, "journalctl", "-u", "unbound",
		"-n", scan, "-o", "short-iso", "--no-pager")
	if err != nil {
		return nil, err
	}
	filter = strings.ToLower(strings.TrimSpace(filter))

	lines := strings.Split(out, "\n")
	queries := make([]Query, 0, limit)
	// Walk newest→oldest so the most recent matching queries are kept.
	for i := len(lines) - 1; i >= 0 && len(queries) < limit; i-- {
		q, ok := parseQueryLine(lines[i])
		if !ok {
			continue
		}
		if filter != "" &&
			!strings.Contains(strings.ToLower(q.Name), filter) &&
			!strings.Contains(q.Client, filter) {
			continue
		}
		queries = append(queries, q)
	}
	return queries, nil
}

// knownTypes guards against treating unbound's other "info:" lines as queries.
var knownTypes = map[string]bool{
	"A": true, "AAAA": true, "PTR": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "SRV": true, "HTTPS": true, "SVCB": true, "CAA": true,
	"DS": true, "DNSKEY": true, "NAPTR": true, "ANY": true,
}

// parseQueryLine extracts a Query from an unbound "log-queries" journal line.
// Expected tail form: "... info: <client-ip> <name>. <TYPE> <CLASS>".
func parseQueryLine(line string) (Query, bool) {
	idx := strings.Index(line, "info: ")
	if idx < 0 {
		return Query{}, false
	}
	ts := ""
	if f := strings.Fields(line); len(f) > 0 {
		ts = f[0] // journald short-iso timestamp
	}
	tail := strings.Fields(line[idx+len("info: "):])
	if len(tail) < 3 {
		return Query{}, false
	}
	if net.ParseIP(tail[0]) == nil {
		return Query{}, false
	}
	qtype := strings.ToUpper(tail[2])
	if !knownTypes[qtype] {
		return Query{}, false
	}
	return Query{
		Time:   ts,
		Client: tail[0],
		Name:   strings.TrimSuffix(tail[1], "."),
		Type:   qtype,
	}, true
}
