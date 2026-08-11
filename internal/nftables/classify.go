package nftables

import (
	"fmt"
	"regexp"
	"strings"
)

// RuleOwner identifies which higher-level LinkGuard control produced a
// managed rule, so the panel can offer "this rule comes from X → open" (see
// the design spec, §2). Both fields are empty for an admin-owned rule
// (chain user_rules). Key is also empty — Label still isn't — for a managed
// rule this package does not specifically recognise: better an honest
// generic "gerenciado pelo LinkGuard" than a guessed, possibly wrong, owner.
type RuleOwner struct {
	Key   string `json:"key,omitempty"`
	Label string `json:"label"`
}

// classifyRule decides whether a rule is managed by LinkGuard (derived from
// a higher-level control, reconciled, not hand-editable here) or the
// admin's own (chain user_rules — the only chain this ever returns
// managed=false for). Every other chain, known or not, is LinkGuard's, so
// an unrecognised rule still reports managed=true with a generic owner —
// the one thing this function must never do is call something the admin's
// when it isn't.
func classifyRule(chain, expr string) (managed bool, owner RuleOwner) {
	const genericLabel = "LinkGuard"

	switch chain {
	case UserChain:
		return false, RuleOwner{}
	case masqueradeChain: // postrouting
		return true, RuleOwner{Key: "nat", Label: "NAT (WANs)"}
	case "mark_hosts":
		return true, RuleOwner{Key: "wan_steering", Label: "Direcionamento por WAN"}
	case InputChain: // input
		if strings.Contains(expr, "dport 123") {
			return true, RuleOwner{Key: "ntp", Label: "NTP"}
		}
		return true, RuleOwner{Label: genericLabel}
	case "forward":
		switch {
		case strings.Contains(expr, "@blocked_hosts"):
			return true, RuleOwner{Key: "host_block", Label: "Hosts bloqueados"}
		case strings.Contains(expr, "@blocklist"):
			return true, RuleOwner{Key: "blocklist", Label: "Destinos bloqueados"}
		default: // the `jump user_rules` line itself, or anything future
			return true, RuleOwner{Label: genericLabel}
		}
	case DNATChain: // prerouting_dnat
		return true, RuleOwner{Key: "port_forward", Label: "Encaminhamento de porta"}
	default: // an unrecognised chain — still LinkGuard's, never the admin's
		return true, RuleOwner{Label: genericLabel}
	}
}

var (
	reOifnameSet = regexp.MustCompile(`oifname (\{[^}]*\}|"[^"]*"|\S+)`)
	reSaddrSet   = regexp.MustCompile(`ip saddr (\{[^}]*\}|"[^"]*"|\S+)`)
	reDNATRule   = regexp.MustCompile(`^(?:iifname \S+ )?(tcp|udp) dport (\d+) dnat ip to ([0-9.]+):(\d+)$`)
)

// extractSetText renders an nft set/token — `{ "a", "b" }`, a single quoted
// token, or a bare token like a CIDR — as a comma-separated, unquoted,
// human-readable list ("a, b" / "a" / "192.168.3.0/24").
func extractSetText(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

// describeRule produces a plain-Portuguese, human description of a parsed
// rule expression (design spec §3: "linguagem de gente ao lado da sintaxe
// nft"), chain-aware because the same syntax means different things in
// different chains. It is a pure function of (chain, expression) so it is
// trivially unit-testable, and it deliberately falls back to the raw
// expression for anything it doesn't specifically recognise — better honest
// than a wrong guess.
func describeRule(chain, expr string) string {
	switch chain {
	case UserChain:
		return describeUserRuleExpression(expr)

	case masqueradeChain: // postrouting
		if strings.Contains(expr, "masquerade") {
			if m := reOifnameSet.FindStringSubmatch(expr); m != nil {
				return "Mascara saída pelas WANs " + extractSetText(m[1])
			}
		}

	case InputChain: // input
		if strings.Contains(expr, "udp dport 123") {
			switch {
			case strings.HasSuffix(expr, "accept"):
				if m := reSaddrSet.FindStringSubmatch(expr); m != nil {
					return "Aceita NTP vindo de " + extractSetText(m[1])
				}
				return "Aceita NTP"
			case strings.HasSuffix(expr, "drop"):
				return "Bloqueia NTP de qualquer outra origem"
			}
		}

	case "forward":
		switch {
		case expr == "jump user_rules":
			return "Avalia as regras personalizadas do admin antes dos bloqueios"
		case strings.Contains(expr, "@blocked_hosts"):
			return "Descarta tráfego de/para hosts bloqueados"
		case strings.Contains(expr, "@blocklist"):
			return "Descarta tráfego de/para destinos bloqueados"
		}

	case "mark_hosts":
		if strings.Contains(expr, "map @host_wan") {
			return "Marca o host de origem com a WAN definida em Direcionamento por WAN"
		}

	case DNATChain: // prerouting_dnat
		if m := reDNATRule.FindStringSubmatch(expr); m != nil {
			proto, extPort, destIP, destPort := m[1], m[2], m[3], m[4]
			return fmt.Sprintf("Encaminha %s/%s para %s:%s", strings.ToUpper(proto), extPort, destIP, destPort)
		}
	}

	return expr // unrecognised: honest raw expression, never a wrong guess
}

// describeUserRuleExpression describes an admin rule (chain user_rules) by
// re-parsing it with parseRuleFields — the same best-effort parser the
// rule-edit modal already relies on to pre-fill its form — rather than
// duplicating field extraction here.
func describeUserRuleExpression(expr string) string {
	f := parseRuleFields(expr)

	verb := "Regra"
	switch strings.ToLower(f.Action) {
	case "accept":
		verb = "Permite"
	case "drop":
		verb = "Bloqueia"
	case "reject":
		verb = "Rejeita"
	}

	var parts []string
	if f.Iif != "" {
		parts = append(parts, "entrada "+f.Iif)
	}
	if f.Oif != "" {
		parts = append(parts, "saída "+f.Oif)
	}
	if f.Saddr != "" {
		parts = append(parts, "origem "+f.Saddr)
	}
	if f.Daddr != "" {
		parts = append(parts, "destino "+f.Daddr)
	}
	if f.Proto != "" {
		p := strings.ToUpper(f.Proto)
		if f.Dport != "" {
			p += ":" + f.Dport
		}
		parts = append(parts, p)
	}

	if len(parts) == 0 {
		return verb + " qualquer tráfego"
	}
	return verb + " " + strings.Join(parts, ", ")
}
