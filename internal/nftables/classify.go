package nftables

import (
	"fmt"
	"regexp"
	"strings"
)

// RuleOwner identifies which higher-level LinkGuard control produced a
// managed rule, so the panel can offer "this rule comes from X → open" (see
// the design spec, §2). Both fields are empty for an admin-owned rule (a
// chain isAdminRuleChain recognises). Key is also empty — Label still isn't —
// for a managed rule this package does not specifically recognise: better an
// honest generic "gerenciado pelo LinkGuard" than a guessed, possibly wrong,
// owner.
type RuleOwner struct {
	Key   string `json:"key,omitempty"`
	Label string `json:"label"`
}

// isAdminRuleChain reports whether chain holds rules the ADMIN wrote, as
// opposed to rules LinkGuard derives from a higher-level control. Since the
// Fase C1 migration that means every group chain (GroupChainPrefix) — the
// legacy user_rules is still listed because a box that has not migrated yet
// (or one being read from an old snapshot) must not have its rules suddenly
// reclassified as LinkGuard's.
//
// The prefix is matched exactly as reconciliation matches it to decide which
// chains are its own to delete: loosening it here would call "the admin's"
// something that isn't, the one mistake classifyRule must never make.
func isAdminRuleChain(chain string) bool {
	return chain == UserChain || strings.HasPrefix(chain, GroupChainPrefix)
}

// classifyRule decides whether a rule is managed by LinkGuard (derived from
// a higher-level control, reconciled, not hand-editable here) or the admin's
// own (an isAdminRuleChain chain — the only ones this ever returns
// managed=false for). Every other chain, known or not, is LinkGuard's, so
// an unrecognised rule still reports managed=true with a generic owner —
// the one thing this function must never do is call something the admin's
// when it isn't.
//
// C-2: the group chains had to be added here, not just to user_rules. A rule
// read from the live grp_ chain and the synthetic entry MergeUserRules builds
// for its disabled sibling are the same admin's rules, in the same group;
// classifying them differently made a single group's list contradict itself,
// and offered "this rule comes from LinkGuard" for a rule the admin typed.
func classifyRule(chain, expr string) (managed bool, owner RuleOwner) {
	const genericLabel = "LinkGuard"

	if isAdminRuleChain(chain) {
		return false, RuleOwner{}
	}

	switch chain {
	case masqueradeChain: // postrouting
		return true, RuleOwner{Key: "nat", Label: "NAT (WANs)"}
	case MarkHostsChain:
		return true, RuleOwner{Key: "wan_steering", Label: "Direcionamento por WAN"}
	case InputChain: // input
		if strings.Contains(expr, "dport 123") {
			return true, RuleOwner{Key: "ntp", Label: "NTP"}
		}
		return true, RuleOwner{Label: genericLabel}
	case ForwardChain:
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
	// C-2: an admin rule reads the same in plain Portuguese wherever it lives
	// — the group chain it lives in today, or the legacy user_rules. Leaving
	// the grp_ chains out let the raw nft expression through as the
	// "description" for exactly the rules the panel most needs to explain.
	if isAdminRuleChain(chain) {
		return describeUserRuleExpression(expr)
	}

	switch chain {
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

	case ForwardChain:
		switch {
		case expr == "jump user_rules":
			return "Avalia as regras personalizadas do admin antes dos bloqueios"
		// saddr e daddr são regras distintas (uma para cada sentido), e
		// precisam de textos distintos: descrever as duas igual faz o par
		// legítimo parecer a duplicação de chain que motivou esta tela
		// (spec §1) — justamente o defeito que ela existe para o admin
		// conseguir enxergar.
		case strings.Contains(expr, "@blocked_hosts"):
			if strings.Contains(expr, "ip daddr") {
				return "Descarta tráfego indo para hosts bloqueados"
			}
			return "Descarta tráfego vindo de hosts bloqueados"
		case strings.Contains(expr, "@blocklist"):
			if strings.Contains(expr, "ip daddr") {
				return "Descarta tráfego indo para destinos bloqueados"
			}
			return "Descarta tráfego vindo de destinos bloqueados"
		}

	case MarkHostsChain:
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
