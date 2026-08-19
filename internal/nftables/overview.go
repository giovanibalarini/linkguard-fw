package nftables

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ChainInfo describes one chain of `table inet linkguard` — its hook
// properties (populated only for base chains, ones with a `type ... hook
// ...` declaration; a regular chain like user_rules, only ever reached via
// `jump`, has none) and its rules, in the order nft prints them.
type ChainInfo struct {
	Name     string      `json:"name"`
	Type     string      `json:"type,omitempty"`
	Hook     string      `json:"hook,omitempty"`
	Priority string      `json:"priority,omitempty"`
	Policy   string      `json:"policy,omitempty"`
	Rules    []ChainRule `json:"rules"`
}

// ChainRule is a single rule inside a chain: its handle, the raw nft
// expression (handle comment and counter clause stripped out), and — only
// when the rule was created with `counter` — its packet/byte totals.
//
// HasCounter is deliberately its own field rather than defaulting
// Packets/Bytes to 0: a rule with no counter ("not measured") and a rule
// whose counter genuinely reads 0 ("measured zero") are different states,
// and collapsing them would silently lie to whoever is reading the panel
// (see the design spec, §3.1).
type ChainRule struct {
	Chain      string `json:"chain"`
	Handle     int    `json:"handle"`
	Expression string `json:"expression"`
	HasCounter bool   `json:"has_counter"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`

	// Managed and Owner classify the rule's origin (design spec §2): a rule
	// is either managed by LinkGuard (derived from a higher-level control,
	// reconciled, not hand-editable here) or the admin's own (chain
	// user_rules — the only chain classifyRule ever calls unmanaged).
	// Description is a plain-Portuguese rendering of Expression for the UI.
	// All three are populated by classifyRule/describeRule in classify.go.
	Managed     bool      `json:"managed"`
	Owner       RuleOwner `json:"owner"`
	Description string    `json:"description"`
	// Desc é a mesma descrição em forma estruturada (issue #109): uma chave e
	// as variáveis dela. Description continua sendo a frase pronta em
	// português, para log, auditoria e quem consome a API; Desc é o que
	// permite ao painel dizer a mesma coisa no idioma de quem está olhando.
	// Chave vazia = não sei descrever, e a tela cai na Description.
	Desc RuleDesc `json:"desc"`

	// ID and Enabled are only ever populated for the user_rules chain, by
	// MergeUserRules (Phase B, design spec §4.1) — every other chain leaves
	// both zero-valued (Enabled nil). ID is the stable DB id, immune to a
	// volatile nft handle changing on every recreation; Enabled is a pointer
	// specifically so "not applicable" (nil, any managed chain) can never be
	// confused with "disabled" (false) — a disabled rule must never look like
	// an active one, nor should an unrelated rule look like it has a
	// disable state at all.
	ID      string `json:"id,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`

	// Applied is C-3's distinct third state: "configured (Enabled=true) but
	// not actually in effect in nft" — never conflated with Enabled=true
	// meaning "in effect", which was the bug (MergeUserRules used to stamp
	// Enabled=true on a DB rule with no live counterpart at all, so the
	// panel — the only surface an admin has to verify what the firewall
	// really does — asserted a rule was active when nft never accepted it).
	// Populated true for every rule actually read from the live table
	// (parseChainRuleLine) and for a user_rules entry MergeUserRules paired
	// to a live rule by identity (I-4); left false for a disabled rule
	// (by design — it was never sent to nft) and for an enabled DB rule
	// MergeUserRules could not find a matching live counterpart for.
	// Meaningful only where Enabled is non-nil (user_rules); irrelevant
	// elsewhere, where it defaults true along with every other rule read
	// straight off the live table.
	Applied bool `json:"applied"`
}

var (
	reChainHeader    = regexp.MustCompile(`^chain (\S+) \{`)
	reTypeLine       = regexp.MustCompile(`^type (\S+) hook (\S+) priority ([^;]+);\s*policy (\S+);`)
	reCounterCapture = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
)

// ListRuleset returns every chain of `table inet linkguard` — the structural
// ones LinkGuard manages (postrouting, input, mark_hosts, forward,
// prerouting_dnat) as well as the admin's user_rules — with every rule's
// handle, raw expression and counters, in nft's own output order. It is
// read-only: unlike ListUserRules (which targets a single chain for the
// existing rule-editing UI), this powers the unified firewall overview.
//
// Parsed from `nft -a list table inet linkguard`: the `-a` flag is what
// stamps each rule line with a stable `# handle N`, without which a rule
// could not be told apart from any other with the same expression (e.g. the
// forward chain's two `@blocked_hosts` drops, one by saddr and one by
// daddr, would otherwise be indistinguishable to a caller that needs to
// address one of them).
func (s *Service) ListRuleset(ctx context.Context) ([]ChainInfo, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "-a", "list", "table", Family, Table)
	if err != nil {
		return nil, err
	}
	return parseTableRuleset(out), nil
}

// parseTableRuleset is the pure parser behind ListRuleset, kept separate so
// it can be exercised directly against captured `nft ... list table` text
// without a live nft binary. It reuses the same handle convention as
// ListUserRules (the reHandle regex, `# handle N`) but — unlike that
// function, which only ever looks at the single user_rules chain and
// discards counters — walks every chain in the table and keeps counters.
//
// The table body has exactly three kinds of top-level block (map, set,
// chain); only chain blocks are walked into and turned into ChainInfo.
// map/set blocks (host_wan, blocklist, blocked_hosts) are skipped whole —
// their element-level view is Managed()'s job, not this one's. Every block
// in this table is flat (one level of nesting, no braces spanning multiple
// lines inside a block), including anonymous sets like `oifname { "a", "b"
// }` in a rule — that pair always opens and closes on the same line — so a
// block's end is unambiguously the first line that is exactly "}" once
// trimmed; no brace-depth counting is needed.
//
// Scope caveat: this parser has no notion of a table boundary — it walks
// every chain block it sees. All of its scoping comes from being fed `nft
// ... list table inet linkguard` by its callers. Switching any of them to
// `nft list ruleset` would silently hand it third-party chains, and
// listGroupChains (which decides what to DELETE, by name prefix) would
// start considering chains that are not ours.
func parseTableRuleset(out string) []ChainInfo {
	chains := []ChainInfo{}
	var cur *ChainInfo
	skippingBlock := false // inside a map/set body, which this function ignores

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		switch {
		case cur != nil: // inside a chain block
			if line == "}" {
				chains = append(chains, *cur)
				cur = nil
				continue
			}
			if m := reTypeLine.FindStringSubmatch(line); m != nil {
				cur.Type = m[1]
				cur.Hook = m[2]
				cur.Priority = strings.TrimSpace(m[3])
				cur.Policy = m[4]
				continue
			}
			cur.Rules = append(cur.Rules, parseChainRuleLine(cur.Name, line))

		case skippingBlock:
			if line == "}" {
				skippingBlock = false
			}

		default: // top level: directly inside `table inet linkguard { ... }`
			switch {
			case strings.HasPrefix(line, "table "):
				// the table's own opening line — nothing to record
			case line == "}":
				// the table's own closing line
			case reChainHeader.MatchString(line):
				m := reChainHeader.FindStringSubmatch(line)
				cur = &ChainInfo{Name: m[1], Rules: []ChainRule{}}
			case strings.HasPrefix(line, "map ") || strings.HasPrefix(line, "set "):
				skippingBlock = true
			}
		}
	}

	return chains
}

// parseChainRuleLine turns one rule line (handle comment and counter clause
// stripped out along the way) into a ChainRule.
func parseChainRuleLine(chainName, line string) ChainRule {
	// Applied: true — this rule was read straight off the live table, so by
	// definition it is in effect. MergeUserRules is the only place that
	// ever overrides this to false, for a user_rules row it could not
	// verify (see ChainRule.Applied's doc comment).
	rule := ChainRule{Chain: chainName, Applied: true}
	clean := line

	if hm := reHandle.FindStringSubmatch(clean); hm != nil {
		rule.Handle, _ = strconv.Atoi(hm[1])
		clean = reHandle.ReplaceAllString(clean, "")
	}
	if cm := reCounterCapture.FindStringSubmatch(clean); cm != nil {
		rule.HasCounter = true
		rule.Packets, _ = strconv.ParseUint(cm[1], 10, 64)
		rule.Bytes, _ = strconv.ParseUint(cm[2], 10, 64)
		clean = reCounterCapture.ReplaceAllString(clean, "")
	}
	rule.Expression = strings.Join(strings.Fields(clean), " ")
	rule.Managed, rule.Owner = classifyRule(chainName, rule.Expression)
	rule.Description = describeRule(chainName, rule.Expression)
	rule.Desc = descStructured(chainName, rule.Expression, !isAdminRuleChain(chainName))
	return rule
}
