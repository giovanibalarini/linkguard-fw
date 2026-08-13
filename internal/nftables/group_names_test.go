package nftables

import (
	"strings"
	"testing"
)

// ─── ApplyGroupNames ────────────────────────────────────────────────────────
//
// describeRule stays a pure function of (chain, expression): it has no way
// to know a group's admin-given name, and giving it one would mean threading
// a groupNames map through parseChainRuleLine → parseTableRuleset →
// ListRuleset — a chain also used by reconciliation's orphan-chain cleanup,
// which has no group name to give it. ApplyGroupNames is a small,
// independent post-processing pass instead: it takes chains already parsed
// by ListRuleset/parseTableRuleset and rewrites the description of any
// forward-chain "jump to a group chain" rule to name the group, using a
// chain→name map the caller (the Overview handler) builds from
// db.ListFirewallGroups().

func TestApplyGroupNamesNamesTheGroupAndItsCondition(t *testing.T) {
	chains := []ChainInfo{{
		Name: ForwardChain,
		Rules: []ChainRule{
			{Chain: ForwardChain, Expression: "ip saddr 192.168.50.0/24 jump grp_a3f21c08", Description: "ip saddr 192.168.50.0/24 jump grp_a3f21c08"},
		},
	}}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Wi-Fi visitantes"})

	got := chains[0].Rules[0].Description
	if !containsAll(got, `"Wi-Fi visitantes"`, "192.168.50.0/24") {
		t.Errorf("descrição tem que nomear o grupo e dizer quando ele é avaliado, obtive %q", got)
	}
}

func TestApplyGroupNamesNoConditionSaysItAppliesToAllTraffic(t *testing.T) {
	chains := []ChainInfo{{
		Name: ForwardChain,
		Rules: []ChainRule{
			{Chain: ForwardChain, Expression: "jump grp_a3f21c08", Description: "jump grp_a3f21c08"},
		},
	}}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Convidados"})

	got := chains[0].Rules[0].Description
	if !containsAll(got, `"Convidados"`, "todo") {
		t.Errorf("grupo sem condição tem que deixar claro que vale para todo o tráfego que chegar ali, obtive %q", got)
	}
}

// TestApplyGroupNamesUnknownGroupFallsBackToRawChainName covers a group
// deleted between the DB read and the nft read: never invent a name, never
// show blank — the raw chain name is the one honest thing left to show
// (project rule: no fake data in the UI).
func TestApplyGroupNamesUnknownGroupFallsBackToRawChainName(t *testing.T) {
	chains := []ChainInfo{{
		Name: ForwardChain,
		Rules: []ChainRule{
			{Chain: ForwardChain, Expression: "jump grp_desconhecido", Description: "jump grp_desconhecido"},
		},
	}}
	ApplyGroupNames(chains, map[string]string{})

	got := chains[0].Rules[0].Description
	if !containsAll(got, "grp_desconhecido") {
		t.Errorf("sem nome conhecido, mostrar a chain crua; obtive %q", got)
	}
}

// TestApplyGroupNamesTolerantOfLeftoverCounterWord: the production path
// (parseChainRuleLine) always strips "counter packets N bytes M" whole, so
// the literal word "counter" should never reach here — but the condition
// parsing must not break if it somehow does (defensive, matches the brief).
func TestApplyGroupNamesTolerantOfLeftoverCounterWord(t *testing.T) {
	chains := []ChainInfo{{
		Name: ForwardChain,
		Rules: []ChainRule{
			{Chain: ForwardChain, Expression: "ip saddr 192.168.50.0/24 counter jump grp_a3f21c08", Description: "x"},
		},
	}}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Wi-Fi visitantes"})

	got := chains[0].Rules[0].Description
	if !containsAll(got, `"Wi-Fi visitantes"`, "192.168.50.0/24") {
		t.Errorf("a palavra 'counter' avulsa não pode vazar para a descrição nem quebrar o parsing, obtive %q", got)
	}
	if containsAll(got, " counter ") {
		t.Errorf("a palavra 'counter' não pode sobrar dentro da descrição, obtive %q", got)
	}
}

// TestApplyGroupNamesLeavesOtherForwardRulesAlone proves the pass only
// touches jump-to-group lines: the jump to user_rules and the blocklist
// drops must come out exactly as parsed.
func TestApplyGroupNamesLeavesOtherForwardRulesAlone(t *testing.T) {
	chains := []ChainInfo{{
		Name: ForwardChain,
		Rules: []ChainRule{
			{Chain: ForwardChain, Expression: "jump user_rules", Description: "Avalia as regras personalizadas do admin antes dos bloqueios"},
			{Chain: ForwardChain, Expression: "ip daddr @blocklist drop", Description: "Descarta tráfego indo para destinos bloqueados"},
		},
	}}
	before := make([]string, len(chains[0].Rules))
	for i, r := range chains[0].Rules {
		before[i] = r.Description
	}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Wi-Fi visitantes"})
	for i, r := range chains[0].Rules {
		if r.Description != before[i] {
			t.Errorf("regra %d sem jump para grupo não podia mudar: antes %q, depois %q", i, before[i], r.Description)
		}
	}
}

// TestApplyGroupNamesLeavesOtherChainsAlone proves the pass is scoped to the
// forward chain — the only chain where a group jump ever legitimately lives.
func TestApplyGroupNamesLeavesOtherChainsAlone(t *testing.T) {
	chains := []ChainInfo{{
		Name: UserChain,
		Rules: []ChainRule{
			{Chain: UserChain, Expression: "jump grp_a3f21c08", Description: "jump grp_a3f21c08"},
		},
	}}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Wi-Fi visitantes"})
	if chains[0].Rules[0].Description != "jump grp_a3f21c08" {
		t.Errorf("chains fora de forward não devem ser reescritas, obtive %q", chains[0].Rules[0].Description)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// Both ApplyGroupNames and MergeGroups locate the jump target with
// strings.LastIndex, and their comments promise the two never disagree —
// but no fixture had "jump " appearing more than once, so swapping either
// one to strings.Index went unnoticed. Pin it: the target is the LAST jump
// on the line, and both functions must agree on that for the same input.
func TestJumpTargetIsTheLastJumpOnTheLine(t *testing.T) {
	expr := `ip saddr 10.0.0.0/8 comment "jump antigo" counter jump grp_realalvo1`

	chains := []ChainInfo{{Name: ForwardChain, Rules: []ChainRule{{Expression: expr}}}}
	ApplyGroupNames(chains, map[string]string{"grp_realalvo1": "Certo", "grp_antigo": "Errado"})
	if !strings.Contains(chains[0].Rules[0].Description, "Certo") {
		t.Errorf("ApplyGroupNames pegou o jump errado: %q", chains[0].Rules[0].Description)
	}

	// MergeGroups tem que enxergar o mesmo alvo, ou uma das duas erra num
	// caso que a outra acerta.
	views := MergeGroups(
		[]StoredGroup{{ID: "a", Name: "Certo", ChainName: "grp_realalvo1", Enabled: true}},
		map[string]ChainInfo{},
		ChainInfo{Name: ForwardChain, Rules: []ChainRule{{Expression: expr, Handle: 7}}},
	)
	if !views[0].Applied {
		t.Error("MergeGroups não enxergou o mesmo alvo de jump que ApplyGroupNames")
	}
}

// M-1. Desde a Fase C2 o jump de um grupo também mora na chain input, e é a
// mesma linha renderizada pelo mesmo código. Sem varrer a input, o admin lia
// o jump da forward em português e o da input em sintaxe nft crua.
func TestApplyGroupNamesAlsoNamesTheJumpsInTheInputChain(t *testing.T) {
	chains := []ChainInfo{
		{Name: InputChain, Rules: []ChainRule{
			{Expression: "udp dport 123 drop", Description: "Bloqueia NTP de qualquer outra origem"},
			{Expression: "ip saddr 192.168.50.0/24 jump grp_a3f21c08", Description: "ip saddr 192.168.50.0/24 jump grp_a3f21c08"},
		}},
	}
	ApplyGroupNames(chains, map[string]string{"grp_a3f21c08": "Acesso ao firewall"})

	if !containsAll(chains[0].Rules[1].Description, "Acesso ao firewall", "192.168.50.0/24") {
		t.Errorf("o jump na chain input não foi nomeado: %q", chains[0].Rules[1].Description)
	}
	// E nenhuma outra linha da input é tocada.
	if chains[0].Rules[0].Description != "Bloqueia NTP de qualquer outra origem" {
		t.Errorf("uma linha que não é jump de grupo foi reescrita: %q", chains[0].Rules[0].Description)
	}
}
