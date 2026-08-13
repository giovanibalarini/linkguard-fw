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

// ─── Grupo restrito a conexões novas na Visão geral ──────────────────────

// liveRulesetWithCtStateNewJumps é saída REAL do `nft -a list table inet
// linkguard` (nftables v1.1.3), capturada num namespace de rede isolado
// (`unshare -rn`) depois de aplicar as linhas que groupJumpTokens emite —
// não a renderização dos nossos próprios tokens, que esconderia justamente
// a classe de bug que este arquivo existe para pegar.
//
// Ela cobre os quatro casos que a Visão geral precisa saber descrever: jump
// restrito com condição (forward), jump irrestrito (forward), jump restrito
// SEM condição nenhuma (input) e jump restrito com condição composta
// (input).
const liveRulesetWithCtStateNewJumps = `table inet linkguard { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		ct state new counter packets 0 bytes 0 jump grp_aaa # handle 7
		iifname "enp5s0" ip saddr 10.0.0.0/8 ct state new counter packets 0 bytes 0 jump grp_bbb # handle 8
	}

	chain forward { # handle 2
		type filter hook forward priority filter; policy accept;
		ip saddr 192.168.50.0/24 ct state new counter packets 0 bytes 0 jump grp_aaa # handle 5
		ip saddr 192.168.60.0/24 counter packets 0 bytes 0 jump grp_bbb # handle 6
	}

	chain grp_aaa { # handle 3
	}

	chain grp_bbb { # handle 4
	}
}
`

// A linha de um grupo "só conexões novas" tem que sair da Visão geral em
// português, dizendo o que muda para o admin: o que já está de pé não passa
// por ali. `ct state new` cru na descrição seria a única linha da tela que o
// admin não pediu, não pode editar e ainda por cima não entende — o mesmo
// defeito que o texto do `ct state related` corrigiu na chain input.
func TestApplyGroupNamesSaysNewConnectionsOnlyInPortuguese(t *testing.T) {
	chains := parseTableRuleset(liveRulesetWithCtStateNewJumps)
	ApplyGroupNames(chains, map[string]string{"grp_aaa": "Wi-Fi visitantes", "grp_bbb": "Convidados"})

	var forward ChainInfo
	for _, c := range chains {
		if c.Name == ForwardChain {
			forward = c
		}
	}
	got := forward.Rules[0].Description
	if !containsAll(got, `"Wi-Fi visitantes"`, "192.168.50.0/24", "só para conexões novas") {
		t.Errorf("a linha restrita tem que nomear o grupo, a condição e a restrição, obtive %q", got)
	}
	if strings.Contains(got, "ct state") {
		t.Errorf("a descrição é prosa: a sintaxe nft já aparece na coluna da expressão, obtive %q", got)
	}
}

// Grupo restrito SEM condição de entrada: dizer "vale para todo o tráfego
// que chegar ali" seria falso — o tráfego já estabelecido passa reto sem ser
// avaliado. Este é o caso em que o texto antigo não só ficava incompleto,
// mas mentia.
func TestApplyGroupNamesNewOnlyWithoutConditionDoesNotClaimAllTraffic(t *testing.T) {
	chains := parseTableRuleset(liveRulesetWithCtStateNewJumps)
	ApplyGroupNames(chains, map[string]string{"grp_aaa": "Acesso ao firewall", "grp_bbb": "Convidados"})

	var input ChainInfo
	for _, c := range chains {
		if c.Name == InputChain {
			input = c
		}
	}
	got := input.Rules[0].Description
	if !containsAll(got, `"Acesso ao firewall"`, "só para conexões novas") {
		t.Errorf("o jump restrito sem condição não foi descrito: %q", got)
	}
	if strings.Contains(got, "todo o tráfego") {
		t.Errorf("com ct state new o grupo NÃO vale para todo o tráfego que chegar ali: %q", got)
	}
	if strings.Contains(got, "ct state") {
		t.Errorf("a descrição é prosa, obtive %q", got)
	}

	// E a condição composta continua inteira na descrição, sem o ct state
	// vazar junto.
	composed := input.Rules[1].Description
	if !containsAll(composed, `"Convidados"`, "enp5s0", "10.0.0.0/8", "só para conexões novas") {
		t.Errorf("condição composta perdeu pedaço: %q", composed)
	}
	if strings.Contains(composed, "ct state") {
		t.Errorf("a descrição é prosa, obtive %q", composed)
	}
}

// E o contrapeso: o grupo que vale para toda conexão — todo grupo que já
// existe — não pode ganhar o aviso. Aviso que aparece em tudo é aviso que
// ninguém lê, e aqui ele diria uma coisa que a linha não faz.
func TestApplyGroupNamesPlainGroupNeverMentionsNewConnectionsOnly(t *testing.T) {
	chains := parseTableRuleset(liveRulesetWithCtStateNewJumps)
	ApplyGroupNames(chains, map[string]string{"grp_aaa": "Wi-Fi visitantes", "grp_bbb": "Convidados"})

	for _, c := range chains {
		if c.Name != ForwardChain {
			continue
		}
		got := c.Rules[1].Description
		if strings.Contains(got, "conexões novas") {
			t.Errorf("grupo de toda conexão ganhou o aviso de conexões novas: %q", got)
		}
		if !containsAll(got, `"Convidados"`, "192.168.60.0/24") {
			t.Errorf("a linha de sempre mudou de descrição: %q", got)
		}
	}
}

// ctStateNewExpr é lido por group_names.go para achar (e tirar da condição) o
// que groupJumpTokens emite. Se os dois divergirem, o `ct state new` volta a
// vazar cru para a descrição — e o teste que pegaria isso é este, não o de
// renderização, porque cada um sozinho continuaria verde.
func TestCtStateNewExprIsExactlyWhatTheJumpEmits(t *testing.T) {
	toks, err := groupJumpTokens(StoredGroup{
		ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
		ConnState: ConnStateNew,
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !strings.Contains(strings.Join(toks, " "), ctStateNewExpr) {
		t.Errorf("a linha emitida %q não contém %q", strings.Join(toks, " "), ctStateNewExpr)
	}
}
