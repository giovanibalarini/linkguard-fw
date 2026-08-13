package nftables

import (
	"strings"
	"testing"
)

func TestGroupChainNameDerivesFromIDNotName(t *testing.T) {
	// O nome digitado nunca entra no nome da chain: renomear quebraria o
	// jump, e um nome com caractere especial viraria injeção no argv do nft.
	got := GroupChainName("a3f21c08-9d4e-4b1a-8c77-0e5b2d6f1a99")
	if got != "grp_a3f21c089d4e" {
		t.Fatalf("nome de chain inesperado: %q", got)
	}
	if strings.ContainsAny(got, " ;\"'`$&|") {
		t.Fatalf("nome de chain com caractere perigoso: %q", got)
	}
	// Determinístico entre chamadas.
	if GroupChainName("a3f21c08-9d4e-4b1a-8c77-0e5b2d6f1a99") != got {
		t.Fatal("GroupChainName não é determinístico")
	}
}

func TestGroupJumpTokensCarriesConditionAndCounter(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_abc123def456",
		CondIif: "enp0s3", CondSaddr: "192.168.50.0/24"}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	want := "iifname enp0s3 ip saddr 192.168.50.0/24 counter jump grp_abc123def456"
	if strings.Join(toks, " ") != want {
		t.Fatalf("jump inesperado:\n  obtive %q\n  queria %q", strings.Join(toks, " "), want)
	}
}

func TestGroupWithoutConditionJumpsUnconditionally(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_abc123def456"}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if strings.Join(toks, " ") != "counter jump grp_abc123def456" {
		t.Fatalf("grupo sem condição deveria pular incondicionalmente, obtive %q",
			strings.Join(toks, " "))
	}
}

func TestValidateGroupRejectsBadCondition(t *testing.T) {
	cases := []struct {
		name string
		g    StoredGroup
	}{
		{"origem IPv6", StoredGroup{Name: "g", CondSaddr: "2001:db8::1"}},
		{"origem lixo", StoredGroup{Name: "g", CondSaddr: "nao-e-ip"}},
		{"destino inválido", StoredGroup{Name: "g", CondDaddr: "999.1.1.1"}},
		{"interface com espaço", StoredGroup{Name: "g", CondIif: "eth0; rm -rf /"}},
		{"fallthrough desconhecido", StoredGroup{Name: "g", Fallthrough: "talvez"}},
		{"sem nome", StoredGroup{Name: "   "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateGroup(c.g); err == nil {
				t.Fatalf("esperava recusa para %+v", c.g)
			}
		})
	}
}

func TestRenderGroupChainAppendsFallthroughLine(t *testing.T) {
	rules := []StoredRule{
		{ID: "r1", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}},
		{ID: "r2", Position: 1, Enabled: false, Fields: RuleFields{Action: "drop", Proto: "udp", Dport: "53"}},
	}
	g := StoredGroup{ID: "x", ChainName: "grp_a", Fallthrough: FallthroughDrop, Rules: rules}

	sets, skipped := renderGroupChain(g)
	if len(skipped) != 0 {
		t.Fatalf("nada deveria ser pulado, obtive %v", skipped)
	}
	if len(sets) != 2 {
		t.Fatalf("esperava 1 regra ativada + 1 linha de fallthrough, obtive %d: %v", len(sets), sets)
	}
	if strings.Join(sets[0], " ") != "tcp dport 443 counter accept" {
		t.Errorf("regra renderizada errada: %q", strings.Join(sets[0], " "))
	}
	if strings.Join(sets[1], " ") != "counter drop" {
		t.Errorf("linha de fallthrough errada: %q", strings.Join(sets[1], " "))
	}
}

func TestRenderGroupChainContinueEmitsNoFinalLine(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_a", Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}
	sets, _ := renderGroupChain(g)
	if len(sets) != 1 {
		t.Fatalf("\"continuar\" não emite linha final; esperava 1 conjunto, obtive %d: %v", len(sets), sets)
	}
}

// The field order groupJumpTokens emits must match buildRuleTokens exactly.
// Both render text that is later compared against nft's own output to decide
// whether a rule/group is actually applied; a divergence here would make that
// comparison fail while nothing is actually wrong — the precise failure mode
// that shipped to production on 2026-08-11 and had to be caught in review.
// Every field is populated at once so a swap between ANY adjacent pair is
// caught, not just the pairs a partial fixture happens to exercise.
func TestGroupJumpTokensFieldOrderMatchesBuildRuleTokens(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_abc123def456",
		CondIif: "enp0s3", CondSaddr: "192.168.50.0/24", CondDaddr: "10.0.0.0/8"}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "iifname enp0s3 ip saddr 192.168.50.0/24 ip daddr 10.0.0.0/8 counter jump grp_abc123def456"
	if got := strings.Join(toks, " "); got != want {
		t.Fatalf("field order diverged from buildRuleTokens:\n  got  %q\n  want %q", got, want)
	}

	// Pin the order against buildRuleTokens itself rather than against a
	// hand-written string alone: if buildRuleTokens ever reorders its fields,
	// this fails and forces groupJumpTokens to follow, instead of the two
	// silently drifting apart.
	ruleToks, err := buildRuleTokens(RuleFields{
		Action: "accept", Iif: "enp0s3", Saddr: "192.168.50.0/24", Daddr: "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("buildRuleTokens: %v", err)
	}
	ruleExpr := strings.Join(ruleToks, " ")
	prefix := "iifname enp0s3 ip saddr 192.168.50.0/24 ip daddr 10.0.0.0/8"
	if !strings.HasPrefix(ruleExpr, prefix) {
		t.Fatalf("buildRuleTokens no longer emits %q first (%q) — groupJumpTokens must be updated to match",
			prefix, ruleExpr)
	}
}

// GroupChainName lowercases hex so the same id can never yield two different
// chain names depending on how the uuid happened to be cased.
func TestGroupChainNameLowercasesHex(t *testing.T) {
	if got := GroupChainName("A3F21C08-9D4E-4B1A-8C77-0E5B2D6F1A99"); got != "grp_a3f21c089d4e" {
		t.Fatalf("uppercase id produced %q", got)
	}
}

func TestIsSystemGroupRecognisesOnlyTheTwoBlockKinds(t *testing.T) {
	for _, k := range []string{GroupKindBlockedHosts, GroupKindBlocklist} {
		if !IsSystemGroup(k) {
			t.Errorf("%q é grupo do sistema", k)
		}
	}
	for _, k := range []string{GroupKindAdmin, "", "qualquer-outra-coisa"} {
		if IsSystemGroup(k) {
			t.Errorf("%q NÃO é grupo do sistema; tratá-lo como tal daria a ele proteções que o admin não pediu", k)
		}
	}
}

// A prova do m-3: IsSystemGroup e forwardChainRules leem o mesmo mapa
// (systemGroupForwardRules), então não existe mais um kind que IsSystemGroup
// reconheça como "do sistema" e forwardChainRules trate como admin — o
// cenário que a revisão apontou como risco futuro (um terceiro kind de
// sistema acrescentado só a um dos dois). Este teste acrescenta um kind
// hipotético ao mapa em tempo de execução e confirma que as duas funções o
// enxergam do mesmo jeito, sem precisar tocar em nenhuma delas.
func TestSystemGroupKindKnownToIsSystemGroupIsAlwaysRenderedAsSystem(t *testing.T) {
	const hypotheticalKind = "kind_de_sistema_hipotetico_para_teste"
	hypotheticalLine := []string{"ip", "saddr", "@hipotetico", "counter", "drop"}
	systemGroupForwardRules[hypotheticalKind] = func() [][]string {
		return [][]string{hypotheticalLine}
	}
	t.Cleanup(func() { delete(systemGroupForwardRules, hypotheticalKind) })

	if !IsSystemGroup(hypotheticalKind) {
		t.Fatal("IsSystemGroup devia reconhecer o kind hipotético recém-acrescentado ao mapa")
	}

	lines := forwardLines([]StoredGroup{{ID: "x", Kind: hypotheticalKind, Enabled: true, Position: 0}})
	if len(lines) != 1 || lines[0] != strings.Join(hypotheticalLine, " ") {
		t.Errorf("forwardChainRules devia renderizar o kind hipotético a partir do mesmo mapa que IsSystemGroup consulta, obtive %v", lines)
	}
}

// Kind vazio é o que toda linha antiga tem depois do ALTER TABLE. Ela é um
// grupo do admin, e confundir isso com "sistema" travaria a edição de grupos
// que o admin criou.
func TestValidateGroupAcceptsEmptyKindAsAdmin(t *testing.T) {
	g := StoredGroup{Name: "Meu grupo", Fallthrough: FallthroughContinue}
	if err := ValidateGroup(g); err != nil {
		t.Fatalf("grupo sem kind tem que valer como do admin: %v", err)
	}
}

// O nome de chain reservado dos grupos do sistema não pode, em nenhuma
// hipótese, passar por nome de chain de grupo do admin: a limpeza de órfãs de
// ReconcileGroups varre o ruleset pelo prefixo grp_ e apaga toda chain que não
// corresponda a um grupo do banco.
func TestSystemChainNamesAreNeverTakenForGroupChains(t *testing.T) {
	for _, name := range []string{SystemChainBlockedHosts, SystemChainBlocklist} {
		if strings.HasPrefix(name, GroupChainPrefix) {
			t.Errorf("%q usa o prefixo das chains de grupo do admin", name)
		}
		if validGroupChainName(name) {
			t.Errorf("%q é aceito como chain de grupo do admin; a limpeza de órfãs passaria a enxergá-lo", name)
		}
	}
	if SystemChainBlockedHosts == SystemChainBlocklist {
		t.Error("os dois grupos do sistema precisam de chain_name distintos (a coluna é UNIQUE)")
	}
}

// ─── Fase C2: escopo ─────────────────────────────────────────────────────

// Escopo desconhecido é recusado, e não normalizado em silêncio: um valor que
// este código não entende, tratado como forward, poria na chain de tráfego
// atravessando um grupo escrito para outra coisa.
func TestValidateGroupRejectsUnknownScope(t *testing.T) {
	g := StoredGroup{Name: "g", Fallthrough: FallthroughContinue, Scope: "output"}
	if err := ValidateGroup(g); err == nil {
		t.Fatal("esperava recusa para um escopo que não é forward nem input")
	}
}

func TestValidateGroupAcceptsTheThreeValidScopes(t *testing.T) {
	for _, scope := range []string{"", ScopeForward, ScopeInput} {
		g := StoredGroup{Name: "g", Fallthrough: FallthroughContinue, Scope: scope}
		if err := ValidateGroup(g); err != nil {
			t.Errorf("escopo %q tinha que ser aceito: %v", scope, err)
		}
	}
}

// Vazio é o valor de toda linha anterior à Fase C2, e todo grupo que existia
// é de tráfego atravessando o firewall.
func TestGroupScopeTreatsEmptyAsForward(t *testing.T) {
	if got := GroupScope(StoredGroup{}); got != ScopeForward {
		t.Errorf("escopo vazio tinha que valer como %q, obtive %q", ScopeForward, got)
	}
	if got := GroupScope(StoredGroup{Scope: ScopeInput}); got != ScopeInput {
		t.Errorf("escopo input não sobreviveu: %q", got)
	}
	// Qualquer coisa fora dos dois conhecidos cai em forward — ValidateGroup
	// é quem recusa o valor; aqui o que não pode acontecer é uma linha
	// estranha virar regra de input por acidente.
	if got := GroupScope(StoredGroup{Scope: "output"}); got != ScopeForward {
		t.Errorf("escopo desconhecido tinha que cair em %q, obtive %q", ScopeForward, got)
	}
}

// ─── Estado da conexão: o grupo que vale só para conexões novas ──────────

// A linha de jump ganha `ct state new` DEPOIS da condição de entrada e ANTES
// do counter. A posição não é estética: a condição de entrada é o que decide
// se o grupo é sequer considerado, e o counter tem que contar o que
// efetivamente saltou para dentro da chain do grupo.
func TestNewOnlyGroupCarriesCtStateOnTheJump(t *testing.T) {
	g := StoredGroup{
		ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
		CondSaddr: "192.168.50.0/24", ConnState: ConnStateNew,
	}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	got := strings.Join(toks, " ")
	want := "ip saddr 192.168.50.0/24 ct state new counter jump grp_aaa"
	if got != want {
		t.Errorf("\n  obtive %q\n  queria %q", got, want)
	}
}

// A garantia que protege toda máquina que já existe: sem a escolha, a linha é
// exatamente a de antes. Se este teste quebrar, um upgrade muda o firewall de
// alguém sem que ninguém tenha pedido.
func TestDefaultGroupEmitsTheExactLineItAlwaysDid(t *testing.T) {
	for _, cs := range []string{"", ConnStateAny} {
		g := StoredGroup{
			ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
			CondSaddr: "192.168.50.0/24", ConnState: cs,
		}
		toks, err := groupJumpTokens(g)
		if err != nil {
			t.Fatalf("conn_state=%q: erro inesperado: %v", cs, err)
		}
		got := strings.Join(toks, " ")
		want := "ip saddr 192.168.50.0/24 counter jump grp_aaa"
		if got != want {
			t.Errorf("conn_state=%q:\n  obtive %q\n  queria %q", cs, got, want)
		}
		if strings.Contains(got, "ct state") {
			t.Errorf("conn_state=%q: vazou ct state para o padrão: %q", cs, got)
		}
	}
}

// Um grupo sem condição de entrada nenhuma continua sendo um jump
// incondicional — só que restrito a conexões novas. Sem este caso, uma
// implementação que pendurasse o `ct state` na última condição escrita (em vez
// de emiti-lo sempre) passaria no teste de cima e sumiria com a restrição aqui,
// que é justo o grupo mais abrangente que existe.
func TestNewOnlyGroupWithoutConditionStillCarriesCtState(t *testing.T) {
	g := StoredGroup{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa",
		Enabled: true, ConnState: ConnStateNew}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	got := strings.Join(toks, " ")
	want := "ct state new counter jump grp_aaa"
	if got != want {
		t.Errorf("\n  obtive %q\n  queria %q", got, want)
	}
}

// Com as três condições escritas, `ct state new` continua entre a última
// delas e o counter — a ordem que o nft reimprime, e a que o classificador do
// painel vai ler.
func TestNewOnlyGroupKeepsCtStateAfterEveryCondition(t *testing.T) {
	g := StoredGroup{ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
		CondIif: "enp0s3", CondSaddr: "192.168.50.0/24", CondDaddr: "10.0.0.0/8",
		ConnState: ConnStateNew}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	got := strings.Join(toks, " ")
	want := "iifname enp0s3 ip saddr 192.168.50.0/24 ip daddr 10.0.0.0/8 ct state new counter jump grp_aaa"
	if got != want {
		t.Errorf("\n  obtive %q\n  queria %q", got, want)
	}
}

// Grupo do sistema (blocked_hosts, blocklist) é lista fechada e renderizado
// por um mapa próprio: bloqueio de host é justamente onde se quer a marreta —
// derrubar na hora inclusive o que já estava estabelecido.
func TestSystemGroupNeverGetsCtState(t *testing.T) {
	for _, kind := range []string{GroupKindBlockedHosts, GroupKindBlocklist} {
		g := StoredGroup{ID: "s", Kind: kind, Enabled: true, ConnState: ConnStateNew}
		for _, toks := range systemGroupForwardRules[g.Kind]() {
			if strings.Contains(strings.Join(toks, " "), "ct state") {
				t.Errorf("kind=%s: grupo do sistema não pode receber ct state", kind)
			}
		}
		// E o mesmo pela porta por onde a forward viva é PROCURADA, para que
		// as duas nunca divirjam sobre a forma da linha do sistema.
		for _, expr := range systemGroupExpressions(kind) {
			if strings.Contains(expr, "ct state") {
				t.Errorf("kind=%s: expressão procurada na forward viva não pode ter ct state: %q", kind, expr)
			}
		}
	}
}

// Valor desconhecido é recusado, e não normalizado em silêncio — mesmo
// raciocínio do escopo: um "established" gravado à mão e tratado como "any"
// aplicaria o grupo a um tráfego diferente do que está escrito na linha.
func TestValidateGroupRejectsUnknownConnState(t *testing.T) {
	for _, cs := range []string{"established", "New", "novo", "new,related"} {
		g := StoredGroup{Name: "g", Fallthrough: FallthroughContinue, ConnState: cs}
		if err := ValidateGroup(g); err == nil {
			t.Errorf("esperava recusa para conn_state %q", cs)
		}
	}
}

func TestValidateGroupAcceptsTheThreeValidConnStates(t *testing.T) {
	for _, cs := range []string{"", ConnStateAny, ConnStateNew} {
		g := StoredGroup{Name: "g", Fallthrough: FallthroughContinue, ConnState: cs}
		if err := ValidateGroup(g); err != nil {
			t.Errorf("conn_state %q tinha que ser aceito: %v", cs, err)
		}
	}
}

// Vazio é o valor de toda linha gravada antes desta coluna existir, e todo
// grupo que já existe vale para toda conexão.
func TestGroupConnStateTreatsEmptyAsAny(t *testing.T) {
	if got := GroupConnState(StoredGroup{}); got != ConnStateAny {
		t.Errorf("conn_state vazio tinha que valer como %q, obtive %q", ConnStateAny, got)
	}
	if got := GroupConnState(StoredGroup{ConnState: ConnStateNew}); got != ConnStateNew {
		t.Errorf("conn_state new não sobreviveu: %q", got)
	}
	// Qualquer coisa fora dos dois conhecidos cai em "any" — ValidateGroup é
	// quem recusa o valor; aqui o que não pode acontecer é uma linha estranha
	// virar restrição de estado por acidente, restringindo um grupo que o
	// admin escreveu para valer sempre.
	if got := GroupConnState(StoredGroup{ConnState: "established"}); got != ConnStateAny {
		t.Errorf("conn_state desconhecido tinha que cair em %q, obtive %q", ConnStateAny, got)
	}
}
