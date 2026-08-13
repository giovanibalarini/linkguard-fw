package nftables

import (
	"strings"
	"testing"
)

// ─── classifyRule ─────────────────────────────────────────────────────────

func TestClassifyRuleUserRulesIsNeverManaged(t *testing.T) {
	managed, owner := classifyRule(UserChain, "ip saddr 192.168.3.10 drop")
	if managed {
		t.Error("user_rules must never be reported as managed — it's the admin's own")
	}
	if owner.Key != "" || owner.Label != "" {
		t.Errorf("admin-owned rule must carry no owner, got %+v", owner)
	}
}

func TestClassifyRuleMasqueradeOwnedByNAT(t *testing.T) {
	managed, owner := classifyRule(masqueradeChain, `oifname { "enp2s0", "enp5s0" } masquerade`)
	if !managed {
		t.Error("postrouting masquerade must be managed")
	}
	if owner.Key != "nat" {
		t.Errorf("owner.Key = %q, want %q", owner.Key, "nat")
	}
	if owner.Label == "" {
		t.Error("owner.Label must not be empty for a recognised managed rule")
	}
}

func TestClassifyRuleMarkHostsOwnedByWanSteering(t *testing.T) {
	managed, owner := classifyRule("mark_hosts", "meta mark set ip saddr map @host_wan")
	if !managed {
		t.Error("mark_hosts must be managed")
	}
	if owner.Key != "wan_steering" {
		t.Errorf("owner.Key = %q, want %q", owner.Key, "wan_steering")
	}
}

func TestClassifyRuleInputNTPOwnedByNTP(t *testing.T) {
	managed, owner := classifyRule(InputChain, "udp dport 123 ip saddr 192.168.3.0/24 accept")
	if !managed || owner.Key != "ntp" {
		t.Errorf("expected managed=true owner.Key=ntp, got managed=%v owner=%+v", managed, owner)
	}
	managed, owner = classifyRule(InputChain, "udp dport 123 drop")
	if !managed || owner.Key != "ntp" {
		t.Errorf("drop counterpart must also be owned by ntp, got managed=%v owner=%+v", managed, owner)
	}
}

func TestClassifyRuleInputUnrecognisedFallsBackWithoutGuessing(t *testing.T) {
	managed, owner := classifyRule(InputChain, "tcp dport 22 accept")
	if !managed {
		t.Error("everything in the input chain (not user_rules) is LinkGuard's, even if unrecognised")
	}
	if owner.Key != "" {
		t.Errorf("must not guess a specific owner for an unrecognised rule, got key %q", owner.Key)
	}
	if owner.Label == "" {
		t.Error("fallback must still carry a generic label (e.g. LinkGuard), not be empty")
	}
}

func TestClassifyRuleForwardBlockedHostsOwnedByHostBlock(t *testing.T) {
	managed, owner := classifyRule("forward", "ip saddr @blocked_hosts drop")
	if !managed || owner.Key != "host_block" {
		t.Errorf("got managed=%v owner=%+v, want managed=true key=host_block", managed, owner)
	}
}

func TestClassifyRuleForwardBlocklistOwnedByBlocklist(t *testing.T) {
	managed, owner := classifyRule("forward", "ip daddr @blocklist drop")
	if !managed || owner.Key != "blocklist" {
		t.Errorf("got managed=%v owner=%+v, want managed=true key=blocklist", managed, owner)
	}
}

func TestClassifyRuleForwardJumpFallsBackWithoutGuessing(t *testing.T) {
	managed, owner := classifyRule("forward", "jump user_rules")
	if !managed {
		t.Error("the jump itself is LinkGuard's structure, not the admin's")
	}
	if owner.Key != "" {
		t.Errorf("must not assign a specific control to the jump line, got key %q", owner.Key)
	}
}

func TestClassifyRuleUnknownChainFallsBackManagedGeneric(t *testing.T) {
	managed, owner := classifyRule("some_future_chain", "ip saddr 10.0.0.0/8 accept")
	if !managed {
		t.Error("anything outside user_rules must default to managed=true (never guess it's the admin's)")
	}
	if owner.Key != "" {
		t.Errorf("unknown chain must not claim a specific owner key, got %q", owner.Key)
	}
	if owner.Label == "" {
		t.Error("unknown chain fallback must still carry a generic label")
	}
}

// ─── describeRule ─────────────────────────────────────────────────────────

func TestDescribeRuleNTPAcceptSingleNetwork(t *testing.T) {
	got := describeRule(InputChain, "udp dport 123 ip saddr 192.168.3.0/24 accept")
	want := "Aceita NTP vindo de 192.168.3.0/24"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// M-6 da revisão final: a fixture estava na ordem `{ 192.168.3.0/24,
// 10.20.0.0/24 }`, que o nft NUNCA imprime — ele ordena os elementos do set, e
// 10.20 vem antes de 192.168. Fixture que não é a saída do nft não prova nada
// sobre a linha que o painel vai receber dele. Mesma classe de defeito já
// corrigida em overview_test.go (M-2 daquela revisão).
func TestDescribeRuleNTPAcceptMultipleNetworks(t *testing.T) {
	got := describeRule(InputChain, "udp dport 123 ip saddr { 10.20.0.0/24, 192.168.3.0/24 } accept")
	want := "Aceita NTP vindo de 10.20.0.0/24, 192.168.3.0/24"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDescribeRuleNTPDrop(t *testing.T) {
	got := describeRule(InputChain, "udp dport 123 drop")
	want := "Bloqueia NTP de qualquer outra origem"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDescribeRuleMasquerade(t *testing.T) {
	got := describeRule(masqueradeChain, `oifname { "enp2s0", "enp5s0" } masquerade`)
	want := "Mascara saída pelas WANs enp2s0, enp5s0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDescribeRuleBlocklistDropMentionsBlockedDestinations(t *testing.T) {
	for _, expr := range []string{"ip daddr @blocklist drop", "ip saddr @blocklist drop"} {
		got := describeRule("forward", expr)
		if !strings.Contains(got, "destinos bloqueados") {
			t.Errorf("describeRule(%q) = %q, want it to mention 'destinos bloqueados'", expr, got)
		}
	}
}

func TestDescribeRuleBlockedHostsDropMentionsBlockedHosts(t *testing.T) {
	for _, expr := range []string{"ip saddr @blocked_hosts drop", "ip daddr @blocked_hosts drop"} {
		got := describeRule("forward", expr)
		if !strings.Contains(got, "hosts bloqueados") {
			t.Errorf("describeRule(%q) = %q, want it to mention 'hosts bloqueados'", expr, got)
		}
	}
}

func TestDescribeRuleJumpUserRulesIsHumanReadable(t *testing.T) {
	got := describeRule("forward", "jump user_rules")
	if got == "" || got == "jump user_rules" {
		t.Errorf("expected a translated description, got raw/empty: %q", got)
	}
}

func TestDescribeRuleMarkHostsMentionsWan(t *testing.T) {
	got := describeRule("mark_hosts", "meta mark set ip saddr map @host_wan")
	if !strings.Contains(strings.ToUpper(got), "WAN") {
		t.Errorf("expected description to mention WAN, got %q", got)
	}
}

func TestDescribeRulePortForward(t *testing.T) {
	got := describeRule(DNATChain, `iifname "enp2s0" tcp dport 8080 dnat ip to 192.168.1.10:80`)
	want := "Encaminha TCP/8080 para 192.168.1.10:80"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDescribeRuleUserRuleAcceptWithCriteria(t *testing.T) {
	got := describeRule(UserChain, "ip saddr 192.168.3.10 tcp dport 22 accept")
	if !strings.Contains(got, "192.168.3.10") || !strings.Contains(got, "22") {
		t.Errorf("expected the description to surface saddr and port, got %q", got)
	}
	if !strings.HasPrefix(strings.ToLower(got), "permite") {
		t.Errorf("expected an accept rule to start with an affirmative verb, got %q", got)
	}
}

func TestDescribeRuleUserRuleDropAnyTraffic(t *testing.T) {
	got := describeRule(UserChain, "counter drop")
	if !strings.Contains(strings.ToLower(got), "bloqueia") {
		t.Errorf("expected a drop rule description to start with a blocking verb, got %q", got)
	}
}

func TestDescribeRuleFallsBackToRawExpressionWhenUnrecognised(t *testing.T) {
	expr := "meta nftrace set 1"
	got := describeRule("some_future_chain", expr)
	if got != expr {
		t.Errorf("unrecognised rule must fall back to the raw expression (honest over wrong); got %q, want %q", got, expr)
	}
}

// ─── end-to-end: ListRuleset/parseTableRuleset populate Managed/Owner/Description ─

func TestParseTableRulesetPopulatesOwnershipAndDescription(t *testing.T) {
	chains := parseTableRuleset(prodTableFixture)

	ur := chainByName(chains, "user_rules")
	_ = ur // empty in this fixture; nothing to assert on rules

	fwd := chainByName(chains, "forward")
	for _, r := range fwd.Rules {
		if !r.Managed {
			t.Errorf("forward-chain rule must be Managed=true: %+v", r)
		}
		if r.Description == "" {
			t.Errorf("every rule must carry a non-empty description: %+v", r)
		}
	}

	pr := chainByName(chains, "postrouting")
	if len(pr.Rules) != 1 || !pr.Rules[0].Managed || pr.Rules[0].Owner.Key != "nat" {
		t.Errorf("postrouting masquerade rule not classified as expected: %+v", pr.Rules)
	}
	if pr.Rules[0].Description != "Mascara saída pelas WANs enp2s0, enp5s0" {
		t.Errorf("unexpected description: %q", pr.Rules[0].Description)
	}

	in := chainByName(chains, "input")
	for _, r := range in.Rules {
		if r.Owner.Key != "ntp" {
			t.Errorf("input chain rule must be owned by ntp: %+v", r)
		}
	}
}

// As regras de saddr e daddr dos conjuntos de bloqueio são um par legítimo,
// uma para cada sentido — não a duplicação de chain do incidente que motivou
// esta tela (spec §1). Descrever as duas com o mesmo texto faz o par honesto
// se passar pelo defeito, na página cujo propósito é justamente deixar esse
// defeito visível. Cada sentido precisa de texto próprio.
func TestDescribeRuleDistinguishesBlockDirection(t *testing.T) {
	pairs := [][2]string{
		{"ip saddr @blocked_hosts counter drop", "ip daddr @blocked_hosts counter drop"},
		{"ip saddr @blocklist counter drop", "ip daddr @blocklist counter drop"},
	}
	for _, p := range pairs {
		from := describeRule(ForwardChain, p[0])
		to := describeRule(ForwardChain, p[1])
		if from == "" || to == "" {
			t.Fatalf("descrição vazia para %q / %q", p[0], p[1])
		}
		if from == to {
			t.Errorf("origem e destino descritos igual (%q): o par vira duplicata aparente na tela", from)
		}
	}
}

// ─── C-2: a chain de um grupo é do ADMIN, como a user_rules era ────────────
//
// Depois da migração da Fase C1 as regras do admin moram nas chains grp_.
// Sem reconhecer o prefixo, a MESMA regra do MESMO admin, no MESMO grupo,
// voltava classificada de dois jeitos: a ativada (lida do nft vivo) como
// "gerenciada pelo LinkGuard" e com a expressão crua no lugar da descrição; a
// desativada (sintética, montada pelo merge) como do admin e em português. Na
// tela isso vira uma lista esquizofrênica — e, pior, o painel oferecendo "esta
// regra vem do LinkGuard" para uma regra que o admin escreveu à mão.
func TestClassifyRuleGroupChainIsNeverManaged(t *testing.T) {
	for _, chain := range []string{"grp_ef46c5a25b73", GroupChainPrefix + "0"} {
		managed, owner := classifyRule(chain, "ip saddr 10.0.0.5 drop")
		if managed {
			t.Errorf("chain %s: a regra é do admin, nunca gerenciada pelo LinkGuard", chain)
		}
		if owner.Key != "" || owner.Label != "" {
			t.Errorf("chain %s: regra do admin não tem dono, obtive %+v", chain, owner)
		}
	}
}

// Uma chain que só PARECE de grupo (sem o separador do prefixo) continua
// sendo de terceiro/do LinkGuard: o prefixo é a marca que a reconciliação usa
// para saber o que é dela, e afrouxá-lo aqui chamaria de "do admin" o que não
// é — o único erro que classifyRule não pode cometer.
func TestClassifyRuleLookalikeChainIsStillManaged(t *testing.T) {
	if managed, _ := classifyRule("grpfoo", "ip saddr 10.0.0.5 drop"); !managed {
		t.Error("chain fora do prefixo grp_ não é do admin")
	}
}

func TestDescribeRuleGroupChainSpeaksPortuguese(t *testing.T) {
	got := describeRule("grp_ef46c5a25b73", "ip saddr 10.0.0.6 accept")
	want := describeUserRuleExpression("ip saddr 10.0.0.6 accept")
	if got != want {
		t.Errorf("a regra do admin dentro de um grupo tem que ser descrita pelo mesmo caminho das outras: obtive %q, esperava %q", got, want)
	}
	if !strings.Contains(got, "Permite") || !strings.Contains(got, "10.0.0.6") {
		t.Errorf("descrição não saiu em português: %q", got)
	}
}

// A linha de jump para um grupo é gerada pelo LinkGuard a partir da condição
// de entrada, então ela é "gerenciada" — mas o controle que a produz é a tela
// de grupos, e é para lá que o "abrir" da Visão geral tem que levar. Sem dono
// nomeado ela cai no rótulo genérico e vira a única regra da tela em que o
// admin PODE agir e não recebe link nenhum.
func TestClassifyRuleGivesTheGroupJumpItsOwnOwner(t *testing.T) {
	managed, owner := classifyRule(ForwardChain, "ip saddr 192.168.50.0/24 counter jump grp_a3f21c08")
	if !managed {
		t.Error("a linha de jump é renderizada pelo LinkGuard, não escrita à mão")
	}
	if owner.Key != "rule_groups" {
		t.Errorf("o dono do jump tem que ser a tela de grupos, obtive %+v", owner)
	}
	if owner.Label == "" {
		t.Error("o dono precisa de rótulo para a tela exibir")
	}
}

// ─── Correções da revisão da Fase C2 ─────────────────────────────────────

// M-1. Desde a Fase C2 a chain input também hospeda o jump dos grupos de
// escopo input, e ele é a mesma linha da forward: gerada pelo LinkGuard a
// partir da condição de entrada, cujo controle dono é a tela de grupos. Sem
// este caso ela caía no rótulo genérico "LinkGuard" — a única regra acionável
// da tela sem o link "abrir".
func TestClassifyRuleGivesTheInputGroupJumpItsOwnOwner(t *testing.T) {
	managed, owner := classifyRule(InputChain, "ip saddr 192.168.50.0/24 jump grp_a3f21c08")
	if !managed {
		t.Error("a linha de jump é renderizada pelo LinkGuard, não escrita à mão")
	}
	if owner.Key != "rule_groups" {
		t.Errorf("o dono do jump na input tem que ser a tela de grupos, obtive %+v", owner)
	}
	if owner.Label == "" {
		t.Error("o dono precisa de rótulo para a tela exibir")
	}
}

// M-2. As duas regras de NTP passaram a carregar `counter`, e é assim que o
// nft as imprime de volta: `counter packets N bytes M`, ANTES do verbo. Os
// fixtures sem counter acima continuam valendo (é o que uma máquina que ainda
// não reconciliou tem vivo), mas deixaram de ser a saída real do que este
// código gera — e é justamente um token a mais no meio da linha que poderia
// quebrar um classificador que casa por sufixo. Aqui a linha entra INTEIRA,
// como o nft a imprime, e passa pelo mesmo parser da produção.
func TestNTPLinesInTheirCounterFormAreStillRecognised(t *testing.T) {
	accept := parseChainRuleLine(InputChain,
		"udp dport 123 ip saddr 192.168.3.0/24 counter packets 5 bytes 380 accept")
	if !accept.Managed || accept.Owner.Key != "ntp" {
		t.Errorf("a linha de accept do NTP com counter perdeu o dono: %+v", accept)
	}
	if accept.Description != "Aceita NTP vindo de 192.168.3.0/24" {
		t.Errorf("descrição da linha de accept com counter = %q", accept.Description)
	}
	if !accept.HasCounter || accept.Packets != 5 || accept.Bytes != 380 {
		t.Errorf("o contador da linha de NTP não foi lido: %+v", accept)
	}

	drop := parseChainRuleLine(InputChain, "udp dport 123 counter packets 2 bytes 152 drop")
	if !drop.Managed || drop.Owner.Key != "ntp" {
		t.Errorf("a linha de drop do NTP com counter perdeu o dono: %+v", drop)
	}
	if drop.Description != "Bloqueia NTP de qualquer outra origem" {
		t.Errorf("descrição da linha de drop com counter = %q", drop.Description)
	}
	if !drop.HasCounter || drop.Packets != 2 || drop.Bytes != 152 {
		t.Errorf("o contador da linha de drop não foi lido: %+v", drop)
	}
}
