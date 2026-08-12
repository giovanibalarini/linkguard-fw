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
