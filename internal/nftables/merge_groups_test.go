package nftables

import "testing"

// Fixture com a forma REAL do nft: interface aspeada e /32 comido. Fixture
// gerado por buildRuleTokens esconderia exatamente a classe de bug que
// custou a revisão de 2026-08-11.
func TestMergeGroupsMarksAppliedFromRealNftOutput(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaa",
		Enabled: true, CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Iif: "enp0s3", Saddr: "10.0.0.1/32",
				Proto: "tcp", Dport: "443"}}}}

	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: `ip saddr 192.168.50.0/24 jump grp_aaa`, Handle: 7,
			HasCounter: true, Packets: 1247, Bytes: 4312576},
	}}
	chains := map[string]ChainInfo{"grp_aaa": {Name: "grp_aaa", Rules: []ChainRule{
		{Expression: `iifname "enp0s3" ip saddr 10.0.0.1 tcp dport 443 accept`,
			Handle: 9, HasCounter: true, Packets: 1219, Bytes: 4302438},
	}}}

	views := MergeGroups([]StoredGroup{g}, chains, forward)
	if len(views) != 1 {
		t.Fatalf("esperava 1 grupo, obtive %d", len(views))
	}
	v := views[0]
	if !v.Applied {
		t.Error("o grupo está na forward e deveria constar como aplicado")
	}
	if v.Packets != 1247 || !v.HasCounter {
		t.Errorf("o contador do grupo tem que vir da linha do jump, obtive %+v", v)
	}
	if len(v.Rules.Rules) != 1 || !v.Rules.Rules[0].Applied {
		t.Errorf("a regra de dentro deveria constar como aplicada: %+v", v.Rules.Rules)
	}
}

// Grupo desligado: não existe jump para ele, e isso é o esperado — não pode
// virar alarme falso de "configurada, não aplicada".
func TestMergeGroupsDisabledGroupIsNotFlaggedUnapplied(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Testes", ChainName: "grp_aaa", Enabled: false,
		Fallthrough: FallthroughContinue}
	views := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})
	if views[0].Applied {
		t.Error("grupo desligado não está aplicado, e isso é o correto")
	}
	if views[0].HasCounter {
		t.Error("sem contador medido, HasCounter tem que ser false — nunca um zero inventado")
	}
}

// Grupo ligado cujo jump sumiu do firewall: é o caso que o selo
// "Configurada, não aplicada" existe para expor.
func TestMergeGroupsEnabledWithoutJumpIsUnapplied(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Servidores", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}
	views := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})
	if views[0].Applied {
		t.Error("grupo ligado sem jump vivo NÃO está aplicado")
	}
}

// A chain de um grupo desligado continua viva e preenchida no nft de
// propósito (ReconcileGroups guarda as regras para quando ele voltar); só o
// jump some. Sem propagar isso, MergeUserRules — escrito para user_rules,
// onde "existe no nft" implica "é alcançada" — marca as regras de dentro
// como aplicadas, e o painel exibiria regra em vigor dentro de um grupo que
// ele mesmo mostra como não aplicado. É a confusão Enabled-vs-Applied que
// já foi achado crítico neste projeto, um nível abaixo.
//
// Este é o estado NORMAL de todo grupo desligado com regras, não uma borda.
func TestMergeGroupsDisabledGroupInnerRulesAreNotApplied(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Testes", ChainName: "grp_aaa", Enabled: false,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}
	chains := map[string]ChainInfo{"grp_aaa": {Name: "grp_aaa", Rules: []ChainRule{
		{Expression: "tcp dport 22 accept", Handle: 9, HasCounter: true, Packets: 3, Bytes: 300},
	}}}

	v := MergeGroups([]StoredGroup{g}, chains, ChainInfo{Name: ForwardChain})[0]
	if v.Applied {
		t.Fatal("grupo desligado não tem jump e não está aplicado")
	}
	if v.Rules.Rules[0].Applied {
		t.Error("nada pula para a chain deste grupo: a regra de dentro NÃO está em vigor")
	}
	// O contador é medição verdadeira de quando o grupo estava ligado —
	// apagá-lo inventaria um "não medido" onde houve medição.
	if !v.Rules.Rules[0].HasCounter || v.Rules.Rules[0].Packets != 3 {
		t.Errorf("o contador medido tem que ser preservado, obtive %+v", v.Rules.Rules[0])
	}
}

// Mesmo raciocínio para o grupo LIGADO cujo jump sumiu do firewall: é o
// estado que o selo "Configurada, não aplicada" existe para expor, e ele
// vale para o grupo e para tudo que está dentro dele.
func TestMergeGroupsEnabledWithoutJumpAlsoUnappliesInnerRules(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Servidores", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}
	chains := map[string]ChainInfo{"grp_aaa": {Name: "grp_aaa", Rules: []ChainRule{
		{Expression: "tcp dport 22 accept", Handle: 9, HasCounter: true, Packets: 3},
	}}}

	v := MergeGroups([]StoredGroup{g}, chains, ChainInfo{Name: ForwardChain})[0]
	if v.Applied || v.Rules.Rules[0].Applied {
		t.Errorf("sem jump vivo, nem o grupo nem as regras estão em vigor: %+v", v)
	}
}

// A ordem exibida tem que ser a que o admin configurou — a ordem em que o
// kernel avalia os grupos. Sem isto, o painel mostraria uma ordem de
// avaliação que não é a real.
func TestMergeGroupsSortsByPosition(t *testing.T) {
	groups := []StoredGroup{
		{ID: "c", Name: "terceiro", ChainName: "grp_ccc", Position: 20},
		{ID: "a", Name: "primeiro", ChainName: "grp_aaa", Position: 1},
		{ID: "b", Name: "segundo", ChainName: "grp_bbb", Position: 10},
	}
	views := MergeGroups(groups, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})
	got := []string{views[0].Name, views[1].Name, views[2].Name}
	want := []string{"primeiro", "segundo", "terceiro"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordem por Position não respeitada: %v", got)
		}
	}
}
