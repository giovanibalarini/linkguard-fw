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
