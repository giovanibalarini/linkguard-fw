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

// Grupo do sistema (bloqueado por host/destino) não tem chain própria nem
// jump: o conteúdo dele são as linhas de drop do named set, direto na
// forward. Applied tem que vir de elas estarem vivas ali — não de um jump
// que este kind de grupo nunca teve. Fixture na forma REAL do nft: o
// `counter` já foi consumido para HasCounter/Packets/Bytes, e não sobra no
// Expression (ver parseChainRuleLine).
func TestMergeGroupsSystemGroupAppliedFromItsSetLines(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts,
		Enabled: true, Position: 0}
	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: "ip saddr @blocked_hosts drop", Handle: 4, HasCounter: true, Packets: 52, Bytes: 4096},
		{Expression: "ip daddr @blocked_hosts drop", Handle: 5, HasCounter: true, Packets: 16, Bytes: 1280},
	}}

	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, forward)[0]
	if !v.Applied {
		t.Error("as linhas do set estão vivas na forward: o grupo está aplicado")
	}
	// O contador do grupo é a soma das linhas dele — aqui não há jump para
	// medir, e as duas linhas juntas são o que o grupo faz.
	if v.Packets != 68 || v.Bytes != 5376 || !v.HasCounter {
		t.Errorf("contador do grupo do sistema errado: %+v", v)
	}
}

// Grupo do sistema desligado (ou, aqui, ligado mas cujas linhas sumiram da
// forward viva — ex.: reconcile ainda não rodou) não tem as linhas dele na
// forward. Applied tem que ser false, e — crucial — HasCounter também: sem
// nenhuma linha medida, inventar um zero mentiria "medido, deu zero" onde a
// verdade é "não sei".
func TestMergeGroupsSystemGroupWithoutItsLinesIsUnapplied(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts, Enabled: true}
	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})[0]
	if v.Applied {
		t.Error("sem as linhas de set vivas, o bloqueio NÃO está em vigor")
	}
	if v.HasCounter {
		t.Error("sem medição, HasCounter é false — nunca um zero inventado")
	}
}

// Um grupo de sistema desligado pelo admin não tem as linhas dele na
// forward — forwardChainRules simplesmente não as emite para um grupo
// desligado — e isso é a verdade, não um alarme: Enabled é o que o admin
// pediu, Applied é o que o kernel faz, e aqui os dois concordam em "não".
func TestMergeGroupsDisabledSystemGroupIsUnappliedWithoutAlarm(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts, Enabled: false}
	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})[0]
	if v.Applied {
		t.Error("grupo de sistema desligado não está aplicado, e isso é o correto")
	}
	if v.HasCounter {
		t.Error("sem medição, HasCounter é false")
	}
}

// Grupo de sistema não tem regras dentro de chain nenhuma — o conteúdo dele
// é o named set, não uma lista de regras. O campo de regras tem que sair
// vazio (fatia zero-length), nunca nil: um JSON `"rules": null` tem cara de
// erro de leitura, quando na verdade é que este grupo simplesmente não usa
// esse campo.
func TestMergeGroupsSystemGroupHasEmptyNotNilRuleChain(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts, Enabled: true}
	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: "ip saddr @blocked_hosts drop", Handle: 4, HasCounter: true, Packets: 52, Bytes: 4096},
		{Expression: "ip daddr @blocked_hosts drop", Handle: 5, HasCounter: true, Packets: 16, Bytes: 1280},
	}}
	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, forward)[0]
	if v.Rules.Rules == nil {
		t.Error("Rules.Rules tem que ser fatia vazia, não nil")
	}
	if len(v.Rules.Rules) != 0 {
		t.Errorf("grupo de sistema não tem regras de chain: %+v", v.Rules.Rules)
	}
}

// ─── Correções da revisão da Fase C2 ─────────────────────────────────────

// M-1. Applied tem que olhar a chain onde o grupo REALMENTE mora. Um grupo de
// escopo input tem o jump dele na chain input, e procurá-lo só na forward o
// deixava eternamente como "configurado, não aplicado" no painel — com o jump
// vivo o tempo todo. Mentira na tela, que é o que este painel existe para não
// fazer.
func TestMergeGroupsAppliedFromTheInputChainForAnInputScopeGroup(t *testing.T) {
	g := StoredGroup{ID: "i", Name: "Acesso ao firewall", ChainName: "grp_iii",
		Kind: GroupKindAdmin, Scope: ScopeInput, Enabled: true,
		CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughContinue}

	chains := map[string]ChainInfo{InputChain: {Name: InputChain, Rules: []ChainRule{
		{Expression: "udp dport 123 drop"},
		{Expression: "ip saddr 192.168.50.0/24 jump grp_iii", Handle: 12,
			HasCounter: true, Packets: 340, Bytes: 21000},
	}}}

	v := MergeGroups([]StoredGroup{g}, chains, ChainInfo{Name: ForwardChain})[0]
	if !v.Applied {
		t.Fatal("o jump está vivo na chain input e o grupo consta como não aplicado")
	}
	if v.Handle != 12 || !v.HasCounter || v.Packets != 340 || v.Bytes != 21000 {
		t.Errorf("o contador do grupo tem que vir da linha do jump na input, obtive %+v", v)
	}
}

// E a recíproca: um jump para a chain do grupo achado na chain ERRADA não
// prova nada. Um grupo de escopo input com jump só na forward (linha velha
// que a reconciliação ainda não removeu) não está em vigor para o tráfego que
// o admin escolheu — dizer "aplicado" ali seria pior do que não dizer nada.
func TestMergeGroupsIgnoresAJumpFoundInTheWrongChain(t *testing.T) {
	inputGroup := StoredGroup{ID: "i", Name: "Acesso ao firewall", ChainName: "grp_iii",
		Kind: GroupKindAdmin, Scope: ScopeInput, Enabled: true, Fallthrough: FallthroughContinue}
	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: "counter jump grp_iii", Handle: 3},
	}}
	if v := MergeGroups([]StoredGroup{inputGroup}, map[string]ChainInfo{}, forward)[0]; v.Applied {
		t.Error("um jump na forward não põe em vigor um grupo de escopo input")
	}

	forwardGroup := StoredGroup{ID: "f", Name: "Visitantes", ChainName: "grp_fff",
		Kind: GroupKindAdmin, Scope: ScopeForward, Enabled: true, Fallthrough: FallthroughContinue}
	chains := map[string]ChainInfo{InputChain: {Name: InputChain, Rules: []ChainRule{
		{Expression: "counter jump grp_fff", Handle: 4},
	}}}
	if v := MergeGroups([]StoredGroup{forwardGroup}, chains, ChainInfo{Name: ForwardChain})[0]; v.Applied {
		t.Error("um jump na input não põe em vigor um grupo de escopo forward")
	}
}

// Grupo do sistema é sempre da forward, qualquer que seja a coluna scope: o
// conteúdo dele é um named set de bloqueio de tráfego atravessando. Uma linha
// de banco com scope=input nele não pode mandar MergeGroups procurar as
// linhas de drop na chain errada e reportar o bloqueio como não aplicado.
func TestMergeGroupsSystemGroupIsReadFromTheForwardEvenWithAnInputScopeRow(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
		Kind: GroupKindBlockedHosts, Scope: ScopeInput, Enabled: true}
	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: "ip saddr @blocked_hosts drop", HasCounter: true},
		{Expression: "ip daddr @blocked_hosts drop", HasCounter: true},
	}}
	if v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, forward)[0]; !v.Applied {
		t.Error("o bloqueio do sistema está vivo na forward e consta como não aplicado")
	}
}
