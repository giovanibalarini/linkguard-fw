package firewallrules

import "testing"

// Issue #83: regra que cita interface inexistente carrega no nft SEM ERRO e
// nunca casa. Aconteceu em produção em 2026-08-10 (reshuffle de PCI,
// enp4s0 → enp5s0), e nada avisou.

func TestGhostAchaAInterfaceRenomeada(t *testing.T) {
	gs := FindGhostIfaces([]IfaceRef{
		{Name: "enp4s0", Action: "drop"},
		{Name: "enp5s0", Action: "accept"},
	}, []string{"enp5s0", "lo"})

	if len(gs) != 1 {
		t.Fatalf("esperava 1 fantasma, veio %d: %+v", len(gs), gs)
	}
	if gs[0].Name != "enp4s0" {
		t.Errorf("fantasma = %q", gs[0].Name)
	}
}

// TestGhostSeparaBloqueioDePermissao é a distinção que decide a gravidade.
//
// Uma regra de accept que deixa de casar só faz o tráfego cair noutra linha.
// Uma de drop que deixa de casar é uma PROTEÇÃO QUE SUMIU, com o painel
// afirmando que ela continua lá.
func TestGhostSeparaBloqueioDePermissao(t *testing.T) {
	sóAccept := FindGhostIfaces([]IfaceRef{{Name: "morta", Action: "accept"}}, []string{"viva"})
	if AnyBlocking(sóAccept) {
		t.Error("regra de accept marcada como bloqueio")
	}

	comDrop := FindGhostIfaces([]IfaceRef{
		{Name: "morta", Action: "accept"},
		{Name: "morta", Action: "drop"},
	}, []string{"viva"})
	if !AnyBlocking(comDrop) {
		t.Error("uma regra de drop entre as citações não marcou o fantasma como bloqueio")
	}
	if comDrop[0].Rules != 2 {
		t.Errorf("contou %d regras, esperava 2", comDrop[0].Rules)
	}

	// reject bloqueia tanto quanto drop — a diferença é o que a origem percebe.
	if !AnyBlocking(FindGhostIfaces([]IfaceRef{{Name: "morta", Action: "reject"}}, []string{"viva"})) {
		t.Error("reject não contou como bloqueio")
	}
}

func TestGhostAgrupaGruposERegras(t *testing.T) {
	gs := FindGhostIfaces([]IfaceRef{
		{Name: "morta", GroupName: "Visitantes"},
		{Name: "morta", GroupName: "DMZ"},
		{Name: "morta", Action: "drop"},
	}, []string{"viva"})

	if len(gs) != 1 {
		t.Fatalf("esperava 1 fantasma, veio %d", len(gs))
	}
	// Ordenado: um alerta cujo texto muda de ordem a cada passada vira ruído.
	if len(gs[0].Groups) != 2 || gs[0].Groups[0] != "DMZ" {
		t.Errorf("grupos = %v, esperava ordenados", gs[0].Groups)
	}
	if gs[0].Rules != 1 {
		t.Errorf("regras = %d, esperava 1", gs[0].Rules)
	}
}

// TestGhostSemInterfacesVivasNaoAcusaNada.
//
// Uma leitura que falhou e devolveu lista vazia geraria um alerta dizendo que a
// máquina inteira é fantasma. O alerta que grita por tudo é o que ninguém lê.
func TestGhostSemInterfacesVivasNaoAcusaNada(t *testing.T) {
	if gs := FindGhostIfaces([]IfaceRef{{Name: "eth0", Action: "drop"}}, nil); len(gs) != 0 {
		t.Errorf("acusou %d fantasmas sem saber quais interfaces existem: %+v", len(gs), gs)
	}
	if gs := FindGhostIfaces([]IfaceRef{{Name: "eth0"}}, []string{"", ""}); len(gs) != 0 {
		t.Error("lista de vivas só com strings vazias deveria contar como desconhecida")
	}
}

// TestGhostIgnoraCitacaoVazia: campo vazio significa "qualquer interface", e
// não uma interface chamada "".
func TestGhostIgnoraCitacaoVazia(t *testing.T) {
	if gs := FindGhostIfaces([]IfaceRef{{Name: "", Action: "drop"}}, []string{"eth0"}); len(gs) != 0 {
		t.Errorf("citação vazia virou fantasma: %+v", gs)
	}
}

// TestGhostEhSensivelACaixa: nomes de interface no Linux são case-sensitive.
// "Aproximar" aqui produziria um falso negativo — dizer que está tudo bem
// quando a regra não casa —, que é o pior dos dois erros possíveis.
func TestGhostEhSensivelACaixa(t *testing.T) {
	gs := FindGhostIfaces([]IfaceRef{{Name: "ETH0", Action: "drop"}}, []string{"eth0"})
	if len(gs) != 1 {
		t.Error("ETH0 com eth0 viva deveria ser fantasma: o kernel distingue as duas")
	}
}

func TestGhostOrdenaASaida(t *testing.T) {
	gs := FindGhostIfaces([]IfaceRef{
		{Name: "zzz", Action: "drop"}, {Name: "aaa", Action: "drop"}, {Name: "mmm", Action: "drop"},
	}, []string{"viva"})
	if len(gs) != 3 || gs[0].Name != "aaa" || gs[2].Name != "zzz" {
		t.Errorf("saída não ordenada: %+v", gs)
	}
}

func TestGhostNadaAAcusarQuandoTudoExiste(t *testing.T) {
	gs := FindGhostIfaces([]IfaceRef{
		{Name: "eth0", Action: "drop"}, {Name: "br-lan", GroupName: "LAN"},
	}, []string{"eth0", "br-lan", "lo"})
	if len(gs) != 0 {
		t.Errorf("acusou fantasma com tudo existindo: %+v", gs)
	}
}
