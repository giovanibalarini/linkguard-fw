package nftables

import (
	"context"
	"strings"
	"testing"
)

func TestMSSClampRules(t *testing.T) {
	got := mssClampRules(zonaOnPrem("wan1", "wan2"))
	if len(got) != 2 {
		t.Fatalf("queria uma regra por WAN, veio %d", len(got))
	}
	want := `oifname "wan1" tcp flags syn / syn,rst counter tcp option maxseg size set rt mtu`
	if s := strings.Join(got[0], " "); s != want {
		t.Errorf("regra:\n  %q\nqueria:\n  %q", s, want)
	}
}

func TestOAjusteNaoCarregaNumeroFixo(t *testing.T) {
	// `rt mtu` é o que torna a regra correta em qualquer link sem perguntar a
	// MTU ao admin — e no-op por construção onde a MTU é 1500. Um número
	// cravado quebraria os dois casos.
	regra := strings.Join(mssClampRules(zonaOnPrem("wan1"))[0], " ")
	if !strings.Contains(regra, "size set rt mtu") {
		t.Errorf("o ajuste não usa a MTU da rota: %q", regra)
	}
	for _, numero := range []string{"1460", "1452", "1440"} {
		if strings.Contains(regra, numero) {
			t.Errorf("a regra cravou um MSS fixo (%s): %q", numero, regra)
		}
	}
}

func TestOAjusteSoValeNoApertoDeMao(t *testing.T) {
	// O MSS só é negociado no SYN. Casar outro pacote seria mexer numa conexão
	// já estabelecida.
	regra := strings.Join(mssClampRules(zonaOnPrem("wan1"))[0], " ")
	if !strings.Contains(regra, "tcp flags syn / syn,rst") {
		t.Errorf("o casamento de flags não está restrito ao SYN: %q", regra)
	}
}

// TestMSSClampSemWANCriaAChainVaziaEmVezDeNaoCriarNada é a virada deliberada de
// um teste que afirmava o contrário.
//
// O QUE ELE AFIRMAVA: sem WAN cadastrada, EnsureMSSClamp não executava NADA —
// o early-return vinha antes do `add chain`. O efeito colateral era a chain
// mss_clamp simplesmente não existir na caixa, nem vazia, e ninguém conseguir
// distinguir "não há link cadastrado" de "a reconciliação quebrou".
//
// O QUE ELE AFIRMA AGORA: a chain é criada e fica VAZIA. Estrutura montada,
// zero regra. É seguro porque a chain é `policy accept` e não decide nada
// sozinha, e é honesto porque o estado passa a ser inspecionável.
//
// O QUE CONTINUA VALENDO, e é a metade que não pode ser perdida: nenhuma REGRA
// é emitida. Uma regra de clamp sem saber por onde se sai é pior do que
// nenhuma.
func TestMSSClampSemWANCriaAChainVaziaEmVezDeNaoCriarNada(t *testing.T) {
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureMSSClamp(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	var criouChain bool
	for _, c := range ex.comandos {
		if strings.Contains(c, "add chain inet linkguard mss_clamp") {
			criouChain = true
		}
		if strings.Contains(c, "add rule") {
			t.Errorf("emitiu regra sem WAN cadastrada: %q", c)
		}
	}
	if !criouChain {
		t.Errorf("a chain mss_clamp tinha de nascer, mesmo vazia: %v", ex.comandos)
	}
}

func TestMSSClampDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureMSSClamp(context.Background(), []string{"wan1"}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}

// ─── O ajuste pela MTU do CAMINHO (o incremento do uplink) ───────────────────

// TestComMTUDeCaminhoConhecidaOClampUsaONumeroRealESoReduz é o bloqueante de
// verdade desta entrega, e não uma melhoria cosmética.
//
// Numa VM de nuvem os nós de dentro têm MTU 9000 e anunciam MSS ~8960. O
// servidor remoto responde com pacotes desse tamanho, que precisam sair por um
// caminho de 1500. Sem o ajuste, ping e DNS funcionam e `docker pull` e `apt`
// PENDURAM — o sintoma mais confuso de diagnosticar que existe, e o cliente
// culpa o produto.
//
// As duas afirmações que este teste faz, e que a forma da regra tem de honrar:
//
//  1. o número sai da MTU do CAMINHO (1500 − 40 = 1460), nunca da que a placa
//     anuncia: um clamp para 8960 é pior do que nenhum, porque parece feito;
//  2. a regra tem a guarda `size > 1460` ANTES do `set`, e por isso só REDUZ.
//     Sem ela a regra escreveria 1460 em todo SYN — inclusive num que já
//     negociou 536 —, e um clamp que AUMENTA o MSS é a forma de quebrar conexão
//     que nenhum teste local pega.
func TestComMTUDeCaminhoConhecidaOClampUsaONumeroRealESoReduz(t *testing.T) {
	regras := mssClampRules(zonaHairpinComMTU(1500, []string{"10.0.0.0/24"}, "ens3"))
	if len(regras) != 1 {
		t.Fatalf("queria UMA regra para o caminho único de saída, veio %d: %v", len(regras), regras)
	}
	want := `oifname { "ens3" } tcp flags syn / syn,rst tcp option maxseg size > 1460 counter tcp option maxseg size set 1460`
	if got := strings.Join(regras[0], " "); got != want {
		t.Errorf("regra:\n  %q\nqueria:\n  %q", got, want)
	}
	// A MTU DA PLACA NÃO PODE APARECER. É o erro que o comentário de
	// mssclamp.go descreve, e ele só se distingue do acerto pelo número.
	if got := strings.Join(regras[0], " "); strings.Contains(got, "8960") || strings.Contains(got, "9000") {
		t.Errorf("o clamp usou a MTU que a placa ANUNCIA em vez da do caminho: %q", got)
	}
	// A guarda tem de vir ANTES do `set`, senão ela não guarda nada.
	tokens := strings.Join(regras[0], " ")
	if strings.Index(tokens, "size > 1460") > strings.Index(tokens, "size set 1460") {
		t.Errorf("a guarda `size > N` está depois do `set`: a regra passaria a AUMENTAR o MSS: %q", tokens)
	}
}

// TestOClampDeCaminhoDescontaOsQuarentaBytesDeCabecalho separa o número do
// caminho do número que vai na regra: MSS = MTU − 20 de IP − 20 de TCP.
func TestOClampDeCaminhoDescontaOsQuarentaBytesDeCabecalho(t *testing.T) {
	casos := map[int]string{
		1500: "1460",
		1492: "1452", // PPPoE, se um dia a plataforma afirmar isso
		1400: "1360",
		576:  "536", // o piso do IPv4: ainda é um número válido
	}
	for mtu, esperado := range casos {
		regras := mssClampRules(zonaHairpinComMTU(mtu, []string{"10.0.0.0/24"}, "ens3"))
		if len(regras) != 1 {
			t.Fatalf("MTU %d: queria uma regra, veio %d", mtu, len(regras))
		}
		regra := strings.Join(regras[0], " ")
		if !strings.Contains(regra, "size > "+esperado+" counter tcp option maxseg size set "+esperado) {
			t.Errorf("MTU %d: queria MSS %s, obtive %q", mtu, esperado, regra)
		}
	}
}

// TestSemMTUDeCaminhoAChainDeAjusteContinuaNascendoVazia: desconhecido continua
// sendo chain vazia, e continua sendo a resposta certa. Uma regra que casa tudo
// e clampa para um valor inventado dá a impressão de que o ajuste está feito.
func TestSemMTUDeCaminhoAChainDeAjusteContinuaNascendoVazia(t *testing.T) {
	casos := map[string]int{
		"a plataforma não afirma nada":   0,
		"o número é lixo abaixo do piso": 500,
		"o número é lixo grande demais":  70000,
		"o número é negativo":            -1,
	}
	for nome, mtu := range casos {
		t.Run(nome, func(t *testing.T) {
			if regras := mssClampRules(zonaHairpinComMTU(mtu, []string{"10.0.0.0/24"}, "ens3")); len(regras) != 0 {
				t.Errorf("emitiu regra a partir de uma MTU de caminho que não dá para acreditar (%d): %v", mtu, regras)
			}
		})
	}

	// E o aviso tem de dizer o motivo VERDADEIRO. "não há vários links para
	// distinguir" deixou de ser a causa no dia em que um link só parou de
	// impedir o ajuste: o que impede agora é não saber o número.
	z := zonaHairpinComMTU(0, []string{"10.0.0.0/24"}, "ens3")
	if motivo := motivoDeMSSClampVazia(z); !strings.Contains(motivo, "MTU do caminho externo desconhecida") {
		t.Errorf("o aviso da chain vazia manda o operador procurar a coisa errada: %q", motivo)
	}
}

// TestOMotivoDaMSSClampNaoContaminaOAvisoDasOutrasChains prende a separação das
// duas funções de motivo.
//
// motivoDeChainVazia escreve o aviso de CINCO chamadores. A conn_mark de uma VM
// de nuvem nasce vazia porque existe um link só para marcar — nunca por causa de
// MTU nenhuma —, e a acct e o registro de conversa nascem vazios por falta de
// CIDR local. Uma frase sobre MTU dentro da função compartilhada faria os três
// apontarem para a rede errada, com a convicção de um aviso que o produto
// emitiu de propósito.
func TestOMotivoDaMSSClampNaoContaminaOAvisoDasOutrasChains(t *testing.T) {
	// Exatamente o cenário hairpin_sem_mtu: uma placa, rede local conhecida,
	// MTU de caminho desconhecida. A conn_mark está vazia aqui de qualquer
	// jeito, porque PerLink() é falso.
	z := zonaHairpinComMTU(0, []string{"10.0.0.0/24"}, "ens3")

	generico := motivoDeChainVazia(z)
	if strings.Contains(generico, "MTU") {
		t.Errorf("o motivo compartilhado passou a falar de MTU; as chains conn_mark, acct e de fluxos "+
			"mandariam o operador investigar a rede errada: %q", generico)
	}
	if !strings.Contains(generico, "não há vários links para distinguir") {
		t.Errorf("o motivo compartilhado deixou de dizer a verdade sobre a conn_mark: %q", generico)
	}

	// E a variante do MSS continua dizendo o motivo dela.
	if especifico := motivoDeMSSClampVazia(z); especifico == generico {
		t.Error("motivoDeMSSClampVazia virou um apelido do genérico: o aviso do ajuste de MSS " +
			"voltou a mandar o operador procurar link para cadastrar quando o que falta é o número")
	}
}

// TestEmVariasWANsOAjusteContinuaSaindoPorRtMtuSejaQualForOPathMTU é A TRAVA DA
// PRODUÇÃO, e o que ela prende é a ORDEM DOS RAMOS de mssClampRules.
//
// Enquanto o ramo por-link for escolhido por PerLink(), nenhum valor que a
// plataforma venha a reportar um dia pode reescrever a chain mss_clamp da caixa
// on-prem. Hoje PathMTU é sempre 0 fora da nuvem — mas "hoje" não é garantia
// nenhuma, e este teste é o que transforma a ordem dos ramos em contrato.
func TestEmVariasWANsOAjusteContinuaSaindoPorRtMtuSejaQualForOPathMTU(t *testing.T) {
	semMTU := mssClampRules(NewZone([]string{"ppp0", "enp2s0"}, []string{"192.168.3.0/24"}, false, 0))
	comMTU := mssClampRules(NewZone([]string{"ppp0", "enp2s0"}, []string{"192.168.3.0/24"}, false, 1500))

	if len(semMTU) != 2 || len(comMTU) != 2 {
		t.Fatalf("a caixa de duas WANs tem de emitir uma regra por WAN: %d sem MTU, %d com MTU", len(semMTU), len(comMTU))
	}
	for i := range semMTU {
		a, b := strings.Join(semMTU[i], " "), strings.Join(comMTU[i], " ")
		if a != b {
			t.Errorf("alimentar a MTU do caminho mudou a regra %d de uma caixa de VÁRIAS interfaces.\nsem MTU: %q\ncom MTU: %q", i, a, b)
		}
		if !strings.Contains(a, "size set rt mtu") || strings.Contains(a, "1460") {
			t.Errorf("a regra %d deixou de usar `rt mtu`: %q", i, a)
		}
	}
}
