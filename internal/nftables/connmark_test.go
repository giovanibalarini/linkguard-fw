package nftables

import (
	"context"
	"strings"
	"testing"
)

func TestConnMarkChainRules(t *testing.T) {
	regras := connMarkChainRules([]WANMark{
		{Interface: "wan1", Mark: 100},
		{Interface: "wan2", Mark: 101},
	})
	if len(regras) != 4 {
		t.Fatalf("queria 2 regras de memória + 2 de restauração (entrada e saída), veio %d", len(regras))
	}
	if got := strings.Join(regras[0], " "); got != `iifname "wan1" ct state new counter ct mark set 0x64` {
		t.Errorf("memória da wan1: %q", got)
	}
	if got := strings.Join(regras[1], " "); got != `iifname "wan2" ct state new counter ct mark set 0x65` {
		t.Errorf("memória da wan2: %q", got)
	}
	if got := strings.Join(regras[2], " "); got != `iifname != { "wan1", "wan2" } ct mark != 0x0 ct direction reply counter meta mark set ct mark` {
		t.Errorf("restauração de entrada: %q", got)
	}
	if got := strings.Join(regras[3], " "); got != `iifname != { "wan1", "wan2" } ct mark != 0x0 ct direction original meta mark == 0x0 counter meta mark set ct mark` {
		t.Errorf("restauração de saída: %q", got)
	}
}

func TestARestauracaoNoPreroutingSoAgeSobreOQueVeioDaLAN(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE, e que quase foi entregue.
	//
	// Antes da memória de saída, `ct mark != 0` significava uma coisa só: "a
	// conexão entrou por uma WAN". Com a memória de saída, conexão nascida na
	// LAN também tem marca — e a RESPOSTA dela é a internet respondendo,
	// chegando por uma WAN.
	//
	// Sem o guarda de interface, a restauração de resposta casaria esse pacote,
	// a `ip rule fwmark` o mandaria para a tabela do link — que só tem
	// `default via <gateway>` — e o SYN-ACK destinado a um host da LAN sairia de
	// volta para o provedor. Toda a LAN sem internet, no instante da
	// reconciliação, persistido para o próximo boot.
	//
	// AS DUAS REGRAS DO PREROUTING PRECISAM DO GUARDA. Foi ter posto a proteção
	// só na regra nova que criou o defeito: a regra velha continuou lendo
	// `ct mark` com o significado antigo.
	wans := []WANMark{{Interface: "wan1", Mark: 100}, {Interface: "wan2", Mark: 101}}
	for _, r := range [][]string{restoreReplyMarkRule(wans), restoreOutboundMarkRule(wans)} {
		got := strings.Join(r, " ")
		if !strings.HasPrefix(got, `iifname != { "wan1", "wan2" }`) {
			t.Errorf("restauração do prerouting sem o guarda de interface: %q", got)
		}
	}

	// E o guarda NÃO pode existir na chain de output: lá não há interface de
	// entrada, e a marca só chega em conexão que entrou por WAN de verdade.
	if got := strings.Join(outputMarkChainRules()[0], " "); strings.Contains(got, "iifname") {
		t.Errorf("a chain de output não tem interface de entrada para casar: %q", got)
	}
}

func TestARestauracaoSoValeParaADirecaoDeResposta(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE, e que era meu, entregue na #120.
	//
	// A chain de prerouting está antes do dstnat e vê as DUAS direções. Sem
	// `ct direction reply`, o pacote que CHEGA da internet para um host da LAN
	// também recebia a marca; o DNAT reescrevia o destino, o kernel decidia a
	// rota já com a marca, casava a `ip rule fwmark` e caía na tabela do link —
	// que só tem `default via <gateway da WAN>`. O SYN destinado ao host da LAN
	// voltava para o provedor.
	//
	// Sintoma: o painel mostra o encaminhamento aplicado, a tradução está na
	// chain de DNAT, e o servidor interno não responde de fora.
	entrada := restoreReplyMarkRule([]WANMark{{Interface: "wan1", Mark: 100}})
	for _, r := range [][]string{entrada, outputMarkChainRules()[0]} {
		got := strings.Join(r, " ")
		if !strings.Contains(got, "ct direction reply") {
			t.Errorf("restauração sem direção: %q — encaminhamento de porta volta pela WAN", got)
		}
		if strings.Contains(got, "ct direction original") {
			t.Errorf("restauração casando a direção original: %q", got)
		}
	}
}

func TestARestauracaoEhSempreAUltima(t *testing.T) {
	// Se a restauração viesse antes da memória, uma conexão nova entrando pela
	// WAN teria a marca restaurada (zero) DEPOIS de gravada — e o caminho de
	// volta se perderia justamente na conexão que a feature existe para tratar.
	regras := connMarkChainRules([]WANMark{{Interface: "wan1", Mark: 100}})
	ultima := strings.Join(regras[len(regras)-1], " ")
	if !strings.Contains(ultima, "meta mark set ct mark") {
		t.Errorf("a última regra não é a de restauração: %q", ultima)
	}
}

func TestMemoriaSoValeParaConexaoNova(t *testing.T) {
	// Sem `ct state new`, um pacote chegando pela outra WAN no meio da conversa
	// reescreveria a marca e mudaria o caminho de volta no meio do caminho.
	regras := connMarkChainRules([]WANMark{{Interface: "wan1", Mark: 100}})
	if !strings.Contains(strings.Join(regras[0], " "), "ct state new") {
		t.Errorf("a regra de memória casa qualquer estado: %q", regras[0])
	}
}

func TestSanitizeWANMarks(t *testing.T) {
	got := sanitizeWANMarks([]WANMark{
		{Interface: "wan2", Mark: 101},
		{Interface: "wan1", Mark: 100},
		{Interface: "wan1", Mark: 999},   // duplicada: fica a primeira
		{Interface: "semmarca", Mark: 0}, // marca zero não identifica caminho
		{Interface: "", Mark: 5},
		{Interface: "nome-absurdamente-longo-demais", Mark: 6},
	})
	if len(got) != 2 {
		t.Fatalf("sobraram %d entradas: %+v", len(got), got)
	}
	// Ordem estável: sem isso a chain é reescrita em ordem diferente a cada
	// boot, e o diff do ruleset vivo vira ruído permanente.
	if got[0].Interface != "wan1" || got[1].Interface != "wan2" {
		t.Errorf("ordem instável: %+v", got)
	}
	if got[0].Mark != 100 {
		t.Errorf("duplicada sobrescreveu a primeira: %+v", got[0])
	}
}

func TestEnsureConnMarkSemWANNaoCriaNada(t *testing.T) {
	// Só a regra de restauração, sem nenhuma de memória, restauraria marcas que
	// ninguém grava — e a chain existiria dando a impressão de estar ligada.
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureConnMark(context.Background(), []WANMark{{Interface: "wan1", Mark: 0}}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, c := range ex.comandos {
		if strings.Contains(c, "nft") {
			t.Errorf("executou nft sem WAN válida: %q", c)
		}
	}
}

func TestEnsureConnMarkDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureConnMark(context.Background(), []WANMark{{Interface: "wan1", Mark: 100}}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}

func TestAChainDeSaidaEhDoTipoRoute(t *testing.T) {
	// `type filter` no hook output escreve a marca e o kernel NÃO refaz a
	// decisão de rota — a feature pareceria configurada e não faria nada. Só
	// `type route` dispara o reroute.
	if !strings.Contains(outputMarkChainSpec, "type route hook output") {
		t.Errorf("chain de saída não é do tipo route: %q", outputMarkChainSpec)
	}
}


func TestConexaoDaLANEhFixadaNaWANEmQueSaiu(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE. Conexão nascida na LAN não tinha dono: a
	// rota padrão em modo balanceado é multipath e o kernel escolhe por hash.
	// Link que cai e volta faz a rota ser reescrita, o hash muda de resposta e
	// as conexões ABERTAS pulam de link — com o conntrack ainda traduzindo a
	// origem para o endereço da WAN antiga, o que faz o provedor descartar por
	// uRPF. Download reabre conexão e parece travar; chamada de vídeo e jogo
	// online morrem.
	regras := connMarkOutChainRules([]WANMark{
		{Interface: "wan1", Mark: 100},
		{Interface: "wan2", Mark: 101},
	})
	if len(regras) != 2 {
		t.Fatalf("queria uma memória de saída por WAN, veio %d", len(regras))
	}
	if got := strings.Join(regras[0], " "); got != `oifname "wan1" ct direction original ct mark == 0x0 counter ct mark set 0x64` {
		t.Errorf("memória de saída da wan1: %q", got)
	}
	if got := strings.Join(regras[1], " "); got != `oifname "wan2" ct direction original ct mark == 0x0 counter ct mark set 0x65` {
		t.Errorf("memória de saída da wan2: %q", got)
	}
}

func TestAMemoriaDeSaidaNaoSobrescreveAMemoriaDeEntrada(t *testing.T) {
	// As duas metades desta feature já se atropelaram uma vez (#120). A memória
	// de saída só grava quando não há marca — a decisão de quem ENTROU manda,
	// porque é ela que sustenta o encaminhamento de porta.
	for _, r := range connMarkOutChainRules([]WANMark{{Interface: "wan1", Mark: 100}}) {
		got := strings.Join(r, " ")
		if !strings.Contains(got, "ct mark == 0x0") {
			t.Errorf("memória de saída sem o guarda de marca zero: %q", got)
		}
		if !strings.Contains(got, "ct direction original") {
			t.Errorf("memória de saída sem a direção original: %q — remarcaria a resposta de um encaminhamento de porta", got)
		}
	}
}

func TestARestauracaoDeSaidaSoValeParaQuemVeioDaLAN(t *testing.T) {
	// ESTA É A CONDIÇÃO QUE IMPEDE A ARMADILHA DA #120 DE VOLTAR. A restauração
	// de saída casa a direção ORIGINAL, que é exatamente a direção que mandava o
	// SYN de um encaminhamento de porta de volta para o provedor. O que a torna
	// segura é o pacote ter de ter ENTRADO POR ONDE NÃO É WAN.
	r := strings.Join(restoreOutboundMarkRule([]WANMark{
		{Interface: "wan1", Mark: 100}, {Interface: "wan2", Mark: 101},
	}), " ")
	if !strings.Contains(r, `iifname != { "wan1", "wan2" }`) {
		t.Errorf("restauração de saída sem excluir as WANs de entrada: %q", r)
	}
	if !strings.Contains(r, "ct direction original") {
		t.Errorf("restauração de saída não casa a direção original: %q", r)
	}
	if !strings.Contains(r, "meta mark == 0x0") {
		t.Errorf("restauração de saída sem deixar o @host_wan ganhar: %q", r)
	}
}

func TestFixacaoPorHostGanhaDaMemoriaDeConexao(t *testing.T) {
	// Fixação escolhida por gente vence memória de conexão. A mark_hosts roda em
	// priority mangle (-150) e a conn_mark em mangle+10 (-140), então quando o
	// admin fixou o aparelho a marca já está posta — e a restauração de saída
	// exige marca zero para agir.
	r := strings.Join(restoreOutboundMarkRule([]WANMark{{Interface: "wan1", Mark: 100}}), " ")
	if !strings.Contains(r, "meta mark == 0x0") {
		t.Fatalf("sem o guarda, a memória de conexão sobrescreveria o direcionamento por host: %q", r)
	}
}
