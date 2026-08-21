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
	if len(regras) != 3 {
		t.Fatalf("queria 2 regras de memória + 1 de restauração, veio %d", len(regras))
	}
	if got := strings.Join(regras[0], " "); got != `iifname "wan1" ct state new counter ct mark set 0x64` {
		t.Errorf("memória da wan1: %q", got)
	}
	if got := strings.Join(regras[1], " "); got != `iifname "wan2" ct state new counter ct mark set 0x65` {
		t.Errorf("memória da wan2: %q", got)
	}
	if got := strings.Join(regras[2], " "); got != `ct mark != 0x0 ct direction reply counter meta mark set ct mark` {
		t.Errorf("restauração: %q", got)
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
	for _, r := range [][]string{restoreMarkRule(), outputMarkChainRules()[0]} {
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
