package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Os testes deste arquivo prendem os defeitos achados na revisão da #115. Cada
// um FALHA sem o conserto correspondente — ver a tabela de mutação do relatório.
//
// Ficam separados de flows_test.go de propósito: aquele arquivo prende o que a
// entrega original decidiu, este prende o que ela errou, e misturar os dois
// esconde qual asserção nasceu de qual pergunta.

// TestFlowsChainRulesContaOSentidoDeVoltaDaConversa prende a metade que
// faltava da medição.
//
// O DEFEITO: com uma regra só (`iifname !=` a lista de WANs), o pacote de
// RESPOSTA — que chega com iifname == wan1 — não casa com nada. O contador
// da tupla passava a ser só o que o aparelho ENVIOU, e um host baixando
// 4 GB do YouTube aparecia na tela com dezenas de MB de ACK, sob uma coluna
// chamada "Volume". A contabilidade da #112 já resolvia isso no arquivo ao
// lado, com um par de regras (acct_up/acct_down); esta entrega copiou
// metade do par.
//
// A chave da regra de volta é INVERTIDA (`ip daddr . ip saddr . th sport`)
// de propósito: no pacote de resposta, quem é local é o destino e a porta
// do serviço é a de origem. Invertendo os três, o pacote de volta cai na
// MESMA tupla da ida e soma no mesmo contador. Validado contra o nft 1.1.3.
func TestFlowsChainRulesContaOSentidoDeVoltaDaConversa(t *testing.T) {
	regras := flowsChainRules([]string{"wan1", "wan2"})
	if len(regras) != 2 {
		t.Fatalf("queria 2 regras (subida e descida), veio %d: %v", len(regras), regras)
	}
	descida := strings.Join(regras[1], " ")
	querido := "iifname { \"wan1\", \"wan2\" } meta l4proto { tcp, udp } " +
		"update @flows { ip daddr . ip saddr . th sport }"
	if descida != querido {
		t.Errorf("regra de descida:\n veio   %s\n queria %s", descida, querido)
	}
}

// TestFlowsChainRulesNaoContaOMesmoPacoteDuasVezes prende a armadilha da forma
// ÓBVIA do conserto acima.
//
// O DEFEITO QUE ISTO EVITA: a segunda regra escrita como `oifname !=` a lista
// de WANs — que é a forma que a contabilidade da #112 usa, e que parece a
// simétrica natural — faria TODO pacote LAN→LAN casar com AS DUAS regras
// (`iifname != wan` é verdadeiro e `oifname != wan` também), pagando dois
// `update` e sendo contado duas vezes, em duas tuplas espelhadas. Casando
// `iifname` NA lista, as duas ficam mutuamente exclusivas: nenhum pacote paga
// dois `update`, e o custo por pacote continua sendo uma escrita de set.
func TestFlowsChainRulesNaoContaOMesmoPacoteDuasVezes(t *testing.T) {
	regras := flowsChainRules([]string{"wan1"})
	if len(regras) != 2 {
		t.Fatalf("queria 2 regras, veio %d", len(regras))
	}
	subida, descida := strings.Join(regras[0], " "), strings.Join(regras[1], " ")
	if !strings.HasPrefix(subida, "iifname != ") {
		t.Errorf("a regra de subida deveria casar `iifname !=` a lista: %s", subida)
	}
	if strings.Contains(descida, "oifname") {
		t.Errorf("a regra de descida usa oifname e se sobrepõe à de subida em todo LAN→LAN: %s", descida)
	}
	if !strings.HasPrefix(descida, "iifname { ") {
		t.Errorf("a regra de descida deveria casar `iifname` NA lista de WANs: %s", descida)
	}
}

// TestParseFlowSetNaoDegradaEmJanelaZeroQuandoNaoReconheceASaida prende a
// degradação silenciosa mais perigosa deste arquivo.
//
// O DEFEITO: parseFlowSet não tinha noção de "isto não parece um set". Uma
// deriva de formato entre versões do nft, um `-S` acrescentado por alguém na
// leitura, ou uma mensagem no lugar de um set caíam em Teto=0, JanelaMinutos=0
// e lista vazia, COM erro nil. A tela então afirmava "Janela dos últimos 0 min"
// e "Nenhuma conversa registrada nesta janela" — confiança máxima, conteúdo
// nenhum, nada propagado. E o `snap.Teto > 0` do cálculo de Cheio garantia que
// nem o aviso de medição cheia aparecesse.
func TestParseFlowSetNaoDegradaEmJanelaZeroQuandoNaoReconheceASaida(t *testing.T) {
	for _, entrada := range []string{
		"",
		"Error: No such file or directory",
		"table inet linkguard_flows {\n\tset flows {\n\t\ttype ipv4_addr . ipv4_addr . inet_service\n\t}\n}",
	} {
		snap, err := parseFlowSet(entrada)
		if err == nil {
			t.Errorf("parseFlowSet(%q) devolveu erro nil com janela %d e teto %d: a tela vai dizer 'janela de 0 min, nenhuma conversa'",
				entrada, snap.JanelaMinutos, snap.Teto)
		}
	}
}

// TestMinutosDeNftNaoLeMilissegundoComoMinuto prende a armadilha que só não
// produzia lixo por causa de uma âncora de regex a uma função de distância.
//
// O nft imprime milissegundo no `expires` dos elementos — medido de verdade:
// "expires 59m59s996ms". A versão anterior consumia o `m` de `ms` como minuto e
// devolvia 1056 para esse texto. Era seguro só porque reFlowTimeout é ancorada
// em linha inteira e nunca captura um `expires`. A próxima pessoa que quiser a
// idade de um elemento vai chamar isto com aquele texto e receber lixo calado.
func TestMinutosDeNftNaoLeMilissegundoComoMinuto(t *testing.T) {
	if got := minutosDeNft("59m59s996ms"); got != 59 {
		t.Errorf("minutosDeNft(%q) = %d, queria 59: o `m` de `ms` foi lido como minuto", "59m59s996ms", got)
	}
	if got := minutosDeNft("500ms"); got != 0 {
		t.Errorf("minutosDeNft(%q) = %d, queria 0", "500ms", got)
	}
}

// TestMinutosDeNftArredondaParaBaixoNosSegundos: arredondar para CIMA fazia a
// tela afirmar uma janela MAIOR do que o kernel guarda ("2m30s" virava 3 min).
// Subestimar a retenção é o lado seguro — nunca faz o admin concluir que uma
// conversa ausente não aconteceu.
func TestMinutosDeNftArredondaParaBaixoNosSegundos(t *testing.T) {
	if got := minutosDeNft("2m30s"); got != 2 {
		t.Errorf("minutosDeNft(\"2m30s\") = %d, queria 2: para cima, a tela promete mais janela do que existe", got)
	}
}

// TestFlowSnapshotReportaOcupacaoParaOAvisoPorProximidade.
//
// O DEFEITO: `Cheio` é uma igualdade contra o `size`, e os elementos expiram
// continuamente — a ocupação oscila logo abaixo do teto e `len < Teto` na maior
// parte do tempo, mesmo com o kernel recusando conversa nova o tempo todo. O
// nft não expõe contador de inserção recusada por set, então a igualdade
// sozinha não faz o trabalho que o comentário dela reivindicava. A medida
// contínua é o que a tela consegue usar para avisar por proximidade.
func TestFlowSnapshotReportaOcupacaoParaOAvisoPorProximidade(t *testing.T) {
	snap := parseOK(t, setDeFluxosComElementos)
	if snap.Ocupacao != 3 {
		t.Errorf("ocupação = %d, queria 3", snap.Ocupacao)
	}
	if snap.Teto != 8192 {
		t.Errorf("teto = %d, queria 8192", snap.Teto)
	}
	if snap.Cheio {
		t.Fatal("3 de 8192 não é cheio")
	}
}

// TestEnsureFlowsDerrubaATabelaQuandoARegraEhRecusada.
//
// O DEFEITO: rebuildChainIn coleta as recusas e SEGUE EM FRENTE, e EnsureFlows
// cria tabela, set e chain ANTES da regra. Numa recusa de regra, os três
// sobreviviam: uma base chain no hook forward atravessando todo o tráfego da
// LAN sem medir nada, um Flows() que responde com SUCESSO um set vazio, e a
// tela dizendo "esta rede não falou com ninguém". Invisível por construção,
// porque os dois chamadores rebaixam este erro para slog.Warn.
func TestEnsureFlowsDerrubaATabelaQuandoARegraEhRecusada(t *testing.T) {
	ex := &execFalso{erros: map[string]error{"add rule": errors.New("Error: syntax error")}}
	s := &Service{exec: ex}
	if err := s.EnsureFlows(context.Background(), []string{"wan1"}, FlowsConfig{Ligado: true}); err == nil {
		t.Fatal("regra recusada devolveu sucesso")
	}
	derrubou := false
	for _, linha := range ex.comandos {
		if strings.HasPrefix(linha, "nft delete table") && strings.Contains(linha, FlowsTable) {
			derrubou = true
		}
	}
	if !derrubou {
		t.Errorf("a chain ficou de pé no hook forward medindo nada, e Flows() devolveria um set vazio com cara de silêncio.\ncomandos: %v", ex.comandos)
	}
}

// execFalsoQueRecusaLeitura devolve um erro de leitura QUALQUER — que não é o
// mesmo que "a tabela não existe".
type execFalsoQueRecusaLeitura struct {
	execFalso
	erro error
}

func (e *execFalsoQueRecusaLeitura) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", e.erro
}

// TestFlowsDistingueMedicaoAusenteDeErroDeLeitura.
//
// O DEFEITO: "a tabela não existe" virava erro genérico, e o handler o traduzia
// em HTTP 500 com faixa vermelha de "não sei". Mas esse estado tem causa e
// conserto conhecidos: a unidade nftables do Debian declara um ExecStop que faz
// flush do ruleset, e o bootstrapdeps HABILITA essa unidade — então um upgrade
// do pacote nftables varre o ruleset vivo. O /etc/nftables.conf traz
// `inet linkguard` de volta; a tabela dos fluxos não está lá POR CONSTRUÇÃO (é
// o ponto da feature), e ninguém a recria até alguém reiniciar o serviço.
func TestFlowsDistingueMedicaoAusenteDeErroDeLeitura(t *testing.T) {
	s := &Service{exec: &execFalsoQueFalhaNaLeitura{}}
	if _, err := s.Flows(context.Background()); !errors.Is(err, ErrFlowsAusente) {
		t.Errorf("tabela ausente deveria virar ErrFlowsAusente, veio %v", err)
	}

	// Um erro de leitura QUALQUER continua sendo erro de leitura: confundir os
	// dois faria a tela dizer "não montada", com conserto sugerido, para uma
	// caixa cujo nft simplesmente não respondeu.
	outro := &execFalsoQueRecusaLeitura{erro: errors.New("permission denied")}
	s2 := &Service{exec: outro}
	if _, err := s2.Flows(context.Background()); err == nil || errors.Is(err, ErrFlowsAusente) {
		t.Errorf("erro de leitura comum virou 'medição ausente': %v", err)
	}
}

// TestTetoPadraoDimensionaParaACardinalidadeDaChave.
//
// O DEFEITO: 8192 dimensionava para a contagem de APARELHOS, e a chave tem TRÊS
// dimensões (origem . destino . porta). Trinta aparelhos × ~200 destinos/hora
// já passam de 8192 — a feature saía de fábrica SATURADA na instalação típica
// e, com o teto batido, respondendo errado à própria pergunta da issue. A
// comparação que expõe a inversão está no arquivo ao lado: accounting.go dá
// `size 65535` a uma chave de UMA dimensão (o endereço do host).
func TestTetoPadraoDimensionaParaACardinalidadeDaChave(t *testing.T) {
	if FlowsTetoPadrao < 32768 {
		t.Errorf("FlowsTetoPadrao = %d: a chave é origem.destino.porta, não aparelho — um só navegador abre dezenas de destinos por site",
			FlowsTetoPadrao)
	}
	// O padrão não pode ser o próprio máximo: sem folga acima dele, o admin que
	// vir "medição cheia" não tem para onde subir.
	if FlowsTetoMaximo <= FlowsTetoPadrao {
		t.Errorf("o teto máximo (%d) não deixa folga acima do padrão (%d)", FlowsTetoMaximo, FlowsTetoPadrao)
	}
}

// TestRulesetNaoPublicaOSetDeConversas prende o vazamento de privacidade que
// atravessava rotas antigas que ninguém olhou ao desenhar a permissão nova.
//
// O DEFEITO: Ruleset era um dump do kernel INTEIRO, inclusive a tabela dos
// fluxos com a tupla origem-destino-porta de cada conversa da rede. Isso saía
// por duas rotas:
//
//   - GET /api/nftables/ruleset, atrás de firewall.read, que está no papel de
//     Operador E dentro de readOnlyPermissions() (papel Visualizador). O papel
//     mais baixo de fábrica lia o conjunto de dados que PermTrafficFlows foi
//     criada para trancar — e sem auditoria nenhuma;
//   - POST /api/nftables/backup (via Save), que congelava a janela inteira numa
//     linha de iptables_backups sem retenção, servida de volta crua por
//     GET /api/nftables/backups.
//
// TestRegistroDeConversaNaoEntraEmPapelDeFabricaAlemDoAdmin não pode ver isto:
// ele varre a lista de permissões dos papéis, não as rotas que devolvem o dado.
func TestRulesetNaoPublicaOSetDeConversas(t *testing.T) {
	ex := &execFalso{}
	s := &Service{exec: ex}
	if _, err := s.Ruleset(context.Background()); err != nil {
		t.Fatalf("Ruleset: %v", err)
	}
	if len(ex.comandos) != 1 {
		t.Fatalf("queria 1 comando, veio %v", ex.comandos)
	}
	// Comparação por TOKEN, e não Contains: um dump irrestrito e um escopado
	// compartilham o prefixo "nft list", e um Contains casaria com os dois.
	campos := strings.Fields(ex.comandos[0])
	querido := []string{"nft", "list", "table", Family, Table}
	if len(campos) != len(querido) {
		t.Fatalf("Ruleset executou %q: um dump irrestrito publica a tabela %s inteira", ex.comandos[0], FlowsTable)
	}
	for i := range querido {
		if campos[i] != querido[i] {
			t.Fatalf("Ruleset executou %q, queria %q", ex.comandos[0], strings.Join(querido, " "))
		}
	}
}

// TestSaveNaoGravaConversaNoBanco: o backup do ruleset ia para o SQLite, e lá
// as tuplas não vencem.
//
// Isso derrubava as três propriedades que o pacote hostflows argumenta: a
// retenção de 5–1440 min virava PERMANENTE, o "nada é escrito em disco" virava
// uma linha de banco, e a permissão escolhida a dedo era contornada por
// firewall.read. O dump irrestrito nem servia para o que o backup faz: Restore
// já é escopado em LinkguardTableBlock, então tudo que não é a tabela do
// firewall naquele blob era peso morto que só vazava.
func TestSaveNaoGravaConversaNoBanco(t *testing.T) {
	ex := &execFalso{}
	s := &Service{exec: ex}
	if _, err := s.Save(context.Background()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, cmd := range ex.comandos {
		campos := strings.Fields(cmd)
		if campos[len(campos)-1] == "ruleset" {
			t.Errorf("Save executou %q: a janela inteira de conversas vai para iptables_backups, sem retenção", cmd)
		}
	}
}
