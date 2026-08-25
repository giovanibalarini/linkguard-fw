package hostflows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Os testes deste arquivo prendem os defeitos achados na revisão da #115. Cada
// um FALHA sem o conserto correspondente — ver a tabela de mutação do relatório.

// fwQueSomeAMedicao devolve ErrFlowsAusente até alguém chamar EnsureFlows —
// que é exatamente o que acontece numa caixa onde o upgrade do pacote nftables
// varreu o ruleset vivo.
type fwQueSomeAMedicao struct {
	montada   bool
	snap      nftables.FlowSnapshot
	montagens int
	leituras  int
}

func (f *fwQueSomeAMedicao) EnsureFlows(_ context.Context, wans []string, _ nftables.FlowsConfig) error {
	f.montagens++
	if len(wans) == 0 {
		return nftables.ErrSemWAN
	}
	f.montada = true
	return nil
}

func (f *fwQueSomeAMedicao) DisableFlows(context.Context) error { f.montada = false; return nil }

func (f *fwQueSomeAMedicao) Flows(context.Context) (nftables.FlowSnapshot, error) {
	f.leituras++
	if !f.montada {
		return nftables.FlowSnapshot{}, nftables.ErrFlowsAusente
	}
	return f.snap, nil
}

// TestConsultarRemontaAMedicaoQueSumiuNoUpgradeDoNftables.
//
// O DEFEITO: a tabela tem exatamente dois criadores — o boot e a mudança de
// link — e nenhum dos dois roda de novo sozinho. Como a unidade nftables do
// Debian faz flush do ruleset no ExecStop, e o bootstrapdeps HABILITA essa
// unidade, um upgrade do pacote nftables varria a tabela e a feature ficava
// morta até alguém reiniciar o serviço, com um 500 genérico como único sinal.
func TestConsultarRemontaAMedicaoQueSumiuNoUpgradeDoNftables(t *testing.T) {
	fw := &fwQueSomeAMedicao{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	// A lista de WANs é a que o boot/mudança de link já passou.
	if err := s.Reconciliar(context.Background(), []string{"wan1"}); err != nil {
		t.Fatalf("Reconciliar: %v", err)
	}
	// O upgrade do pacote varre o ruleset vivo.
	fw.montada = false
	s.invalidarCache()

	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar depois do flush: %v", err)
	}
	if !res.Montada {
		t.Fatalf("a medição não foi remontada sozinha: %+v", res)
	}
	if len(res.Conversas) == 0 {
		t.Error("remontou mas devolveu lista vazia")
	}
}

// TestConsultarNaoDisfarcaMedicaoAusenteDeSilencio.
//
// Quando a remontagem NÃO pega (por exemplo, sem lista de WANs conhecida), o
// que a tela recebe tem de ser um TERCEIRO estado. Lista vazia diria "este
// aparelho não falou com ninguém", que é falso; um 500 genérico diria "não sei",
// perdendo uma causa e um conserto que são conhecidos.
func TestConsultarNaoDisfarcaMedicaoAusenteDeSilencio(t *testing.T) {
	fw := &fwQueSomeAMedicao{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	// Sem Reconciliar: o serviço não conhece WAN nenhuma, então não remonta.
	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("medição ausente virou erro de servidor: %v", err)
	}
	if !res.Ligado {
		t.Error("ligado=false: a tela vai mostrar o convite para LIGAR uma feature que já está ligada")
	}
	if res.Montada {
		t.Error("montada=true com a tabela ausente")
	}
	if len(res.Conversas) != 0 {
		t.Error("devolveu conversa com a medição ausente")
	}
}

// TestCheioNaoDesapareceQuandoOSetEsvazia prende o aviso PEGAJOSO.
//
// O DEFEITO: `Cheio` é uma igualdade instantânea contra o teto, e os elementos
// expiram sem parar. Um set que estourou o teto às 3h05 e descartou milhares de
// conversas pode estar em 60% às 3h20 — e o aviso sumia, com o silêncio dele se
// lendo como "nada se perdeu". O dnstap.Mapa guarda um `cheio` pegajoso por
// exatamente esta razão; esta entrega citava aquele precedente e implementava o
// oposto.
func TestCheioNaoDesapareceQuandoOSetEsvazia(t *testing.T) {
	fw := &fwFalso{snap: nftables.FlowSnapshot{
		Fluxos: amostra, JanelaMinutos: 60, Teto: 3, Ocupacao: 3, Cheio: true,
	}}
	s := NovoServico(fw, bancoLigado(60, 8192))
	relogio := time.Now()
	s.agora = func() time.Time { return relogio }

	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if !res.Cheio || !res.JaEsteveCheio {
		t.Fatalf("primeira leitura: cheio=%v ja=%v", res.Cheio, res.JaEsteveCheio)
	}

	// As tuplas vencem e o set folga. O instantâneo deixa de estar cheio.
	fw.snap = nftables.FlowSnapshot{Fluxos: amostra, JanelaMinutos: 60, Teto: 3000, Ocupacao: 3}
	relogio = relogio.Add(2 * ValidadeDoCache)

	res2, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("segunda consulta: %v", err)
	}
	if res2.Cheio {
		t.Error("o instantâneo deveria ter deixado de estar cheio")
	}
	if !res2.JaEsteveCheio {
		t.Error("o aviso sumiu: a tela vai deixar o admin concluir que nada se perdeu nesta janela")
	}
}

// TestSalvarConfigZeraOAvisoPegajoso: o pegajoso afirma "encheu em algum
// momento DESTA janela", e salvar a configuração recria o set do zero — a
// janela de que ele falava deixou de existir. Sem isto, um aviso de ontem
// grudaria para sempre.
func TestSalvarConfigZeraOAvisoPegajoso(t *testing.T) {
	fw := &fwFalso{snap: nftables.FlowSnapshot{
		Fluxos: amostra, JanelaMinutos: 60, Teto: 3, Ocupacao: 3, Cheio: true,
	}}
	s := NovoServico(fw, bancoLigado(60, 8192))
	if _, err := s.Consultar(context.Background(), "", 50); err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if !s.jaEsteveCheioAgora() {
		t.Fatal("não marcou o pegajoso")
	}

	fw.snap = nftables.FlowSnapshot{Fluxos: amostra, JanelaMinutos: 15, Teto: 9000, Ocupacao: 3}
	if err := s.SalvarConfig(context.Background(),
		nftables.FlowsConfig{Ligado: true, JanelaMinutos: 15, Teto: 9000}, []string{"wan1"}); err != nil {
		t.Fatalf("SalvarConfig: %v", err)
	}
	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if res.JaEsteveCheio {
		t.Error("o aviso sobreviveu à recriação do set: ele fala de uma janela que não existe mais")
	}
}

// TestNomesLigadosSegueOColetorNaoOPonteiro.
//
// O DEFEITO: a resposta dizia `nomes_ligados: s.nomes != nil`, e o main.go chama
// SetNomes INCONDICIONALMENTE com dnstap.Servico.Mapa(), que nunca é nil. O
// campo era `true` em todo binário de produção, e o aviso "o mapa de nomes está
// desligado — ligue-o em Serviços de rede" era código morto. Quem tinha o dnstap
// desligado via uma tabela inteira de números crus sem explicação nenhuma —
// exatamente o defeito que o comentário do main.go diz estar prevenindo.
func TestNomesLigadosSegueOColetorNaoOPonteiro(t *testing.T) {
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	// Ponteiro NÃO-NIL, coletor DESLIGADO: é o estado de toda caixa com dnstap
	// desligado, e era o que se disfarçava de "mapa disponível".
	s.SetNomes(nomesFalsos{"8.8.8.8": "dns.google"}, coletorDesligado)

	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if res.NomesLigados {
		t.Error("nomes_ligados=true com o coletor desligado: o aviso da tela vira código morto")
	}
	// E não pode batizar nada: um nome vindo de um mapa que ninguém alimenta é
	// um nome velho apresentado como fato de agora.
	for _, c := range res.Conversas {
		if c.Nome != "" {
			t.Errorf("batizou %s com o coletor desligado: %q", c.Destino, c.Nome)
		}
	}
}

// TestRespostaCarregaOTetoBatidoDoMapaDeNomes: um destino sem nome tem duas
// causas que a tela precisa separar — o DNS nunca viu, ou viu e a entrada foi
// despejada para caber outra. A interface Nomes só expunha Nome(), então a
// segunda causa morria na fronteira do pacote.
func TestRespostaCarregaOTetoBatidoDoMapaDeNomes(t *testing.T) {
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	s.SetNomes(nomesCheios{"8.8.8.8": "dns.google"}, coletorLigado)

	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if !res.NomesCheio {
		t.Error("o mapa despejou entrada por teto e a tela não tem como dizer isso")
	}
}

// TestRespostaCarimbaAHoraDaLeituraDoKernel.
//
// O DEFEITO: o componente busca uma vez e fica parado enquanto o modal estiver
// aberto. Sem a hora da leitura, nada na tela distingue um número de agora de um
// de quarenta minutos atrás — que é o mesmo congelamento que o cache deste
// pacote recusa cometer do lado dele.
//
// O carimbo é o da LEITURA DO KERNEL, não o da serialização: servida do cache, a
// resposta tem de continuar dizendo quando o kernel foi lido de verdade.
func TestRespostaCarimbaAHoraDaLeituraDoKernel(t *testing.T) {
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	relogio := time.Now()
	s.agora = func() time.Time { return relogio }

	res, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if res.LidoEm.IsZero() {
		t.Fatal("sem carimbo: a tela não consegue dizer de quando é o número")
	}
	lidoEm := res.LidoEm

	// Dentro da validade do cache o kernel NÃO é relido — e o carimbo tem de
	// continuar apontando para a leitura de verdade, não para agora.
	relogio = relogio.Add(ValidadeDoCache / 2)
	res2, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("segunda consulta: %v", err)
	}
	if fw.leituras != 1 {
		t.Fatalf("o cache não segurou a segunda leitura: %d", fw.leituras)
	}
	if !res2.LidoEm.Equal(lidoEm) {
		t.Errorf("resposta de cache carimbou %v, mas o kernel foi lido em %v", res2.LidoEm, lidoEm)
	}
}

// TestSalvarConfigPropagaARecusaDeMontarSemWAN.
//
// O DEFEITO: EnsureFlows devolvia nil sem WAN, SalvarConfig lia isso como
// sucesso e o handler respondia 200 com ligado=true. O admin clicava "Ligar
// registro", recebia sucesso, e caía numa falha de leitura sem nenhuma pista de
// que a causa era a lista de WANs vazia.
//
// A configuração CONTINUA gravada — é o comportamento certo: a escolha do admin
// vale, e passa a produzir medição quando houver um link WAN.
func TestSalvarConfigPropagaARecusaDeMontarSemWAN(t *testing.T) {
	fw := &fwQueSomeAMedicao{snap: instantaneoDeTeste()}
	banco := &bancoFalso{}
	s := NovoServico(fw, banco)

	err := s.SalvarConfig(context.Background(),
		nftables.FlowsConfig{Ligado: true, JanelaMinutos: 60, Teto: 8192}, nil)
	if !errors.Is(err, nftables.ErrSemWAN) {
		t.Fatalf("queria ErrSemWAN, veio %v: a tela vai dizer LIGADO sobre um kernel vazio", err)
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if !cfg.Ligado {
		t.Error("a escolha do admin foi descartada junto com a recusa de montar")
	}
}

// TestConsultasSeguidasNaoRefazemOSortDoSetInteiro.
//
// agregar aloca uma linha por tupla e ordena o set INTEIRO a cada chamada. Com
// o teto máximo isso é milhões de bytes de alocação e um O(n log n) por
// requisição, numa appliance de 2 GB — e era justamente o custo que o comentário
// de ValidadeDoCache dizia estar protegendo e não protegia: o cache poupava o
// `nft list set` e deixava o sort passar inteiro.
func TestConsultasSeguidasNaoRefazemOSortDoSetInteiro(t *testing.T) {
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	relogio := time.Now()
	s.agora = func() time.Time { return relogio }

	primeira, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	segunda, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	// A mesma pergunta sobre o mesmo instantâneo tem de devolver a MESMA fatia,
	// não uma recém-ordenada.
	if len(primeira.Conversas) == 0 {
		t.Fatal("sem conversas para comparar")
	}
	if &primeira.Conversas[0] != &segunda.Conversas[0] {
		t.Error("a agregação foi refeita: o sort do set inteiro roda a cada requisição, com o cache quente")
	}

	// Vencido o cache, tudo é refeito — um agregado que sobrevivesse ao
	// instantâneo que o gerou seria o congelamento que o cache existe para
	// impedir.
	relogio = relogio.Add(2 * ValidadeDoCache)
	terceira, err := s.Consultar(context.Background(), "", 50)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if &terceira.Conversas[0] == &segunda.Conversas[0] {
		t.Error("o agregado sobreviveu ao vencimento do instantâneo")
	}
}
