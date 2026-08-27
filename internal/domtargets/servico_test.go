package domtargets

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// nftFalso é o kernel de mentira: guarda os lotes que recebeu e devolve o que
// o teste mandou ele "ter".
//
// segurar existe para o teste conseguir prender o alimentador DENTRO do
// AplicarLote, que é onde o produto de verdade fica preso: o executor tem teto
// de 30s e AplicarLote pode chamá-lo duas vezes. Um falso que devolve na hora
// prova a metade fácil do contrato.
type nftFalso struct {
	mu        sync.Mutex
	lotes     []nftables.Lote
	kernel    nftables.DomKernel
	erroLe    error
	erroLote  error
	resultado nftables.ResultadoLote
	segurar   chan struct{}
	dryRun    bool
}

func (n *nftFalso) AplicarLote(_ context.Context, l nftables.Lote) (nftables.ResultadoLote, error) {
	n.mu.Lock()
	n.lotes = append(n.lotes, l)
	prender := n.segurar
	res, err := n.resultado, n.erroLote
	n.mu.Unlock()
	if prender != nil {
		<-prender
	}
	return res, err
}

func (n *nftFalso) DomElementos(context.Context) (nftables.DomKernel, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.erroLe != nil {
		return nftables.DomKernel{}, n.erroLe
	}
	return n.kernel, nil
}

func (n *nftFalso) IsDryRun() bool { return n.dryRun }

func (n *nftFalso) quantos() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.lotes)
}

func (n *nftFalso) ultimo() nftables.Lote {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.lotes) == 0 {
		return nftables.Lote{}
	}
	return n.lotes[len(n.lotes)-1]
}

// kernelCheio é o DomKernel com as três estruturas marcadas como lidas, que é o
// que uma leitura bem-sucedida produz.
func kernelCheio(bloq, bloq6, wan []netip.Addr) nftables.DomKernel {
	return nftables.DomKernel{
		Bloq: bloq, Bloq6: bloq6, Wan: wan,
		LidoBloq: true, LidoBloq6: true, LidoWan: true,
	}
}

// TestObservarNuncaBloqueiaComAFilaCheia é o contrato inegociável do
// alimentador.
//
// Observar roda dentro do laço que DRENA o socket unix do unbound. Bloquear ali
// para de drenar, o buffer enche e o unbound passa a descartar entrega — quer
// dizer, contrapressão no resolver da rede inteira por causa de uma escrita de
// firewall. O que não cabe tem de ser contado e jogado fora, não esperado.
func TestObservarNuncaBloqueiaComAFilaCheia(t *testing.T) {
	s := NovoServico(nil) // sem Run: ninguém drena a fila
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Estagio: Ativo}})
	r := &dnstap.Resposta{Nome: "exemplo.com", Enderecos: []netip.Addr{end(t, "8.8.8.8")}, TTL: time.Minute}

	pronto := make(chan struct{})
	go func() {
		for n := 0; n < TamanhoDaFila*3; n++ {
			s.Observar(r)
		}
		close(pronto)
	}()
	select {
	case <-pronto:
	case <-time.After(2 * time.Second):
		t.Fatal("Observar bloqueou com a fila cheia — é contrapressão no unbound")
	}
	if s.Descartes() == 0 {
		t.Fatal("a fila encheu e nada foi contado como descarte")
	}
}

// TestObservarCopiaOsEnderecosDoChamador.
//
// O *dnstap.Resposta que chega aqui é o MESMO ponteiro que o mapa da #116
// acabou de receber, sem cópia pelo caminho. O alimentador o leva para outra
// goroutine e o guarda por até uma janela inteira; sem a cópia, isso é memória
// compartilhada entre dois donos e uma corrida esperando um refactor do outro
// lado.
func TestObservarCopiaOsEnderecosDoChamador(t *testing.T) {
	s := NovoServico(nil)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Estagio: Ativo}})
	addrs := []netip.Addr{end(t, "8.8.8.8")}
	s.Observar(&dnstap.Resposta{Nome: "exemplo.com", Enderecos: addrs, TTL: time.Minute})

	addrs[0] = end(t, "192.168.3.1") // o dono original mexeu depois

	o := <-s.fila
	if o.addrs[0] != end(t, "8.8.8.8") {
		t.Fatalf("o alimentador compartilhou memória com o chamador: %v", o.addrs[0])
	}
}

// TestUmaJanelaViraUmLoteSo prende a coalescência.
//
// Vinte máquinas abrindo a mesma página geram vinte respostas de DNS no mesmo
// instante. Sem a janela, isso seria vinte forks de nft e vinte transações
// netlink para escrever o mesmo punhado de endereços.
func TestUmaJanelaViraUmLoteSo(t *testing.T) {
	nft := &nftFalso{}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	for n := 1; n <= 20; n++ {
		s.Observar(&dnstap.Resposta{
			Nome:      "exemplo.com",
			Enderecos: []netip.Addr{netip.AddrFrom4([4]byte{8, 0, 0, byte(n)})},
			TTL:       time.Hour,
		})
	}

	prazo := time.After(3 * time.Second)
	for nft.quantos() == 0 {
		select {
		case <-prazo:
			t.Fatal("a janela fechou e nenhum lote saiu")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(2 * JanelaDeCoalescencia) // deixa um segundo lote aparecer, se houver
	if n := nft.quantos(); n != 1 {
		t.Fatalf("vinte respostas na mesma janela viraram %d lotes", n)
	}
	nft.mu.Lock()
	defer nft.mu.Unlock()
	if len(nft.lotes[0].AdicionarBloq) != 20 {
		t.Fatalf("o lote não juntou tudo: %d adições", len(nft.lotes[0].AdicionarBloq))
	}
}

// TestRenovacaoSaiComORemoverEOAdicionarDoMesmoEndereco.
//
// Medido no nft da caixa: um `add` sobre elemento existente é aceito em
// silêncio e NÃO renova o prazo. Se o lote saísse só com o `add`, "renovar"
// seria um comando que não faz nada e o endereço sairia no meio do uso — a
// falha mais cara possível, porque parece ter funcionado.
func TestRenovacaoSaiComORemoverEOAdicionarDoMesmoEndereco(t *testing.T) {
	a := end(t, "8.8.8.8")
	l := montarLote(
		[]Escrita{{Addr: a, Prazo: time.Hour, Capacidade: Barrar, Substituir: true}},
		nil,
	)
	if len(l.RemoverBloq) != 1 || l.RemoverBloq[0] != a {
		t.Fatalf("a renovação saiu sem a remoção: %+v", l.RemoverBloq)
	}
	if len(l.AdicionarBloq) != 1 || l.AdicionarBloq[0].Addr != a {
		t.Fatalf("a renovação saiu sem a adição: %+v", l.AdicionarBloq)
	}
}

// TestCadaFamiliaVaiParaASuaEstrutura.
//
// `dom_blocked` é `type ipv4_addr` e `dom_blocked6` é `type ipv6_addr`. Um
// endereço v6 mandado para o primeiro derruba o `nft -f` inteiro, e com ele
// TODOS os endereços daquela rodada — inclusive os que estavam certos.
func TestCadaFamiliaVaiParaASuaEstrutura(t *testing.T) {
	v4, v6 := end(t, "8.8.8.8"), end(t, "2606:4700::1111")
	l := montarLote([]Escrita{
		{Addr: v4, Prazo: time.Hour, Capacidade: Barrar},
		{Addr: v6, Prazo: time.Hour, Capacidade: Barrar},
	}, nil)
	if len(l.AdicionarBloq) != 1 || l.AdicionarBloq[0].Addr != v4 {
		t.Fatalf("o set v4 recebeu o que não devia: %+v", l.AdicionarBloq)
	}
	if len(l.AdicionarBloq6) != 1 || l.AdicionarBloq6[0].Addr != v6 {
		t.Fatalf("o set v6 recebeu o que não devia: %+v", l.AdicionarBloq6)
	}
}

// TestV6DeDominioDirecionadoNaoCaiNoSetDeBloqueio.
//
// Não existe par v6 do map de direcionamento, e é de propósito: não há política
// de rota v6 neste produto. O endereço v6 de um domínio DIRECIONADO tem de ser
// descartado, e nunca empurrado para o set de bloqueio — não conseguir
// direcionar é uma coisa; BARRAR o que o admin mandou direcionar é outra, e
// derruba o serviço que ele estava tentando priorizar.
func TestV6DeDominioDirecionadoNaoCaiNoSetDeBloqueio(t *testing.T) {
	v6 := end(t, "2606:4700::1111")
	l := montarLote([]Escrita{
		{Addr: v6, Prazo: time.Hour, Capacidade: Direcionar, Marca: 0x12c},
	}, nil)
	if !l.Vazio() {
		t.Fatalf("um v6 de domínio direcionado virou comando: %+v", l)
	}
}

// TestOMapDeDirecionamentoLevaAMarcaEOSetDeBloqueioNao.
func TestOMapDeDirecionamentoLevaAMarcaEOSetDeBloqueioNao(t *testing.T) {
	a, b := end(t, "8.8.8.8"), end(t, "1.1.1.1")
	l := montarLote([]Escrita{
		{Addr: a, Prazo: time.Hour, Capacidade: Direcionar, Marca: 0x12c},
		{Addr: b, Prazo: time.Hour, Capacidade: Barrar},
	}, nil)
	if len(l.AdicionarWan) != 1 || l.AdicionarWan[0].Marca != 0x12c {
		t.Fatalf("a marca não chegou ao map: %+v", l.AdicionarWan)
	}
	if len(l.AdicionarBloq) != 1 || l.AdicionarBloq[0].Marca != 0 {
		t.Fatalf("o set de bloqueio recebeu marca: %+v", l.AdicionarBloq)
	}
}

// TestNaoSaemDoisDeletesDoMesmoElemento.
//
// Um `delete` de elemento ausente derruba a transação inteira (medido). Dois
// `delete` do mesmo elemento no mesmo arquivo garantem que o segundo erre — o
// lote cai fora por um comando que a gente mesmo escreveu duas vezes.
func TestNaoSaemDoisDeletesDoMesmoElemento(t *testing.T) {
	a := end(t, "8.8.8.8")
	l := montarLote(
		[]Escrita{{Addr: a, Prazo: time.Hour, Capacidade: Barrar, Substituir: true}},
		[]Remocao{{Addr: a, Capacidade: Barrar}},
	)
	if len(l.RemoverBloq) != 1 {
		t.Fatalf("saíram %d remoções do mesmo elemento", len(l.RemoverBloq))
	}
}

// TestEstadoContaOKernelENaoAMemoria.
//
// O índice é um espelho, e espelho atrasa: o elemento pode ter expirado
// sozinho, o lote pode ter falhado, alguém pode ter dado flush por fora. Este
// produto já entregou uma tela que afirmava o que o kernel não tinha, e a
// diferença entre "o painel diz que está bloqueado" e "está bloqueado" é a
// única coisa que esta tela precisa acertar.
func TestEstadoContaOKernelENaoAMemoria(t *testing.T) {
	nft := &nftFalso{kernel: kernelCheio(
		[]netip.Addr{end(t, "8.8.8.8"), end(t, "9.9.9.9")}, nil, nil,
	)}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
	// O índice conhece TRÊS endereços; o kernel só tem dois, e um dos que ele
	// tem (9.9.9.9) nenhum domínio reivindica.
	aprender(t, s.idx, "exemplo.com", []netip.Addr{
		end(t, "8.8.8.8"), end(t, "1.1.1.1"), end(t, "4.4.4.4"),
	}, time.Hour)

	e := s.Estado(context.Background())
	if !e.KernelLido {
		t.Fatal("a leitura do kernel deu certo e o estado não marcou")
	}
	if e.Barrados != 2 {
		t.Fatalf("a contagem veio da memória: barrados=%d (o kernel tem 2)", e.Barrados)
	}
	if e.Orfaos != 1 {
		t.Fatalf("o endereço sem dono no kernel não apareceu: orfaos=%d", e.Orfaos)
	}
	if len(e.Dominios) != 1 || e.Dominios[0].NoKernel == nil || *e.Dominios[0].NoKernel != 1 {
		t.Fatalf("o crédito por domínio não veio do kernel: %+v", e.Dominios)
	}
	// E o par que denuncia a divergência sem reconciliação nenhuma: o índice
	// acha que escreveu três, o kernel tem um deste domínio.
	if e.Dominios[0].NoIndice != 3 {
		t.Fatalf("o que o índice acha que escreveu não apareceu: %+v", e.Dominios[0])
	}
	if e.Dominios[0].Rotatividade != 3 {
		t.Fatalf("a rotatividade (que é observação, não kernel) sumiu: %+v", e.Dominios[0])
	}
}

// TestEstadoSeparaVazioDeNaoConsegiuPerguntar.
//
// Um erro de leitura que virasse zero produziria uma tela dizendo que nada está
// bloqueado — a mentira mais cara que esta tela pode contar, porque o operador
// age em cima dela.
func TestEstadoSeparaVazioDeNaoConsegiuPerguntar(t *testing.T) {
	nft := &nftFalso{erroLe: errors.New("nft sumiu")}
	s := NovoServico(nft)
	e := s.Estado(context.Background())
	if e.KernelLido {
		t.Fatal("a leitura falhou e o estado disse que leu")
	}
	if e.KernelErro == "" {
		t.Fatal("a falha de leitura não foi dita")
	}
}

// TestSemAplicadorOAlimentadorAprendeENaoQuebra. Uma caixa sem nft configurado
// continua contando o que o DNS ensinou; o que ela não faz é escrever.
func TestSemAplicadorOAlimentadorAprendeENaoQuebra(t *testing.T) {
	s := NovoServico(nil)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	s.Observar(&dnstap.Resposta{Nome: "exemplo.com", Enderecos: []netip.Addr{end(t, "8.8.8.8")}, TTL: time.Hour})
	time.Sleep(3 * JanelaDeCoalescencia)

	e := s.Estado(ctx)
	if e.KernelLido {
		t.Fatal("sem aplicador não há kernel para ler, e o estado disse que leu")
	}
	if e.Contadores.Novos != 1 {
		t.Fatalf("o alimentador deixou de aprender sem nft: %+v", e.Contadores)
	}
}

// TestObservarNaoEnfileiraNomeQueNenhumDominioCobre.
//
// A fila de 256 é o único amortecedor entre o laço que drena o unbound e o
// consumidor. Sem filtro ela é preenchida quase inteira por ruído — google.com,
// telemetria de celular — e a resposta do domínio LISTADO disputa vaga com ele:
// quando o consumidor atrasa, o descarte fica enviesado CONTRA o que interessa,
// na proporção do tráfego que não interessa.
//
// E numa caixa sem nenhum domínio listado, que é o estado de toda instalação
// desta entrega, cada resposta de DNS da rede acordava uma goroutine, pegava um
// mutex e fazia caminhada de rótulos para nada.
func TestObservarNaoEnfileiraNomeQueNenhumDominioCobre(t *testing.T) {
	s := NovoServico(nil)
	s.DefinirAlvos([]Alvo{{Dominio: "netflix.com", Estagio: Ativo}})

	for n := 0; n < TamanhoDaFila*2; n++ {
		s.Observar(&dnstap.Resposta{
			Nome:      "windowsupdate.com",
			Enderecos: []netip.Addr{end(t, "8.8.8.8")},
			TTL:       time.Minute,
		})
	}
	if len(s.fila) != 0 {
		t.Fatalf("ruído entrou na fila: %d", len(s.fila))
	}
	if s.Descartes() != 0 {
		t.Fatalf("ruído foi contado como descarte e apaga o número que explica o sintoma real: %d", s.Descartes())
	}

	// O sinal continua entrando, e é ele que a fila mede.
	s.Observar(&dnstap.Resposta{
		Nome:      "www.netflix.com",
		Enderecos: []netip.Addr{end(t, "8.8.8.8")},
		TTL:       time.Minute,
	})
	if len(s.fila) != 1 {
		t.Fatalf("o domínio listado não entrou na fila: %d", len(s.fila))
	}
}

// esperarAte roda a condição até ela valer, ou falha. Existe porque o
// alimentador é assíncrono por desenho e todo teste dele precisaria do mesmo
// laço com sleep.
func esperarAte(t *testing.T, cond func() bool) {
	t.Helper()
	prazo := time.Now().Add(3 * time.Second)
	for time.Now().Before(prazo) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("a condição não valeu dentro do prazo")
}

// TestLoteQueFalhaNaoDeixaOIndiceAcharQueEscreveu.
//
// O defeito: Aprender gravava expira, escritoCap e escritoMarca ANTES de
// qualquer contato com o kernel. Se o lote falhava de vez, o endereço nunca
// entrava e o índice achava que sim — a próxima resposta caía em SemComando, e
// ele só voltaria a ser emitido depois de 2/3 do prazo. Com o piso de dez
// minutos e o teto de uma hora, isso é de 6,7 a 40 minutos de firewall não
// barrando o que a tela mostra barrado.
//
// "Volta sozinho" é verdade na mecânica e enganoso na conclusão.
func TestLoteQueFalhaNaoDeixaOIndiceAcharQueEscreveu(t *testing.T) {
	nft := &nftFalso{erroLote: errors.New("nft recusou")}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	r := &dnstap.Resposta{
		Nome:      "exemplo.com",
		Enderecos: []netip.Addr{end(t, "8.8.8.8")},
		TTL:       time.Hour,
	}
	s.Observar(r)
	esperarAte(t, func() bool { return s.idx.Contadores().NaoConfirmados == 1 })

	// O índice não pode ter guardado o endereço: ele nunca chegou ao kernel, e
	// guardá-lo consome vaga dos dois tetos por um bloqueio que não existe.
	if c := s.idx.Contadores(); c.Vivos != 0 {
		t.Fatalf("o índice guardou o que o kernel não recebeu: vivos=%d", c.Vivos)
	}

	// E a próxima resposta reemite NA HORA, em vez de esperar 2/3 do prazo.
	s.Observar(r)
	esperarAte(t, func() bool { return nft.quantos() == 2 })
	l := nft.ultimo()
	if len(l.AdicionarBloq) != 1 {
		t.Fatalf("o reensino não saiu: %+v", l)
	}
	if len(l.RemoverBloq) != 0 {
		t.Fatal("o reensino saiu com delete de um elemento que nunca entrou — derruba a transação inteira")
	}
}

// TestOAlimentadorContinuaAprendendoComOKernelPreso.
//
// O caso que quebrava o produto e que o teste anterior não pegava: o consumidor
// PRESO dentro do AplicarLote. Com o fork do nft dentro do select do Run, o
// case da fila não era avaliado enquanto o nft estivesse de pé — e o teto é de
// 30s por chamada, duas chamadas por lote. Sessenta segundos em que TODA
// observação era descartada, inclusive a do endereço novo do domínio que acabou
// de ser promovido.
//
// O que este teste prende não é "Observar retorna" (isso o outro já prende),
// é QUANTO TEMPO o alimentador fica cego. Com a escritora separada, a resposta
// é: nada.
func TestOAlimentadorContinuaAprendendoComOKernelPreso(t *testing.T) {
	soltar := make(chan struct{})
	nft := &nftFalso{segurar: soltar}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	// Primeira resposta: vira lote, e a escritora fica presa nele.
	s.Observar(&dnstap.Resposta{
		Nome:      "exemplo.com",
		Enderecos: []netip.Addr{end(t, "8.8.8.1")},
		TTL:       time.Hour,
	})
	esperarAte(t, func() bool { return nft.quantos() == 1 })

	// Com a escritora presa, o alimentador tem de continuar drenando a fila.
	for n := 2; n <= 50; n++ {
		s.Observar(&dnstap.Resposta{
			Nome:      "exemplo.com",
			Enderecos: []netip.Addr{netip.AddrFrom4([4]byte{8, 0, 0, byte(n)})},
			TTL:       time.Hour,
		})
	}
	esperarAte(t, func() bool { return s.idx.Contadores().Novos == 50 })
	if s.Descartes() != 0 {
		t.Fatalf("o alimentador descartou com a escritora presa: %d", s.Descartes())
	}
	close(soltar)
}

// TestDefinirAlvosNaoPenduraComOKernelPreso.
//
// O ajuste ia por um canal de dados com fundo 8. Com o Run atrasado — e ele
// ficava atrasado até sessenta segundos por lote — a chamada ficava PENDURADA,
// e o ctx que ela recebia era o de vida do processo: não voltava nunca. No boot
// isso é uma goroutine vazando em silêncio; na parte 4, com a API chamando
// isto de um handler, é a requisição do admin pendurada.
func TestDefinirAlvosNaoPenduraComOKernelPreso(t *testing.T) {
	soltar := make(chan struct{})
	nft := &nftFalso{segurar: soltar}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	s.Observar(&dnstap.Resposta{
		Nome:      "exemplo.com",
		Enderecos: []netip.Addr{end(t, "8.8.8.8")},
		TTL:       time.Hour,
	})
	esperarAte(t, func() bool { return nft.quantos() == 1 })

	// A escritora está presa. Trinta trocas de lista não podem pendurar
	// ninguém, e o fundo do canal antigo era oito.
	pronto := make(chan struct{})
	go func() {
		for n := 0; n < 30; n++ {
			s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ensaio}})
			s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
		}
		close(pronto)
	}()
	select {
	case <-pronto:
	case <-time.After(5 * time.Second):
		t.Fatal("DefinirAlvos pendurou com a escritora presa")
	}
	close(soltar)
}

// TestOLacoEhReerguidoDepoisDeUmPanicoEIssoAparece.
//
// Sem recover, um pânico no laço derruba o consumidor e o desenho passa a
// funcionar AO CONTRÁRIO do que deveria: Observar continua não bloqueando (o
// resolver sobrevive, que é o certo), a fila enche em segundos, e cada resposta
// de DNS da caixa passa a incrementar descartes para sempre. Enquanto isso
// Estado continua devolvendo KernelLido true e as contagens do kernel — que são
// reais, só que de elementos que ninguém renova mais e que vão vencer sozinhos
// ao longo da hora seguinte.
//
// Quer dizer: a tela afirmaria que o alimentador está vivo com ele morto. Por
// isso o teste cobra as duas coisas — que ele volte, E que o pânico apareça.
func TestOLacoEhReerguidoDepoisDeUmPanicoEIssoAparece(t *testing.T) {
	var vezes atomic.Int64
	s := NovoServico(nil)
	s.DefinirFonteDeProtegidos(func() []netip.Prefix {
		if vezes.Add(1) == 1 {
			panic("a fonte de protegidos explodiu")
		}
		return nil
	})
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	esperarAte(t, func() bool { return s.Estado(ctx).Reinicios == 1 })

	// E reerguido quer dizer FUNCIONANDO, não só de pé.
	s.Observar(&dnstap.Resposta{
		Nome:      "exemplo.com",
		Enderecos: []netip.Addr{end(t, "8.8.8.8")},
		TTL:       time.Hour,
	})
	esperarAte(t, func() bool { return s.idx.Contadores().Novos == 1 })
	if e := s.Estado(ctx); !e.Vivo {
		t.Fatal("o alimentador está rodando e o estado diz que não")
	}
}

// TestARemocaoQueOReenvioPerdeVoltaParaAFila.
//
// O reenvio entra sem os delete. As remoções que ele deixa para trás são a
// metade cara: uma remoção perdida é o kernel continuar barrando por até uma
// hora um domínio que a tela já mostra desligado — palavra por palavra o
// defeito que o doc-comment de DefinirAlvos diz existir para impedir.
//
// Ela volta para a fila, e não para sempre: o motivo mais provável de o delete
// ter falhado é o elemento já não existir, e insistir seria um fork por janela.
// Ao desistir, o número aparece.
func TestARemocaoQueOReenvioPerdeVoltaParaAFila(t *testing.T) {
	a := end(t, "8.8.8.8")
	nft := &nftFalso{resultado: nftables.ResultadoLote{
		Reenviado:        true,
		RemocoesPerdidas: []netip.Addr{a},
	}}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

	ctx, cancelar := context.WithCancel(context.Background())
	defer cancelar()
	go s.Run(ctx)

	s.Observar(&dnstap.Resposta{Nome: "exemplo.com", Enderecos: []netip.Addr{a}, TTL: time.Hour})
	// Espera a CONFIRMAÇÃO, e não o lote: sem ela o índice ainda não acredita
	// que o endereço está no kernel, e a remoção nem seria emitida.
	esperarAte(t, func() bool { return s.idx.Contadores().Confirmados == 1 })

	// Baixar para ensaio manda tirar o endereço do kernel. O falso vai dizer
	// que a remoção ficou para trás.
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ensaio}})

	// Ela tem de ser TENTADA de novo, e depois desistida com o número à vista.
	esperarAte(t, func() bool { return s.Estado(ctx).RemocoesDesistidas == 1 })
	deletes := 0
	nft.mu.Lock()
	for _, l := range nft.lotes {
		deletes += len(l.RemoverBloq)
	}
	nft.mu.Unlock()
	if deletes < 2 {
		t.Fatalf("a remoção perdida não voltou para a fila: %d delete(s) no total", deletes)
	}
}

// TestSemLerOKernelALinhaDoDominioNaoAfirmaZero.
//
// Um domínio ativo e barrando com NoKernel igual a 0 renderiza igual em três
// situações completamente diferentes: ninguém consultou o nome ainda (normal),
// os endereços venceram e o índice não sabe (bug), e a leitura do kernel
// falhou. A terceira é a cara: com um int cru, uma falha de nft faz TRINTA
// domínios ativos aparecerem como se nada estivesse bloqueado.
//
// Por isso NoKernel é ponteiro: nil é "não consegui perguntar" e zero é
// "perguntei e não tem". E NoIndice fica ao lado, para a divergência
// aparecer sem reconciliação nenhuma.
func TestSemLerOKernelALinhaDoDominioNaoAfirmaZero(t *testing.T) {
	nft := &nftFalso{erroLe: errors.New("sem CAP_NET_ADMIN")}
	s := NovoServico(nft)
	s.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
	aprender(t, s.idx, "exemplo.com", []netip.Addr{end(t, "8.8.8.8")}, time.Hour)

	e := s.Estado(context.Background())
	if e.KernelLido {
		t.Fatal("a leitura falhou e o estado disse que leu")
	}
	if len(e.Dominios) != 1 {
		t.Fatalf("a linha do domínio sumiu: %+v", e.Dominios)
	}
	if e.Dominios[0].NoKernel != nil {
		t.Fatalf("a tela afirmou uma contagem do kernel sem ter conseguido lê-lo: %v", *e.Dominios[0].NoKernel)
	}
	if e.Dominios[0].NoIndice != 1 {
		t.Fatalf("o que o índice acha que escreveu não aparece: %+v", e.Dominios[0])
	}
}

// TestObservandoSeparaNinguemAcessouDeNaoEstouOlhando.
//
// O alvo por domínio aprende SÓ pelo dnstap. Com o coletor desligado o
// alimentador sobe e roda feliz — Vivo continua true, o laço está de pé —, mas
// Observar nunca é chamado, e a tela mostra rotatividade zero e último
// aprendizado zero em todo domínio listado. Igualzinho a "ninguém acessou estes
// nomes", e as duas leituras levam a ações opostas: promover um domínio achando
// que ele é inofensivo, ou dar um bloqueio por funcionando quando ele não pode
// funcionar.
func TestObservandoSeparaNinguemAcessouDeNaoEstouOlhando(t *testing.T) {
	ctx := context.Background()

	s := NovoServico(nil)
	if v := s.Estado(ctx).Observando; v != nil {
		t.Errorf("sem fonte ligada, Observando devia ser nil (não sei); veio %v", *v)
	}

	s.DefinirFonteDeObservacao(func() bool { return false })
	v := s.Estado(ctx).Observando
	if v == nil || *v {
		t.Fatalf("coletor desligado devia dar false; veio %v", v)
	}

	// E a leitura é A CADA CHAMADA: o admin liga o dnstap na tela de serviços
	// de rede sem reiniciar nada, e um valor congelado no arranque estaria
	// errado a partir do primeiro clique.
	ligado := false
	s.DefinirFonteDeObservacao(func() bool { return ligado })
	if v := s.Estado(ctx).Observando; v == nil || *v {
		t.Fatal("devia estar desligado ainda")
	}
	ligado = true
	if v := s.Estado(ctx).Observando; v == nil || !*v {
		t.Fatal("ligar o coletor não mudou a resposta: o valor ficou congelado no arranque")
	}
}
