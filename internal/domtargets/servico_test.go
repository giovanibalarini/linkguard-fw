package domtargets

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// nftFalso é o kernel de mentira: guarda os lotes que recebeu e devolve o que
// o teste mandou ele "ter".
type nftFalso struct {
	mu     sync.Mutex
	lotes  []nftables.Lote
	kernel nftables.DomKernel
	erroLe error
}

func (n *nftFalso) AplicarLote(_ context.Context, l nftables.Lote) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lotes = append(n.lotes, l)
	return nil
}

func (n *nftFalso) DomElementos(context.Context) (nftables.DomKernel, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.erroLe != nil {
		return nftables.DomKernel{}, n.erroLe
	}
	return n.kernel, nil
}

func (n *nftFalso) quantos() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.lotes)
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
	s.idx.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})

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
		map[netip.Addr]Escrita{a: {Addr: a, Prazo: time.Hour, Capacidade: Barrar, Substituir: true}},
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
	l := montarLote(map[netip.Addr]Escrita{
		v4: {Addr: v4, Prazo: time.Hour, Capacidade: Barrar},
		v6: {Addr: v6, Prazo: time.Hour, Capacidade: Barrar},
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
	l := montarLote(map[netip.Addr]Escrita{
		v6: {Addr: v6, Prazo: time.Hour, Capacidade: Direcionar, Marca: 0x12c},
	}, nil)
	if !l.Vazio() {
		t.Fatalf("um v6 de domínio direcionado virou comando: %+v", l)
	}
}

// TestOMapDeDirecionamentoLevaAMarcaEOSetDeBloqueioNao.
func TestOMapDeDirecionamentoLevaAMarcaEOSetDeBloqueioNao(t *testing.T) {
	a, b := end(t, "8.8.8.8"), end(t, "1.1.1.1")
	l := montarLote(map[netip.Addr]Escrita{
		a: {Addr: a, Prazo: time.Hour, Capacidade: Direcionar, Marca: 0x12c},
		b: {Addr: b, Prazo: time.Hour, Capacidade: Barrar},
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
		map[netip.Addr]Escrita{a: {Addr: a, Prazo: time.Hour, Capacidade: Barrar, Substituir: true}},
		map[netip.Addr]Remocao{a: {Addr: a, Capacidade: Barrar}},
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
	nft := &nftFalso{kernel: nftables.DomKernel{
		Bloq: []netip.Addr{end(t, "8.8.8.8"), end(t, "9.9.9.9")},
	}}
	s := NovoServico(nft)
	s.idx.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
	// O índice conhece TRÊS endereços; o kernel só tem dois, e um dos que ele
	// tem (9.9.9.9) nenhum domínio reivindica.
	s.idx.Aprender("exemplo.com", []netip.Addr{
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
	if len(e.Dominios) != 1 || e.Dominios[0].NoKernel != 1 {
		t.Fatalf("o crédito por domínio não veio do kernel: %+v", e.Dominios)
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
	s.idx.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo}})
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
