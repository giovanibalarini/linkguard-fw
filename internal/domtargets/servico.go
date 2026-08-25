package domtargets

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// O alimentador (#123, terceira parte).
//
// A FORMA DELE É DITADA POR ONDE ELE É CHAMADO. Observar roda dentro do laço
// que lê o frame stream do unbound (internal/dnstap/servico.go, logo depois do
// Aprender do mapa). Aquele laço é o que drena o socket unix: parar ali é parar
// de drenar, o buffer enche e o unbound passa a descartar entrega — quer dizer,
// contrapressão no resolver da rede inteira por causa de uma escrita de
// firewall. Por isso Observar NUNCA bloqueia: é um envio com `default` numa
// fila com fundo, e o que não cabe é CONTADO e jogado fora.
//
// Perder observação é aceitável e travar o DNS não é. Um endereço descartado
// aqui volta na próxima resposta — o cliente reconsulta a cada TTL, e o TTL de
// quem tem muitos clientes é curto. Um resolver travado não volta.
//
// A JANELA DE 200 ms existe pelo mesmo motivo pelo qual o lote existe: cada
// rodada é um fork de nft e uma transação netlink. Vinte máquinas abrindo a
// mesma página geram vinte respostas de DNS no mesmo instante, e sem a janela
// isso seria vinte forks para escrever o mesmo punhado de endereços. Duzentos
// milissegundos é curto o bastante para ninguém perceber e longo o bastante
// para juntar a rajada.
//
// ESTA PARTE NÃO MUDA UM PACOTE. As estruturas que ele enche não são olhadas
// por nenhuma chain — ver o cabeçalho de internal/nftables/dominios.go. E
// nenhum domínio nasce fora do ensaio, então o caminho de escrita existe e fica
// parado até alguém promover um domínio, o que nesta parte nenhum código faz.

// Aplicador é o pedaço do nftables.Service de que o alimentador precisa.
//
// É uma interface e não o tipo concreto porque o teste desta parte não pode
// depender de ter nft na máquina — e porque escrever no kernel é exatamente a
// fronteira que a parte pura deste pacote não atravessa.
type Aplicador interface {
	AplicarLote(ctx context.Context, l nftables.Lote) error
	DomElementos(ctx context.Context) (nftables.DomKernel, error)
}

const (
	// TamanhoDaFila é o fundo do canal entre o laço do dnstap e o alimentador.
	//
	// Duzentos e cinquenta e seis cobre com folga a rajada de uma rede de
	// escritório. Maior não ajudaria: se o alimentador está atrás por mais que
	// isso, ele está atrás de um problema que fila nenhuma resolve, e o que
	// importa nesse caso é o contador de descartes SUBIR e aparecer.
	TamanhoDaFila = 256

	// JanelaDeCoalescencia é quanto o alimentador junta antes de escrever.
	JanelaDeCoalescencia = 200 * time.Millisecond

	// CadenciaDePoda é de quanto em quanto tempo o índice esquece o que já
	// venceu no kernel. Não gera comando — ver Indice.Podar.
	CadenciaDePoda = time.Minute
)

// observacao é a cópia do que a resposta ensinou.
//
// É CÓPIA de propósito. O *dnstap.Resposta que chega em Observar é o MESMO
// ponteiro que o mapa da #116 acabou de receber, sem cópia pelo caminho. Hoje o
// Aprender de lá só lê, mas o alimentador levaria esse ponteiro para outra
// goroutine e o guardaria por até uma janela inteira — e leitura compartilhada
// que funciona por acidente é a que quebra na primeira mudança do outro lado.
type observacao struct {
	nome  string
	addrs []netip.Addr
	ttl   time.Duration
}

// Servico é o alimentador.
type Servico struct {
	idx *Indice
	nft Aplicador

	fila    chan observacao
	ajustes chan Ajuste

	descartes   atomic.Uint64
	lotes       atomic.Uint64
	errosDeLote atomic.Uint64

	// pendEscritas e pendRemocoes acumulam dentro da janela e são tocados SÓ
	// pela goroutine do Run. Mapa e não lista porque o mesmo endereço reensinado
	// duas vezes na mesma janela tem de virar UMA linha: duas viram um `delete`
	// depois do `add` que acabou de entrar.
	pendEscritas map[netip.Addr]Escrita
	pendRemocoes map[netip.Addr]Remocao
}

// NovoServico cria o alimentador. nft nil é legítimo — o alimentador continua
// aprendendo e contando, e não escreve nada.
func NovoServico(nft Aplicador) *Servico {
	return &Servico{
		idx:          NovoIndice(nil),
		nft:          nft,
		fila:         make(chan observacao, TamanhoDaFila),
		ajustes:      make(chan Ajuste, 8),
		pendEscritas: map[netip.Addr]Escrita{},
		pendRemocoes: map[netip.Addr]Remocao{},
	}
}

// Indice devolve o índice, para quem precisa consultar a lista de domínios.
func (s *Servico) Indice() *Indice { return s.idx }

// Observar recebe o que uma resposta de DNS ensinou. NUNCA BLOQUEIA.
//
// Ver o cabeçalho do arquivo para por que essa é a única propriedade
// inegociável desta função: quem chama é o laço que drena o socket do unbound.
func (s *Servico) Observar(r *dnstap.Resposta) {
	if s == nil || r == nil || r.Nome == "" || len(r.Enderecos) == 0 {
		return
	}
	o := observacao{
		nome:  r.Nome,
		ttl:   r.TTL,
		addrs: append(make([]netip.Addr, 0, len(r.Enderecos)), r.Enderecos...),
	}
	select {
	case s.fila <- o:
	default:
		s.descartes.Add(1)
	}
}

// Descartes é quantas observações não couberam na fila.
//
// Precisa aparecer na tela. Um alimentador que descarta está aprendendo menos
// endereços do que o resolver ensinou, e o sintoma para quem usa é "às vezes
// passa" — o pior tipo de relato de bloqueio, e o único jeito de explicá-lo é
// este número.
func (s *Servico) Descartes() uint64 { return s.descartes.Load() }

// DefinirAlvos troca a lista de domínios e agenda o que a troca exige do
// kernel.
//
// O ajuste vai pela mesma janela do resto em vez de aplicar na hora: é a
// goroutine do Run que é dona das listas pendentes, e deixar a goroutine da API
// mexer nelas seria uma corrida sobre o que vai para o firewall. Duzentos
// milissegundos de atraso numa mudança de política ninguém percebe.
func (s *Servico) DefinirAlvos(ctx context.Context, alvos []Alvo) {
	aj := s.idx.DefinirAlvos(alvos)
	if aj.Vazio() {
		return
	}
	select {
	case s.ajustes <- aj:
	case <-ctx.Done():
	}
}

// Run junta o que chegou e escreve uma vez por janela.
func (s *Servico) Run(ctx context.Context) {
	// Timer parado, armado só quando existe o que escrever: um ticker de 200 ms
	// acordaria cinco vezes por segundo, para sempre, numa caixa que passa a
	// maior parte do tempo sem um único domínio listado.
	janela := time.NewTimer(time.Hour)
	if !janela.Stop() {
		<-janela.C
	}
	armada := false
	poda := time.NewTicker(CadenciaDePoda)
	defer poda.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case o := <-s.fila:
			s.absorver(o)
		case aj := <-s.ajustes:
			s.acumular(aj.Escritas, aj.Remocoes)
		case <-janela.C:
			armada = false
			s.descarregar(ctx)
			continue
		case <-poda.C:
			s.idx.Podar()
			continue
		}
		if !armada && (len(s.pendEscritas) > 0 || len(s.pendRemocoes) > 0) {
			janela.Reset(JanelaDeCoalescencia)
			armada = true
		}
	}
}

func (s *Servico) absorver(o observacao) {
	aj := s.idx.Aprender(o.nome, o.addrs, o.ttl)
	s.acumular(aj.Escritas, aj.Remocoes)
}

func (s *Servico) acumular(es []Escrita, rs []Remocao) {
	for _, r := range rs {
		s.pendRemocoes[r.Addr] = r
	}
	for _, e := range es {
		s.pendEscritas[e.Addr] = e
	}
}

// descarregar monta um Lote com tudo que se juntou e o aplica UMA vez.
func (s *Servico) descarregar(ctx context.Context) {
	if len(s.pendEscritas) == 0 && len(s.pendRemocoes) == 0 {
		return
	}
	lote := montarLote(s.pendEscritas, s.pendRemocoes)
	clear(s.pendEscritas)
	clear(s.pendRemocoes)
	if lote.Vazio() || s.nft == nil {
		return
	}
	s.lotes.Add(1)
	if err := s.nft.AplicarLote(ctx, lote); err != nil {
		s.errosDeLote.Add(1)
		// Registra e segue. O lote perdido volta sozinho: o endereço continua
		// no índice com o prazo que ele TERIA recebido, e a próxima resposta
		// que o reensine dentro do último terço o manda de novo. Insistir aqui
		// seria repetir um fork que acabou de falhar, com o laço parado.
		slog.Warn("alvo por domínio: o lote não entrou no kernel", "err", err)
	}
}

// montarLote separa v4 de v6 e barrar de direcionar.
//
// A SEPARAÇÃO POR FAMÍLIA NÃO É COSMÉTICA: `dom_blocked` é `type ipv4_addr` e
// `dom_blocked6` é `type ipv6_addr`. Um endereço v6 mandado para o primeiro
// derruba o `nft -f` inteiro, e com ele todos os endereços daquela rodada.
//
// O direcionamento só tem estrutura v4 (de propósito — não existe política de
// rota v6 neste produto), então endereço v6 de domínio direcionado é
// DESCARTADO aqui, e não empurrado para o set de bloqueio: não conseguir
// direcionar é uma coisa; BARRAR o que o admin mandou direcionar seria outra, e
// muito pior.
func montarLote(escritas map[netip.Addr]Escrita, remocoes map[netip.Addr]Remocao) nftables.Lote {
	// Conjuntos, e não listas, para não emitir dois `delete` do mesmo elemento
	// na mesma transação — o segundo erra por elemento ausente e derruba o lote
	// inteiro, que é a medição do doc-comment de AplicarLote.
	remBloq := map[netip.Addr]bool{}
	remBloq6 := map[netip.Addr]bool{}
	remWan := map[netip.Addr]bool{}

	marcarRemocao := func(a netip.Addr, c Capacidade) {
		switch {
		case c == Direcionar && a.Is4():
			remWan[a] = true
		case c == Direcionar:
			// v6 nunca entrou no map de direcionamento; não há o que apagar.
		case a.Is4():
			remBloq[a] = true
		default:
			remBloq6[a] = true
		}
	}

	for _, r := range remocoes {
		marcarRemocao(r.Addr, r.Capacidade)
	}

	var l nftables.Lote
	for _, e := range ordenarEscritas(escritas) {
		if e.Substituir {
			marcarRemocao(e.Addr, e.Capacidade)
		}
		ent := nftables.Entrada{Addr: e.Addr, Prazo: e.Prazo, Marca: e.Marca}
		switch {
		case e.Capacidade == Direcionar && e.Addr.Is4():
			l.AdicionarWan = append(l.AdicionarWan, ent)
		case e.Capacidade == Direcionar:
			continue
		case e.Addr.Is4():
			l.AdicionarBloq = append(l.AdicionarBloq, ent)
		default:
			l.AdicionarBloq6 = append(l.AdicionarBloq6, ent)
		}
	}

	l.RemoverBloq = ordenarAddrs(remBloq)
	l.RemoverBloq6 = ordenarAddrs(remBloq6)
	l.RemoverWan = ordenarAddrs(remWan)
	return l
}

// ordenarEscritas dá ordem estável ao que sai de um mapa.
//
// Não é estética: sem ordem, o script do nft muda de forma a cada rodada com o
// mesmo conteúdo, e todo teste e toda leitura de log viram adivinhação.
func ordenarEscritas(m map[netip.Addr]Escrita) []Escrita {
	out := make([]Escrita, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

func ordenarAddrs(m map[netip.Addr]bool) []netip.Addr {
	if len(m) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// EstadoDominio é uma linha da tela.
type EstadoDominio struct {
	Dominio    string     `json:"dominio"`
	Capacidade Capacidade `json:"capacidade"`
	Estagio    Estagio    `json:"estagio"`
	// NoKernel é quantos endereços DESTE domínio o kernel tem agora. Vem da
	// leitura das estruturas cruzada com o índice, e não de uma contagem em
	// memória — ver o doc-comment de Estado.
	NoKernel int `json:"no_kernel"`
	// Rotatividade é quantos endereços distintos ele já ensinou. Este número é
	// de OBSERVAÇÃO, não de estado do firewall: ele conta o que o DNS disse,
	// inclusive para domínio em ensaio, que não escreve nada.
	Rotatividade         int  `json:"rotatividade"`
	RotatividadeTruncada bool `json:"rotatividade_truncada"`
}

// Estado é o que a tela lê.
type Estado struct {
	// Barrados, Barrados6 e Direcionados vêm DO KERNEL.
	Barrados     int `json:"barrados"`
	Barrados6    int `json:"barrados6"`
	Direcionados int `json:"direcionados"`
	// Orfaos são endereços que o kernel tem e nenhum domínio reivindica.
	Orfaos int `json:"orfaos"`
	// KernelLido separa "zero endereços" de "não consegui perguntar". Sem esta
	// distinção, um erro de leitura vira uma tela dizendo que nada está
	// bloqueado — que é a mentira mais cara que esta tela pode contar.
	KernelLido bool   `json:"kernel_lido"`
	KernelErro string `json:"kernel_erro,omitempty"`

	Descartes   uint64     `json:"descartes"`
	Lotes       uint64     `json:"lotes"`
	ErrosDeLote uint64     `json:"erros_de_lote"`
	Contadores  Contadores `json:"contadores"`

	Dominios []EstadoDominio `json:"dominios"`
}

// Estado lê o KERNEL e monta o que a tela mostra.
//
// A CONTAGEM VEM DAS ESTRUTURAS DO NFTABLES, NUNCA DO ÍNDICE EM MEMÓRIA. O
// índice é um espelho, e espelho atrasa: o elemento pode ter expirado sozinho,
// o lote pode ter falhado, alguém pode ter dado flush por fora, o processo pode
// ter reiniciado com o kernel cheio. Este produto já entregou uma tela que
// afirmava o que o kernel não tinha, e a diferença entre "o painel diz que está
// bloqueado" e "está bloqueado" é a única coisa que a tela precisa acertar.
//
// O índice entra só para emprestar a IDENTIDADE — qual domínio ensinou qual
// endereço — porque essa é a parte que o kernel não guarda, de propósito (ver o
// cabeçalho de internal/nftables/dominios.go).
func (s *Servico) Estado(ctx context.Context) Estado {
	e := Estado{
		Descartes:   s.descartes.Load(),
		Lotes:       s.lotes.Load(),
		ErrosDeLote: s.errosDeLote.Load(),
		Contadores:  s.idx.Contadores(),
		Dominios:    []EstadoDominio{},
	}

	var porDominio map[string]int
	if s.nft != nil {
		k, err := s.nft.DomElementos(ctx)
		if err != nil {
			e.KernelErro = err.Error()
		} else {
			e.KernelLido = true
			e.Barrados = len(k.Bloq)
			e.Barrados6 = len(k.Bloq6)
			e.Direcionados = len(k.Wan)
			todos := make([]netip.Addr, 0, len(k.Bloq)+len(k.Bloq6)+len(k.Wan))
			todos = append(todos, k.Bloq...)
			todos = append(todos, k.Bloq6...)
			todos = append(todos, k.Wan...)
			porDominio, e.Orfaos = s.idx.Reivindicantes(todos)
		}
	}

	for _, a := range s.idx.Alvos() {
		rot, truncada := s.idx.Rotatividade(a.Dominio)
		e.Dominios = append(e.Dominios, EstadoDominio{
			Dominio:              a.Dominio,
			Capacidade:           a.Capacidade,
			Estagio:              a.Estagio,
			NoKernel:             porDominio[a.Dominio],
			Rotatividade:         rot,
			RotatividadeTruncada: truncada,
		})
	}
	return e
}
