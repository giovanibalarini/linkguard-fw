package domtargets

import (
	"context"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"sort"
	"sync"
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
// firewall. Por isso Observar NUNCA bloqueia, NUNCA pega lock e NUNCA aloca
// antes de saber que a resposta interessa.
//
// O FILTRO DE Observar É SEM LOCK, e tem de continuar sendo. Ele casa o nome
// num RETRATO imutável da lista de domínios, publicado por DefinirAlvos e
// trocado por ponteiro atômico. Chamar Indice.Casar aqui seria o caminho óbvio
// e o errado: aquele lock é segurado por Podar varrendo 4096 registros, por
// Creditar varrendo até 8192 endereços do kernel e por reconciliar dando uma
// volta inteira no índice — quer dizer, poria o laço que drena o socket do
// unbound atrás de uma requisição HTTP.
//
// E O FILTRO PRECISA EXISTIR: sem ele a fila de 256 é preenchida quase inteira
// por ruído (google.com, telemetria de celular), e a resposta do domínio
// listado — o sinal — disputa vaga com ele. Quando o consumidor atrasa, o
// descarte fica enviesado CONTRA o que interessa, na proporção do tráfego que
// não interessa. Numa caixa sem domínio listado, que é o estado de toda
// instalação desta entrega, o custo cai a um carregamento de ponteiro.
//
// QUEM DRENA A FILA NÃO É QUEM ESCREVE NO KERNEL, e essa separação é a segunda
// correção de fundo. O nft roda no executor com prazo de 30s e AplicarLote pode
// rodá-lo DUAS vezes: sessenta segundos de teto. Com o fork dentro do select do
// Run, esse era o tempo em que o alimentador ficava cego — e uma fila de 256
// numa caixa com trinta clientes enche em menos de um segundo. Agora o lote
// pronto é entregue a uma goroutine escritora por um canal de fundo um, com
// prazo próprio (TempoLimiteDoLote), e o laço volta a drenar na mesma volta.
//
// O QUE FICA PENDENTE NÃO SE PERDE: quando a escritora ainda está ocupada, o
// lote NÃO é descartado — as listas pendentes continuam onde estão e a janela
// rearma. Descartar seria perder remoção, e remoção perdida é o kernel barrando
// por até uma hora um domínio que a tela já mostra desligado.
//
// A JANELA DE 200 ms existe pelo mesmo motivo pelo qual o lote existe: cada
// rodada é um fork de nft e uma transação netlink. Vinte máquinas abrindo a
// mesma página geram vinte respostas de DNS no mesmo instante, e sem a janela
// isso seria vinte forks para escrever o mesmo punhado de endereços.
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
	AplicarLote(ctx context.Context, l nftables.Lote) (nftables.ResultadoLote, error)
	DomElementos(ctx context.Context) (nftables.DomKernel, error)
	// IsDryRun existe aqui porque a tela precisa dele: em dry-run o lote é
	// contado e não escrito, enquanto a leitura do kernel é de verdade. Sem
	// dizer isso, a tela mostra "412 lotes aplicados, 0 erros, 0 endereços no
	// kernel" — cada número certo isoladamente e a leitura conjunta falsa.
	IsDryRun() bool
}

const (
	// TamanhoDaFila é o fundo do canal entre o laço do dnstap e o alimentador.
	//
	// Duzentos e cinquenta e seis cobre com folga a rajada de uma rede de
	// escritório — e agora só entra nela resposta de domínio LISTADO, então ela
	// mede o sinal e não o ruído. Maior não ajudaria: se o alimentador está
	// atrás por mais que isso, ele está atrás de um problema que fila nenhuma
	// resolve, e o que importa nesse caso é o contador de descartes SUBIR.
	TamanhoDaFila = 256

	// JanelaDeCoalescencia é quanto o alimentador junta antes de escrever.
	JanelaDeCoalescencia = 200 * time.Millisecond

	// CadenciaDePoda é de quanto em quanto tempo o índice esquece o que já
	// venceu no kernel, as faixas próprias são recarregadas e os contadores que
	// se mexeram vão para o log. Não gera comando — ver Indice.Podar.
	CadenciaDePoda = time.Minute

	// TempoLimiteDoLote é o prazo do nft de UM lote.
	//
	// O executor tem teto de 30s e AplicarLote pode chamá-lo duas vezes. Um
	// nft -f com algumas dezenas de elementos que passa de cinco segundos já
	// falhou — insistir sessenta não melhora nada e segura a escritora, que é a
	// única que pode aplicar o lote seguinte.
	TempoLimiteDoLote = 5 * time.Second

	// MaxTentativasDeRemocao é quantas vezes uma remoção volta para a fila
	// depois de o reenvio a ter deixado para trás.
	//
	// Duas, e não infinitas: o motivo mais provável de o delete ter falhado é o
	// elemento já não existir, e nesse caso insistir é um fork por janela para
	// sempre. Ao desistir, o número aparece — desistir em silêncio seria trocar
	// um laço por uma mentira.
	MaxTentativasDeRemocao = 2
)

// observacao é a cópia do que a resposta ensinou.
//
// É CÓPIA de propósito. O *dnstap.Resposta que chega em Observar é o MESMO
// ponteiro que o mapa da #116 acabou de receber, sem cópia pelo caminho. Hoje o
// Aprender de lá só lê, mas o alimentador levaria esse ponteiro para outra
// goroutine e o guardaria por até uma janela inteira — e leitura compartilhada
// que funciona por acidente é a que quebra na primeira mudança do outro lado.
//
// A cópia é feita DEPOIS do filtro: alocar antes fazia o caminho do descarte
// pagar por uma resposta que não interessava a ninguém.
type observacao struct {
	nome  string
	addrs []netip.Addr
	ttl   time.Duration
}

// chavePend identifica uma pendência por endereço E estrutura.
//
// Só pelo endereço, duas trocas de capacidade do mesmo endereço dentro da mesma
// janela de 200 ms perdiam a remoção do meio: sobrava um delete da estrutura
// errada e um add que, sobre elemento existente, não renova.
type chavePend struct {
	addr netip.Addr
	capa Capacidade
}

// remocaoPend é uma remoção com o número de vezes que ela já foi tentada.
type remocaoPend struct {
	rem        Remocao
	tentativas int
}

// loteEmVoo é o que a escritora recebe: o lote pronto para o nft e o que o
// alimentador precisa saber de volta se ele não entrar inteiro.
type loteEmVoo struct {
	lote nftables.Lote
	// adicoes são os endereços que o lote tenta pôr no kernel. É a lista que
	// vira Confirmar ou NaoConfirmado, e é ela que faz o espelho do índice
	// avançar só quando o kernel avançou.
	adicoes []netip.Addr
	// remocoes leva a capacidade e a CONTA DE TENTATIVAS junto, que o
	// nftables.Lote já não carrega: sem a capacidade, uma remoção que o reenvio
	// deixou para trás não saberia de qual estrutura ela saía; sem a conta, ela
	// voltaria para a fila com o contador zerado a cada volta, e a desistência
	// nunca chegaria — um fork por janela, para sempre.
	remocoes map[netip.Addr]remocaoPend
}

// Servico é o alimentador.
type Servico struct {
	idx *Indice
	nft Aplicador

	fila chan observacao
	// acordar é SINAL, e não dado: o que mudou fica numa lista com lock e este
	// canal só diz que há algo a olhar. Um canal de dados com fundo pendurava
	// quem chamasse DefinirAlvos com o Run atrasado, e o ramo de desistência
	// perdia o ajuste em silêncio — com o índice já mudado, quer dizer, com o
	// kernel barrando um domínio que a tela mostra desligado.
	acordar chan struct{}
	// paraEscrever tem fundo UM: mais de um lote em voo não ajuda (o nft
	// serializa no netlink de qualquer jeito) e esconderia o atraso.
	paraEscrever chan loteEmVoo
	devolvidas   chan []remocaoPend

	// retrato é a lista de domínios publicada para Observar ler SEM LOCK.
	retrato atomic.Pointer[map[string]Alvo]

	// fonteProtegidos diz quais faixas são da própria caixa. Recarregada a cada
	// poda porque o endereço da WAN muda sozinho num link discado.
	fonteProtegidos func() []netip.Prefix

	mu          sync.Mutex
	ajustesPend []Ajuste

	descartes          atomic.Uint64
	ignoradas          atomic.Uint64
	lotes              atomic.Uint64
	errosDeLote        atomic.Uint64
	reenvios           atomic.Uint64
	remocoesDesistidas atomic.Uint64
	reinicios          atomic.Uint64
	vivo               atomic.Bool
	ultimoLog          atomic.Uint64

	// pendEscritas e pendRemocoes acumulam dentro da janela e são tocados SÓ
	// pela goroutine do Run. Mapa e não lista porque o mesmo endereço reensinado
	// duas vezes na mesma janela tem de virar UMA linha: duas viram um delete
	// depois do add que acabou de entrar.
	pendEscritas map[chavePend]Escrita
	pendRemocoes map[chavePend]remocaoPend
}

// NovoServico cria o alimentador. nft nil é legítimo — o alimentador continua
// aprendendo e contando, e não escreve nada.
func NovoServico(nft Aplicador) *Servico {
	s := &Servico{
		idx:             NovoIndice(nil),
		nft:             nft,
		fila:            make(chan observacao, TamanhoDaFila),
		acordar:         make(chan struct{}, 1),
		paraEscrever:    make(chan loteEmVoo, 1),
		devolvidas:      make(chan []remocaoPend, 8),
		fonteProtegidos: PrefixosLocais,
		pendEscritas:    map[chavePend]Escrita{},
		pendRemocoes:    map[chavePend]remocaoPend{},
	}
	vazio := map[string]Alvo{}
	s.retrato.Store(&vazio)
	return s
}

// Indice devolve o índice, para quem precisa consultar a lista de domínios.
func (s *Servico) Indice() *Indice { return s.idx }

// DefinirFonteDeProtegidos troca de onde vêm as faixas da própria caixa.
//
// O padrão (PrefixosLocais) já pega tudo que está numa interface — o endereço
// da WAN e o prefixo da LAN, v4 e v6. Quem monta o produto acrescenta o que a
// caixa usa e não tem na interface: o gateway de um uplink ponto a ponto, os
// hosts de monitoração, o servidor de teste de DNS.
func (s *Servico) DefinirFonteDeProtegidos(f func() []netip.Prefix) {
	if f != nil {
		s.fonteProtegidos = f
	}
}

// Observar recebe o que uma resposta de DNS ensinou. NUNCA BLOQUEIA E NUNCA
// PEGA LOCK.
//
// Ver o cabeçalho do arquivo: quem chama é o laço que drena o socket do
// unbound, e essas duas são as propriedades inegociáveis desta função.
func (s *Servico) Observar(r *dnstap.Resposta) {
	if s == nil || r == nil || r.Nome == "" || len(r.Enderecos) == 0 {
		return
	}
	alvos := s.retrato.Load()
	if alvos == nil || len(*alvos) == 0 {
		return
	}
	_, casou := CasarEm(*alvos, r.Nome)
	if !casou {
		s.ignoradas.Add(1)
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

// Descartes é quantas observações DE DOMÍNIO LISTADO não couberam na fila.
//
// Precisa aparecer, e agora aparece: o laço da poda emite uma linha de log
// sempre que este número (ou qualquer outro que denuncie perda) se mexeu no
// último minuto. Um alimentador que descarta está aprendendo menos endereços do
// que o resolver ensinou, e o sintoma para quem usa é "às vezes passa" — o
// pior tipo de relato de bloqueio, e o único jeito de explicá-lo é este número.
//
// Ele conta só o que INTERESSA. Um contador que subia por causa de xbox.com não
// explicava coisa nenhuma sobre netflix.com.
func (s *Servico) Descartes() uint64 { return s.descartes.Load() }

// DefinirAlvos troca a lista de domínios e agenda o que a troca exige do
// kernel.
//
// NÃO BLOQUEIA E NÃO PERDE, e as duas coisas são correção de defeito. O ajuste
// ia por um canal com fundo: com o Run atrasado a chamada ficava pendurada para
// sempre (o ctx era o do processo), e quando o ctx caía o ajuste sumia SEM
// contador e SEM log — com o índice já trocado e as remoções já geradas, quer
// dizer, com o kernel barrando por até uma hora um domínio que a tela mostra
// desligado. Agora o pendente mora numa lista com lock e o canal só acorda.
func (s *Servico) DefinirAlvos(alvos []Alvo) {
	aj := s.idx.DefinirAlvos(alvos)
	s.publicarRetrato()
	if aj.Vazio() {
		return
	}
	s.mu.Lock()
	s.ajustesPend = append(s.ajustesPend, aj)
	s.mu.Unlock()
	s.acordarLaco()
}

// publicarRetrato troca o mapa que Observar lê sem lock. O mapa é imutável
// depois de publicado — quem muda a lista publica um novo.
func (s *Servico) publicarRetrato() {
	lista := s.idx.Alvos()
	m := make(map[string]Alvo, len(lista))
	for _, a := range lista {
		m[a.Dominio] = a
	}
	s.retrato.Store(&m)
}

func (s *Servico) acordarLaco() {
	select {
	case s.acordar <- struct{}{}:
	default:
	}
}

// Run junta o que chegou e escreve uma vez por janela.
//
// O laço é REERGUIDO depois de um pânico. Sem isso, um pânico dentro dele
// derruba o consumidor e o desenho passa a funcionar ao contrário do que
// deveria: Observar continua não bloqueando (o resolver sobrevive, que é o
// certo), a fila enche em segundos, cada resposta vira um descarte para sempre,
// e Estado continua respondendo com o kernel — que é real, só que de elementos
// que ninguém renova mais. A tela afirmaria que o alimentador está vivo com ele
// morto, e é por isso que Vivo e Reinicios são campos e não uma inferência.
func (s *Servico) Run(ctx context.Context) {
	s.vivo.Store(true)
	defer s.vivo.Store(false)
	go s.escrever(ctx)
	for ctx.Err() == nil {
		s.laco(ctx)
	}
}

// laco é uma volta inteira do alimentador, do começo ao ctx cancelado ou ao
// pânico. Devolve para Run, que o reergue.
func (s *Servico) laco(ctx context.Context) {
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		s.reinicios.Add(1)
		slog.Error("alvo por domínio: o alimentador entrou em pânico e foi reerguido",
			"panico", p, "pilha", string(debug.Stack()))
		// Um respiro antes de voltar: pânico que se repete a cada volta viraria
		// um laço quente escrevendo log.
		time.Sleep(100 * time.Millisecond)
	}()

	// DENTRO do laço, e não em Run: aqui embaixo do recover. A lista vem de
	// fora (interfaces da máquina, banco), e o que vem de fora não pode
	// derrubar o alimentador antes de ele nascer.
	s.recarregarProtegidos()

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
		case <-s.acordar:
			s.drenarAjustes()
		case rs := <-s.devolvidas:
			s.recolocarRemocoes(rs)
		case <-janela.C:
			armada = false
			s.descarregar()
		case <-poda.C:
			s.rodarPoda()
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

func (s *Servico) drenarAjustes() {
	s.mu.Lock()
	pend := s.ajustesPend
	s.ajustesPend = nil
	s.mu.Unlock()
	for _, aj := range pend {
		s.acumular(aj.Escritas, aj.Remocoes)
	}
}

func (s *Servico) acumular(es []Escrita, rs []Remocao) {
	for _, r := range rs {
		k := chavePend{addr: r.Addr, capa: r.Capacidade}
		p := s.pendRemocoes[k]
		p.rem = r
		s.pendRemocoes[k] = p
	}
	for _, e := range es {
		s.pendEscritas[chavePend{addr: e.Addr, capa: e.Capacidade}] = e
	}
}

// recolocarRemocoes põe de volta na fila o que o reenvio deixou para trás.
//
// Com conta de tentativas: o motivo mais provável de um delete falhar é o
// elemento já não existir, e nesse caso insistir para sempre é um fork por
// janela. Ao desistir o número aparece — ver Estado.RemocoesDesistidas.
func (s *Servico) recolocarRemocoes(ps []remocaoPend) {
	for _, p := range ps {
		k := chavePend{addr: p.rem.Addr, capa: p.rem.Capacidade}
		p.tentativas++
		if p.tentativas >= MaxTentativasDeRemocao {
			s.remocoesDesistidas.Add(1)
			slog.Warn("alvo por domínio: desisti de tirar um endereço do kernel",
				"endereco", p.rem.Addr.String(), "estrutura", string(p.rem.Capacidade),
				"tentativas", p.tentativas)
			delete(s.pendRemocoes, k)
			continue
		}
		s.pendRemocoes[k] = p
	}
}

// descarregar monta um Lote com tudo que se juntou e o ENTREGA à escritora.
//
// Se a escritora ainda está ocupada, o pendente FICA onde está e a janela
// rearma. Descartar o lote seria perder remoção — e remoção perdida é o kernel
// barrando por até uma hora um domínio que a tela já mostra desligado.
func (s *Servico) descarregar() {
	if len(s.pendEscritas) == 0 && len(s.pendRemocoes) == 0 {
		return
	}
	escritas := ordenarEscritas(s.pendEscritas)
	remocoes := ordenarRemocoes(s.pendRemocoes)
	lote := montarLote(escritas, remocoes)
	if lote.Vazio() {
		// Nada disto vira comando (v6 de domínio direcionado, endereço
		// inválido). Limpar é o certo: manter faria a janela rearmar para
		// sempre em cima de um lote que nunca sai.
		clear(s.pendEscritas)
		clear(s.pendRemocoes)
		return
	}
	v := loteEmVoo{
		lote:     lote,
		adicoes:  adicoesDoLote(lote),
		remocoes: make(map[netip.Addr]remocaoPend, len(s.pendRemocoes)),
	}
	for _, p := range s.pendRemocoes {
		v.remocoes[p.rem.Addr] = p
	}
	select {
	case s.paraEscrever <- v:
		clear(s.pendEscritas)
		clear(s.pendRemocoes)
	default:
		// A escritora ainda está com o lote anterior. Fica tudo pendente e a
		// janela rearma sozinha na volta do laço.
	}
}

func adicoesDoLote(l nftables.Lote) []netip.Addr {
	out := make([]netip.Addr, 0, len(l.AdicionarBloq)+len(l.AdicionarBloq6)+len(l.AdicionarWan))
	for _, es := range [][]nftables.Entrada{l.AdicionarBloq, l.AdicionarBloq6, l.AdicionarWan} {
		for _, e := range es {
			out = append(out, e.Addr)
		}
	}
	return out
}

// escrever é a goroutine que fala com o kernel, e a única.
//
// Ela existe para o fork do nft NÃO ficar no caminho que drena a fila. Tem
// recover próprio pelo mesmo motivo do laço: morrer aqui em silêncio deixaria
// os lotes empilhando no canal sem ninguém para aplicá-los.
func (s *Servico) escrever(ctx context.Context) {
	for ctx.Err() == nil {
		s.voltaDeEscrita(ctx)
	}
}

func (s *Servico) voltaDeEscrita(ctx context.Context) {
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		s.reinicios.Add(1)
		slog.Error("alvo por domínio: a escritora entrou em pânico e foi reerguida",
			"panico", p, "pilha", string(debug.Stack()))
		time.Sleep(100 * time.Millisecond)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-s.paraEscrever:
			s.aplicar(ctx, v)
		}
	}
}

// aplicar manda o lote ao kernel e diz ao índice o que ele DE FATO recebeu.
//
// É aqui que o espelho avança, e só aqui. O índice decide e não grava: sem esta
// confirmação, um lote que falha vira um endereço que o índice dá por escrito e
// só volta a mexer 2/3 de prazo depois — até quarenta minutos de firewall não
// barrando o que a tela mostra barrado.
func (s *Servico) aplicar(ctx context.Context, v loteEmVoo) {
	if s.nft == nil {
		// Sem aplicador não há kernel do qual divergir, e Estado responde
		// KernelLido falso. Confirmar mantém o índice coerente consigo mesmo,
		// que é o único retrato que existe nessa configuração.
		s.idx.Confirmar(v.adicoes)
		return
	}
	ctxLote, cancelar := context.WithTimeout(ctx, TempoLimiteDoLote)
	defer cancelar()
	s.lotes.Add(1)
	res, err := s.nft.AplicarLote(ctxLote, v.lote)
	if err != nil {
		s.errosDeLote.Add(1)
		s.idx.NaoConfirmado(v.adicoes)
		s.devolver(v.todasRemocoes())
		slog.Warn("alvo por domínio: o lote não entrou no kernel", "err", err)
		return
	}
	if res.Completo() {
		s.idx.Confirmar(v.adicoes)
		return
	}
	// O reenvio entrou, mas sem os delete e sem os add de renovação: o que
	// ficou de fora não pode ser dado por feito.
	s.reenvios.Add(1)
	s.idx.NaoConfirmado(res.NaoConfirmados)
	s.idx.Confirmar(exceto(v.adicoes, res.NaoConfirmados))
	s.devolver(v.remocoesDe(res.RemocoesPerdidas))
}

func (v loteEmVoo) todasRemocoes() []remocaoPend {
	out := make([]remocaoPend, 0, len(v.remocoes))
	for _, r := range v.remocoes {
		out = append(out, r)
	}
	return out
}

func (v loteEmVoo) remocoesDe(addrs []netip.Addr) []remocaoPend {
	out := make([]remocaoPend, 0, len(addrs))
	for _, a := range addrs {
		r, ok := v.remocoes[a]
		if ok {
			out = append(out, r)
		}
	}
	return out
}

func (s *Servico) devolver(rs []remocaoPend) {
	if len(rs) == 0 {
		return
	}
	select {
	case s.devolvidas <- rs:
		s.acordarLaco()
	default:
		s.remocoesDesistidas.Add(uint64(len(rs)))
		slog.Warn("alvo por domínio: remoções perdidas sem caber na fila de volta", "quantas", len(rs))
	}
}

func exceto(todos []netip.Addr, fora []netip.Addr) []netip.Addr {
	if len(fora) == 0 {
		return todos
	}
	bloqueados := make(map[netip.Addr]bool, len(fora))
	for _, a := range fora {
		bloqueados[a] = true
	}
	out := make([]netip.Addr, 0, len(todos))
	for _, a := range todos {
		if !bloqueados[a] {
			out = append(out, a)
		}
	}
	return out
}

// rodarPoda é o minuto do alimentador: esquece o que venceu, recarrega as
// faixas próprias e põe no log o que se mexeu.
//
// O log existe porque, enquanto não há rota nem métrica lendo Estado, os modos
// de falha deste arquivo são todos MUDOS: a fila enchendo, o lote falhando, a
// remoção desistida e o pânico reerguido só existem como um número em memória
// que ninguém pede. Uma linha por minuto, e só quando algo mudou, transforma
// isso em algo que aparece no journal.
func (s *Servico) rodarPoda() {
	podados := s.idx.Podar()
	s.recarregarProtegidos()

	c := s.idx.Contadores()
	perdas := s.descartes.Load() + s.errosDeLote.Load() + s.reenvios.Load() +
		s.remocoesDesistidas.Load() + s.reinicios.Load() +
		c.Recusados + c.RecusadosProprios + c.EstouroGlobal + c.EstouroPorDominio +
		c.NaoConfirmados + c.DirecionadoV6Descartado
	if perdas == s.ultimoLog.Load() {
		return
	}
	s.ultimoLog.Store(perdas)
	slog.Warn("alvo por domínio: o alimentador perdeu ou recusou alguma coisa no último minuto",
		"descartes", s.descartes.Load(),
		"erros_de_lote", s.errosDeLote.Load(),
		"reenvios", s.reenvios.Load(),
		"remocoes_desistidas", s.remocoesDesistidas.Load(),
		"reinicios", s.reinicios.Load(),
		"recusados", c.Recusados,
		"recusados_proprios", c.RecusadosProprios,
		"estouros", c.EstouroGlobal+c.EstouroPorDominio,
		"nao_confirmados", c.NaoConfirmados,
		"direcionado_v6", c.DirecionadoV6Descartado,
		"podados", podados,
		"vivos", c.Vivos)
}

func (s *Servico) recarregarProtegidos() {
	if s.fonteProtegidos == nil {
		return
	}
	s.idx.DefinirProtegidos(s.fonteProtegidos())
}

// montarLote separa v4 de v6 e barrar de direcionar.
//
// A SEPARAÇÃO POR FAMÍLIA NÃO É COSMÉTICA: dom_blocked é type ipv4_addr e
// dom_blocked6 é type ipv6_addr. Um endereço v6 mandado para o primeiro derruba
// o nft -f inteiro, e com ele todos os endereços daquela rodada.
//
// O direcionamento só tem estrutura v4 (de propósito — não existe política de
// rota v6 neste produto). Endereço v6 de domínio direcionado nem chega aqui: o
// índice o recusa na entrada, contando DirecionadoV6Descartado, para o índice
// continuar espelhando o kernel e a tela poder dizer por que o domínio
// "direcionado" não direciona. O descarte abaixo é o cinto de segurança.
func montarLote(escritas []Escrita, remocoes []Remocao) nftables.Lote {
	// Conjuntos, e não listas, para não emitir dois delete do mesmo elemento na
	// mesma transação — o segundo erra por elemento ausente e derruba o lote
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
	for _, e := range escritas {
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
func ordenarEscritas(m map[chavePend]Escrita) []Escrita {
	out := make([]Escrita, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr.Less(out[j].Addr)
		}
		return out[i].Capacidade < out[j].Capacidade
	})
	return out
}

func ordenarRemocoes(m map[chavePend]remocaoPend) []Remocao {
	out := make([]Remocao, 0, len(m))
	for _, p := range m {
		out = append(out, p.rem)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr.Less(out[j].Addr)
		}
		return out[i].Capacidade < out[j].Capacidade
	})
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
	// NoKernel é quantos endereços DESTE domínio o kernel tem agora, e é um
	// ponteiro de propósito: nil quer dizer "não consegui perguntar" e zero
	// quer dizer "perguntei e não tem". Um int cru fazia os dois estados
	// renderizarem igual, e um deles é uma falha de leitura fazendo trinta
	// domínios ativos aparecerem como se nada estivesse bloqueado.
	NoKernel *int `json:"no_kernel"`
	// NoIndice é quantos endereços deste domínio o índice acha que escreveu.
	// NoIndice maior que zero com NoKernel apontando para zero é a divergência
	// aparecendo sem precisar de reconciliação nenhuma.
	NoIndice int `json:"no_indice"`
	// NoTeto é estado AGORA; Estouros é histórico. Os dois juntos separam
	// "estabilizou" de "continua com 64 de 300 endereços".
	NoTeto bool `json:"no_teto"`
	Teto   int  `json:"teto"`
	// Estouros, Recusados, RecusadosProprios, SemVaga e DirecionadoV6 são
	// cumulativos DESTE domínio, que é o que um contador global não diz.
	Estouros          uint64 `json:"estouros"`
	Recusados         uint64 `json:"recusados"`
	RecusadosProprios uint64 `json:"recusados_proprios"`
	SemVaga           uint64 `json:"sem_vaga"`
	DirecionadoV6     uint64 `json:"direcionado_v6"`
	// UltimoAprendizado é unix, zero quando ninguém consultou este nome ainda.
	// É o que separa "normal, esperado" de "consultaram e nada entrou".
	UltimoAprendizado int64 `json:"ultimo_aprendizado"`
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
	// ForaDeLugar são endereços que o kernel tem numa estrutura que não é a que
	// o índice escolheu — o mesmo endereço barrado e direcionado ao mesmo
	// tempo, ou sobrando de uma troca cujo delete se perdeu. Ver Credito.
	ForaDeLugar int `json:"fora_de_lugar"`
	// Ilegiveis são itens que o parser da leitura não reconheceu, e existem
	// para as contagens acima não parecerem exatas quando não são.
	Ilegiveis int `json:"ilegiveis"`
	// KernelLido separa "zero endereços" de "não consegui perguntar".
	// Sem esta distinção, um erro de leitura vira uma tela dizendo que nada
	// está bloqueado — a mentira mais cara que esta tela pode contar. Só é
	// verdadeiro quando as TRÊS estruturas responderam.
	KernelLido bool   `json:"kernel_lido"`
	KernelErro string `json:"kernel_erro,omitempty"`
	// DryRun existe porque em dry-run o lote é CONTADO e não escrito, enquanto
	// a leitura do kernel é de verdade: sem este campo a tela diria
	// "412 lotes, 0 erros, 0 endereços", com cada número certo e a leitura
	// conjunta falsa.
	DryRun bool `json:"dry_run"`
	// Vivo e Reinicios dizem se o alimentador está de pé. Um alimentador morto
	// tem de ser um campo, e não uma inferência a partir de um contador subindo.
	Vivo      bool   `json:"vivo"`
	Reinicios uint64 `json:"reinicios"`

	// Descartes são observações DE DOMÍNIO LISTADO que não couberam na fila.
	// Ignoradas são as que nem entraram nela por não casar com domínio nenhum,
	// e estão separadas porque só a primeira explica "às vezes passa".
	Descartes uint64 `json:"descartes"`
	Ignoradas uint64 `json:"ignoradas"`
	// Reenvios e RemocoesDesistidas são os dois jeitos de um lote entrar pela
	// metade sem devolver erro.
	Lotes              uint64     `json:"lotes"`
	ErrosDeLote        uint64     `json:"erros_de_lote"`
	Reenvios           uint64     `json:"reenvios"`
	RemocoesDesistidas uint64     `json:"remocoes_desistidas"`
	Contadores         Contadores `json:"contadores"`

	Dominios []EstadoDominio `json:"dominios"`
}

// Estado lê o KERNEL e monta o que a tela mostra.
//
// A CONTAGEM VEM DAS ESTRUTURAS DO NFTABLES, NUNCA DO ÍNDICE EM MEMÓRIA. O
// índice é um espelho, e espelho atrasa: o elemento pode ter expirado sozinho,
// o lote pode ter falhado, alguém pode ter dado flush por fora, o processo pode
// ter reiniciado com o kernel cheio. Este produto já entregou uma tela que
// afirmava o que o kernel não tinha, e a diferença entre "o painel diz que
// está bloqueado" e "está bloqueado" é a única coisa que a tela precisa
// acertar.
//
// O índice entra por dois motivos. Um é emprestar a IDENTIDADE — qual domínio
// ensinou qual endereço — que é a parte que o kernel não guarda, de propósito.
// O outro é NoIndice: sem o que o índice acha que escreveu ao lado do que o
// kernel tem, a divergência só apareceria numa reconciliação que não existe.
func (s *Servico) Estado(ctx context.Context) Estado {
	e := Estado{
		Vivo:               s.vivo.Load(),
		Reinicios:          s.reinicios.Load(),
		Descartes:          s.descartes.Load(),
		Ignoradas:          s.ignoradas.Load(),
		Lotes:              s.lotes.Load(),
		ErrosDeLote:        s.errosDeLote.Load(),
		Reenvios:           s.reenvios.Load(),
		RemocoesDesistidas: s.remocoesDesistidas.Load(),
		Contadores:         s.idx.Contadores(),
		Dominios:           []EstadoDominio{},
	}

	var cred Credito
	if s.nft != nil {
		e.DryRun = s.nft.IsDryRun()
		k, err := s.nft.DomElementos(ctx)
		if err != nil {
			e.KernelErro = err.Error()
		}
		// KernelLido é TUDO ou nada de propósito: com uma das três estruturas
		// sem responder, somar as outras duas produz um número que parece a
		// verdade do kernel e não é.
		e.KernelLido = k.Tudo()
		if e.KernelLido {
			e.Barrados = len(k.Bloq)
			e.Barrados6 = len(k.Bloq6)
			e.Direcionados = len(k.Wan)
			e.Ilegiveis = k.Ilegiveis
			cred = s.idx.Creditar(k)
			e.Orfaos = cred.Orfaos
			e.ForaDeLugar = cred.ForaDeLugar
		}
	}

	for _, l := range s.idx.Linhas() {
		e.Dominios = append(e.Dominios, s.linhaDaTela(l, cred, e.KernelLido))
	}
	return e
}

func (s *Servico) linhaDaTela(l LinhaDominio, cred Credito, kernelLido bool) EstadoDominio {
	ed := EstadoDominio{
		Dominio:              l.Alvo.Dominio,
		Capacidade:           l.Alvo.Capacidade,
		Estagio:              l.Alvo.Estagio,
		NoIndice:             l.NoIndice,
		NoTeto:               l.NoTeto,
		Teto:                 l.Teto,
		Estouros:             l.Estouros,
		Recusados:            l.Recusados,
		RecusadosProprios:    l.RecusadosProprios,
		SemVaga:              l.SemVaga,
		DirecionadoV6:        l.DirecionadoV6,
		Rotatividade:         l.Rotatividade,
		RotatividadeTruncada: l.RotatividadeTruncada,
	}
	if !l.UltimoAprendizado.IsZero() {
		ed.UltimoAprendizado = l.UltimoAprendizado.Unix()
	}
	if kernelLido {
		n := cred.PorDominio[l.Alvo.Dominio]
		ed.NoKernel = &n
	}
	return ed
}

// DefinirFonteDeEnderecosProprios é o jeito curto de ligar a proteção do item
// mais grave deste pacote.
//
// Junta o que está nas interfaces (que já pega o endereço da WAN e o prefixo da
// LAN, v4 e v6) com a lista de endereços que a caixa USA e não tem numa
// interface: o gateway de um uplink ponto a ponto, os hosts de monitoração, o
// servidor de teste de DNS. É chamada a cada poda, porque o endereço da WAN
// muda sozinho num link discado — uma lista tirada só no boot protegeria o
// endereço de ontem.
func (s *Servico) DefinirFonteDeEnderecosProprios(f func() []string) {
	if f == nil {
		return
	}
	s.fonteProtegidos = func() []netip.Prefix {
		return append(PrefixosLocais(), PrefixosDeEnderecos(f())...)
	}
}
