package domtargets

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ddns"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// O índice do alvo por domínio (#123), terceira parte: a decisão.
//
// O QUE ESTE ARQUIVO É. Aqui mora tudo que decide, e nada que executa. Ele
// recebe "o resolver respondeu tais endereços para tal nome" e devolve "isto
// precisa ir para o kernel" — sem tocar em nft, em banco, em socket nem em
// relógio de parede. É de propósito: a parte que decide é a que erra caro e a
// que precisa de teste, e teste que precisa de root não é rodado.
//
// O ÍNDICE ESPELHA O KERNEL, e essa é a invariante que segura o resto. Só entra
// aqui endereço que foi (ou está indo) para uma das três estruturas do
// nftables. Endereço de domínio em ensaio NÃO entra: ensaio não escreve, e um
// índice que guardasse o que o kernel não tem voltaria a produzir a tela que
// afirma o que não é.
//
// O QUE ELE PROTEGE, EM ORDEM DE GRAVIDADE:
//
//  1. Endereço que não pode virar regra nunca entra (Utilizavel). É a proteção
//     mais importante do arquivo: sem ela um domínio hostil responde com o
//     endereço da LAN do cliente e o firewall passa a agir contra a própria
//     rede a mando de um terceiro.
//  2. Reensinar endereço fresco não gera comando (a decisão de 1/3). Um domínio
//     popular com TTL de 30s e vinte clientes geraria dezenas de forks de nft
//     por minuto para não mudar nada.
//  3. O que estoura APARECE (Contadores). Set alimentado por DNS sem teto é
//     vazamento de memória; teto sem contador é vazamento de informação.

// Capacidade é o que o admin pediu para o domínio.
type Capacidade string

const (
	// Barrar joga os endereços do domínio nos sets de bloqueio.
	Barrar Capacidade = "barrar"
	// Direcionar joga os endereços no map que escolhe a WAN.
	Direcionar Capacidade = "direcionar"
)

// Estagio é o quanto o domínio pode fazer.
type Estagio string

const (
	// Ensaio é onde TODO domínio nasce, e o que ele significa é literal: o
	// produto aprende os endereços, conta a rotatividade e não escreve uma
	// linha no kernel.
	//
	// Existe porque casar tráfego por nome é a capacidade deste produto com a
	// maior distância entre "parece certo" e "está certo": um domínio de CDN
	// compartilhado põe no set o endereço que serve outros mil sites, e o
	// sintoma é a rede inteira caindo por causa de um bloqueio que o admin
	// achou pequeno. O ensaio deixa ele ver o estrago ANTES.
	Ensaio Estagio = "ensaio"
	// Ativo escreve no kernel. Só se chega aqui por ação explícita.
	Ativo Estagio = "ativo"
)

// Alvo é um domínio como o admin o listou.
type Alvo struct {
	// Dominio já vem normalizado por NormalizarDominio.
	Dominio    string
	Capacidade Capacidade
	Estagio    Estagio
	// Marca é a da WAN escolhida, e só é lida em Direcionar.
	Marca uint32
}

const (
	// MaxPorDominio é o teto de endereços vivos de UM domínio.
	//
	// Sessenta e quatro é largo para um serviço normal e apertado para uma CDN
	// grande — e é isso que se quer. Um domínio que bate no teto não está sendo
	// bloqueado de verdade: ele tem mais endereços do que cabe, e o que o admin
	// precisa é ver o contador, não ganhar um set cheio que bloqueia metade.
	MaxPorDominio = 64

	// MaxEnderecos é o teto global do índice.
	//
	// Fica FOLGADAMENTE abaixo do `size 8192` das estruturas do kernel de
	// propósito. Quem tem de dizer "não cabe" é este índice, aqui, com um
	// contador que a tela lê — e não o nft, no meio de um lote, com um erro que
	// derruba a transação inteira e leva junto os endereços que caberiam.
	MaxEnderecos = 4096

	// FracaoDeRenovacao: só renova quando resta menos de 1/(este número) do
	// prazo concedido. Ver Aprender.
	FracaoDeRenovacao = 3

	// MaxRotatividadeLembrada limita quantos endereços distintos por domínio o
	// índice lembra para a conta de rotatividade.
	//
	// A conta é um sinal de produto ("este nome muda de endereço a cada
	// resposta, bloquear por endereço não vai funcionar"), e sinal de produto
	// não justifica um set que cresce para sempre. Ao bater no teto o índice
	// para de crescer e MARCA a conta como truncada, em vez de mentir um número
	// parado.
	MaxRotatividadeLembrada = 512

	// FolgaDePoda é o quanto o índice espera, DEPOIS do vencimento, para
	// esquecer um endereço.
	//
	// Não é frescura: o prazo do kernel começa a correr quando o `nft -f`
	// chega, que é até uma janela de coalescência mais um fork depois de o
	// índice ter marcado o vencimento. Podar no instante exato deixaria uma
	// fresta em que o índice acha que o endereço sumiu e o kernel ainda o tem —
	// e nessa fresta o reensino sairia como `add` sem `delete`, que o nft
	// aceita em silêncio e NÃO renova. É exatamente a falha medida no
	// doc-comment de AplicarLote, entrando pela porta dos fundos.
	FolgaDePoda = 30 * time.Second
)

// Escrita é um endereço que precisa ir para o kernel.
type Escrita struct {
	Addr  netip.Addr
	Prazo time.Duration
	// Capacidade diz em qual estrutura ele entra.
	Capacidade Capacidade
	Marca      uint32
	// Substituir diz que ele JÁ ESTÁ nessa mesma estrutura e precisa sair antes
	// de entrar de novo. É o que renova o prazo — sem o `delete` junto, o `add`
	// é aceito em silêncio e não mexe no vencimento.
	Substituir bool
}

// Remocao é um endereço que precisa sair do kernel.
type Remocao struct {
	Addr netip.Addr
	// Capacidade diz de qual estrutura ele sai, que nem sempre é a mesma em
	// que ele vai entrar depois.
	Capacidade Capacidade
}

// Ajuste é o par de listas que uma mudança na lista de domínios produz.
type Ajuste struct {
	Escritas []Escrita
	Remocoes []Remocao
}

// Vazio diz se não há nada a fazer.
func (a Ajuste) Vazio() bool { return len(a.Escritas) == 0 && len(a.Remocoes) == 0 }

// Contadores é o que estourou, o que foi recusado e o que foi economizado.
//
// Tudo aqui é cumulativo desde o boot e nada aqui é contagem de endereço vivo:
// contagem de endereço vivo quem responde é o kernel. Ver Servico.Estado.
type Contadores struct {
	// Recusados são endereços que o filtro semântico barrou. Um número que sobe
	// é um domínio devolvendo endereço que não podia — a tela precisa mostrar,
	// porque é assim que um envenenamento aparece.
	Recusados uint64
	// Recusados4 é o recorte v4 do acima, que é o que quase sempre importa:
	// endereço de LAN recusado é v4 em praticamente toda instalação.
	Recusados4 uint64
	// EstouroPorDominio e EstouroGlobal são endereços que NÃO entraram por
	// falta de espaço. Estouro silencioso vira "por que este site passa?".
	EstouroPorDominio uint64
	EstouroGlobal     uint64
	// Novos, Renovacoes e SemComando medem o trabalho. SemComando é o que a
	// decisão de 1/3 economizou, e é o número que justifica ela existir.
	Novos      uint64
	Renovacoes uint64
	SemComando uint64
	// NaoCasados e EmEnsaio são respostas que passaram por aqui e não viraram
	// nada — a primeira porque nenhum domínio listado as cobre, a segunda
	// porque o domínio ainda não foi promovido.
	NaoCasados uint64
	EmEnsaio   uint64
	// Trocas são endereços que mudaram de estrutura (ou de marca da WAN)
	// porque a lista de domínios mudou embaixo deles. Separadas de Renovacoes
	// porque não são a mesma coisa: renovar é o prazo esticando, trocar é o
	// endereço saindo de um set e entrando noutro.
	Trocas uint64
	// PodadosTotal é quanto o índice já esqueceu por vencimento.
	PodadosTotal uint64
}

type registro struct {
	// dominios são os que reivindicam este endereço. É o refcount: apagar um
	// domínio NÃO tira o endereço enquanto outro o reivindicar, porque o
	// endereço continua servindo o outro nome e tirá-lo desbloquearia o que o
	// admin mandou bloquear.
	dominios map[string]bool
	// expira e concedido são o espelho do prazo que o kernel recebeu.
	expira    time.Time
	concedido time.Duration
	// escritoCap e escritoMarca são em qual estrutura ele está DE FATO. Sem
	// guardar isto, uma troca de capacidade adicionaria na estrutura nova sem
	// tirar da velha — e o endereço ficaria barrado para sempre.
	escritoCap   Capacidade
	escritoMarca uint32
}

type rotatividade struct {
	distintos map[netip.Addr]bool
	truncada  bool
}

// Indice guarda a lista de domínios, o que cada um ensinou e o que o kernel
// recebeu.
//
// Tem lock próprio porque tem dois lados: a goroutine do alimentador escreve
// (Aprender, Podar) e a da tela lê (Estado, Rotatividade), e a lista de
// domínios muda pelo caminho da API. O lock é interno e nunca é segurado
// enquanto se roda nft — o executor fica do lado de fora deste arquivo
// justamente para que isso não possa acontecer.
type Indice struct {
	mu    sync.Mutex
	agora func() time.Time

	alvos map[string]Alvo
	ends  map[netip.Addr]*registro
	// porDominio é a contagem viva por domínio, mantida junto de ends para o
	// teto não custar uma varredura a cada endereço aprendido.
	porDominio map[string]int
	vistos     map[string]*rotatividade

	cont Contadores
}

// NovoIndice cria o índice vazio. agora nil vale time.Now — o parâmetro existe
// para o teste poder envelhecer um prazo sem dormir.
func NovoIndice(agora func() time.Time) *Indice {
	if agora == nil {
		agora = time.Now
	}
	return &Indice{
		agora:      agora,
		alvos:      map[string]Alvo{},
		ends:       map[netip.Addr]*registro{},
		porDominio: map[string]int{},
		vistos:     map[string]*rotatividade{},
	}
}

// NormalizarDominio põe o nome na forma em que o índice compara, e diz se ele
// serve como entrada de lista.
//
// RECUSA NOME DE UM RÓTULO SÓ, e isso não é rigor gratuito: como o casamento é
// por sufixo em fronteira de rótulo, listar `com` casaria com a internet
// inteira. Um erro de digitação na tela não pode ter esse alcance.
//
// Recusa também o que não é nome de máquina (curinga, barra, espaço): não há
// curinga nem regex neste casamento, e aceitar `*.exemplo.com` aqui criaria a
// expectativa de um recurso que não existe.
func NormalizarDominio(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.Trim(d, ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	if !strings.Contains(d, ".") || strings.Contains(d, "..") {
		return "", false
	}
	for _, r := range d {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-'
		if !ok {
			return "", false
		}
	}
	return d, true
}

// prefixosProibidos completa o que ddns.IsPrivate não cobre.
//
// ddns.IsPrivate resolve loopback, link-local, RFC1918, fc00::/7, não
// especificado e CGNAT — que é o que ele foi escrito para resolver. Falta o
// resto do espaço que NÃO pode virar regra de firewall, e a lista abaixo é esse
// resto. Cada linha existe porque a alternativa é o produto escrever no kernel
// um endereço que um terceiro escolheu:
//
//   - 0.0.0.0/8 e 240.0.0.0/4 (que inclui 255.255.255.255): nunca são destino.
//   - 192.0.0.0/24, as TEST-NETs e 198.18.0.0/15: reservados, e o que aparece
//     numa resposta de verdade é engano ou sondagem.
//   - 2001:db8::/32: documentação.
//   - 2002::/16 (6to4), 2001::/32 (Teredo) e 64:ff9b::/96 (NAT64): os três
//     EMBUTEM um endereço v4 dentro do v6, e é por aí que um domínio hostil
//     contrabandearia a LAN do cliente por baixo de um filtro que só olha v4.
var prefixosProibidos = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

// Utilizavel diz se um endereço aprendido pode virar regra.
//
// É A PROTEÇÃO MAIS IMPORTANTE DESTE PACOTE. O endereço vem de uma resposta de
// DNS, quer dizer: de um servidor que não é nosso, escolhido por quem registrou
// o nome. Sem este filtro, o admin lista um domínio, o dono daquele domínio
// responde 192.168.0.1 ou 224.0.0.1, e o produto barra a própria LAN — ou, no
// direcionamento, manda o tráfego da rede inteira para a tabela de rota de uma
// WAN. Um terceiro escolhendo o que o nosso firewall faz.
//
// Endereço v4 embutido em v6 (::ffff:1.2.3.4) é RECUSADO em vez de
// desembrulhado: ele não tem o que fazer num registro AAAA legítimo, e
// desembrulhar seria aceitar a forma que existe justamente para enganar filtro.
func Utilizavel(a netip.Addr) bool {
	if !a.IsValid() || a.Is4In6() {
		return false
	}
	if a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if ddns.IsPrivate(a) {
		return false
	}
	for _, p := range prefixosProibidos {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// DefinirAlvos troca a lista inteira de domínios e devolve o que o kernel
// precisa receber por causa da troca.
//
// TIRAR UM DOMÍNIO DA LISTA, OU BAIXÁ-LO PARA ENSAIO, TEM DE TIRAR OS ENDEREÇOS
// DELE DO KERNEL NA HORA. Deixar para o vencimento manteria até uma hora de
// bloqueio depois de o admin ter desligado o bloqueio — que é o pior tipo de
// defeito de firewall, porque a tela já diz que está desligado.
func (i *Indice) DefinirAlvos(alvos []Alvo) Ajuste {
	i.mu.Lock()
	defer i.mu.Unlock()

	novos := make(map[string]Alvo, len(alvos))
	for _, a := range alvos {
		d, ok := NormalizarDominio(a.Dominio)
		if !ok {
			continue
		}
		a.Dominio = d
		// Estágio e capacidade desconhecidos caem no lado seguro: quem não diz
		// que é ativo está em ensaio, e quem não diz que é direcionamento
		// barra. Um campo em branco vindo do banco não pode virar
		// direcionamento silencioso da rede inteira.
		if a.Estagio != Ativo {
			a.Estagio = Ensaio
		}
		if a.Capacidade != Direcionar {
			a.Capacidade = Barrar
		}
		novos[d] = a
	}
	i.alvos = novos
	return i.reconciliar()
}

// Alvos devolve a lista corrente, ordenada, para a tela.
func (i *Indice) Alvos() []Alvo {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]Alvo, 0, len(i.alvos))
	for _, a := range i.alvos {
		out = append(out, a)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Dominio < out[y].Dominio })
	return out
}

// reconciliar reavalia todo endereço vivo contra a lista corrente. Chamada com
// o lock segurado.
func (i *Indice) reconciliar() Ajuste {
	var aj Ajuste
	agora := i.agora()
	for addr, r := range i.ends {
		// Quem não está mais na lista, ou caiu para ensaio, deixa de
		// reivindicar. O refcount é o que decide se o endereço sai.
		for d := range r.dominios {
			a, ok := i.alvos[d]
			if ok && a.Estagio == Ativo {
				continue
			}
			delete(r.dominios, d)
			i.baixarContagem(d)
		}
		capa, marca, temDono := i.capEfetiva(r.dominios)
		if !temDono {
			aj.Remocoes = append(aj.Remocoes, Remocao{Addr: addr, Capacidade: r.escritoCap})
			i.soltar(addr, r)
			continue
		}
		if capa == r.escritoCap && marca == r.escritoMarca {
			continue
		}
		// Trocou de estrutura (ou de marca da WAN): sai da antiga e entra na
		// nova. As duas coisas na mesma rodada, porque um `delete` sem `add`
		// deixa o domínio sem tratamento nenhum e um `add` sem `delete` deixa o
		// mesmo endereço nas duas estruturas.
		aj.Remocoes = append(aj.Remocoes, Remocao{Addr: addr, Capacidade: r.escritoCap})
		aj.Escritas = append(aj.Escritas, Escrita{
			Addr: addr, Prazo: r.concedido, Capacidade: capa, Marca: marca,
		})
		r.escritoCap, r.escritoMarca = capa, marca
		r.expira = agora.Add(r.concedido)
	}
	return aj
}

// soltar tira o endereço do índice e devolve as vagas de quem o reivindicava.
func (i *Indice) soltar(addr netip.Addr, r *registro) {
	for d := range r.dominios {
		i.baixarContagem(d)
	}
	delete(i.ends, addr)
}

func (i *Indice) baixarContagem(d string) {
	i.porDominio[d]--
	if i.porDominio[d] <= 0 {
		delete(i.porDominio, d)
	}
}

// capEfetiva decide em qual estrutura o endereço entra quando mais de um
// domínio o reivindica. Chamada com o lock segurado.
//
// BARRAR GANHA DE DIRECIONAR, sempre. Bloquear é uma promessa de negação;
// direcionar é uma preferência de saída. Se o mesmo endereço serve um nome
// barrado e um nome direcionado, honrar o direcionamento seria desbloquear em
// silêncio o que o admin mandou bloquear — e ninguém veria, porque a tela
// continuaria mostrando o domínio como barrado.
func (i *Indice) capEfetiva(dominios map[string]bool) (Capacidade, uint32, bool) {
	if len(dominios) == 0 {
		return "", 0, false
	}
	nomes := make([]string, 0, len(dominios))
	for d := range dominios {
		nomes = append(nomes, d)
	}
	if len(nomes) > 1 {
		// Ordem estável: com dois domínios de direcionamento reivindicando o
		// mesmo endereço, a marca escolhida não pode depender da ordem de
		// iteração do mapa, senão o endereço trocaria de WAN sozinho a cada
		// reconciliação.
		sort.Strings(nomes)
	}
	var marca uint32
	achouDirecionar := false
	for _, d := range nomes {
		a, ok := i.alvos[d]
		if !ok || a.Estagio != Ativo {
			continue
		}
		if a.Capacidade == Barrar {
			return Barrar, 0, true
		}
		if !achouDirecionar {
			achouDirecionar, marca = true, a.Marca
		}
	}
	if achouDirecionar {
		return Direcionar, marca, true
	}
	return "", 0, false
}

// Casar acha o domínio listado que cobre este nome, se houver.
//
// SUFIXO EM FRONTEIRA DE RÓTULO, e nada além disso. `netflix.com` cobre
// `netflix.com` e `www.netflix.com`; NÃO cobre `evilnetflix.com`, que é o
// ataque óbvio contra um casamento feito com strings.HasSuffix cru — e que
// listaria como Netflix um domínio que qualquer um registra em cinco minutos.
//
// O MAIS ESPECÍFICO GANHA: com `netflix.com` barrado e `assistir.netflix.com`
// direcionado, quem perguntou pelo segundo recebe o segundo. A busca sobe
// rótulo a rótulo a partir do nome inteiro, então a primeira coincidência já é
// a mais específica — sem varrer a lista, que num índice de centenas de
// domínios seria uma varredura inteira por resposta de DNS.
func (i *Indice) Casar(nome string) (Alvo, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.casar(nome)
}

func (i *Indice) casar(nome string) (Alvo, bool) {
	n := strings.ToLower(strings.Trim(strings.TrimSpace(nome), "."))
	for n != "" {
		if a, ok := i.alvos[n]; ok {
			return a, true
		}
		p := strings.IndexByte(n, '.')
		if p < 0 {
			return Alvo{}, false
		}
		n = n[p+1:]
	}
	return Alvo{}, false
}

// Aprender registra o que uma resposta de DNS ensinou e devolve o que precisa
// ir para o kernel.
//
// Devolve um Ajuste VAZIO na esmagadora maioria das chamadas, e é isso que se
// quer:
//
//   - o nome não casa com domínio nenhum (o caso comum num resolver de rede);
//   - o domínio está em ensaio, e ensaio não escreve;
//   - os endereços já estão lá com prazo fresco.
//
// A DECISÃO DE 1/3. Um endereço só é renovado quando resta menos de um terço do
// prazo que ele recebeu. Sem isso, cada resposta repetida viraria um
// `delete`+`add`: um domínio popular com TTL de 30 segundos e vinte clientes na
// rede geraria dezenas de forks de nft por minuto para não mudar nada. Com um
// terço, o prazo mínimo de 10 minutos vira uma escrita a cada ~6,7 minutos por
// endereço no pior caso, e o terço restante é folga de sobra para um lote
// falhar e ser refeito antes de o kernel deixar o endereço vencer.
func (i *Indice) Aprender(nome string, addrs []netip.Addr, ttl time.Duration) Ajuste {
	i.mu.Lock()
	defer i.mu.Unlock()

	var aj Ajuste
	alvo, ok := i.casar(nome)
	if !ok {
		i.cont.NaoCasados++
		return aj
	}

	// A rotatividade é contada TAMBÉM em ensaio — é para isso que o ensaio
	// existe. Quem lista um domínio de CDN precisa ver, antes de promover, que
	// ele já ensinou trezentos endereços distintos.
	i.anotarRotatividade(alvo.Dominio, addrs)

	if alvo.Estagio != Ativo {
		i.cont.EmEnsaio++
		return aj
	}

	prazo := grampear(ttl)
	agora := i.agora()

	for _, a := range addrs {
		if !Utilizavel(a) {
			i.cont.Recusados++
			if a.Is4() {
				i.cont.Recusados4++
			}
			continue
		}

		r, existe := i.ends[a]
		if !existe {
			if len(i.ends) >= MaxEnderecos {
				i.cont.EstouroGlobal++
				continue
			}
			if i.porDominio[alvo.Dominio] >= MaxPorDominio {
				i.cont.EstouroPorDominio++
				continue
			}
			i.ends[a] = &registro{
				dominios:     map[string]bool{alvo.Dominio: true},
				expira:       agora.Add(prazo),
				concedido:    prazo,
				escritoCap:   alvo.Capacidade,
				escritoMarca: alvo.Marca,
			}
			i.porDominio[alvo.Dominio]++
			i.cont.Novos++
			aj.Escritas = append(aj.Escritas, Escrita{
				Addr: a, Prazo: prazo, Capacidade: alvo.Capacidade, Marca: alvo.Marca,
			})
			continue
		}

		// Já conhecido. Um domínio a mais pode estar reivindicando o mesmo
		// endereço — o refcount cresce, e isso sozinho não é motivo para
		// escrever coisa nenhuma no kernel.
		if !r.dominios[alvo.Dominio] {
			if i.porDominio[alvo.Dominio] >= MaxPorDominio {
				i.cont.EstouroPorDominio++
			} else {
				r.dominios[alvo.Dominio] = true
				i.porDominio[alvo.Dominio]++
			}
		}

		capa, marca, temDono := i.capEfetiva(r.dominios)
		if !temDono {
			continue
		}
		trocou := capa != r.escritoCap || marca != r.escritoMarca
		vencendo := r.expira.Sub(agora) < r.concedido/FracaoDeRenovacao

		if !trocou && !vencendo {
			i.cont.SemComando++
			continue
		}
		if trocou {
			// Trocar de estrutura é SAIR de uma e ENTRAR na outra, e as duas
			// metades têm de sair na mesma rodada. Só a entrada deixaria o
			// endereço nas duas ao mesmo tempo — barrado e direcionado —, e o
			// que sobra na estrutura errada não é renovado por ninguém: ele
			// some sozinho no vencimento, o que faz o defeito aparecer só de
			// vez em quando e nunca no momento em que foi criado.
			aj.Remocoes = append(aj.Remocoes, Remocao{Addr: a, Capacidade: r.escritoCap})
			i.cont.Trocas++
		} else {
			i.cont.Renovacoes++
		}
		// Substituir é o `delete` da RENOVAÇÃO, e vale só quando o endereço
		// continua na mesma estrutura: numa troca, quem apaga é a Remocao
		// acima, e um segundo `delete` no set de destino erraria por elemento
		// ausente e derrubaria o lote inteiro.
		r.escritoCap, r.escritoMarca = capa, marca
		r.expira = agora.Add(prazo)
		r.concedido = prazo
		aj.Escritas = append(aj.Escritas, Escrita{
			Addr: a, Prazo: prazo, Capacidade: capa, Marca: marca, Substituir: !trocou,
		})
	}
	return aj
}

// grampear põe o TTL da resposta entre o piso e o teto do nftables.
//
// Os limites são os MESMOS do pacote nftables de propósito, importados de lá em
// vez de copiados: dois números iguais escritos em dois lugares viram dois
// números diferentes no primeiro ajuste, e a divergência apareceria como um
// índice que acha que renovou e um kernel que já tinha expirado.
func grampear(d time.Duration) time.Duration {
	switch {
	case d < nftables.DomTTLPiso:
		return nftables.DomTTLPiso
	case d > nftables.DomTTLTeto:
		return nftables.DomTTLTeto
	default:
		return d
	}
}

func (i *Indice) anotarRotatividade(dominio string, addrs []netip.Addr) {
	rt := i.vistos[dominio]
	if rt == nil {
		rt = &rotatividade{distintos: map[netip.Addr]bool{}}
		i.vistos[dominio] = rt
	}
	for _, a := range addrs {
		if !Utilizavel(a) || rt.distintos[a] {
			continue
		}
		if len(rt.distintos) >= MaxRotatividadeLembrada {
			rt.truncada = true
			return
		}
		rt.distintos[a] = true
	}
}

// Rotatividade diz quantos endereços DISTINTOS aquele domínio já ensinou, e se
// a conta foi truncada.
//
// É o número que decide se casar por domínio faz sentido para aquele nome. Um
// domínio com rotatividade 3 é um servidor; um com rotatividade 300 é uma CDN,
// e bloqueá-la por endereço vai bloquear junto o que ela serve para os outros —
// que é exatamente o estrago que o estágio de ensaio existe para mostrar antes.
//
// O booleano NÃO é detalhe de implementação: sem ele, um domínio que estourou o
// teto de lembrança mostraria para sempre o mesmo número, e o admin leria
// "estabilizou" onde o certo é "não sei mais contar".
func (i *Indice) Rotatividade(dominio string) (int, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	rt := i.vistos[dominio]
	if rt == nil {
		return 0, false
	}
	return len(rt.distintos), rt.truncada
}

// Podar esquece o que já venceu no kernel e devolve quantos saíram.
//
// Não gera comando nenhum: quem apaga é o próprio nftables, pelo `timeout` do
// elemento. O que esta função faz é impedir que o índice — e com ele o refcount
// e os tetos — cresça guardando endereço que o kernel já não tem.
//
// A FolgaDePoda existe porque os dois relógios não são o mesmo. Ver a
// constante.
func (i *Indice) Podar() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	corte := i.agora().Add(-FolgaDePoda)
	n := 0
	for addr, r := range i.ends {
		if r.expira.After(corte) {
			continue
		}
		i.soltar(addr, r)
		n++
	}
	i.cont.PodadosTotal += uint64(n)
	return n
}

// Contadores devolve uma cópia do que estourou, do que foi recusado e do que
// foi economizado.
func (i *Indice) Contadores() Contadores {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cont
}

// Reivindicantes credita cada endereço LIDO DO KERNEL aos domínios que o
// ensinaram, e devolve a contagem por domínio.
//
// Existe para a tela poder dizer "netflix.com: 12 endereços barrados agora" sem
// que esse 12 venha da memória. Quem entra aqui é a lista que o kernel
// devolveu; o índice só empresta a identidade, que é a parte que o kernel não
// guarda (ver o cabeçalho de internal/nftables/dominios.go).
//
// Endereço que o kernel tem e o índice não conhece é contado em órfãos: é sobra
// de um flush perdido, de um reinício do processo com o kernel cheio ou de um
// domínio removido — e precisa aparecer, porque é um bloqueio valendo que
// ninguém reivindica.
func (i *Indice) Reivindicantes(addrs []netip.Addr) (porDominio map[string]int, orfaos int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	porDominio = map[string]int{}
	for _, a := range addrs {
		r, ok := i.ends[a]
		if !ok || len(r.dominios) == 0 {
			orfaos++
			continue
		}
		for d := range r.dominios {
			porDominio[d]++
		}
	}
	return porDominio, orfaos
}
