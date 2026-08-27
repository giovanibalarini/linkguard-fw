package domtargets

import (
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/ddns"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// O índice do alvo por domínio (#123), terceira parte: a decisão.
//
// O QUE ESTE ARQUIVO É. Aqui mora tudo que decide, e nada que executa. Ele
// recebe "o resolver respondeu tais endereços para tal nome" e devolve
// "isto precisa ir para o kernel" — sem tocar em nft, em banco, em socket
// nem em relógio de parede. É de propósito: a parte que decide é a que erra
// caro e a que precisa de teste, e teste que precisa de root não é rodado.
//
// O ÍNDICE ESPELHA O KERNEL, e essa é a invariante que segura o resto. Só entra
// aqui endereço que foi (ou está indo) para uma das três estruturas do
// nftables. Endereço de domínio em ensaio NÃO entra: ensaio não escreve, e um
// índice que guardasse o que o kernel não tem voltaria a produzir a tela que
// afirma o que não é. Pelo mesmo motivo o índice distingue "eu decidi
// escrever" de "o kernel recebeu" — ver registro.escrito e NaoConfirmado.
//
// O QUE ELE PROTEGE, EM ORDEM DE GRAVIDADE:
//
//  1. Endereço que não pode virar regra nunca entra. São DOIS filtros, e os
//     dois são obrigatórios: Utilizavel recusa por CATEGORIA (privado,
//     reservado, documentação, o que embute v4 dentro de v6) e protegido()
//     recusa o que é NOSSO — a faixa da WAN, o gateway, a LAN v6. O segundo não
//     é redundância: o endereço público do link é público por construção, e um
//     domínio hostil que responde com ele põe o firewall contra a própria
//     caixa passando pelo primeiro filtro sem esbarrar em nada.
//  2. Reensinar endereço fresco não gera comando (a decisão de 1/3). Um domínio
//     popular com TTL de 30s e vinte clientes geraria dezenas de forks de nft
//     por minuto para não mudar nada.
//  3. O que estoura APARECE (Contadores, e por domínio em Linhas). Set
//     alimentado por DNS sem teto é vazamento de memória; teto sem contador é
//     vazamento de informação; e contador global sem o nome do domínio é ruído
//     com aparência de medição.

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
	// maior distância entre "parece certo" e "está certo": um domínio
	// de CDN compartilhado põe no set o endereço que serve outros mil sites, e
	// o sintoma é a rede inteira caindo por causa de um bloqueio que o admin
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
	// precisa é ver o contador DAQUELE domínio, não ganhar um set cheio que
	// bloqueia metade. Ver LinhaDominio.NoTeto e LinhaDominio.Estouros.
	MaxPorDominio = 64

	// MaxEnderecos é o teto global do índice.
	//
	// Fica FOLGADAMENTE abaixo do size 8192 das estruturas do kernel de
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
	// Não é frescura: o prazo do kernel começa a correr quando o nft -f chega,
	// que é até uma janela de coalescência mais um fork depois de o índice ter
	// marcado o vencimento. Podar no instante exato deixaria uma fresta em que
	// o índice acha que o endereço sumiu e o kernel ainda o tem — e nessa
	// fresta o reensino sairia como add sem delete, que o nft aceita em
	// silêncio e NÃO renova. É exatamente a falha medida no doc-comment de
	// AplicarLote, entrando pela porta dos fundos.
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
	// de entrar de novo. É o que renova o prazo — sem o delete junto, o add é
	// aceito em silêncio e não mexe no vencimento.
	//
	// Só é verdade quando o índice tem MOTIVO para crer que o elemento está lá:
	// um delete de elemento ausente derruba a transação inteira, e emitir um
	// por um endereço que nunca foi escrito é derrubar o lote por conta
	// própria. Ver registro.escrito.
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
// Quase tudo aqui é cumulativo desde o boot. As DUAS exceções são Vivos e
// Dominios, que são estado agora — e existem porque sem eles não dá para
// comparar o índice com o kernel, que é o pré-requisito de toda a tela.
type Contadores struct {
	// Recusados são endereços que o filtro de CATEGORIA barrou. Um número que
	// sobe é um domínio devolvendo endereço que não podia — e a recusa por
	// domínio, que é o que diz QUAL, está em LinhaDominio.
	Recusados uint64
	// Recusados4 é o recorte v4 do acima, que é o que quase sempre importa:
	// endereço de LAN recusado é v4 em praticamente toda instalação.
	Recusados4 uint64
	// RecusadosProprios são endereços que pertencem à PRÓPRIA caixa ou às
	// redes dela. É a categoria mais grave: nenhum deles é recusado por
	// Utilizavel, porque todos são públicos por construção. Ver protegido.
	RecusadosProprios uint64
	// EstouroPorDominio e EstouroGlobal são endereços que NÃO entraram por
	// falta de espaço. Estouro silencioso vira "por que este site passa?".
	EstouroPorDominio uint64
	EstouroGlobal     uint64
	// SemVagaNoRefcount é outra coisa: o endereço ESTÁ no kernel, posto lá por
	// outro domínio, e este domínio não ganhou crédito por ele por estar no
	// teto. Contar junto com EstouroPorDominio misturaria dois estados que
	// pedem ações opostas do admin.
	SemVagaNoRefcount uint64
	// DirecionadoV6Descartado são endereços v6 de domínio DIRECIONADO. Não
	// existe par v6 do map de direcionamento (de propósito), então eles não
	// entram em estrutura nenhuma — e sem este contador a tela mostraria um
	// domínio "direcionado" que não direciona, sem uma linha dizendo por
	// quê.
	DirecionadoV6Descartado uint64
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
	// porque a lista de domínios mudou embaixo deles.
	Trocas uint64
	// NaoConfirmados são escritas que o kernel NÃO recebeu e que o índice
	// desacreditou. Ver NaoConfirmado.
	NaoConfirmados uint64
	// Confirmados é o par: escritas que o kernel ACEITOU. Os dois lado a lado
	// são o que separa trabalho feito de trabalho tentado — Lotes sozinho conta
	// as duas coisas como uma.
	Confirmados uint64
	// PromovidosDoEnsaio são endereços que foram para o kernel NO ATO da
	// promoção, aproveitando o que o ensaio já tinha aprendido. É a medida do
	// que o admin teria esperado o DNS reensinar. Ver Indice.ensaiados.
	PromovidosDoEnsaio uint64
	// PodadosTotal é quanto o índice já esqueceu por vencimento.
	PodadosTotal uint64
	// Vivos e Dominios são ESTADO, não histórico: quantos endereços o índice
	// acha que escreveu e quantos domínios têm ao menos um. Sem eles não há
	// como pôr lado a lado o desejado e o real.
	Vivos    int
	Dominios int
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
	// escrito é a diferença entre "eu decidi escrever" e "o kernel
	// recebeu", e ela é o pé de todo delete que este índice manda emitir.
	//
	// Enquanto for falso, nenhuma Remocao e nenhum Substituir sai por este
	// endereço: um delete de elemento AUSENTE derruba a transação inteira
	// (medido), e emitir um por algo que nunca entrou é derrubar o próprio
	// lote. Vira verdadeiro só quando o chamador confirma que o nft aceitou.
	escrito bool
	// duvidoso marca o endereço cuja última escrita NÃO foi confirmada. Ele
	// força a próxima resposta a reemitir, em vez de esperar 2/3 de um prazo
	// que o kernel pode nunca ter concedido.
	duvidoso bool
	// pendente é uma escrita deste endereço a caminho do kernel, e os pend* são
	// o que ela vai gravar no espelho SE o nft aceitar. Ficam separados dos
	// campos de verdade porque o índice não pode anotar como feito o que ainda
	// pode falhar — ver Confirmar.
	pendente  bool
	pendPrazo time.Duration
	pendCap   Capacidade
	pendMarca uint32
}

type rotatividade struct {
	distintos map[netip.Addr]bool
	truncada  bool
}

// estatDominio é o que aconteceu com UM domínio.
//
// Existe porque contador global não é atribuível: "houve 40.000 estouros por
// domínio" numa caixa com trinta domínios listados não diz qual deles está
// meio-bloqueado, e é justamente essa a pergunta que o admin faz.
type estatDominio struct {
	recusados         uint64
	recusadosProprios uint64
	estouros          uint64
	semVaga           uint64
	direcionadoV6     uint64
	ultimoAprendizado time.Time
	// avisou limita o log a UMA linha por domínio: uma recusa costuma vir em
	// rajada, e um aviso por endereço recusado é o jeito de o log virar ruído
	// exatamente no minuto em que ele importa.
	avisou bool
}

// Indice guarda a lista de domínios, o que cada um ensinou e o que o kernel
// recebeu.
//
// O LOCK NUNCA PODE SER TOCADO PELO CAMINHO DO Observar. Ele é segurado por
// Podar varrendo 4096 registros, por Creditar varrendo até 8192 endereços
// vindos do kernel e por reconciliar dando uma volta inteira no índice — quer
// dizer, por caminhos que nascem numa requisição HTTP. Pôr o laço que drena o
// socket do unbound atrás dele é a contrapressão no resolver que este pacote
// inteiro foi desenhado para evitar. É RWMutex porque os leitores dominam, e
// isso reduz o estrago de um painel que atualiza a cada poucos segundos — mas
// não muda a regra acima.
type Indice struct {
	mu    sync.RWMutex
	agora func() time.Time

	alvos map[string]Alvo
	ends  map[netip.Addr]*registro
	// porDominio é a contagem viva por domínio, mantida junto de ends para o
	// teto não custar uma varredura a cada endereço aprendido.
	porDominio map[string]int
	vistos     map[string]*rotatividade
	estat      map[string]*estatDominio
	// ensaiados é o que o DNS ensinou de um domínio que ainda NÃO escreve:
	// endereço -> quando o prazo daquele aprendizado vence.
	//
	// NÃO É O ESPELHO, e a distinção é a razão de ser um mapa separado em vez
	// de uma marca dentro de ends. O espelho responde "o que o kernel tem", e
	// misturar nele endereço de ensaio produziria de volta a tela que afirma
	// bloqueio onde não há. Este mapa responde outra pergunta: "se eu promover
	// agora, o que já dá para aplicar sem esperar o próximo DNS".
	//
	// Ele existe porque sem ele promover não fazia nada. O admin apertava
	// promover, a tela dizia ativo, e o kernel só recebia o primeiro endereço
	// quando algum cliente da rede fizesse uma consulta NOVA que chegasse ao
	// resolver — o que com cache de TTL longo, e com o cache do próprio
	// navegador em cima, é meia hora ou mais de firewall aberto embaixo de uma
	// tela que diz fechado. Ver replayEnsaio.
	ensaiados map[string]map[netip.Addr]time.Time

	// protegidos são as faixas da PRÓPRIA caixa. Ver DefinirProtegidos.
	protegidos []netip.Prefix

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
		estat:      map[string]*estatDominio{},
		ensaiados:  map[string]map[netip.Addr]time.Time{},
	}
}

// NormalizarDominio põe o nome na forma em que o índice compara, e diz se ele
// serve como entrada de lista.
//
// RECUSA NOME DE UM RÓTULO SÓ, e isso não é rigor gratuito: como o casamento é
// por sufixo em fronteira de rótulo, listar com casaria com a internet inteira.
// Um erro de digitação na tela não pode ter esse alcance.
//
// Recusa também o que não é nome de máquina (curinga, barra, espaço): não há
// curinga nem regex neste casamento, e aceitar *.exemplo.com aqui criaria a
// expectativa de um recurso que não existe.
func NormalizarDominio(s string) (string, bool) {
	return validate.NormalizeDomainTarget(s)
}

// prefixosProibidos4 é o espaço v4 que NÃO pode virar regra e que
// ddns.IsPrivate não cobre.
//
// ddns.IsPrivate resolve loopback, link-local, RFC1918, fc00::/7, não
// especificado e CGNAT — que é o que ele foi escrito para resolver. Cada linha
// abaixo existe porque a alternativa é o produto escrever no kernel um endereço
// que um terceiro escolheu:
//
//   - 0.0.0.0/8 e 240.0.0.0/4 (que inclui 255.255.255.255): nunca são destino.
//   - 192.0.0.0/24, as TEST-NETs e 198.18.0.0/15: reservados, e o que aparece
//     numa resposta de verdade é engano ou sondagem.
//   - 192.88.99.0/24: o anycast de relay 6to4, formalmente aposentado pela RFC
//     7526. Ele é roteável, então passa por todo teste de "é público" — e é
//     o par v4 exato do 2002::/16, que já estava barrado.
//   - 192.31.196.0/24 e 192.175.48.0/24: AS112. Quem responde ali responde por
//     todo mundo, e barrar por endereço não significa nada.
var prefixosProibidos4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// O v6 é filtrado AO CONTRÁRIO do v4, e essa inversão é a correção de um
// defeito real: a lista de bloqueio v6 anterior tinha buracos que nenhuma
// leitura acha, e cada buraco é uma forma de contrabandear um v4 (ou um
// endereço local) por baixo de um filtro que só olha o que ele conhece.
//
// Passavam, medidos: 64:ff9b:1::/48 (o NAT64 de uso LOCAL, RFC 8215, primo do
// 64:ff9b::/96 que estava barrado), ::/96 e ::ffff:0:0:0/96 (as outras duas
// formas de v4-dentro-de-v6, que Is4In6 não reconhece), 2001:2::/48
// (benchmarking, gêmeo do 198.18.0.0/15 que estava lá), 3fff::/20
// (documentação, RFC 9637), 0100::/64 (descarte), 5f00::/16 (SRv6),
// 2001:10::/28 e 2001:20::/28 (ORCHID) e 3ffe::/16 (6bone).
//
// ACEITAR SÓ 2000::/3 e enumerar o ruim DENTRO dela fecha todos de uma vez, e
// fecha também o que a IANA ainda vai alocar fora do espaço global — que é a
// parte que uma lista de bloqueio nunca consegue prometer.
var (
	prefixoGUA = netip.MustParsePrefix("2000::/3")

	// prefixosProibidos6 é o que, mesmo dentro de 2000::/3, não é destino de
	// verdade: 2001::/23 é o bloco inteiro de atribuições de protocolo da IETF
	// (Teredo, benchmarking, ORCHID, AS112-v6), e o resto é documentação, 6to4
	// e 6bone.
	prefixosProibidos6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3ffe::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

// Utilizavel diz se um endereço aprendido pode virar regra, olhando só para a
// CATEGORIA dele.
//
// É metade da proteção mais importante deste pacote — a outra metade é
// protegido(), e as duas são obrigatórias. O endereço vem de uma resposta de
// DNS, quer dizer: de um servidor que não é nosso, escolhido por quem registrou
// o nome. Sem este filtro, o admin lista um domínio, o dono daquele domínio
// responde 192.168.0.1 ou 224.0.0.1, e o produto barra a própria LAN — ou, no
// direcionamento, manda o tráfego da rede inteira para a tabela de rota de uma
// WAN. Um terceiro escolhendo o que o nosso firewall faz.
//
// O QUE ELE NÃO PEGA, e por isso protegido() existe: endereço PÚBLICO que é
// nosso. O da WAN é público por construção — o pacote ddns existe justamente
// para publicá-lo — e o GUA da LAN, com prefixo delegado, também.
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
	if a.Is4() {
		for _, p := range prefixosProibidos4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	if !prefixoGUA.Contains(a) {
		return false
	}
	for _, p := range prefixosProibidos6 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// DefinirProtegidos troca a lista de faixas da PRÓPRIA caixa.
//
// É A SEGUNDA METADE DO FILTRO, e a que Utilizavel não tem como fazer: todo
// endereço de que a caixa depende é de categoria PÚBLICA, por construção.
//
//   - O endereço da WAN é público — o pacote ddns existe para publicá-lo. Um
//     domínio hostil que responde com ele põe o IP do próprio link em dom_wan
//     com a marca da outra WAN, ou em dom_blocked com prazo de uma hora.
//   - Em PPPoE e em uplink com /30 ou /29 público, o GATEWAY é público. Com
//     dom_blocked ligado na forward, o gateway lá dentro é a LAN inteira sem
//     uplink por causa de uma resposta de DNS de terceiro.
//   - Com prefixo delegado, os hosts da LAN têm GUA. É literalmente o ataque
//     que o cabeçalho deste arquivo diz impedir, na família em que
//     ddns.IsPrivate não tem nada a dizer.
//
// A lista é de PREFIXOS e não de endereços: as redes a que a caixa está
// diretamente ligada contam inteiras, senão o vizinho da LAN fica de fora e o
// ataque só muda de alvo. Ela é recarregada junto com a lista de domínios,
// porque o endereço da WAN muda sozinho num link discado.
func (i *Indice) DefinirProtegidos(ps []netip.Prefix) {
	i.mu.Lock()
	defer i.mu.Unlock()
	limpos := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.IsValid() {
			limpos = append(limpos, p.Masked())
		}
	}
	i.protegidos = limpos
}

// protegido diz se o endereço é nosso. Chamada com o lock segurado.
func (i *Indice) protegido(a netip.Addr) bool {
	for _, p := range i.protegidos {
		if p.Contains(a) {
			return true
		}
	}
	return false
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

	// Quem ACABOU de virar ativo. Só esses replicam o aprendizado do ensaio:
	// domínio que já estava ativo tem os endereços dele no espelho, e replicar
	// a lista inteira a cada mudança de estado de WAN daria uma volta no poço
	// de todo mundo para não decidir nada.
	promovidos := make([]Alvo, 0, 4)
	for d, a := range novos {
		if a.Estagio != Ativo {
			continue
		}
		antigo, tinha := i.alvos[d]
		if !tinha || antigo.Estagio != Ativo {
			promovidos = append(promovidos, a)
		}
	}
	sort.Slice(promovidos, func(x, y int) bool { return promovidos[x].Dominio < promovidos[y].Dominio })

	i.alvos = novos
	i.esquecerNaoListados()
	return i.reconciliar(promovidos)
}

// esquecerNaoListados apaga a observação de domínio que saiu da lista.
//
// Rotatividade e estatística são medições de UMA configuração. Um domínio
// removido e recolocado meses depois mostraria a conta acumulada da
// configuração anterior — um número atravessando épocas diferentes, apresentado
// como se fosse da atual. Domínio que só BAIXOU para ensaio continua na lista e
// mantém a conta, que é o certo: o ensaio existe para acumular esse número.
func (i *Indice) esquecerNaoListados() {
	for d := range i.vistos {
		_, ok := i.alvos[d]
		if !ok {
			delete(i.vistos, d)
		}
	}
	for d := range i.estat {
		_, ok := i.alvos[d]
		if !ok {
			delete(i.estat, d)
		}
	}
	// O aprendizado de ensaio segue a mesma regra, e por um motivo mais duro
	// que o da estatística: promover um domínio recolocado meses depois
	// escreveria no kernel os endereços da configuração ANTERIOR — que a essa
	// altura pertencem a outro serviço.
	for d := range i.ensaiados {
		_, ok := i.alvos[d]
		if !ok {
			delete(i.ensaiados, d)
		}
	}
}

// guardarEnsaio anota o que o DNS ensinou de um domínio que ainda não escreve.
// Com o lock segurado.
//
// Guarda o VENCIMENTO, não só o endereço, e é essa a diferença entre a
// promoção aplicar o que vale agora e ela ressuscitar o que já rodou. Uma CDN
// troca de endereço o dia inteiro; o que ela servia às oito da manhã pode ser
// de outro cliente às dez, e escrever isso num set de bloqueio barra um site
// que o admin nunca listou. Endereço vencido não é replicado — ver replayEnsaio.
//
// Aplica só o filtro de CATEGORIA aqui. Os dois filtros de verdade (Utilizavel
// e protegido) rodam no caminho normal, no momento de escrever, que é quando
// eles têm de valer: a lista de faixas protegidas muda com a WAN, e uma decisão
// tomada no ensaio de ontem não pode dispensar a checagem de hoje.
func (i *Indice) guardarEnsaio(dominio string, addrs []netip.Addr, prazo time.Duration, agora time.Time) {
	poco := i.ensaiados[dominio]
	if poco == nil {
		poco = map[netip.Addr]time.Time{}
		i.ensaiados[dominio] = poco
	}
	vence := agora.Add(prazo)
	for _, a := range addrs {
		if !Utilizavel(a) {
			continue
		}
		if _, ja := poco[a]; ja {
			poco[a] = vence
			continue
		}
		if len(poco) >= MaxPorDominio {
			// Cheio: primeiro joga fora o que já venceu, que é lixo por
			// definição. Se ainda não couber, o novo não entra — o mesmo
			// "recusa quando não cabe" do resto do arquivo, e não uma
			// substituição que faria o poço decidir sozinho qual endereço do
			// domínio o admin vai bloquear.
			i.limparEnsaioVencido(poco, agora)
			if len(poco) >= MaxPorDominio {
				continue
			}
		}
		poco[a] = vence
	}
}

func (i *Indice) limparEnsaioVencido(poco map[netip.Addr]time.Time, agora time.Time) {
	for a, vence := range poco {
		if !vence.After(agora) {
			delete(poco, a)
		}
	}
}

// replayEnsaio aplica, na promoção, o que o ensaio já aprendeu. Com o lock
// segurado.
//
// Passa pelo MESMO absorverEndereco do caminho normal, de propósito: os tetos,
// os dois filtros, o refcount e a regra de "barrar ganha de direcionar" são a
// parte que decide se um endereço pode virar regra, e uma segunda porta de
// entrada que os pulasse seria a forma de o produto escrever exatamente o que
// esses filtros existem para impedir.
func (i *Indice) replayEnsaio(aj *Ajuste, alvo Alvo, agora time.Time) {
	poco := i.ensaiados[alvo.Dominio]
	if len(poco) == 0 {
		return
	}
	i.limparEnsaioVencido(poco, agora)

	// Ordem estável: os tetos fazem o índice recusar a partir de um ponto, e
	// com iteração de mapa QUAIS endereços entram mudaria a cada promoção.
	restantes := make([]netip.Addr, 0, len(poco))
	for a := range poco {
		restantes = append(restantes, a)
	}
	sort.Slice(restantes, func(x, y int) bool { return restantes[x].Less(restantes[y]) })

	est := i.estatDe(alvo.Dominio)
	antes := len(aj.Escritas)
	for _, a := range restantes {
		if !i.aceitavel(alvo.Dominio, est, a) {
			delete(poco, a)
			continue
		}
		if !podeEntrar(a, alvo.Capacidade) {
			i.cont.DirecionadoV6Descartado++
			est.direcionadoV6++
			continue
		}
		// O prazo é o que RESTA daquele aprendizado, grampeado pelos mesmos
		// limites do caminho normal.
		i.absorverEndereco(aj, alvo, est, a, grampear(poco[a].Sub(agora)), agora)
	}
	i.cont.PromovidosDoEnsaio += uint64(len(aj.Escritas) - antes)
}

// Alvos devolve a lista corrente, ordenada, para a tela.
func (i *Indice) Alvos() []Alvo {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Alvo, 0, len(i.alvos))
	for _, a := range i.alvos {
		out = append(out, a)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Dominio < out[y].Dominio })
	return out
}

// podeEntrar diz se o par (endereço, capacidade) tem alguma estrutura no
// kernel para onde ir.
//
// Só existe um caso em que não tem: v6 com DIRECIONAR. Não há par v6 do map de
// direcionamento, e isso é de propósito — não existe política de rota v6 neste
// produto. O endereço então não entra em lugar nenhum, e o índice não pode
// guardá-lo: guardar seria quebrar a invariante do espelho, consumir vaga dos
// dois tetos e emitir uma escrita que o montador do lote descarta em silêncio.
func podeEntrar(a netip.Addr, c Capacidade) bool {
	return c != Direcionar || a.Is4()
}

// estatDe pega (ou cria) a estatística daquele domínio. Com o lock segurado.
func (i *Indice) estatDe(d string) *estatDominio {
	e := i.estat[d]
	if e == nil {
		e = &estatDominio{}
		i.estat[d] = e
	}
	return e
}

// reconciliar reavalia todo endereço vivo contra a lista corrente. Chamada com
// o lock segurado.
func (i *Indice) reconciliar(promovidos []Alvo) Ajuste {
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
			if ok {
				// Rebaixado para ensaio, e não removido: o endereço sai do
				// kernel agora (é o resto deste laço), mas o que o DNS ensinou
				// continua sabido. Sem isto, rebaixar e promover de volta
				// jogaria fora o aprendizado e devolveria a espera pelo próximo
				// DNS que esta correção existe para eliminar.
				i.guardarEnsaio(d, []netip.Addr{addr}, r.expira.Sub(agora), agora)
			}
			delete(r.dominios, d)
			i.baixarContagem(d)
		}
		capa, marca, temDono := i.capEfetiva(r.dominios)
		if temDono && !podeEntrar(addr, capa) {
			// O dono efetivo virou direcionamento e o endereço é v6: ele deixa
			// de ter estrutura para onde ir, e um índice que o guardasse
			// deixaria de espelhar o kernel.
			i.cont.DirecionadoV6Descartado++
			for d := range r.dominios {
				i.estatDe(d).direcionadoV6++
			}
			temDono = false
		}
		if !temDono {
			if r.escrito {
				aj.Remocoes = append(aj.Remocoes, Remocao{Addr: addr, Capacidade: r.escritoCap})
			}
			i.soltar(addr, r)
			continue
		}
		if capa == r.escritoCap && marca == r.escritoMarca {
			continue
		}
		// Trocou de estrutura (ou de marca da WAN): sai da antiga e entra na
		// nova. As duas coisas na mesma rodada, porque um delete sem add deixa
		// o domínio sem tratamento nenhum e um add sem delete deixa o mesmo
		// endereço nas duas estruturas.
		if r.escrito {
			aj.Remocoes = append(aj.Remocoes, Remocao{Addr: addr, Capacidade: r.escritoCap})
		}
		aj.Escritas = append(aj.Escritas, Escrita{
			Addr: addr, Prazo: r.concedido, Capacidade: capa, Marca: marca,
		})
		r.pendente = true
		r.pendPrazo = r.concedido
		r.pendCap = capa
		r.pendMarca = marca
	}
	for _, a := range promovidos {
		i.replayEnsaio(&aj, a, agora)
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
// SUFIXO EM FRONTEIRA DE RÓTULO, e nada além disso. netflix.com cobre
// netflix.com e www.netflix.com; NÃO cobre evilnetflix.com, que é o ataque
// óbvio contra um casamento feito com strings.HasSuffix cru — e que listaria
// como Netflix um domínio que qualquer um registra em cinco minutos.
//
// O MAIS ESPECÍFICO GANHA: com netflix.com barrado e assistir.netflix.com
// direcionado, quem perguntou pelo segundo recebe o segundo. A busca sobe
// rótulo a rótulo a partir do nome inteiro, então a primeira coincidência já é
// a mais específica — sem varrer a lista, que num índice de centenas de
// domínios seria uma varredura inteira por resposta de DNS.
//
// NÃO CHAME ISTO DO CAMINHO DO Observar. Ele pega o lock do índice, e esse lock
// é segurado por Podar, por Creditar e por reconciliar — ver o doc-comment do
// campo mu. O filtro do alimentador é feito num retrato sem lock, em
// Servico.Observar.
func (i *Indice) Casar(nome string) (Alvo, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.casar(nome)
}

func (i *Indice) casar(nome string) (Alvo, bool) {
	return CasarEm(i.alvos, nome)
}

// CasarEm é o casamento por sufixo em fronteira de rótulo, feito num mapa que o
// chamador escolhe.
//
// Está aqui fora, e recebe o mapa, porque o alimentador precisa DA MESMA regra
// sem tocar no lock do índice: ele casa num retrato imutável publicado por
// Servico.DefinirAlvos. Duas implementações do casamento seriam duas regras
// diferentes no primeiro ajuste — e a divergência apareceria como um domínio
// que a tela lista e o alimentador ignora.
func CasarEm(alvos map[string]Alvo, nome string) (Alvo, bool) {
	n := strings.ToLower(strings.Trim(strings.TrimSpace(nome), "."))
	for n != "" {
		a, ok := alvos[n]
		if ok {
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
// delete+add: um domínio popular com TTL de 30 segundos e vinte clientes na
// rede geraria dezenas de forks de nft por minuto para não mudar nada. Com um
// terço, o prazo mínimo de 10 minutos vira uma escrita a cada ~6,7 minutos por
// endereço no pior caso, e o terço restante é folga de sobra para um lote
// falhar e ser refeito antes de o kernel deixar o endereço vencer.
//
// O QUE ELE NÃO FAZ MAIS É DAR A ESCRITA POR FEITA. O prazo, a estrutura e a
// marca só entram no espelho quando o chamador confirma que o nft aceitou — ver
// Confirmar e NaoConfirmado. Antes disso o registro fica pendente, e um índice
// que já tivesse anotado o prazo novo esperaria 2/3 dele para mexer num
// endereço que o kernel nunca recebeu.
func (i *Indice) Aprender(nome string, addrs []netip.Addr, ttl time.Duration) Ajuste {
	i.mu.Lock()
	defer i.mu.Unlock()

	var aj Ajuste
	alvo, ok := i.casar(nome)
	if !ok {
		i.cont.NaoCasados++
		return aj
	}

	est := i.estatDe(alvo.Dominio)
	agora := i.agora()
	est.ultimoAprendizado = agora

	// A rotatividade é contada TAMBÉM em ensaio — é para isso que o ensaio
	// existe. Quem lista um domínio de CDN precisa ver, antes de promover, que
	// ele já ensinou trezentos endereços distintos.
	i.anotarRotatividade(alvo.Dominio, addrs)

	if alvo.Estagio != Ativo {
		i.cont.EmEnsaio++
		// Ensaio continua não escrevendo uma linha no kernel — só passa a
		// LEMBRAR, para que promover aplique na hora em vez de esperar o
		// resolver reensinar. Ver Indice.ensaiados.
		i.guardarEnsaio(alvo.Dominio, addrs, grampear(ttl), agora)
		return aj
	}

	prazo := grampear(ttl)
	for _, a := range addrs {
		if !i.aceitavel(alvo.Dominio, est, a) {
			continue
		}
		if !podeEntrar(a, alvo.Capacidade) {
			i.cont.DirecionadoV6Descartado++
			est.direcionadoV6++
			continue
		}
		i.absorverEndereco(&aj, alvo, est, a, prazo, agora)
	}
	return aj
}

// aceitavel roda os DOIS filtros e conta a recusa no lugar em que ela é
// atribuível.
//
// Contador global não responde a pergunta que o admin faz. "Houve 40.000
// recusas" numa caixa com trinta domínios listados não diz qual domínio está
// devolvendo endereço que não podia — e envenenamento é exatamente o evento
// para o qual este filtro existe.
func (i *Indice) aceitavel(dominio string, est *estatDominio, a netip.Addr) bool {
	if !Utilizavel(a) {
		i.cont.Recusados++
		if a.Is4() {
			i.cont.Recusados4++
		}
		est.recusados++
		i.avisarRecusa(dominio, est, a, "categoria reservada")
		return false
	}
	if i.protegido(a) {
		i.cont.RecusadosProprios++
		est.recusadosProprios++
		i.avisarRecusa(dominio, est, a, "endereço da própria caixa ou das redes dela")
		return false
	}
	return true
}

// avisarRecusa põe UMA linha no log por domínio.
//
// Uma por domínio, e não uma por endereço: a recusa chega em rajada (uma
// resposta traz vários A), e um aviso por endereço é o jeito de o log virar
// ruído justamente no minuto em que ele importa. O contador continua subindo
// para os dois lados — a linha é o que faz alguém ir olhar.
func (i *Indice) avisarRecusa(dominio string, est *estatDominio, a netip.Addr, motivo string) {
	if est.avisou {
		return
	}
	est.avisou = true
	slog.Warn("alvo por domínio: endereço recusado",
		"dominio", dominio, "endereco", a.String(), "motivo", motivo)
}

// absorverEndereco é a decisão de um endereço só. Com o lock segurado.
func (i *Indice) absorverEndereco(aj *Ajuste, alvo Alvo, est *estatDominio, a netip.Addr, prazo time.Duration, agora time.Time) {
	r, existe := i.ends[a]
	if !existe {
		if len(i.ends) >= MaxEnderecos {
			i.cont.EstouroGlobal++
			est.estouros++
			return
		}
		if i.porDominio[alvo.Dominio] >= MaxPorDominio {
			i.cont.EstouroPorDominio++
			est.estouros++
			return
		}
		i.ends[a] = &registro{
			dominios:  map[string]bool{alvo.Dominio: true},
			expira:    agora.Add(prazo),
			concedido: prazo,
			pendente:  true,
			pendPrazo: prazo,
			pendCap:   alvo.Capacidade,
			pendMarca: alvo.Marca,
		}
		i.porDominio[alvo.Dominio]++
		i.cont.Novos++
		aj.Escritas = append(aj.Escritas, Escrita{
			Addr: a, Prazo: prazo, Capacidade: alvo.Capacidade, Marca: alvo.Marca,
		})
		return
	}
	i.absorverConhecido(aj, r, alvo, est, a, prazo, agora)
}

// absorverConhecido trata o endereço que o índice já tem. Com o lock segurado.
func (i *Indice) absorverConhecido(aj *Ajuste, r *registro, alvo Alvo, est *estatDominio, a netip.Addr, prazo time.Duration, agora time.Time) {
	// Um domínio a mais pode estar reivindicando o mesmo endereço — o refcount
	// cresce, e isso sozinho não é motivo para escrever coisa nenhuma no
	// kernel. Não caber no refcount NÃO é o mesmo que não caber no kernel: o
	// endereço está lá, posto por outro domínio, e o que falta é o crédito.
	if !r.dominios[alvo.Dominio] {
		if i.porDominio[alvo.Dominio] >= MaxPorDominio {
			i.cont.SemVagaNoRefcount++
			est.semVaga++
		} else {
			r.dominios[alvo.Dominio] = true
			i.porDominio[alvo.Dominio]++
		}
	}

	capa, marca, temDono := i.capEfetiva(r.dominios)
	if !temDono || !podeEntrar(a, capa) {
		return
	}
	if r.pendente {
		// Já há uma escrita deste endereço a caminho do kernel. Emitir outra
		// agora é mandar o mesmo comando duas vezes na mesma transação.
		i.cont.SemComando++
		return
	}
	trocou := capa != r.escritoCap || marca != r.escritoMarca
	vencendo := r.duvidoso || r.expira.Sub(agora) < r.concedido/FracaoDeRenovacao
	if !trocou && !vencendo {
		i.cont.SemComando++
		return
	}
	if trocou {
		// Trocar de estrutura é SAIR de uma e ENTRAR na outra, e as duas
		// metades têm de sair na mesma rodada. Só a entrada deixaria o endereço
		// nas duas ao mesmo tempo — barrado e direcionado —, e o que sobra na
		// estrutura errada não é renovado por ninguém: some sozinho no
		// vencimento, o que faz o defeito aparecer só de vez em quando e nunca
		// no momento em que foi criado.
		if r.escrito {
			aj.Remocoes = append(aj.Remocoes, Remocao{Addr: a, Capacidade: r.escritoCap})
		}
		i.cont.Trocas++
	} else {
		i.cont.Renovacoes++
	}
	r.pendente = true
	r.pendPrazo = prazo
	r.pendCap = capa
	r.pendMarca = marca
	// Substituir é o delete da RENOVAÇÃO, e vale só quando o endereço continua
	// na mesma estrutura E o índice tem motivo para crer que ele está lá: numa
	// troca quem apaga é a Remocao acima, e um delete de elemento ausente
	// derruba o lote inteiro.
	aj.Escritas = append(aj.Escritas, Escrita{
		Addr: a, Prazo: prazo, Capacidade: capa, Marca: marca, Substituir: !trocou && r.escrito,
	})
}

// Confirmar é o kernel dizendo que recebeu.
//
// É AQUI, E SÓ AQUI, QUE O ESPELHO AVANÇA. Antes desta chamada o índice sabe
// que decidiu escrever e não sabe se o nft aceitou — e essa diferença é o que
// separa uma tela certa de uma que afirma bloqueio onde não há. Sem ela, um
// lote perdido virava um endereço que o índice dava por escrito e só voltava a
// mexer 2/3 de prazo depois: até quarenta minutos de firewall não barrando o
// que a tela mostrava barrado.
func (i *Indice) Confirmar(addrs []netip.Addr) {
	i.mu.Lock()
	defer i.mu.Unlock()
	agora := i.agora()
	for _, a := range addrs {
		r, ok := i.ends[a]
		if !ok || !r.pendente {
			continue
		}
		r.expira = agora.Add(r.pendPrazo)
		r.concedido = r.pendPrazo
		r.escritoCap = r.pendCap
		r.escritoMarca = r.pendMarca
		r.escrito = true
		r.pendente = false
		r.duvidoso = false
		i.cont.Confirmados++
	}
}

// NaoConfirmado é o kernel NÃO tendo recebido, e desfaz a crença do índice.
//
// São dois casos, e eles pedem coisas opostas:
//
//   - o endereço nunca chegou ao kernel. O índice não pode guardá-lo: é a
//     invariante do arquivo, e guardar consome vaga dos dois tetos por um
//     bloqueio que não existe. Sai, e a vaga volta.
//   - a RENOVAÇÃO dele não aconteceu. O elemento continua lá com o prazo
//     ANTIGO, então o índice não pode avançar o vencimento (e não avançou:
//     quem avança é Confirmar). Fica marcado como duvidoso, o que faz a próxima
//     resposta reemitir na hora em vez de esperar o terço.
func (i *Indice) NaoConfirmado(addrs []netip.Addr) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	n := 0
	for _, a := range addrs {
		r, ok := i.ends[a]
		if !ok || !r.pendente {
			continue
		}
		r.pendente = false
		i.cont.NaoConfirmados++
		n++
		if !r.escrito {
			i.soltar(a, r)
			continue
		}
		r.duvidoso = true
	}
	return n
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
	i.mu.RLock()
	defer i.mu.RUnlock()
	rt := i.vistos[dominio]
	if rt == nil {
		return 0, false
	}
	return len(rt.distintos), rt.truncada
}

// Podar esquece o que já venceu no kernel e devolve quantos saíram.
//
// Não gera comando nenhum: quem apaga é o próprio nftables, pelo timeout do
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
		if r.pendente || r.expira.After(corte) {
			continue
		}
		i.soltar(addr, r)
		n++
	}
	i.cont.PodadosTotal += uint64(n)

	// O aprendizado de ensaio vence pelo mesmo relógio. Não conta em
	// PodadosTotal — aquele número é sobre o que o kernel tinha, e somar aqui
	// misturaria endereço que estava barrado com endereço que nunca esteve.
	for d, poco := range i.ensaiados {
		i.limparEnsaioVencido(poco, corte)
		if len(poco) == 0 {
			delete(i.ensaiados, d)
		}
	}
	return n
}

// Contadores devolve uma cópia do que estourou, do que foi recusado e do que
// foi economizado, com o estado do índice junto.
func (i *Indice) Contadores() Contadores {
	i.mu.RLock()
	defer i.mu.RUnlock()
	c := i.cont
	c.Vivos = len(i.ends)
	c.Dominios = len(i.porDominio)
	return c
}

// Credito é o resultado de pôr o que o kernel TEM ao lado do que o índice acha
// que escreveu.
type Credito struct {
	// PorDominio conta cada endereço UMA vez por domínio que o reivindica,
	// mesmo que o kernel o tenha em mais de uma estrutura.
	PorDominio map[string]int
	// Orfaos são endereços que o kernel tem e nenhum domínio reivindica: sobra
	// de um flush perdido, de um reinício do processo com o kernel cheio ou de
	// um domínio removido. Precisam aparecer, porque são bloqueio valendo que
	// ninguém pediu.
	Orfaos int
	// ForaDeLugar são endereços que o kernel tem numa estrutura que NÃO é a que
	// o índice escolheu — quer dizer, o mesmo endereço barrado e direcionado ao
	// mesmo tempo, ou sobrando na estrutura de onde uma troca deveria tê-lo
	// tirado.
	//
	// Sem este número a divergência é invisível: o endereço não é órfão (o
	// índice o conhece), as duas contagens da tela o somam duas vezes, e o
	// resto na estrutura errada não é renovado por ninguém — some sozinho em
	// até uma hora, que é o defeito que aparece de vez em quando e nunca no
	// momento em que foi criado.
	ForaDeLugar int
}

// Creditar credita cada endereço LIDO DO KERNEL aos domínios que o ensinaram.
//
// Existe para a tela poder dizer "netflix.com: 12 endereços barrados agora"
// sem que esse 12 venha da memória. Quem entra aqui é o que o kernel devolveu;
// o índice só empresta a identidade, que é a parte que o kernel não guarda (ver
// o cabeçalho de internal/nftables/dominios.go).
//
// RECEBE O DomKernel INTEIRO, e não uma lista concatenada de endereços, porque
// achatar as três estruturas joga fora justamente a informação que denuncia a
// divergência: de qual delas o endereço veio.
func (i *Indice) Creditar(k nftables.DomKernel) Credito {
	i.mu.RLock()
	defer i.mu.RUnlock()
	c := Credito{PorDominio: map[string]int{}}
	creditado := make(map[netip.Addr]bool, len(k.Bloq)+len(k.Bloq6)+len(k.Wan))
	for _, par := range []struct {
		addrs []netip.Addr
		capa  Capacidade
	}{
		{k.Bloq, Barrar},
		{k.Bloq6, Barrar},
		{k.Wan, Direcionar},
	} {
		for _, a := range par.addrs {
			r, ok := i.ends[a]
			if !ok || len(r.dominios) == 0 {
				c.Orfaos++
				continue
			}
			if r.escrito && r.escritoCap != par.capa {
				c.ForaDeLugar++
			}
			if creditado[a] {
				continue
			}
			creditado[a] = true
			for d := range r.dominios {
				c.PorDominio[d]++
			}
		}
	}
	return c
}

// LinhaDominio é o retrato de UM domínio, tirado sob um lock só.
//
// Existe inteira por dois motivos. O primeiro é que a tela precisa saber, por
// domínio, o que hoje só existia somado: quanto estourou, quanto foi recusado,
// se ele está NO TETO agora. O segundo é que montá-la com três chamadas
// separadas pegava o lock do índice uma vez por domínio, e esse é o mesmo lock
// que o alimentador precisa para aprender.
type LinhaDominio struct {
	Alvo                 Alvo
	Rotatividade         int
	RotatividadeTruncada bool
	// NoIndice é quantos endereços deste domínio o índice acha que escreveu.
	// É o par de NoKernel: com um dos dois só dá para dizer que algo está
	// errado quando os dois batem, que é justamente quando não está.
	NoIndice int
	// NoTeto é estado AGORA, e não histórico. Um domínio parado no teto para de
	// gerar resposta nova (os clientes já têm tudo em cache) e o contador
	// cumulativo congela — o admin lê "estabilizou" onde o certo é
	// "continua com 64 de 300 endereços".
	NoTeto bool
	Teto   int
	// Estouros, Recusados, RecusadosProprios, SemVaga e DirecionadoV6 são
	// cumulativos DESTE domínio.
	Estouros          uint64
	Recusados         uint64
	RecusadosProprios uint64
	SemVaga           uint64
	DirecionadoV6     uint64
	// UltimoAprendizado separa "ninguém consultou este nome ainda" de
	// "consultaram e nada entrou". Sem ele, os dois estados são a mesma
	// linha na tela, e um deles é o firewall não estar barrando.
	UltimoAprendizado time.Time
}

// Linhas tira o retrato de todos os domínios listados.
func (i *Indice) Linhas() []LinhaDominio {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]LinhaDominio, 0, len(i.alvos))
	for d, a := range i.alvos {
		l := LinhaDominio{
			Alvo:     a,
			NoIndice: i.porDominio[d],
			NoTeto:   i.porDominio[d] >= MaxPorDominio,
			Teto:     MaxPorDominio,
		}
		rt := i.vistos[d]
		if rt != nil {
			l.Rotatividade = len(rt.distintos)
			l.RotatividadeTruncada = rt.truncada
		}
		e := i.estat[d]
		if e != nil {
			l.Estouros = e.estouros
			l.Recusados = e.recusados
			l.RecusadosProprios = e.recusadosProprios
			l.SemVaga = e.semVaga
			l.DirecionadoV6 = e.direcionadoV6
			l.UltimoAprendizado = e.ultimoAprendizado
		}
		out = append(out, l)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Alvo.Dominio < out[y].Alvo.Dominio })
	return out
}
