package nftables

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"
)

// Proteção do próprio appliance contra o que chega pelas WANs (issue #119,
// fase 1).
//
// O QUE ESTAVA ABERTO, MEDIDO EM PRODUÇÃO (2026-08-20). A chain input é
// `policy accept` e o ruleset inteiro tinha 8 regras casando IPv4 e ZERO
// casando IPv6. A tabela é `inet`, então os pacotes IPv6 atravessam a chain,
// não casam com nada e são aceitos pela política. O painel escuta em `*:9997`
// e o SSH em `[::]:22` — os dois em dual-stack.
//
// O QUE FAZIA ISSO NÃO SER UM INCIDENTE ATÉ AGORA, E ISSO É O PONTO. As duas
// WANs da caixa de produção têm endereço IPv4 PRIVADO (192.168.18.92 e
// 192.168.15.2): ela fica atrás do NAT dos roteadores do provedor, e é o NAT —
// não este firewall — que barra a entrada. Em IPv6 esse acidente não existe:
// as duas interfaces têm endereço GLOBAL vindo de RA (2804:...), sem NAT
// nenhum no caminho. O IPv6 não abriu um buraco novo; ele tirou a cortina que
// escondia o buraco que sempre esteve lá.
//
// POR QUE UM DROP ESCOPADO POR WAN, E NÃO `policy drop`. Trocar a política da
// input é a issue #78, e ela está travada por um problema de desenho registrado
// em survival.go: sem `ct state established` a política restritiva mata todo
// retorno de conexão de saída (apt, updater, unbound, chrony), e COM ele a
// sessão SSH do operador sobrevive ao próprio bloqueio e faz o teste dos 90
// segundos mentir. Não existe valor da flag em que as duas propriedades valham.
//
// Esta lista não esbarra em nada disso, e é por construção:
//
//   - o drop casa `ct state new`. O retorno de conexão de saída é
//     `established`, nunca `new` — então o apt, o updater e o unbound não são
//     tocados, sem precisar de uma linha de `established accept` em lugar
//     nenhum;
//   - o drop casa `iifname` das WANs. A sessão do operador entra pela LAN, e
//     por isso NÃO PODE ser cortada por estas regras. O trancar-se-do-lado-de-
//     fora, que é o que trava a #78, aqui não é possível.
//
// É a parte da #78 que dá para entregar sem o pré-requisito que falta — e é
// justamente a parte que corresponde ao que está exposto de verdade.
//
// ONDE ELAS ENTRAM NA CHAIN, E POR QUÊ NO FIM. Depois dos jumps dos grupos, e
// isso é deliberado: um grupo de escopo input que LIBERE alguma coisa vinda da
// WAN precisa ser avaliado antes, senão o produto anularia em silêncio uma
// decisão explícita do admin. É a mesma objeção que survival.go levanta contra
// emitir as regras de sobrevivência acima dos jumps.
//
// AS LIBERAÇÕES SÃO O QUE SEPARA ISTO DE UM CORTE DE INTERNET. Cada uma
// corresponde a uma coisa que chega pela WAN como `ct state new` e sem a qual
// algo quebra dias depois, sem relação visível com a mudança:
//
//   - `udp dport 68` — o REBIND do cliente DHCP sai de 0.0.0.0:68 para
//     broadcast e não casa a tupla de retorno do conntrack. Sem esta linha, a
//     WAN por DHCP não renova depois de um flap. Sintoma: "a internet caiu
//     sozinha na quarta". A lição é de survival.go, não foi redescoberta aqui;
//   - `nd-router-advert` e a vizinhança IPv6 — o RA é `new` e é o que mantém a
//     rota padrão IPv6 viva. Em produção ela expira em ~30 min (`expires
//     1734sec`): sem esta linha, o IPv6 morre inteiro meia hora depois do
//     deploy, e o IPv4 continua funcionando, que é exatamente o que faz
//     ninguém relacionar o sintoma com o firewall;
//   - `udp dport 546` — o cliente DHCPv6. Não está em uso hoje (a LAN não tem
//     prefixo delegado), e é justamente por isso que precisa estar aqui: o dia
//     em que alguém ligar delegação de prefixo não pode ser o dia em que
//     descobre que o firewall a bloqueia;
//   - `icmpv6 packet-too-big` — o PMTUD do IPv6 depende dele e não há
//     fragmentação em trânsito para compensar. Bloqueá-lo não derruba a
//     conexão: faz páginas grandes travarem no meio, que é pior de diagnosticar
//     do que uma queda;
//   - `ct status dnat` — o encaminhamento de porta que aponta para a PRÓPRIA
//     máquina vira tráfego de input depois do DNAT. Mesma linha e mesma razão
//     de ForwardSurvivalRules.
//
// O QUE FICA DE FORA: nada além do que não foi listado. `echo-request` chegou a
// ficar de fora e VOLTOU com taxa limitada — ver o comentário na regra sobre o
// que a bateria H mostrou.

// WANInputRules devolve as liberações e o descarte do que chega às WANs sem ter
// sido pedido.
//
// Lista vazia quando não há WAN conhecida — numa instalação recém-feita, que
// nasce sem link nenhum, o resultado é byte a byte o de antes. Um firewall que
// descartasse "tudo que vem da WAN" sem saber quais são as WANs descartaria
// nada ou tudo, e as duas respostas estão erradas.
func WANInputRules(z Zone, access AdminAccess, gerenciaFechada, contencaoLigada bool, wireGuardPorts ...int) [][]string {
	if !z.Discriminates() {
		return nil
	}

	// AS DUAS FORMAS DE DIZER "VEIO DE FORA", E POR QUE SÃO DUAS.
	//
	// `deFora` é o eixo da plataforma: interface na caixa de várias NICs, CIDR
	// de origem na de VNIC única. É ele que conserta o defeito desta chain em
	// hairpin — `iifname { ens3 }` casa TUDO ali, e o descarte final cortava
	// DNS, NTP e painel vindos das outras máquinas da própria rede.
	//
	// `porIface` é o eixo de interface SEMPRE, e existe só para as linhas
	// exclusivamente IPv6. Na família `inet`, `ip saddr` casa apenas IPv4 (ver
	// sanitizeNetworks): renderizadas pelo eixo de CIDR, essas quatro linhas
	// deixariam de casar qualquer pacote e o IPv6 perderia a vizinhança, os
	// erros de PMTUD e o cliente DHCPv6 — com `policy drop`, IPv6 pararia por
	// inteiro. Em hairpin elas casam mais do que deveriam; as quatro são
	// `accept` de infraestrutura, então casar demais não afrouxa nada que já
	// não estivesse liberado. Ver o aviso no fim desta função para o lado que
	// NÃO se resolve assim.
	deFora := z.FromExternal()
	porIface := z.FromExternalByIface()

	regras := [][]string{
		// Vizinhança e descoberta de roteador. Primeiro porque, sem isto, nada
		// de IPv6 funciona depois — inclusive as liberações abaixo, que seriam
		// aceitas e nunca alcançadas.
		zoneRule(porIface, "icmpv6", "type",
			"{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }",
			"counter", "accept"),

		// Os erros de ICMPv6 que não podem sumir: PMTUD e diagnóstico.
		zoneRule(porIface, "icmpv6", "type",
			"{ packet-too-big, time-exceeded, parameter-problem, destination-unreachable }",
			"counter", "accept"),

		// A caixa como CLIENTE de DHCP, nas duas famílias.
		zoneRule(deFora, "udp", "dport", "68", "counter", "accept"),
		zoneRule(porIface, "udp", "dport", "546", "counter", "accept"),

		// Encaminhamento de porta que aponta para a própria máquina.
		zoneRule(deFora, "ct", "status", "dnat", "counter", "accept"),
	}

	// AS PORTAS DE GERÊNCIA FICAM ABERTAS, E ISTO É UMA CORREÇÃO, NÃO UM
	// DESCUIDO.
	//
	// A primeira versão desta lista não tinha esta linha, e a VM de validação
	// mostrou o custo em quinze minutos: instalação nova, o admin clica em
	// "detectar links" — o caminho normal do produto —, o auto-detect cadastra
	// como WAN a interface que tem a rota padrão, a reconciliação aplica o
	// descarte, e a máquina descarta a porta 22 e a do painel. SSH e painel
	// mortos, sem nada na tela, sem caminho de volta. Numa caixa de uma NIC só
	// isso não é caso de canto: é o comportamento.
	//
	// O produto já tinha decidido esta questão, e eu tinha decidido diferente
	// sem perceber. O survival.go recusa ligar `policy drop` exatamente para
	// não trancar o admin do lado de fora, mesmo ao custo de o firewall ficar
	// permissivo — "não trancar o admin" vale mais do que "fechar tudo". Uma
	// regra que se aplica sozinha, na reconciliação, sem ninguém pedir, não
	// pode ser a exceção a esse princípio: quem apanha dela não tem nem o
	// consolo de saber o que apertou.
	//
	// O que sobra ainda vale: tudo que passar a escutar nesta máquina nasce
	// protegido pela WAN, nas duas famílias. O que fica exposto são duas portas
	// conhecidas — e a fase 3 desta issue mostra isso na tela, com um botão para
	// fechá-las, passando pela janela de confirmação de 90 segundos. Aí, sim: se
	// fechar cortar o acesso de quem apertou, reverte sozinho. É a diferença
	// entre uma exposição VISÍVEL e uma exposição ACIDENTAL, que é a única que
	// este produto não pode ter.
	// PING NA WAN CONTINUA RESPONDENDO, COM TAXA LIMITADA — e isto é uma
	// reversão da primeira versão desta lista, que o deixava de fora "de
	// propósito".
	//
	// O argumento para tirá-lo era bom no papel: o monitor de link deste
	// produto pinga para FORA, e a resposta dele é `established`, então nada do
	// produto precisa de echo-request de entrada. O que o papel não continha era
	// a bateria H: o roteamento de resposta por WAN (#120) é verificado com um
	// ping ao endereço da WAN secundária, e existe para que quem chega por uma
	// WAN seja respondido por ela. Sem echo-request, esse ping morre — e o
	// sintoma não é "o firewall parou de responder ping", é "a WAN2 parou de
	// funcionar", investigado no lugar errado.
	//
	// Vale para quem opera também: pingar o endereço da WAN é o primeiro
	// diagnóstico que um operador ou o suporte do provedor faz. Uma caixa que
	// deixa de responder num upgrade, sem ninguém ter mexido nisso, é o tipo de
	// mudança silenciosa que este projeto trata como o pior defeito possível.
	//
	// `limit rate` é um CASAMENTO, não um modificador (a lição da #122): o
	// pacote que EXCEDE a taxa não casa esta regra e cai no descarte abaixo. É
	// isso que torna o limite um limite de verdade, e não um enfeite.
	regras = append(regras,
		zoneRule(deFora, "icmp", "type", "echo-request", "limit", "rate", "5/second", "counter", "accept"),
		zoneRule(porIface, "icmpv6", "type", "echo-request", "limit", "rate", "5/second", "counter", "accept"),
	)

	// O FECHAMENTO É PARÂMETRO PRÓPRIO, E NÃO UM CAMPO DE AdminAccess, e a
	// diferença é a armadilha desta entrega.
	//
	// portasDeGerencia é compartilhada com SurvivalRules (survival.go), que
	// emite a MESMA liberação na chain input inteira, sem escopo de interface,
	// como anti-lockout de `policy drop`. Um campo em AdminAccess faria "fechar
	// a gerência na WAN" apagar também esse anti-lockout global — o admin
	// pedindo para fechar uma porta na internet e perdendo o acesso pela LAN
	// junto, sem nada na tela sugerindo a ligação.
	if !gerenciaFechada {
		if portas := portasDeGerencia(access); portas != "" {
			// A CONTENÇÃO VEM ANTES DA LIBERAÇÃO, e a ordem é a decisão
			// (#127): a liberação é um `accept`, e accept curto-circuita a
			// chain. Com o descarte de quem está contido DEPOIS dela, a
			// contenção não valeria nada — quem está sendo contido bate
			// exatamente nessas portas.
			//
			// E as duas andam JUNTAS com a liberação, não soltas: com a
			// gerência fechada não há accept a proteger, o descarte genérico da
			// WAN já cuida de tudo, e um set que nada alimenta é enfeite com
			// cara de proteção. Foi um teste que apontou isso — a asserção de
			// que fechar a gerência tira TODA linha de `tcp dport` da chain.
			// A CONTENÇÃO É OPT-IN (#127), e o padrão desligado é correção.
			//
			// Ligada por padrão, ela trancou a VM de validação em uma execução:
			// o próprio arnês faz centenas de chamadas de API, uma conexão nova
			// cada, e excedeu a taxa. No nível do firewall não dá para
			// distinguir automação legítima de varredura só pela taxa — quem usa
			// a API de fora parece igual a um scanner.
			if contencaoLigada {
				regras = append(regras, abuseRules(z, portas)...)
			}
			regras = append(regras, zoneRule(deFora, "tcp", "dport", portas, "counter", "accept"))
		}
	}

	// WireGuard escuta na própria caixa. A liberação fica na mesma fonte
	// canônica da proteção WAN e antes do drop final; assim ela acompanha toda
	// WAN atual sem PostUp, shell ou uma segunda chain que outra reconciliação
	// apagaria. A connection mark de #120 continua lembrando por qual WAN o
	// handshake entrou e marca a resposta no hook output.
	if len(wireGuardPorts) > 0 {
		if port := wireGuardPorts[0]; port >= 1 && port <= 65535 {
			regras = append(regras, zoneRule(deFora, "udp", "dport", strconv.Itoa(port), "counter", "accept"))
		}
	}

	// O QUE ESTA LINHA FAZ: descarta o que chega pelas WANs sem ter sido
	// pedido de dentro. `ct state new` é o que garante que ela não toca em
	// resposta de conexão de saída.
	//
	// EM HAIRPIN ESTE DESCARTE PASSA A VALER SÓ PARA IPv4, E ISSO É UMA
	// LACUNA ENTREGUE ABERTA, não um detalhe. `ip saddr != { rede local }` não
	// casa pacote IPv6 nenhum na família `inet`, então o que chega de fora por
	// IPv6 deixa de ser descartado e cai na `policy accept` da chain. A saída
	// honesta é `ip6 saddr != { prefixo local }`, e ela precisa do prefixo
	// IPv6 de dentro — que fonte nenhuma deste produto conhece hoje: nem o
	// netsvc, que só guarda a sub-rede IPv4, nem o IMDS, cujo subnet_cidr é v4.
	//
	// Emitir um descarte v6 sem esse prefixo seria descartar TAMBÉM o que vem
	// da própria rede, inclusive a vizinhança que as linhas acima liberam —
	// isto é, trocar uma exposição por uma queda. Este produto já escolheu
	// entre as duas coisas (ver o bloco sobre as portas de gerência, acima) e
	// escolheu não trancar. O que não pode é isso acontecer calado, então
	// acontece com aviso.
	if z.Hairpin() {
		slog.Warn("proteção de entrada: nesta máquina o descarte vale só para IPv4; o que chegar de fora por IPv6 NÃO é descartado (falta o prefixo IPv6 da rede local)",
			"wans", z.WANIfaces())
	}
	return append(regras, zoneRule(deFora, "ct", "state", "new", "counter", "drop"))
}

// portasDeGerencia devolve o set de portas que não podem ser fechadas sem o
// admin mandar: a do SSH e a do painel.
//
// A do painel NÃO é fixa — 8080 é o default do binário, 9997 o do .deb, e quem
// põe proxy usa outra. Fixá-la aqui deixaria justamente quem não usa o padrão
// trancado do lado de fora, que é o cenário que esta função existe para
// impedir. Mesma razão registrada em SurvivalRules.
// portasDeGerenciaLista é a MESMA decisão de portasDeGerencia, em número em vez
// de texto — a tela precisa da lista para dizer quais portas estão abertas, e
// duas listas que pudessem discordar seriam a divergência silenciosa que a fase
// 3 existe para fechar.
func portasDeGerenciaLista(a AdminAccess) []int {
	portas := append([]int(nil), a.SSHPorts...)
	if len(portas) == 0 {
		portas = []int{22}
	}
	if a.PanelPort > 0 {
		portas = append(portas, a.PanelPort)
	}
	sort.Ints(portas)
	out := make([]int, 0, len(portas))
	vista := map[int]bool{}
	for _, p := range portas {
		if p <= 0 || vista[p] {
			continue
		}
		vista[p] = true
		out = append(out, p)
	}
	return out
}

func portasDeGerencia(a AdminAccess) string {
	// Não saber onde o sshd escuta cai no padrão — a alternativa seria não
	// liberar porta nenhuma, que é justamente trancar o admin do lado de fora.
	// Ver SSHPorts em internal/system.
	portas := portasDeGerenciaLista(a)
	if len(portas) == 0 {
		return ""
	}
	partes := make([]string, 0, len(portas))
	for _, p := range portas {
		partes = append(partes, strconv.Itoa(p))
	}
	return "{ " + strings.Join(partes, ", ") + " }"
}
