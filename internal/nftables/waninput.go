package nftables

import (
	"fmt"
	"log/slog"
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
// O QUE FICA DE FORA, DE PROPÓSITO: `echo-request`. Responder ping na WAN é
// escolha, não necessidade — o monitor de link deste produto pinga para FORA, e
// a resposta dele é `established`. Quem quiser responder cria um grupo de
// escopo input, que é avaliado antes desta lista.

// WANInputRules devolve as liberações e o descarte do que chega às WANs sem ter
// sido pedido.
//
// Lista vazia quando não há WAN conhecida — numa instalação recém-feita, que
// nasce sem link nenhum, o resultado é byte a byte o de antes. Um firewall que
// descartasse "tudo que vem da WAN" sem saber quais são as WANs descartaria
// nada ou tudo, e as duas respostas estão erradas.
func WANInputRules(wanIfaces []string) [][]string {
	nomes := make([]string, 0, len(wanIfaces))
	vistos := map[string]bool{}
	for _, iface := range wanIfaces {
		if iface == "" || vistos[iface] {
			continue
		}
		if !reIface.MatchString(iface) {
			// Este nome vem do banco e é interpolado no argv do nft, que junta
			// os argumentos e parseia o resultado — mesma porta que reIface
			// fecha nos outros geradores deste pacote.
			slog.Error("interface ignorada ao montar a proteção de entrada da WAN: nome inseguro",
				"interface", iface)
			continue
		}
		vistos[iface] = true
		nomes = append(nomes, fmt.Sprintf("%q", iface))
	}
	if len(nomes) == 0 {
		return nil
	}
	set := "{ " + strings.Join(nomes, ", ") + " }"

	return [][]string{
		// Vizinhança e descoberta de roteador. Primeiro porque, sem isto, nada
		// de IPv6 funciona depois — inclusive as liberações abaixo, que seriam
		// aceitas e nunca alcançadas.
		{"iifname", set, "icmpv6", "type",
			"{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }",
			"counter", "accept"},

		// Os erros de ICMPv6 que não podem sumir: PMTUD e diagnóstico.
		{"iifname", set, "icmpv6", "type",
			"{ packet-too-big, time-exceeded, parameter-problem, destination-unreachable }",
			"counter", "accept"},

		// A caixa como CLIENTE de DHCP, nas duas famílias.
		{"iifname", set, "udp", "dport", "68", "counter", "accept"},
		{"iifname", set, "udp", "dport", "546", "counter", "accept"},

		// Encaminhamento de porta que aponta para a própria máquina.
		{"iifname", set, "ct", "status", "dnat", "counter", "accept"},

		// O QUE ESTA LINHA FAZ: descarta o que chega pelas WANs sem ter sido
		// pedido de dentro. `ct state new` é o que garante que ela não toca em
		// resposta de conexão de saída.
		{"iifname", set, "ct", "state", "new", "counter", "drop"},
	}
}
