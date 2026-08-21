package nftables

import (
	"os"
	"strings"
)

// O que a tela precisa contar e não contava (issue #119, fase 3).
//
// AS DUAS PRIMEIRAS FASES MEXERAM EM REGRA; ESTA MEXE EM AFIRMAÇÃO, e é a que
// fecha a issue. O ruleset passou a proteger mais, mas a tela continuou
// descrevendo um firewall que não é o que está rodando — e num produto cujo
// valor é o operador confiar no que lê, omissão e mentira custam igual.
//
// São três verdades, todas medidas na caixa de produção em 2026-08-21:
//
//  1. AS PORTAS DE GERÊNCIA ESTÃO ABERTAS NAS WANs. É decisão deliberada da
//     fase 1 — sem ela, clicar em "detectar links" trancava o admin do lado de
//     fora —, mas é uma exposição, e exposição que ninguém vê é acidente
//     esperando. Hoje a única forma de descobrir é ler `nft list chain`.
//
//  2. IPv6 NÃO É ROTEADO PARA A LAN. O produto liga `net.ipv4.ip_forward` e
//     nunca o equivalente de IPv6 (internal/routes.ForwardingSysctl). Isso não
//     é defeito: é a razão de o furo do `forward` em IPv6 estar LATENTE e não
//     ativo. Mas quem lê "firewall protegido" não tem como saber que metade da
//     internet moderna simplesmente não passa por aqui.
//
//  3. AS REGRAS POR ENDEREÇO SÓ VALEM IPv4. `ip saddr`/`ip daddr` não casam
//     IPv6, então um grupo do admin que bloqueia um endereço bloqueia metade do
//     que ele acha que bloqueia — no dia em que houver IPv6. A exceção é o
//     bloqueio de host, que desde a fase 2 casa por endereço físico e vale nas
//     duas famílias. Dizer a regra sem a exceção assustaria à toa; dizer a
//     exceção sem a regra seria a mentira de sempre.
//
// NADA AQUI MUDA UMA REGRA. Este arquivo só lê e conta.

// IPv6ForwardingSysctl é o equivalente IPv6 do que routes.ForwardingSysctl liga.
// O produto NÃO escreve neste arquivo — só olha.
const IPv6ForwardingSysctl = "/proc/sys/net/ipv6/conf/all/forwarding"

// Exposure é o retrato honesto do que o firewall deixa passar hoje.
type Exposure struct {
	// ManagementOpenOnWAN diz se as portas de gerência estão liberadas no que
	// chega pelas WANs.
	ManagementOpenOnWAN bool `json:"management_open_on_wan"`
	// ManagementPorts são as portas liberadas, para a tela não precisar
	// adivinhar quais — a do painel não é fixa e a do SSH vem do socket.
	ManagementPorts []int `json:"management_ports,omitempty"`
	// WANInterfaces são as interfaces onde essa liberação vale.
	WANInterfaces []string `json:"wan_interfaces,omitempty"`
	// IPv6Forwarding é "on", "off" ou "unknown". Três estados porque "não
	// consegui ler" não é "está desligado": responder "off" a uma leitura que
	// falhou seria inventar a resposta tranquilizadora.
	IPv6Forwarding string `json:"ipv6_forwarding"`
	// AddressRulesIPv4Only diz se as regras por endereço casam só IPv4.
	AddressRulesIPv4Only bool `json:"address_rules_ipv4_only"`
	// HostBlockCoversIPv6 é a exceção da fase 2, dita junto de propósito.
	HostBlockCoversIPv6 bool `json:"host_block_covers_ipv6"`
	// Error explica por que o retrato veio incompleto. A tela mostra o aviso em
	// vez de desenhar meia verdade como se fosse a inteira — mesmo contrato de
	// survivalView.Error.
	Error string `json:"error,omitempty"`
}

// ExposureNow monta o retrato a partir das MESMAS fontes que escrevem a chain,
// e não de uma lista à parte.
//
// Vem daí a única garantia que importa aqui: se a regra mudar e este retrato
// não, é porque alguém mudou a regra sem mudar a fonte — e nesse caso o resto
// do produto já está quebrado. Uma tela que mantivesse a sua própria cópia da
// verdade divergiria em silêncio, que é o defeito que esta fase existe para
// fechar.
func (s *Service) ExposureNow() Exposure {
	e := Exposure{
		IPv6Forwarding: leIPv6Forwarding(s.ipv6FwdPath),
		// Propriedade estática dos emissores de regra de grupo: groupJumpTokens
		// e o renderizador de regra escrevem `ip saddr`/`ip daddr`.
		AddressRulesIPv4Only: true,
		// A exceção da fase 2: `ether saddr @blocked_macs` não tem família.
		HostBlockCoversIPv6: true,
	}

	wans, err := s.wanInterfaces()
	if err != nil {
		e.Error = err.Error()
		return e
	}
	if len(wans) == 0 {
		// Sem WAN conhecida a proteção de entrada não emite regra nenhuma, e
		// portanto não há liberação a anunciar. Dizer "aberto" aqui seria
		// verdade pelo motivo errado — está aberto porque não há regra, não
		// porque a liberação existe.
		return e
	}
	e.WANInterfaces = wans

	acesso, err := s.adminAccess()
	if err != nil {
		// Este é o caso em que reconcileInputChain CANCELA a proteção inteira
		// (ver o comentário lá): sem saber as portas, nada é emitido. A tela
		// precisa dizer isso, porque é o estado em que a caixa está mais
		// aberta e o painel teria a melhor cara.
		e.Error = err.Error()
		return e
	}
	fechada, err := s.wanMgmtClosed()
	if err != nil {
		e.Error = err.Error()
		return e
	}
	e.ManagementOpenOnWAN = !fechada
	// As portas saem MESMO FECHADAS: é o que a tela usa para dizer "estas
	// deixaram de responder", e para o botão de reabrir saber o que promete.
	e.ManagementPorts = portasDeGerenciaLista(acesso)
	return e
}

// leIPv6Forwarding traduz o sysctl em "on"/"off"/"unknown".
func leIPv6Forwarding(caminho string) string {
	b, err := os.ReadFile(caminho)
	if err != nil {
		// Kernel sem IPv6, /proc não montado, ou leitura negada. Nenhum dos
		// três é "está desligado".
		return "unknown"
	}
	switch strings.TrimSpace(string(b)) {
	case "0":
		return "off"
	case "":
		return "unknown"
	default:
		// Qualquer valor diferente de zero liga o encaminhamento.
		return "on"
	}
}
