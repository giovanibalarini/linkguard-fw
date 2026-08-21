package netsvc

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// A coerência do que o admin digita na tela de DHCP/DNS (issue #161).
//
// A FORMA DE DEFEITO QUE ESTE ARQUIVO FECHA, e ela se repetia em seis campos:
// a API aceitava um valor que o kea ou o unbound recusam DEPOIS; a resposta era
// 200 porque o apply é assíncrono; o valor PERSISTIA, então o estrago não era
// uma requisição perdida e sim o subsistema inteiro travado; e a mensagem que
// sobrava era a do daemon, que não nomeia o campo culpado.
//
// A regra que organiza tudo aqui: VALIDAR O QUE O DAEMON EXIGE, no lugar onde o
// valor entra. `net.ParseIP` responde "isso é um endereço?" quando a pergunta é
// "isso é um endereço IPv4 dentro desta sub-rede?" — e responder a pergunta
// errada com sucesso é como o valor chega ao kea.
//
// Os limites abaixo foram MEDIDOS nos binários do Debian 13 (kea-dhcp4 2.6.3,
// unbound-checkconf 1.22.0), não deduzidos das man pages.

// DentroDaSubrede diz se o endereço pertence à sub-rede servida.
//
// Sub-rede vazia devolve true: quem ainda não escolheu a rede não pode ser
// impedido de preencher o resto do formulário, e o kea só reclama quando as
// duas coisas existem.
func DentroDaSubrede(ip, cidr string) bool {
	if strings.TrimSpace(cidr) == "" {
		return true
	}
	rede, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	return rede.Contains(addr)
}

// ValidaConfig confere a coerência ENTRE os campos, que é o que nenhuma
// validação campo-a-campo pegava.
//
// Devolve a mensagem pronta para a tela: quem lê precisa saber qual campo
// consertar, e o texto do kea diz que "a config é inválida" sem dizer qual
// linha a invalidou.
func ValidaConfig(c Config) error {
	if c.Gateway != "" {
		if !validate.IPv4(c.Gateway) {
			return fmt.Errorf("o endereço do firewall na rede (%q) precisa ser IPv4: é ele que o servidor de DNS usa para escutar, e um endereço IPv6 aqui derruba o DNS da rede", c.Gateway)
		}
		if !DentroDaSubrede(c.Gateway, c.SubnetCIDR) {
			// Medido: o kea-dhcp4 ACEITA um gateway fora da sub-rede sem dizer
			// nada — quem quebra é o unbound, que tenta escutar num endereço
			// que a máquina não tem. Por isso a checagem mora aqui e não lá.
			return fmt.Errorf("o endereço do firewall na rede (%q) está fora da sub-rede %q; os aparelhos receberiam um gateway inalcançável", c.Gateway, c.SubnetCIDR)
		}
	}
	for nome, v := range map[string]string{"início da faixa": c.RangeStart, "fim da faixa": c.RangeEnd} {
		if v == "" {
			continue
		}
		if !validate.IPv4(v) {
			return fmt.Errorf("o %s (%q) precisa ser um endereço IPv4", nome, v)
		}
		if !DentroDaSubrede(v, c.SubnetCIDR) {
			// Medido no kea-dhcp4 2.6.3: "a pool of type V4 ... does not match
			// the prefix of a subnet".
			return fmt.Errorf("o %s (%q) está fora da sub-rede %q; o servidor de DHCP recusa a configuração inteira e nenhuma alteração de DHCP ou DNS passa a valer", nome, v, c.SubnetCIDR)
		}
	}
	for _, d := range c.DNSToClients {
		if d != "" && !validate.IPv4(d) {
			return fmt.Errorf("o DNS entregue aos aparelhos (%q) precisa ser um endereço IPv4", d)
		}
	}
	if c.DomainSuffix != "" && !validate.DomainWire(c.DomainSuffix) {
		return fmt.Errorf("o domínio local (%q) não é um nome válido; rótulo vazio (dois pontos seguidos) ou com mais de 63 caracteres faz o servidor de DNS recusar a configuração inteira", c.DomainSuffix)
	}
	return nil
}
