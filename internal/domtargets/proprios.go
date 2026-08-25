package domtargets

import (
	"net"
	"net/netip"
	"strings"
)

// As faixas da PRÓPRIA caixa (#123).
//
// POR QUE ISTO EXISTE. Utilizavel recusa endereço por CATEGORIA — privado,
// reservado, documentação, o que embute v4 dentro de v6. Todo endereço de que
// esta caixa depende passa por esse filtro sem esbarrar em nada, porque todos
// são de categoria PÚBLICA por construção:
//
//   - o endereço da WAN é público, e o pacote ddns existe justamente para
//     publicá-lo;
//   - em PPPoE e em uplink com /30 ou /29 público, o gateway é público;
//   - com prefixo delegado, os hosts da LAN têm endereço global v6.
//
// Sem esta lista, um domínio hostil responde com o IP do próprio link e ele
// entra em dom_wan com a marca da outra WAN, ou em dom_blocked com prazo de uma
// hora. Com o gateway lá dentro e o set ligado na forward, é a LAN inteira sem
// uplink por causa de uma resposta de DNS de terceiro.

// PrefixosLocais devolve as faixas que estão nas interfaces desta máquina.
//
// Lê do kernel pelo net.Interfaces da biblioteca padrão: sem fork, sem parser
// de saída de comando e sem depender de o ip estar no PATH — este código roda a
// cada minuto e não pode custar um processo.
//
// DEVOLVE O PREFIXO, E NÃO O ENDEREÇO. As redes a que a caixa está diretamente
// ligada contam inteiras: proteger só o endereço da caixa deixaria o vizinho da
// LAN de fora, e o ataque só mudaria de alvo — o estrago de barrar um host da
// própria LAN é o mesmo.
//
// Devolve o que conseguiu. Uma interface que some no meio da varredura não é
// motivo para deixar a lista vazia, que é o estado sem proteção nenhuma.
func PrefixosLocais() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, in := range ifaces {
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p, ok := prefixoDe(a)
			if ok {
				out = append(out, p)
			}
		}
	}
	return out
}

func prefixoDe(a net.Addr) (netip.Prefix, bool) {
	rede, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	ip, ok := netip.AddrFromSlice(rede.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := rede.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	if ip.Is4() && bits > 32 {
		// Máscara v4 contada em 128 bits (o que acontece quando o endereço vem
		// mapeado): traz de volta para a escala da família certa.
		bits -= 96
	}
	p := netip.PrefixFrom(ip, bits)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// PrefixosDeEnderecos transforma endereços soltos em prefixos de host.
//
// É como o gateway de um uplink ponto a ponto, os hosts de monitoração e o
// servidor de teste de DNS entram na lista: eles não estão em interface
// nenhuma, e são exatamente os endereços de que o produto depende para saber se
// o link está de pé. Texto que não é endereço é ignorado — a lista vem do banco
// e um campo em branco não pode derrubar a proteção inteira.
//
// Cada texto pode trazer vários endereços separados por vírgula ou espaço, que
// é como o banco guarda os hosts de monitoração de um link. E pode vir em forma
// de rede (a.b.c.d/24), que é como o endereço de um link costuma ser escrito.
func PrefixosDeEnderecos(textos []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(textos))
	for _, t := range textos {
		for _, campo := range strings.FieldsFunc(t, separadorDeLista) {
			p, ok := prefixoDeTexto(campo)
			if ok {
				out = append(out, p)
			}
		}
	}
	return out
}

func separadorDeLista(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
}

func prefixoDeTexto(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err == nil {
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}
