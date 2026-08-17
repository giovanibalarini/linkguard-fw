// Package validate reúne as validações de campo compartilhadas entre camadas:
// as mesmas regras que o handler HTTP aplica no que um admin digita precisam
// valer, palavra por palavra, no que uma restauração de backup grava no banco
// sem passar por handler nenhum.
//
// Antes disto as regex viviam em internal/api/handlers (netsvc.go, ntp.go) e
// só eram alcançáveis por quem pudesse importar aquele pacote — internal/backup
// não pode (o handler já importa internal/backup, seria ciclo). Duplicar a
// regex do outro lado é exatamente a divergência silenciosa que a revisão de
// arquitetura condena (ARQ-7): uma cópia endurece, a outra não, e o caminho
// mais perigoso fica com a regra mais frouxa.
//
// Este pacote é folha de propósito: só a biblioteca padrão entra aqui, para
// que qualquer camada possa importá-lo sem risco de ciclo.
package validate

import (
	"net"
	"regexp"
	"strings"
)

// Validadores estritos para valores renderizados em configs de unbound/Kea.
var (
	// reDNSDomain is intentionally lenient about structure — single-label names
	// ("lan", "localhost") and underscore labels ("_dmarc.example.com") are all
	// legitimate for a DNS blocklist or a DHCP domain suffix — but strict about
	// charset. The value is written into unbound.conf, so anything outside
	// [a-z0-9._-] (quotes, spaces, ';', newlines) must be rejected.
	reDNSDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)

	// reNetIface: charset de nome de interface, com o teto de IFNAMSIZ-1 (15)
	// do kernel. A regra de que ao menos um caractere seja alfanumérico NÃO
	// está aqui — ver Iface, que a aplica separadamente e explica por quê.
	reNetIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

	// reNTPServer guards values rendered into the chrony drop-in via string
	// formatting — hostname or IP, no spaces/quotes/control characters.
	reNTPServer = regexp.MustCompile(`^[a-zA-Z0-9.:-]{1,253}$`)
)

// Domain reports whether d is acceptable as a DNS name written into
// unbound.conf (blocklist entry ou domain_suffix do DHCP).
func Domain(d string) bool {
	return d != "" && len(d) <= 253 && reDNSDomain.MatchString(d)
}

// Iface reports whether s is acceptable as a network interface name.
//
// Exige ao menos um alfanumérico, além do charset (issue #61). Só a regex
// aceitava ".", "..", "-" e "_" — nomes compostos inteiramente de pontuação.
// A barra é que barrava "../etc", não o "..".
//
// O dano direto era limitado: ".." não é nome de interface válido no Linux, e
// internal/keaunbound se defende por conta própria. Mas o valor é interpolado
// por concatenação de string em configuração lida por um daemon ROOT
// (unbound.conf, kea-dhcp4.conf) e em comandos `ip` e `nft`, e um validador
// que aceita travessia de diretório como nome é uma base ruim para todo mundo
// que confia nele — inclusive para o próximo chamador, que não vai reler a
// regex antes de usar.
//
// A regra é "pelo menos um alfanumérico", e não uma lista de nomes proibidos,
// porque lista de proibidos erra por omissão: ela precisaria prever ".", "..",
// "...", "-", "._-" e todas as combinações. Exigir um alfanumérico elimina a
// classe inteira de uma vez, e não recusa nada legítimo — não existe interface
// de verdade sem uma letra ou um dígito no nome.
func Iface(s string) bool {
	if !reNetIface.MatchString(s) {
		return false
	}
	return strings.ContainsFunc(s, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
	})
}

// NTPServer reports whether s is acceptable as a chrony server entry.
func NTPServer(s string) bool { return reNTPServer.MatchString(s) }

// NormalizeMAC lowercases and trims s, returning "" if it is not a valid MAC
// address. O retorno vazio é o sinal de rejeição — quem chama compara com "".
func NormalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, err := net.ParseMAC(s); err != nil {
		return ""
	}
	return s
}
