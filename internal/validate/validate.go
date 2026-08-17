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
	reNetIface  = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

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
func Iface(s string) bool { return reNetIface.MatchString(s) }

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
