// Package netif's integrity rules — pure functions, no I/O. Fase 2 só valida
// o subconjunto relevante a interfaces físicas (spec 19/07 §5.2); as regras
// de VLAN/bridge (ciclos, unicidade de tag, etc.) ficam para a Fase 3.
package netif

import (
	"fmt"
	"net"

	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// O nome da interface é validado por validate.Iface, e NÃO por uma regex local.
//
// Aqui havia uma cópia — `^[a-zA-Z0-9._-]{1,15}$` — idêntica à que morava em
// internal/validate. O comentário daquele pacote já dizia por que isso é ruim:
// "uma cópia endurece, a outra não, e o caminho mais perigoso fica com a regra
// mais frouxa" (ARQ-7). Foi exatamente o que aconteceu. A issue #61 endureceu
// validate.Iface para recusar nome feito só de pontuação (".", "..", "-"), e
// esta cópia continuou aceitando — no lugar em que o nome é interpolado sem
// escape num CAMINHO DE ARQUIVO e no corpo de uma unit do systemd-networkd
// (networkd.Render), que é o sink que o CodeQL aponta como path-injection.
//
// A regra continua deliberadamente mais estrita do que a do kernel: ela guarda
// contra a quebra de linha injetando diretiva no arquivo da unit e contra a
// barra escapando do diretório de destino.

// ValidateIface checks the addressing fields are internally consistent.
// Name is validated unconditionally (every AddrMode renders it into a file
// path and a systemd-networkd [Match] section). AddrMode="static" requires a
// valid CIDR; a present Gateway must parse as an IP inside that CIDR's
// network. AddrMode="dhcp"/"none" ignore CIDR/Gateway entirely (they're
// meaningless in those modes).
func ValidateIface(i Iface) error {
	if !validate.Iface(i.Name) {
		return fmt.Errorf("nome de interface inválido: %q", i.Name)
	}
	if i.AddrMode != AddrModeStatic {
		return nil
	}
	ip, ipNet, err := net.ParseCIDR(i.CIDR)
	if err != nil {
		return fmt.Errorf("cidr inválido para %s: %w", i.Name, err)
	}
	if i.Gateway == "" {
		return nil
	}
	gw := net.ParseIP(i.Gateway)
	if gw == nil {
		return fmt.Errorf("gateway inválido para %s: %q não é um IP", i.Name, i.Gateway)
	}
	if !ipNet.Contains(gw) {
		return fmt.Errorf("gateway %s fora da rede %s (interface %s)", i.Gateway, ipNet.String(), i.Name)
	}
	_ = ip // ip é o endereço da própria interface, já validado pelo ParseCIDR acima
	return nil
}
