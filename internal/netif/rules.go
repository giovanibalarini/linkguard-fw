// Package netif's integrity rules — pure functions, no I/O. Fase 2 só valida
// o subconjunto relevante a interfaces físicas (spec 19/07 §5.2); as regras
// de VLAN/bridge (ciclos, unicidade de tag, etc.) ficam para a Fase 3.
package netif

import (
	"fmt"
	"net"
)

// ValidateIface checks the addressing fields are internally consistent.
// AddrMode="static" requires a valid CIDR; a present Gateway must parse as an
// IP inside that CIDR's network. AddrMode="dhcp"/"none" ignore CIDR/Gateway
// entirely (they're meaningless in those modes).
func ValidateIface(i Iface) error {
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
