//go:build !linux

package links

import "errors"

var errBindToDeviceUnsupported = errors.New("SO_BINDTODEVICE só está disponível no Linux")

func bindSocketToDevice(int, string) error {
	// Não fazer fallback para roteamento genérico: isso faria uma verificação
	// de WAN parecer saudável pela saída de outra WAN.
	return errBindToDeviceUnsupported
}
