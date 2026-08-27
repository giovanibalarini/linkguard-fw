//go:build linux

package links

import "syscall"

func bindSocketToDevice(fd int, device string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}
