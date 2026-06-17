//go:build !linux

package system

import "fmt"

func diskUsageSyscall(path string) (diskInfo, error) {
	return diskInfo{}, fmt.Errorf("disk usage not supported on this platform")
}
