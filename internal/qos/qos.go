// Package qos applies per-interface CAKE queue control without invoking a
// shell. Every external command is passed to firewall.Executor as separate
// command and argument tokens.
package qos

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

const (
	MinBandwidthMbps = 1
	MaxBandwidthMbps = 1_000_000
)

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

// Config is the desired queue-control configuration for one WAN interface.
type Config struct {
	Interface    string `json:"interface"`
	Enabled      bool   `json:"enabled"`
	UploadMbps   int    `json:"upload_mbps"`
	DownloadMbps int    `json:"download_mbps"`
	Interactive  bool   `json:"interactive"`
}

// Validate rejects values that cannot safely become ip/tc arguments.
func (c Config) Validate() error {
	if !validInterfaceName(c.Interface) {
		return fmt.Errorf("invalid interface name %q", c.Interface)
	}
	if err := validateBandwidth("upload", c.UploadMbps, c.Enabled); err != nil {
		return err
	}
	if err := validateBandwidth("download", c.DownloadMbps, c.Enabled); err != nil {
		return err
	}
	return nil
}

func validInterfaceName(iface string) bool {
	return iface != "." && iface != ".." && interfaceNamePattern.MatchString(iface)
}

func validateBandwidth(direction string, mbps int, required bool) error {
	if !required && mbps == 0 {
		return nil
	}
	if mbps < MinBandwidthMbps || mbps > MaxBandwidthMbps {
		return fmt.Errorf("%s bandwidth must be between %d and %d Mbps", direction, MinBandwidthMbps, MaxBandwidthMbps)
	}
	return nil
}

// IFBName returns a stable Linux interface name derived from the WAN name.
// The prefix plus eleven hexadecimal digits fits Linux's 15-byte limit.
func IFBName(iface string) string {
	sum := sha256.Sum256([]byte(iface))
	return "ifb-" + hex.EncodeToString(sum[:])[:11]
}
