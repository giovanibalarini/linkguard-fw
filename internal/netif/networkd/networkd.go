// Package networkd implements the systemd-networkd Provider for netif —
// rendering and applying interface addressing config. Fase 2 only handles
// physical interfaces (prefix "10-"); VLAN ("20-") and bridge ("30-") prefixes
// are reserved for Fase 3, per spec 19/07 §5.3.
package networkd

import (
	"fmt"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/netif"
)

const defaultNetworkDir = "/etc/systemd/network"

// ConfigFile is one rendered systemd-networkd unit file.
type ConfigFile struct {
	Path    string
	Content string
}

// Render produces the .network file for a physical interface. Pure — no I/O,
// safe to call for a preview without touching the system. Every file carries
// the "# managed by linkguard" header (spec 19/07 §5.3) — Apply (Task 4) only
// ever deletes a file that has this exact header, never anything else.
//
// dir overrides the target directory — pass "" in production to use
// defaultNetworkDir ("/etc/systemd/network"); tests pass a t.TempDir() so
// they never touch the real system path. Service (Task 5) is the only
// production caller and always forwards its own configurable networkDir.
func Render(i netif.Iface, dir string) ConfigFile {
	if dir == "" {
		dir = defaultNetworkDir
	}
	var body strings.Builder
	body.WriteString("# managed by linkguard\n\n")
	body.WriteString("[Match]\n")
	fmt.Fprintf(&body, "Name=%s\n\n", i.Name)
	body.WriteString("[Network]\n")

	switch i.AddrMode {
	case netif.AddrModeStatic:
		fmt.Fprintf(&body, "Address=%s\n", i.CIDR)
		if i.Gateway != "" {
			fmt.Fprintf(&body, "Gateway=%s\n", i.Gateway)
		}
	case netif.AddrModeDHCP:
		body.WriteString("DHCP=yes\n")
	case netif.AddrModeNone:
		// Sem Address=/DHCP= — interface sobe sem endereço IP.
	}

	return ConfigFile{
		Path:    fmt.Sprintf("%s/10-%s.network", dir, i.Name),
		Content: body.String(),
	}
}
