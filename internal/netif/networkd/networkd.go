// Package networkd implements the systemd-networkd Provider for netif —
// rendering and applying interface addressing config. Fase 2 only handles
// physical interfaces (prefix "10-"); VLAN ("20-") and bridge ("30-") prefixes
// are reserved for Fase 3, per spec 19/07 §5.3.
package networkd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
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

// Apply writes f atomically (temp file in the same directory, then rename —
// atomic because it's the same filesystem, the first such pattern in this
// codebase) and reloads systemd-networkd. A no-op write in dry-run mode,
// matching the convention every other Provider in this codebase follows
// (see internal/keaunbound.ReloadConfigs).
//
// Fase 2 never removes or changes an interface's type, so `networkctl reload`
// always suffices — `reconfigure` (needed when a .netdev is added/removed)
// is deferred to Fase 3.
func Apply(ctx context.Context, exec firewall.Executor, f ConfigFile) error {
	if exec.IsDryRun() {
		return nil
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".linkguard-networkd-*.tmp")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário em %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(f.Content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("escrever conteúdo temporário: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("fechar arquivo temporário: %w", err)
	}
	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mover %s para %s: %w", tmpPath, f.Path, err)
	}

	if _, err := exec.Execute(ctx, "networkctl", "reload"); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	return nil
}
