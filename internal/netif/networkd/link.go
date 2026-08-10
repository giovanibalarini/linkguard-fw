// Package networkd (this file): .link files pin a persistent kernel
// interface name to a physical NIC's MAC address, independent of PCI slot
// position — see
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
// Separate from Render/Apply (.network) because .link files have different
// semantics: read by udev at coldplug, never hot-reloaded, so writing one
// never calls `networkctl reload`.
package networkd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// RenderLink produces a systemd .link file that pins name to whatever
// physical NIC currently has mac. Pure — no I/O, mirrors Render's
// signature/style: dir "" means defaultNetworkDir in production, tests pass
// a t.TempDir().
func RenderLink(mac, name, dir string) ConfigFile {
	if dir == "" {
		dir = defaultNetworkDir
	}
	var body strings.Builder
	body.WriteString("# managed by linkguard\n\n")
	body.WriteString("[Match]\n")
	fmt.Fprintf(&body, "MACAddress=%s\n\n", mac)
	body.WriteString("[Link]\n")
	fmt.Fprintf(&body, "Name=%s\n", name)

	return ConfigFile{
		Path:    fmt.Sprintf("%s/10-%s.link", dir, name),
		Content: body.String(),
	}
}

// WriteLinkFile writes a .link file atomically (temp file + rename, same
// pattern as Apply) but deliberately does NOT call `networkctl reload` —
// .link files are read by udev at coldplug, not by networkd's live reload,
// so they only take effect after a reboot. Re-triggering a live production
// NIC with traffic passing is explicitly out of scope (spec §3) — always
// reboot, never re-trigger. A no-op in dry-run mode, same convention as
// Apply/Remove.
func WriteLinkFile(exec firewall.Executor, f ConfigFile) error {
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
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("ajustar permissão do arquivo temporário: %w", err)
	}
	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mover %s para %s: %w", tmpPath, f.Path, err)
	}
	return nil
}

// RemoveLinkFile deletes a previously-written .link file. Idempotent: a
// missing file is treated as success, not an error — the caller may be
// pruning a file that was already removed by a prior partial run. Same
// "reboot-only" rule as WriteLinkFile: deliberately does NOT call
// `networkctl reload` — removing a .link file has no live effect either,
// only after the next reboot. A no-op in dry-run mode, same convention as
// WriteLinkFile.
func RemoveLinkFile(exec firewall.Executor, path string) error {
	if exec.IsDryRun() {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remover %s: %w", path, err)
	}
	return nil
}
