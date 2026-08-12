// Package sysprep is the single place that knows what has to exist on the
// filesystem BEFORE linkguard-fw.service is allowed to start.
//
// Why this is a package and not three copies of the same shell:
//
// The unit runs with ProtectSystem=strict and lists the paths it may write
// to in ReadWritePaths=. systemd builds the mount namespace when the service
// STARTS, and an unprefixed ReadWritePaths= entry that does not exist at
// that moment does not merely get skipped — namespace setup fails and the
// unit dies with 226/NAMESPACE, in a restart loop, without executing a
// single line of the binary (and firing OnFailure=linkguard-notify-down on
// every attempt). Prefixing the entry with `-` avoids the crash but does NOT
// create a mount: a directory that appears later (because apt installed the
// package that owns it) stays read-only for the already-running process.
//
// Until now this pre-creation lived only in the .deb's postinst, so
// `deploy/install.sh` and `make install` produced a machine where the
// service could not start at all — reproduced on the bare test VM:
//
//	linkguard-fw.service: Failed to set up mount namespacing:
//	/etc/nftables.conf: No such file or directory
//	linkguard-fw.service: Main process exited, code=exited, status=226/NAMESPACE
//
// All three installation paths now call the same code: the binary itself,
// via `linkguard-fw --prepare-system`. The .deb can do that because postinst
// runs after the binary is unpacked; install.sh and `make install` do it
// right after copying the binary into place.
//
// TestEveryUnprefixedReadWritePathIsPrepared and its siblings
// (packaging_test.go) tie this list to the unit file and to the three
// installers, so the next path added to ReadWritePaths= cannot silently
// reopen the trap.
package sysprep

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// NftablesConfPath is the ruleset file LinkGuard owns end to end. It used to
// arrive with the nftables package (a Depends:); since the base moved to
// Recommends: — so `dpkg -i` on a bare box installs AND configures, and the
// service comes up to install the base itself — it may simply not exist on a
// first boot.
const NftablesConfPath = "/etc/nftables.conf"

// nftablesConfSeed is what an empty, LinkGuard-owned ruleset file looks like.
// Creating it empty is safe: the first Persist() rewrites the whole file, and
// this header is exactly what Persist() generates on top.
const nftablesConfSeed = "#!/usr/sbin/nft -f\n\n" +
	"# Arquivo gerenciado pelo LinkGuard FW.\n" +
	"# Vazio até o primeiro apply de firewall.\n"

// Entry is one filesystem object the service needs in place before it starts.
type Entry struct {
	// Path is absolute, exactly as it appears in the unit's ReadWritePaths=.
	Path string
	// Dir distinguishes a directory (created with MkdirAll) from a seeded file.
	Dir bool
	// Mode is applied only when this run creates the object. An entry that
	// already exists is left alone: on a box that already has the owning
	// package, the owner/mode belong to that package.
	Mode fs.FileMode
	// Seed is the initial content of a file entry.
	Seed string
	// Why is the one-line reason, printed by --prepare-system so an operator
	// reading the install log can tell what this is for.
	Why string
}

// Entries is the whole contract, in the order they are created.
var Entries = []Entry{
	{
		Path: "/var/lib/linkguard-fw", Dir: true, Mode: 0o750,
		Why: "estado do LinkGuard (banco, marcadores de aplicação)",
	},
	{
		Path: "/etc/linkguard-fw", Dir: true, Mode: 0o750,
		Why: "configuração do LinkGuard",
	},
	{
		Path: NftablesConfPath, Dir: false, Mode: 0o644, Seed: nftablesConfSeed,
		Why: "regras do firewall; sem ele a unidade morre em 226/NAMESPACE e nunca chega a instalar o nftables",
	},
	{
		Path: "/etc/kea", Dir: true, Mode: 0o755,
		Why: "config do DHCP; precisa existir no start para o kea instalado sob demanda ser configurável sem reiniciar",
	},
	{
		Path: "/etc/unbound/unbound.conf.d", Dir: true, Mode: 0o755,
		Why: "config do DNS; mesma razão do /etc/kea",
	},
}

// Prepare creates whatever is missing, under root (""/"/" for the real
// filesystem; a temp dir in tests). It is idempotent and never touches an
// object that already exists.
//
// It returns one human-readable line per object it actually created — the
// install log an operator reads — and the first error that stopped it.
func Prepare(root string) ([]string, error) {
	var created []string
	for _, e := range Entries {
		path := filepath.Join(root, e.Path)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if e.Dir {
			if err := os.MkdirAll(path, e.Mode); err != nil {
				return created, fmt.Errorf("criar %s: %w", e.Path, err)
			}
			// MkdirAll honours umask; force the intended mode.
			if err := os.Chmod(path, e.Mode); err != nil {
				return created, fmt.Errorf("ajustar modo de %s: %w", e.Path, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return created, fmt.Errorf("criar %s: %w", filepath.Dir(e.Path), err)
			}
			if err := os.WriteFile(path, []byte(e.Seed), e.Mode); err != nil {
				return created, fmt.Errorf("criar %s: %w", e.Path, err)
			}
			if err := os.Chmod(path, e.Mode); err != nil {
				return created, fmt.Errorf("ajustar modo de %s: %w", e.Path, err)
			}
		}
		created = append(created, e.Path+" — "+e.Why)
	}
	return created, nil
}

// Paths returns just the paths, for the packaging tests and for anyone who
// needs to know what this package owns.
func Paths() []string {
	out := make([]string, 0, len(Entries))
	for _, e := range Entries {
		out = append(out, e.Path)
	}
	return out
}

// Covers reports whether Prepare guarantees the given path exists: it is one
// of the entries, it lives inside a directory this package creates, or it is
// an ancestor of one (MkdirAll creates /etc/unbound on the way to
// /etc/unbound/unbound.conf.d).
func Covers(path string) bool {
	for _, e := range Entries {
		switch {
		case e.Path == path:
			return true
		case e.Dir && strings.HasPrefix(path, e.Path+"/"):
			return true
		case strings.HasPrefix(e.Path, path+"/"):
			return true
		}
	}
	return false
}
