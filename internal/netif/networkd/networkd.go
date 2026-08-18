// Package networkd implements the systemd-networkd Provider for netif —
// rendering and applying interface addressing config. Fase 2 only handles
// physical interfaces (prefix "10-"); VLAN ("20-") and bridge ("30-") prefixes
// are reserved for Fase 3, per spec 19/07 §5.3.
package networkd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const defaultNetworkDir = "/etc/systemd/network"

// ResolveNetworkDir returns dir if non-empty, otherwise the package's
// production default. Exported so callers outside this package (e.g.
// internal/netif's Service, which needs to glob the directory for orphaned
// managed-file cleanup) can resolve the same effective directory Render/
// RenderLink use internally, without duplicating the default path string.
func ResolveNetworkDir(dir string) string {
	if dir == "" {
		return defaultNetworkDir
	}
	return dir
}

// ConfigFile is one rendered systemd-networkd unit file.
type ConfigFile struct {
	Path    string
	Content string
	// Dir é o diretório em que este arquivo DEVE ficar — o mesmo que foi
	// passado a Render/RenderLink.
	//
	// Ele existe para que Apply possa provar a contenção em vez de confiar na
	// forma do Path. Sem ele, o ponto que executa o os.Rename como root só
	// consegue inspecionar a string que recebeu; com ele, consegue perguntar
	// "isto está dentro de onde eu mandei escrever?" — que é a pergunta certa,
	// e a única que sobrevive a uma mudança no validador de nome de interface.
	//
	// Vazio é aceito e cai na conferência de forma, para não quebrar chamador
	// antigo (o rollback em netif/service.go monta um ConfigFile a partir de um
	// Path já gravado).
	Dir string
}

// IfaceSpec is the minimal addressing info Render needs to produce a
// .network file. Deliberately NOT netif.Iface: internal/netif's Service
// (Task 5) needs to import this package to call Render/Apply, so this
// package must not import internal/netif in turn (that would be an import
// cycle — internal/netif -> internal/netif/networkd -> internal/netif).
// AddrMode holds the same string values as netif.AddrMode
// ("static"/"dhcp"/"none") — callers in package netif pass those through
// directly, since IfaceEdit.AddrMode is already a plain string.
type IfaceSpec struct {
	Name     string
	AddrMode string
	CIDR     string
	Gateway  string
}

// Render produces the .network file for a physical interface. Pure — no I/O,
// safe to call for a preview without touching the system. Every file carries
// the "# managed by linkguard" header (spec 19/07 §5.3) so that a *future*
// cleanup/deletion step can tell managed files apart from unmanaged ones.
// Nothing today reads or acts on this header — Apply (Task 4) writes/renames
// the single ConfigFile it's given; Remove deletes a file entirely (used when
// rolling back a first-time adoption that had no prior file to restore).
// Orphaned-file cleanup based on this header is not yet implemented.
//
// dir overrides the target directory — pass "" in production to use
// defaultNetworkDir ("/etc/systemd/network"); tests pass a t.TempDir() so
// they never touch the real system path. Service (Task 5) is the only
// production caller and always forwards its own configurable networkDir.
func Render(i IfaceSpec, dir string) ConfigFile {
	if dir == "" {
		dir = defaultNetworkDir
	}
	var body strings.Builder
	body.WriteString("# managed by linkguard\n\n")
	body.WriteString("[Match]\n")
	fmt.Fprintf(&body, "Name=%s\n\n", i.Name)
	body.WriteString("[Network]\n")

	switch i.AddrMode {
	case "static":
		fmt.Fprintf(&body, "Address=%s\n", i.CIDR)
		if i.Gateway != "" {
			fmt.Fprintf(&body, "Gateway=%s\n", i.Gateway)
		}
	case "dhcp":
		body.WriteString("DHCP=yes\n")
	case "none":
		// Sem Address=/DHCP= — interface sobe sem endereço IP.
	}

	return ConfigFile{
		Path:    fmt.Sprintf("%s/10-%s.network", dir, i.Name),
		Content: body.String(),
		Dir:     dir,
	}
}

// IsActive reports whether systemd-networkd is the unit actually managing
// the network on this host. Production still runs on `ifupdown` (spec adendo
// 2026-07-28) — on those hosts `networkctl reload` fails outright (its D-Bus
// service isn't registered), so Apply/Remove use this to skip the reload
// call instead of treating the whole write as a failure.
func IsActive(ctx context.Context, exec firewall.Executor) bool {
	_, err := exec.ExecuteRead(ctx, "systemctl", "is-active", "systemd-networkd")
	return err == nil
}

// reload calls `networkctl reload` when systemd-networkd is actually
// managing the host, otherwise logs and skips it. Skipping (rather than
// erroring) is what lets Apply/Remove still succeed — and Service still
// register the pending change and its commit/confirm safety net — on a host
// where the Provider is legitimately inert per spec §14 (ifupdown hosts
// today), instead of leaving an unmanaged orphan file with no rollback.
func reload(ctx context.Context, exec firewall.Executor, path string) error {
	if !IsActive(ctx, exec) {
		slog.Warn("systemd-networkd inativo — arquivo de interface escrito/removido mas reload pulado, sem efeito real na rede até a migração ifupdown→networkd", "path", path)
		return nil
	}
	if _, err := exec.Execute(ctx, "networkctl", "reload"); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	return nil
}

// Apply writes f atomically (temp file in the same directory, then rename —
// atomic because it's the same filesystem, the first such pattern in this
// codebase) and reloads systemd-networkd. A no-op write in dry-run mode,
// matching the convention every other Provider in this codebase follows
// (see internal/keaunbound.ReloadConfigs). Apply itself never deletes a
// file — see Remove for that.
//
// Fase 2 never changes an interface's type, so `networkctl reload` always
// suffices — `reconfigure` (needed when a .netdev is added/removed) is
// deferred to Fase 3.
// safeUnitPath confere que p é o caminho absoluto de um arquivo solto DENTRO de
// root, e o devolve. Recusa em vez de normalizar.
//
// A conferência contra root é a que vale: ela pergunta "isto está onde eu mandei
// escrever?", que é a única pergunta que sobrevive a uma mudança no validador de
// nome de interface — e foi a distância entre o validador e o os.Rename que
// deixou uma cópia divergente da regex sobreviver nesta base (ver o comentário
// de internal/netif/rules.go).
//
// Recusar travessia em vez de resolvê-la é deliberado: normalizar
// "/etc/systemd/network/../../passwd" para "/etc/passwd" faria a escrita
// ACONTECER, num lugar que o chamador não pediu, em silêncio e como root. Um
// caminho produzido por Render nunca tem ".."; se aparecer, quem montou errou.
//
// root vazio cai só na conferência de forma, para não quebrar o chamador que
// monta um ConfigFile a partir de um Path já gravado (o rollback de
// netif/service.go).
func safeUnitPath(p, root string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("caminho de unit precisa ser absoluto: %q", p)
	}
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return "", fmt.Errorf("caminho de unit aponta para um diretório: %q", p)
	}
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." || part == "." {
			return "", fmt.Errorf("caminho de unit com travessia: %q", p)
		}
	}
	clean := filepath.Clean(p)
	if strings.TrimSpace(filepath.Base(clean)) == "" {
		return "", fmt.Errorf("caminho de unit sem nome de arquivo: %q", p)
	}

	if root == "" {
		return clean, nil
	}
	cleanRoot := filepath.Clean(root)
	// O arquivo tem de ser filho DIRETO da raiz. Comparar o diretório-pai, em
	// vez de usar HasPrefix na string inteira, evita o clássico "/etc/systemd/
	// network-do-atacante" passar por começar igual a "/etc/systemd/network".
	if filepath.Dir(clean) != cleanRoot {
		return "", fmt.Errorf("caminho de unit fora de %s: %q", cleanRoot, p)
	}
	return clean, nil
}

func Apply(ctx context.Context, exec firewall.Executor, f ConfigFile) error {
	if exec.IsDryRun() {
		return nil
	}
	// O caminho é conferido contra o diretório de destino ANTES de qualquer
	// escrita (alerta go/path-injection do CodeQL).
	//
	// f.Path é montado por Render interpolando o NOME DA INTERFACE, que vem do
	// cliente. Hoje netif.ValidateIface já recusa barra e nome feito só de
	// pontuação — mas essa validação mora noutro pacote, e é chamada por quem
	// monta o ConfigFile, não por quem escreve o arquivo. Esta função é a que
	// tem o os.Rename na mão, e ela não pode depender de o chamador ter feito a
	// coisa certa: até hoje ela dependia, e foi assim que uma cópia divergente
	// da regex sobreviveu nesta base (ver o comentário de internal/netif/rules.go).
	dest, err := safeUnitPath(f.Path, f.Dir)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dest)
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
	// os.CreateTemp sempre cria o arquivo em 0600, independente do umask, e
	// os.Rename preserva o modo da origem — sem isto o arquivo final ficaria
	// legível só pelo dono. Config de endereçamento de interface não é
	// segredo; seguimos a convenção 0644 do resto do codebase (ex.:
	// internal/nftables, internal/keaunbound, internal/hosttraffic,
	// internal/routes).
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("ajustar permissão do arquivo temporário: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mover %s para %s: %w", tmpPath, dest, err)
	}

	return reload(ctx, exec, dest)
}

// Remove deletes path entirely and reloads systemd-networkd — used when
// rolling back a first-time interface adoption, where the pre-change state
// was "no .network file at all", not an empty one (writing an empty file via
// Apply would leave an unrestricted [Match] with an empty [Network] block,
// not restore the original unmanaged state). A no-op in dry-run mode, same
// convention as Apply. Idempotent: path already missing is treated as
// success, not an error.
func Remove(ctx context.Context, exec firewall.Executor, path string) error {
	if exec.IsDryRun() {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remover %s: %w", path, err)
	}

	return reload(ctx, exec, path)
}
