// Package keaunbound is the high-performance DHCP/DNS Provider: Kea (DHCP) +
// unbound (DNS). It follows the "generate config + reload service" model used
// for nftables — the panel owns /etc/kea/kea-dhcp4.conf and the unbound config,
// and restarts the daemons. It implements netsvc.Provider.
package keaunbound

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/sysprep"
)

const (
	KeaConfPath      = "/etc/kea/kea-dhcp4.conf"
	UnboundConfPath  = "/etc/unbound/unbound.conf.d/linkguard.conf"
	KeaLeasesPath    = "/var/lib/kea/kea-leases4.csv"
	ResolvConfPath   = "/etc/resolv.conf"
	DhclientConfPath = "/etc/dhcp/dhclient.conf"

	keaService             = "kea-dhcp4-server"
	unboundService         = "unbound"
	keaBinDefault          = "/usr/sbin/kea-dhcp4"
	unboundCheckBinDefault = "/usr/sbin/unbound-checkconf"

	// The Debian packages this backend IS. They are Recommends: (not
	// Depends:) of linkguard-fw on purpose — see the Makefile's deb target —
	// so a box can legitimately arrive without them, and LinkGuard brings
	// them in when the admin turns DHCP/DNS on (ensurePackages).
	keaPackage     = "kea-dhcp4-server"
	unboundPackage = "unbound"

	// dnsRootDataPackage is named explicitly because the install runs with
	// --no-install-recommends: Debian's unbound only *recommends*
	// dns-root-data, but its shipped drop-in
	// (/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf) points
	// auto-trust-anchor-file at /var/lib/unbound/root.key unconditionally.
	// Without the data package that key never materialises and unbound dies
	// at startup with "module init for module validator failed" — installed,
	// enabled, and not serving a single query. Measured on the test VM, and
	// exactly the "configurado ≠ funcionando" state this project treats as
	// worse than not installing at all.
	dnsRootDataPackage = "dns-root-data"

	// unboundActivatedMarker is the copy of the unbound config that was last
	// ACTIVATED — the one the running daemon is actually serving with.
	//
	// It exists because "what is on disk" is not the same question. The
	// restart decision used to compare the file at s.unboundConf against the
	// new content, and that file is written BEFORE the reload: if an apply
	// wrote both configs and then died on Kea's reload-or-restart, the next
	// apply saw old == new, decided a graceful SIGHUP was enough, and left
	// unbound on the sockets it was started with (127.0.0.1) — LAN with no
	// DNS, panel saying "aplicado". That is the exact defect
	// unboundNeedsRestart was introduced to fix, coming back through
	// another door.
	//
	// Written only after the reload/restart of unbound succeeded, so a
	// half-finished apply can never be mistaken for an activated one. Lives
	// under /var/lib (state, not configuration) and is never read by any
	// daemon. On a box upgrading from before this file existed the marker is
	// absent, so the first apply restarts unbound once — a sub-second DNS
	// blip, on the safe side of the question.
	unboundActivatedMarker = "/var/lib/linkguard-fw/unbound-applied.conf"
)

// Service is the Kea+unbound Provider. Config paths and the Kea binary are
// fields (defaulted to the system paths) so tests can point them at a temp dir.
type Service struct {
	exec firewall.Executor
	// installExec is the executor used ONLY for the on-demand apt install.
	// It is separate because the two workloads have nothing in common: an
	// `nft`/`systemctl`/`kea-dhcp4 -t` call that has not answered in 30s is
	// hung, while an apt-get fetching kea + unbound + dns-root-data (~10 MB)
	// over an office link routinely takes longer than that.
	//
	// Sharing the 30s executor was actively harmful, not merely slow: when
	// the deadline fired, the apt did NOT die with it — systemd-run's
	// transient unit finishes the transaction regardless — so LinkGuard
	// answered 503 "não conseguiu instalar", raised a CRITICAL alert and
	// burned its single retry on the dpkg lock, all while apt was installing
	// successfully. A lie in the opposite direction, and worse than the
	// original defect.
	//
	// Defaults to exec (tests and dry-run); main.go points it at a
	// long-deadline executor.
	installExec firewall.Executor
	keaConf     string
	unboundConf string
	// unboundApplied is a copy of the unbound config LinkGuard last
	// ACTIVATED — not merely wrote to disk. See unboundActivatedMarker.
	unboundApplied  string
	keaBin          string
	unboundCheckBin string
	resolvConf      string
	dhclientConf    string
}

// NewService creates the provider.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:            exec,
		installExec:     exec,
		keaConf:         KeaConfPath,
		unboundConf:     UnboundConfPath,
		unboundApplied:  unboundActivatedMarker,
		keaBin:          keaBinDefault,
		unboundCheckBin: unboundCheckBinDefault,
		resolvConf:      ResolvConfPath,
		dhclientConf:    DhclientConfPath,
	}
}

// SetInstallExecutor points the on-demand package install at an executor with
// a deadline sized for a package download. See Service.installExec.
func (s *Service) SetInstallExecutor(e firewall.Executor) {
	if e != nil {
		s.installExec = e
	}
}

// Backend implements netsvc.Provider.
func (s *Service) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }

// EnsureKeaDirReadable relaxes /etc/kea's directory permissions so both
// LinkGuard's own config validation and kea-dhcp4-server's own startup can
// actually read the config that lives there. Debian's kea-dhcp-server
// package ships the directory owned _kea:_kea mode 0750; kea-dhcp4's
// AppArmor profile grants path-based read access under /etc/kea/** but not
// the dac_override/dac_read_search capabilities needed to bypass that Unix
// DAC restriction, so even root gets "Unable to open file" despite the file
// itself being 0644 and the AppArmor path rule allowing it — the directory
// blocks traversal before either of those checks matter. LinkGuard owns this
// the same way it owns nftables bootstrap/ip_forward/conntrack accounting:
// called at every startup so it self-heals regardless of what a package
// reinstall resets it to. Best-effort — a failure here surfaces later as a
// real validate/reload error instead of blocking startup.
func (s *Service) EnsureKeaDirReadable() {
	dir := filepath.Dir(s.keaConf)
	if err := os.Chmod(dir, 0o755); err != nil {
		slog.Warn("could not relax kea config directory permissions; DHCP apply may fail under AppArmor", "path", dir, "err", err)
	}
}

// ensurePackages makes the machine able to serve DHCP/DNS before this
// provider tries to configure it: kea-dhcp4-server and unbound are installed
// here, on demand, at the moment the admin applies a DHCP/DNS change.
//
// Why here and not at boot: installing them at startup would take over
// services nobody asked for (bootstrapdeps' package doc). Why both at once
// and not one per feature: ReloadConfigs is a single operation that writes
// BOTH configs and reloads BOTH daemons — there is no state in which this
// provider applies one and not the other, so needing one and not the other
// is not a state that exists either. The apt mechanics (transient unit,
// non-interactive flags, retry after refreshing the index) live in
// bootstrapdeps.InstallPackages/EnsureInstalled, the single place in the
// codebase that knows how a package gets installed.
//
// Returns the packages it actually installed — empty on every apply after
// the first, since the fast path is one dpkg-query per package and no apt
// call at all.
//
// The two failure modes are deliberately different errors with the same
// shape (*netsvc.PrereqError, an admin-facing sentence):
//
//   - apt could not install it: say which package, why, what stops working
//     and the manual command (bootstrapdeps does that wording);
//   - the package is there but its config directory is not writable by this
//     process: the systemd trap, see writableDir.
//
// dns-root-data é o único que NÃO é pré-requisito duro sempre (I-2 da
// revisão final). Ele é obrigatório quando é o LinkGuard que vai instalar o
// unbound nesta passada: um unbound recém-instalado sem a âncora DNSSEC da
// raiz nem sobe, e entregar um resolvedor habilitado que não responde uma
// consulta é pior do que não instalar. Numa máquina onde o unbound JÁ está
// instalado e servindo, ele deixa de ser condição para aplicar: exigi-lo ali
// trancava o admin fora de toda mudança de DHCP/DNS enquanto o apt não
// pudesse instalar — e a hora de mexer em DHCP/DNS costuma ser exatamente a
// hora em que a WAN está ruim. Vira aviso no ApplyResult, que a tela mostra
// junto do "aplicado".
func (s *Service) ensurePackages(ctx context.Context) ([]string, []string, error) {
	if s.exec.IsDryRun() {
		return nil, nil, nil
	}
	// A âncora só é indispensável agora se o unbound vai nascer nesta
	// passada — e nesse caso os três entram num apt só.
	required := []string{keaPackage, unboundPackage}
	freshUnbound := len(bootstrapdeps.Missing(ctx, s.exec, unboundPackage)) > 0
	if freshUnbound {
		required = append(required, dnsRootDataPackage)
	}

	installed, err := bootstrapdeps.EnsureInstalled(ctx, s.installExec, required...)
	if err != nil {
		return installed, nil, &netsvc.PrereqError{Msg: err.Error()}
	}

	var warnings []string
	if !freshUnbound {
		// Já instalado é o caso comum e custa um dpkg-query. Ausente, tenta
		// trazer — e se não der, o apply segue com o aviso.
		got, derr := bootstrapdeps.EnsureInstalled(ctx, s.installExec, dnsRootDataPackage)
		installed = append(installed, got...)
		if derr != nil {
			slog.Warn("dns-root-data ausente e não instalável; DHCP/DNS aplicado assim mesmo", "err", derr)
			warnings = append(warnings, "O pacote "+dnsRootDataPackage+" não está instalado e o LinkGuard não "+
				"conseguiu instalá-lo agora. A configuração foi aplicada e o DNS continua respondendo, mas "+
				"falta a âncora DNSSEC da raiz (/var/lib/unbound/root.key): se o unbound for reiniciado sem "+
				"ela, pode não voltar a subir e a LAN fica sem DNS. Instale quando a máquina tiver rede: "+
				"apt-get install -y "+dnsRootDataPackage+".")
		}
	}

	if len(installed) > 0 {
		// A freshly installed kea ships /etc/kea as _kea:_kea 0750, which
		// blocks both this process's config write and kea-dhcp4's own read
		// (see EnsureKeaDirReadable). Startup already self-heals that, but
		// the package was just installed *after* startup — fixing it only at
		// the next boot would mean the first apply after an on-demand
		// install is the one that fails.
		s.EnsureKeaDirReadable()
	}
	for _, dir := range []string{filepath.Dir(s.keaConf), filepath.Dir(s.unboundConf)} {
		if err := writableDir(dir); err != nil {
			return installed, warnings, &netsvc.PrereqError{Msg: sandboxHint(dir, err)}
		}
	}
	return installed, warnings, nil
}

// writableDir reports whether this process can create a file in dir — the
// question that actually matters, answered the same way the code that
// follows will ask it (os.CreateTemp), instead of inferring it from
// permission bits that a read-only mount overrides anyway.
//
// The probe name deliberately has no ".conf" suffix: this runs inside
// /etc/unbound/unbound.conf.d, which Debian's unbound.conf pulls in with
// `include-toplevel: ".../*.conf"` — same reasoning as validateUnbound's own
// temp file.
//
// The name is also fixed rather than random (it used to be os.CreateTemp):
// a process killed between creating the probe and removing it left the file
// behind, and nothing ever collected it — one more piece of litter in /etc
// per unlucky restart. With a fixed name there can only ever be one, and the
// sweep below removes it (plus anything left by the old random-suffix
// version) before probing again.
//
// Concurrency-safe by construction: two applies racing on the same directory
// can only make each other's Remove find the file already gone, which is not
// an error here — the question being answered is "can this process create a
// file in dir", and it was answered by the create.
func writableDir(dir string) error {
	for _, leftover := range globQuiet(filepath.Join(dir, writeProbeName+"*")) {
		_ = os.Remove(leftover)
	}
	path := filepath.Join(dir, writeProbeName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeProbeName is the fixed name of the write probe. See writableDir.
const writeProbeName = ".linkguard-write-probe"

func globQuiet(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// sandboxHint delegates to sysprep.SandboxHint: the sentence is identical
// for DHCP, DNS and NTP, and it belongs next to the code that pre-creates
// those directories in the first place (internal/sysprep).
func sandboxHint(dir string, err error) string {
	return sysprep.SandboxHint(dir, err)
}

// EnsureResolvConf makes the box actually use its own resolver (unbound on
// 127.0.0.1) instead of whatever nameservers the WAN's DHCP lease proposes.
//
// Found in production on 2026-08-10: /etc/resolv.conf pointed at the ISP,
// and nothing in this codebase managed that file — so the appliance was
// silently bypassing its own DNS, losing the blocklist and the query
// visibility unbound provides. Rewriting resolv.conf alone would not hold:
// dhclient rewrites it on every lease renewal, which is why this also adds
// a `supersede domain-name-servers` directive so dhclient stops proposing
// the ISP's servers in the first place (working with dhclient rather than
// fighting it).
//
// Self-heals on every start, like the other Ensure* calls. Best-effort: a
// failure is logged as a warning rather than blocking startup. A dedicated
// dns-resolver health check to surface this failure in the UI is planned
// but not implemented yet.
//
// Gated on unbound actually being enabled: the Debian package lists unbound
// as `Recommends:`, never `Depends:`, so it can legitimately be absent (or
// present but failed to start). Unconditionally pointing resolv.conf at
// 127.0.0.1 on such a box, and stripping the ISP's servers from dhclient's
// config, would leave nothing answering DNS at all — silently breaking the
// updater's fetch from GitHub releases, Telegram/webhook notifications, the
// AI digest, and chrony's pool hostnames. Do NOT remove this guard "to
// simplify" without re-reading this comment: it is the difference between
// gaining a resolver and losing name resolution entirely.
//
// `systemctl is-enabled` (not `is-active`) is used deliberately: it answers
// from unit configuration rather than current process state, so it gives
// the same answer regardless of where in the boot sequence this runs,
// instead of racing unbound's own startup.
func (s *Service) EnsureResolvConf(ctx context.Context) {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-enabled", "unbound")
	if err != nil || strings.TrimSpace(out) != "enabled" {
		slog.Info("resolver local (unbound) não está instalado/habilitado; resolv.conf foi deixado como está", "path", s.resolvConf, "systemctl_output", strings.TrimSpace(out), "err", err)
		return
	}

	const body = "# managed by linkguard\nnameserver 127.0.0.1\n"
	if err := s.exec.WriteFile(s.resolvConf, []byte(body), 0o644); err != nil {
		slog.Warn("não foi possível apontar o resolv.conf para o resolver local", "path", s.resolvConf, "err", err)
	} else {
		slog.Info("resolv.conf apontando para o resolver local (unbound)", "path", s.resolvConf)
	}

	const directive = "supersede domain-name-servers 127.0.0.1;"
	current, err := os.ReadFile(s.dhclientConf)
	if err != nil && !os.IsNotExist(err) {
		slog.Warn("não foi possível ler a config do dhclient; o DNS do provedor pode voltar na renovação do lease", "path", s.dhclientConf, "err", err)
		return
	}
	updated := ensureSupersedeDirective(string(current), directive)
	if updated == string(current) {
		return // already in place, exactly as we want it — this runs on every boot
	}
	if err := s.exec.WriteFile(s.dhclientConf, []byte(updated), 0o644); err != nil {
		slog.Warn("não foi possível fixar o DNS local na config do dhclient", "path", s.dhclientConf, "err", err)
	}
}

// ensureSupersedeDirective returns dhclient.conf content updated so exactly
// one *active* `supersede domain-name-servers` statement is present, with
// the given directive's value. LinkGuard owns this option outright — the
// whole point of the feature is that the box always resolves through its
// own unbound — so any other active statement for it is wrong and gets
// replaced in place, not left alongside a second, conflicting one (dhclient
// treats two modifier statements for one option as at best last-wins, at
// worst a parse failure that breaks DHCP on that WAN at lease renewal).
//
// Matching is line-based, not a full dhclient.conf grammar parse: a line is
// "active" if, after stripping leading whitespace, it does not start with
// `#` and its whitespace-separated fields start with "supersede",
// "domain-name-servers". This is deliberately field-based rather than a
// literal substring match, so it isn't fooled by a commented-out leftover
// (which must never count as "already in place") and isn't blind to a
// pre-existing directive that merely differs in spacing or value (which
// must be replaced, not duplicated). Everything else in the file is left
// untouched, in order.
func ensureSupersedeDirective(content, directive string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+1)
	found := false
	for _, line := range lines {
		if isActiveSupersedeDomainNameServers(line) {
			if found {
				continue // drop a redundant duplicate active statement
			}
			found = true
			if strings.TrimSpace(line) == directive {
				out = append(out, line) // already exactly right, leave untouched
			} else {
				out = append(out, directive) // wrong value/spacing: replace in place
			}
			continue
		}
		out = append(out, line)
	}
	if found {
		return strings.Join(out, "\n")
	}

	// No active directive found (file absent, or only commented-out
	// occurrences) — append ours.
	updated := strings.Join(out, "\n")
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n# managed by linkguard — mantém o resolver local mesmo após renovação de lease\n" + directive + "\n"
	return updated
}

// isActiveSupersedeDomainNameServers reports whether line is a live (not
// commented-out) dhclient.conf `supersede domain-name-servers ...`
// statement, regardless of its value or exact spacing.
func isActiveSupersedeDomainNameServers(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	return len(fields) >= 2 && fields[0] == "supersede" && fields[1] == "domain-name-servers"
}

// GenerateConfigs renders the Kea (DHCP) and unbound (DNS) config files.
// ntpServer is threaded straight through to GenerateKeaConfig — see its doc
// comment and netsvc.Provider.GenerateConfigs.
func (s *Service) GenerateConfigs(c netsvc.Config, res []netsvc.Reservation, blocked []string, ntpServer string) ([]netsvc.ConfigFile, error) {
	files, _, err := s.generateConfigs(c, res, blocked, ntpServer)
	return files, err
}

// generateConfigs is GenerateConfigs plus the render warnings (list entries
// dropped as invalid), which the Provider interface's preview signature has
// no use for but ReloadConfigs has to report to the admin.
func (s *Service) generateConfigs(c netsvc.Config, res []netsvc.Reservation, blocked []string, ntpServer string) ([]netsvc.ConfigFile, []string, error) {
	unbound, warnings, err := GenerateUnboundConfig(c, blocked)
	if err != nil {
		return nil, warnings, err
	}
	return []netsvc.ConfigFile{
		{Path: s.keaConf, Content: GenerateKeaConfig(c, res, ntpServer)},
		{Path: s.unboundConf, Content: unbound},
	}, warnings, nil
}

// ReloadConfigs writes the configs and reloads the services via systemd's
// canonical reload-or-restart, which keeps them systemd-tracked: unbound (which
// ships an ExecReload) reloads in place with no downtime; Kea (no ExecReload) is
// cleanly restarted, its memfile leases surviving. The Kea config is validated
// first (kea-dhcp4 -t) — critical, since a restart with a broken config would
// take DHCP down. If validation fails, nothing is written or reloaded and the
// running config is left intact.
//
// The first step is ensurePackages: on a machine that never had
// kea-dhcp4-server/unbound, LinkGuard installs them here rather than failing
// with an unexplained error about a directory that only exists because the
// package does (the defect this step was added for — see ensurePackages).
func (s *Service) ReloadConfigs(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string, ntpServer string) (netsvc.ApplyResult, error) {
	installed, prereqWarnings, err := s.ensurePackages(ctx)
	if err != nil {
		return netsvc.ApplyResult{Warnings: prereqWarnings, Installed: installed}, err
	}

	files, warnings, err := s.generateConfigs(c, res, blocked, ntpServer)
	// Um pré-requisito que degradou para aviso (dns-root-data ausente com o
	// unbound já instalado) vale para o apply inteiro, inclusive quando ele
	// falha mais adiante por outro motivo: os dois avisos são fatos
	// independentes sobre a mesma passada.
	warnings = append(prereqWarnings, warnings...)
	if err != nil {
		// I-7: a singular field this config cannot do without (the LAN IP
		// unbound binds to, the subnet it answers for) did not survive
		// validation. Rendering "the rest" would produce a config that is
		// perfectly valid to unbound-checkconf and silently useless to the
		// office — nothing is written, nothing is reloaded.
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("config do unbound inválida (nada aplicado): %w", err)
	}

	// Validate both candidates before touching anything in production —
	// neither is written, nor is anything reloaded, unless both pass. This
	// used to only validate Kea; the unbound side landed on disk with no
	// pre-apply check at all (finding #3 in the input-validation audit), so
	// a broken unbound.conf could sit there and survive a reboot, taking DNS
	// down at the next boot with no admin action in between.
	var keaContent, unboundContent string
	for _, f := range files {
		switch f.Path {
		case s.keaConf:
			keaContent = f.Content
		case s.unboundConf:
			unboundContent = f.Content
		}
	}
	if err := s.validateKea(ctx, keaContent); err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("config do Kea inválida (nada aplicado): %w", err)
	}
	if err := s.validateUnbound(ctx, unboundContent); err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("config do unbound inválida (nada aplicado): %w", err)
	}

	// Whether unbound needs a real restart or the graceful reload is enough
	// (see unboundNeedsRestart). Compared against what was last ACTIVATED,
	// never against what is on disk: the config file is written before the
	// reload, so an apply that wrote it and then failed further down would
	// otherwise make the NEXT apply believe nothing changed. See
	// unboundActivatedMarker.
	restartUnbound := slices.Contains(installed, unboundPackage) ||
		unboundNeedsRestart(readFileOrEmpty(s.unboundApplied), unboundContent)

	// Sem `if !IsDryRun()` à volta: quem decide agora é o executor. Era
	// justamente essa guarda repetida — e esquecida em dois lugares — que fazia
	// o dry-run vazar.
	for _, f := range files {
		if err := s.exec.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil {
			return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("write %s: %w", f.Path, err)
		}
	}

	var out []string
	for _, svc := range []string{keaService, unboundService} {
		action := "reload-or-restart"
		if svc == unboundService && restartUnbound {
			action = "restart"
		}
		// Clear a leftover failed state first. systemd gives a unit a limited
		// number of restarts in an interval; once spent, every later start
		// answers "Start request repeated too quickly" — which is what the
		// admin then reads on the panel, instead of whatever was actually
		// wrong. Seen on the test VM: unbound came up broken once (missing
		// DNSSEC anchor), and after the cause was fixed the applies kept
		// failing with that message until someone ran reset-failed over SSH.
		// This never hides a real problem: if the service is still broken,
		// the reload right below fails again — with the true error.
		_, _ = s.exec.Execute(ctx, "systemctl", "reset-failed", svc)
		o, err := s.exec.Execute(ctx, "systemctl", action, svc)
		out = append(out, svc+": "+o)
		if err != nil {
			return netsvc.ApplyResult{Output: strings.Join(out, "; "), Warnings: warnings, Installed: installed}, fmt.Errorf("reload %s: %w", svc, err)
		}
	}

	// Só agora — com os dois daemons recarregados sem erro — esta config
	// pode ser chamada de "ativada". É este arquivo, e não o do /etc, que a
	// próxima decisão de restart compara.
	{
		if err := s.exec.WriteFile(s.unboundApplied, []byte(unboundContent), 0o600); err != nil {
			// Não é motivo para falhar o apply (que deu certo); o custo de
			// perder o marcador é um restart a mais no próximo apply, que é
			// o lado seguro da dúvida.
			slog.Warn("não foi possível registrar a config do unbound ativada; o próximo apply pode reiniciar o unbound sem necessidade",
				"path", s.unboundApplied, "err", err)
		}
	}
	return netsvc.ApplyResult{Output: strings.Join(out, "; "), Warnings: warnings, Installed: installed}, nil
}

// unboundNeedsRestart reports whether the change between two rendered
// unbound configs requires a real restart instead of the graceful reload.
//
// Debian's unbound.service has `ExecReload=/bin/kill -HUP $MAINPID`, and
// SIGHUP makes unbound re-read its configuration but NOT re-open its
// listening sockets. Measured on the test VM: after an on-demand install the
// daemon was listening only on 127.0.0.1 (the package's own default), the
// LinkGuard drop-in with `interface: 192.168.3.3` was written, the reload
// ran, systemd reported success, the panel showed "aplicado" — and the LAN
// had no DNS at all. `systemctl restart` fixed it instantly. "Config
// aplicada ≠ funcionando" (FEATURES.md) is exactly this.
//
// Restarting on every save would be the easy answer and the wrong one: it
// drops the resolver (and its cache) for every blocklist entry an admin
// adds. So only a change in what unbound LISTENS on forces the restart;
// everything else — blocklist, forwarders, cache tuning — keeps the
// graceful reload SIGHUP is fine for.
func unboundNeedsRestart(oldConf, newConf string) bool {
	return listenLines(oldConf) != listenLines(newConf)
}

// listenLines reduces an unbound config to its `interface:` directives, in
// order, as a single comparable string.
func listenLines(conf string) string {
	var got []string
	for _, line := range strings.Split(conf, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "interface:") {
			got = append(got, strings.Join(strings.Fields(line), " "))
		}
	}
	return strings.Join(got, "\n")
}

// readFileOrEmpty returns a file's contents, or "" when it cannot be read —
// which for this caller is the same answer ("nothing is configured yet, so
// this is a change").
func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// validateKea writes the candidate config to a temp file and runs the Kea
// config-test mode against it. Read-only, so it runs even in dry-run.
//
// The temp file is created next to the real Kea config (in the same
// directory as s.keaConf, normally /etc/kea) instead of the system /tmp:
// Debian's kea-dhcp4 package ships an AppArmor profile
// (/etc/apparmor.d/usr.sbin.kea-dhcp4) that only grants kea-dhcp4 read
// access under /etc/kea/ — a file in /tmp is invisible to it regardless of
// Unix permissions, and `kea-dhcp4 -t` fails with "Unable to open file".
// /etc/kea is already writable by this process (see ReadWritePaths in
// deploy/linkguard-fw.service), so no new capability is needed.
func (s *Service) validateKea(ctx context.Context, content string) error {
	f, err := os.CreateTemp(filepath.Dir(s.keaConf), "kea-validate-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_, err = s.exec.ExecuteRead(ctx, s.keaBin, "-t", f.Name())
	return err
}

// validateUnbound writes the candidate unbound config to a temp file and
// runs unbound-checkconf against it — the unbound-side sibling of
// validateKea, added because ReloadConfigs used to write unbound.conf with
// no pre-apply check at all (finding #3, input-validation-audit.md): a
// broken config landed on disk and survived a reboot, taking DNS down at
// the next boot with no admin action in between (confirmed as a real
// production incident, not a hypothetical, in the session that produced the
// audit).
//
// The temp file is created next to the real unbound config for the same
// reason validateKea's is created next to the real Kea config — see that
// function's doc comment. unbound-checkconf has no AppArmor profile
// confining it on Debian the way kea-dhcp4 does, so this placement isn't
// strictly required for unbound-checkconf itself, but keeping both
// validators structurally identical is worth more than the marginal
// freedom to use the system temp dir here, and it costs nothing.
//
// unbound-checkconf is optional at runtime: Debian's unbound package is a
// Recommends:, not a Depends:, of this project (see EnsureResolvConf's doc
// comment for why that guard exists elsewhere too) — a box can legitimately
// run without unbound installed, or with unbound installed but its checker
// missing (a minimal/manually-trimmed install). Treating a missing checker
// as a hard failure would block every DHCP/DNS apply on such a box, which
// is strictly worse than the gap this validation closes — so a missing
// binary is logged and treated as "validation not possible here, proceed",
// never as a validation failure.
func (s *Service) validateUnbound(ctx context.Context, content string) error {
	// I-6: "the checker isn't installed" is decided HERE, by looking for the
	// binary, before it is ever run — not afterwards by pattern-matching the
	// error text. firewall.RealExecutor folds the command's stderr into the
	// error string, and plenty of genuine unbound-checkconf rejections name
	// a file that is missing ("… /var/lib/unbound/root.key: no such file or
	// directory"), which the old substring match read as "tool absent,
	// proceed". That turned a validation whose entire purpose is to fail
	// closed into one that failed open on exactly the configs it exists to
	// stop. After this point every error from the checker is a real
	// rejection and aborts the apply.
	if err := binaryInstalled(s.unboundCheckBin); err != nil {
		slog.Warn("unbound-checkconf não encontrado; pulando validação pré-apply do unbound.conf (o pacote unbound é Recommends:, não Depends:, deste projeto)", "bin", s.unboundCheckBin, "err", err)
		return nil
	}

	// I-5: the suffix must NOT be ".conf". This temp file is created inside
	// /etc/unbound/unbound.conf.d (see above), and Debian's unbound.conf
	// pulls in that whole directory with `include-toplevel:
	// "/etc/unbound/unbound.conf.d/*.conf"`. Kill this process between the
	// CreateTemp and the deferred Remove — a crash, an OOM kill, a package
	// upgrade restarting the service — and a leftover fragment with a
	// duplicate `interface:`/`local-zone` stays behind for unbound to load
	// at the next start: DNS dead at the next boot, with nobody having
	// touched anything. ".tmp" keeps the file on the same filesystem (the
	// reason it is here at all) while staying outside the glob.
	f, err := os.CreateTemp(filepath.Dir(s.unboundConf), "unbound-validate-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()

	_, err = s.exec.ExecuteRead(ctx, s.unboundCheckBin, f.Name())
	return err
}

// binaryInstalled reports (as an error) whether bin can actually be run.
// exec.LookPath answers exactly that question for both spellings — a path
// (checked for existence and the execute bit) and a bare command name
// (searched in $PATH) — which is the same resolution os/exec itself would
// perform a moment later. This is the only honest way to tell "the tool
// isn't installed here" from "the tool ran and rejected the config": the
// executor reports both as a plain error string, and only the first may be
// treated as "validation not possible, proceed".
func binaryInstalled(bin string) error {
	_, err := exec.LookPath(bin)
	return err
}

// ─── Kea (DHCP) ──────────────────────────────────────────────────────────────

type keaConfig struct {
	Dhcp4 keaDhcp4 `json:"Dhcp4"`
}
type keaDhcp4 struct {
	InterfacesConfig keaIfaces   `json:"interfaces-config"`
	LeaseDatabase    keaLeaseDB  `json:"lease-database"`
	ValidLifetime    int         `json:"valid-lifetime"`
	Subnet4          []keaSubnet `json:"subnet4"`
}
type keaIfaces struct {
	Interfaces []string `json:"interfaces"`
}
type keaLeaseDB struct {
	Type    string `json:"type"`
	Persist bool   `json:"persist"`
	Name    string `json:"name"`
}
type keaSubnet struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Pools        []keaPool        `json:"pools"`
	OptionData   []keaOption      `json:"option-data"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}
type keaPool struct {
	Pool string `json:"pool"`
}
type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}
type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

// GenerateKeaConfig renders kea-dhcp4.conf (pure function, JSON). ntpServer,
// when non-empty, adds a DHCP option 42 (ntp-servers) pointing clients at
// it — normally the firewall's own LAN IP (netsvc.Config.Gateway), the same
// address already used for the routers option, passed in by the caller
// rather than read from the DB here (see docs/superpowers/specs/
// 2026-08-11-ntp-server-for-lan-design.md §5: the NTP toggle lives in
// internal/timesync, a package this one must not import, to avoid either
// package reaching into the other's config). An empty string omits the
// option entirely, matching today's behaviour exactly.
func GenerateKeaConfig(c netsvc.Config, reservations []netsvc.Reservation, ntpServer string) string {
	lease := c.LeaseHours
	if lease <= 0 {
		lease = 12
	}
	opts := []keaOption{}
	if c.Gateway != "" {
		opts = append(opts, keaOption{Name: "routers", Data: c.Gateway})
	}
	if len(c.DNSToClients) > 0 {
		opts = append(opts, keaOption{Name: "domain-name-servers", Data: strings.Join(c.DNSToClients, ", ")})
	}
	if c.DomainSuffix != "" {
		opts = append(opts, keaOption{Name: "domain-name", Data: c.DomainSuffix})
	}
	if ntpServer != "" {
		opts = append(opts, keaOption{Name: "ntp-servers", Data: ntpServer})
	}

	rs := append([]netsvc.Reservation(nil), reservations...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].IP < rs[j].IP })
	kres := make([]keaReservation, 0, len(rs))
	for _, r := range rs {
		kres = append(kres, keaReservation{
			HWAddress: strings.ToLower(r.MAC),
			IPAddress: r.IP,
			Hostname:  r.Hostname,
		})
	}

	cfg := keaConfig{Dhcp4: keaDhcp4{
		InterfacesConfig: keaIfaces{Interfaces: []string{c.Interface}},
		LeaseDatabase:    keaLeaseDB{Type: "memfile", Persist: true, Name: KeaLeasesPath},
		ValidLifetime:    lease * 3600,
		Subnet4: []keaSubnet{{
			ID:           1,
			Subnet:       c.SubnetCIDR,
			Pools:        []keaPool{{Pool: c.RangeStart + " - " + c.RangeEnd}},
			OptionData:   opts,
			Reservations: kres,
		}},
	}}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return "// Managed by LinkGuard FW — do not edit by hand.\n" + string(out) + "\n"
}

// ParseKeaLeases parses Kea's memfile CSV. Columns:
//
//	address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,...
//
// Kea appends rows; the last row per address is authoritative. Only state 0
// (assigned) leases are returned.
func ParseKeaLeases(content string) []netsvc.Lease {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return []netsvc.Lease{}
	}
	type rec struct {
		l     netsvc.Lease
		state string
	}
	latest := map[string]rec{} // address -> last row
	order := []string{}
	for i, row := range rows {
		if i == 0 || len(row) < 10 {
			continue // header or malformed
		}
		addr := row[0]
		exp, _ := strconv.ParseInt(row[4], 10, 64)
		if _, seen := latest[addr]; !seen {
			order = append(order, addr)
		}
		latest[addr] = rec{
			l:     netsvc.Lease{IP: addr, MAC: strings.ToLower(row[1]), Expiry: exp, Hostname: row[8]},
			state: row[9],
		}
	}
	out := []netsvc.Lease{}
	for _, addr := range order {
		if latest[addr].state == "0" { // 0 = assigned/active
			out = append(out, latest[addr].l)
		}
	}
	return out
}

// reUnboundDomain mirrors internal/validate's own reDNSDomain (same charset,
// same rationale): single-label names ("lan", "localhost") and underscore
// labels ("_dmarc.example.com") are legitimate, but anything outside
// [a-z0-9._-] — quotes, spaces, ';', and critically a newline — must be
// rejected, because the value is concatenated straight into a
// local-zone/access-control/interface directive in unbound.conf.
//
// Duplicated here on purpose: este é o ponto de renderização, e a checagem tem
// de valer independentemente do que qualquer chamador já tenha validado antes
// (ver GenerateUnboundConfig). Até 2026-08-17 a outra cópia morava em
// internal/api/handlers e a duplicação era ainda obrigatória por ciclo de
// importação; hoje internal/validate é folha e poderia ser importado — a cópia
// fica por defesa em profundidade, não por impedimento.
var reUnboundDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)

func validRenderDomain(d string) bool {
	return d != "" && len(d) <= 253 && reUnboundDomain.MatchString(d)
}

// ─── unbound (DNS) ───────────────────────────────────────────────────────────

// GenerateUnboundConfig renders the unbound config fragment (pure function,
// aside from the slog.Warn calls below, which — like
// nftables.sanitizeNetworks and timesync.GenerateChronyConf — are the only
// side effect and never influence the return value).
//
// Every value this function interpolates by string concatenation is
// re-validated here, not just trusted from the caller: internal/api/handlers
// validates at the point an admin saves a value (validate.Domain,
// validate.Iface, net.ParseIP/ParseCIDR — see internal/validate), but this
// function is the last
// place before a root daemon (unbound) reads the result, and it has callers
// that skip the handler entirely — most concretely, a restored backup
// (internal/backup), whose settings/blocklist entries went
// straight to the DB with no validator in front of them before this fix,
// and any row written under an older, laxer rule (validate.Domain's own doc
// comment already flagged this history for the blocklist).
//
// What happens to a value that fails depends on what that value IS (I-7):
//
//   - A singular field the service cannot do without — Gateway (the LAN
//     address unbound binds to) and SubnetCIDR (the network it answers
//     for) — fails the whole render, returning an error. Skipping either
//     one produces a config unbound-checkconf happily accepts and that
//     answers nobody on the LAN: DNS dead for the whole office, apply
//     reporting success, panel still displaying the value that was
//     dropped. An empty value is not a failure — it is the admin choosing
//     not to set it — only a non-empty value that does not parse is.
//   - A list entry (blocklist domain, upstream) is skipped and counted, the
//     same "one bad entry must not sink the good ones" contract
//     nftables.sanitizeNetworks and timesync.GenerateChronyConf apply to
//     their own lists. The counts come back as warnings so the apply status
//     can say the list shrank instead of leaving that fact in the journal.
func GenerateUnboundConfig(c netsvc.Config, blocked []string) (string, []string, error) {
	var warnings []string
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteString("\n") }

	w("# Managed by LinkGuard FW — do not edit by hand.")
	w("server:")
	if c.Gateway != "" {
		if net.ParseIP(c.Gateway) == nil {
			return "", warnings, fmt.Errorf("gateway inválido (%q): sem ele o unbound só escutaria em 127.0.0.1 e a LAN ficaria sem DNS", c.Gateway)
		}
		w("  interface: " + c.Gateway) // bind on the firewall LAN IP
	}
	w("  interface: 127.0.0.1")
	w("  access-control: 127.0.0.0/8 allow")
	if c.SubnetCIDR != "" {
		if _, _, err := net.ParseCIDR(c.SubnetCIDR); err != nil {
			return "", warnings, fmt.Errorf("sub-rede inválida (%q): sem o access-control correspondente o unbound recusaria as consultas da LAN: %w", c.SubnetCIDR, err)
		}
		w("  access-control: " + c.SubnetCIDR + " allow")
	}
	w("  hide-identity: yes")
	w("  hide-version: yes")
	w("  prefetch: yes")
	w("  num-threads: 2")
	w("  msg-cache-size: 64m")
	w("  rrset-cache-size: 128m")
	if c.LogQueries {
		w("  log-queries: yes")
	}
	if c.DomainSuffix != "" {
		// Not a singular must-have: without it the LAN still resolves, it
		// just loses the local suffix — so this stays skip-and-warn, but
		// the admin is told instead of only the journal.
		if validRenderDomain(c.DomainSuffix) {
			w("  local-zone: \"" + c.DomainSuffix + ".\" transparent")
		} else {
			slog.Warn("domain_suffix inválido descartado na renderização do unbound.conf", "domain_suffix", c.DomainSuffix)
			warnings = append(warnings, fmt.Sprintf("domínio local %q é inválido e não foi aplicado ao DNS", c.DomainSuffix))
		}
	}

	if len(blocked) > 0 {
		var validBlocked []string
		skippedBlocked := 0
		for _, d := range blocked {
			if !validRenderDomain(d) {
				slog.Warn("domínio inválido descartado na renderização do unbound.conf (blocklist)", "domain", d)
				skippedBlocked++
				continue
			}
			validBlocked = append(validBlocked, d)
		}
		if skippedBlocked > 0 {
			warnings = append(warnings, fmt.Sprintf("%d domínio(s) da lista de bloqueio são inválidos e não foram aplicados ao DNS", skippedBlocked))
		}
		if len(validBlocked) > 0 {
			w("  # DNS filtering (blocklist) — NXDOMAIN")
			sort.Strings(validBlocked)
			for _, d := range validBlocked {
				w("  local-zone: \"" + d + ".\" always_nxdomain")
			}
		}
	}

	if len(c.Upstreams) > 0 {
		var validUpstreams []string
		skippedUpstreams := 0
		for _, up := range c.Upstreams {
			if net.ParseIP(up) == nil {
				slog.Warn("upstream DNS inválido descartado na renderização do unbound.conf", "upstream", up)
				skippedUpstreams++
				continue
			}
			validUpstreams = append(validUpstreams, up)
		}
		if skippedUpstreams > 0 {
			warnings = append(warnings, fmt.Sprintf("%d servidor(es) DNS de encaminhamento são inválidos e não foram aplicados", skippedUpstreams))
		}
		if len(validUpstreams) > 0 {
			w("forward-zone:")
			w("  name: \".\"")
			for _, up := range validUpstreams {
				w("  forward-addr: " + up)
			}
		}
	}
	return b.String(), warnings, nil
}

// ─── Provider apply / leases ─────────────────────────────────────────────────

// Apply writes both config files and restarts kea-dhcp4 + unbound. Part of
// netsvc.Provider's original, pre-NTP surface — not on the auto-apply path
// (ReloadConfigs is), so it has no NTP-toggle context of its own; it always
// renders without the ntp-servers option.
//
// Verified 2026-08-11 (NTP review Fix, "Minor" list): as of this writing
// nothing in the codebase actually calls this method — NetsvcHandler.Apply
// (the "Aplicar agora" button) goes through doReload -> ReloadConfigs,
// which does thread ntpServerOption() through. Left inert rather than
// wired up: doing so would mean either duplicating ntpServerOption's
// db-read-and-decide logic into this package (which owns neither ntpCfgKey
// nor internal/timesync.Config) or growing this method's signature to take
// an ntpServer string that its one remaining purpose — satisfying the
// netsvc.Provider interface — has no caller to supply. If a future caller
// does appear, that caller (like NetsvcHandler already does for
// ReloadConfigs) is the right place to decide the ntpServer value and pass
// it through the existing GenerateConfigs(..., ntpServer) parameter, not
// this method inventing its own.
func (s *Service) Apply(ctx context.Context, c netsvc.Config, res []netsvc.Reservation, blocked []string) (string, error) {
	files, err := s.GenerateConfigs(c, res, blocked, "")
	if err != nil {
		return "", err
	}
	for _, f := range files {
		if err := s.exec.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", f.Path, err)
		}
	}
	return s.exec.Execute(ctx, "systemctl", "restart", "kea-dhcp4-server", "unbound")
}

// Leases reads and parses the active Kea leases.
func (s *Service) Leases(ctx context.Context) ([]netsvc.Lease, error) {
	out, err := s.exec.ExecuteRead(ctx, "cat", KeaLeasesPath)
	if err != nil {
		return nil, err
	}
	return ParseKeaLeases(out), nil
}

// compile-time check that Service satisfies the Provider interface.
var _ netsvc.Provider = (*Service)(nil)
