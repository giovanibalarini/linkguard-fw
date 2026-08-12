// Package bootstrapdeps makes LinkGuard the owner of its own base
// prerequisites: on a bare machine, the appliance installs the packages it
// cannot work without instead of assuming somebody prepared the ground.
//
// This is the literal reading of the product premise ("instalar o LinkGuard é
// entregar a ele a máquina", FEATURES.md): the LinkGuard package goes in
// first, on a machine with nothing on it, and it coordinates the rest.
//
// Why the service does this instead of the .deb declaring Depends::
//
//   - a Debian package cannot install other packages from its own maintainer
//     scripts — dpkg holds /var/lib/dpkg/lock-frontend for the whole run, so
//     an apt-get call inside postinst dies with "Could not get lock";
//   - with the base in Depends:, `dpkg -i` on a bare box leaves the package
//     in `iU` (unpacked, not configured): the unit is never enabled and the
//     panel never comes up, so there is nothing left to explain the failure
//     to the operator;
//   - with the base in Recommends: (see the deb target in the Makefile),
//     `dpkg -i` installs AND configures, the service starts, and this
//     package finishes the job from inside a running process — where the
//     dpkg lock is long gone and where a failure has somewhere to be
//     reported.
//
// Scope is deliberately narrow: only the base, only at startup. The optional
// packages (kea-dhcp4-server, unbound, chrony, smartmontools) stay on-demand,
// installed when the admin turns the corresponding feature on — installing
// them at boot would take over services the admin never asked for.
package bootstrapdeps

import (
	"context"
	"log/slog"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// BasePackages is what LinkGuard cannot do its job without: the packet
// filter, the routing/addressing tools and the probe used to tell a WAN link
// apart from a dead one. Everything else the product manages is optional and
// installed on demand.
var BasePackages = []string{"nftables", "iproute2", "iptables", "iputils-ping"}

// consequences answers the only question that matters when one of these is
// missing: what stops working? An alert that merely lists package names
// leaves the operator to guess how bad it is — and this alert is raised
// precisely in the situation where the appliance is installed but is NOT
// filtering anything, which is the most dangerous state it can be in.
// TestEveryBasePackageHasAConsequence guards this map against drifting from
// BasePackages.
var consequences = map[string]string{
	"nftables":     "sem ele não existe filtro de pacote nenhum: o firewall não bloqueia, o NAT não é aplicado e nenhuma regra do painel tem efeito",
	"iproute2":     "sem ele o LinkGuard não lê nem escreve rotas: failover, balanceamento entre WANs e direcionamento por host param",
	"iptables":     "sem ele as regras legadas (compatibilidade e port forward antigo) não podem ser lidas nem aplicadas",
	"iputils-ping": "sem ele não há sonda de latência/perda: todo link WAN fica sem diagnóstico e o failover deixa de detectar queda",
}

// Alerter is the panel-facing side of Ensure. Kept as a local interface (same
// approach as alerts.Notifier) so this package does not import
// internal/alerts and drag its storage dependency into the boot path.
type Alerter interface {
	// BaseDepsMissing raises the critical, unresolved alert that says the box
	// is running without its base packages.
	BaseDepsMissing(detail string) error
	// BaseDepsOK clears it after LinkGuard installed what was missing.
	BaseDepsOK(detail string) error
}

// Ensure guarantees the base packages at startup, and is honest when it
// cannot: it never pretends, and it never takes the process down.
//
// The sequence is detect -> install -> re-detect. The re-detection is what
// the verdict is based on, not apt's exit code: a partially successful run
// (one package resolved, another not) must alert about what is STILL missing,
// not about what was missing before the attempt.
//
// On an already-provisioned box this costs one dpkg-query per package and
// nothing else — no apt call, no alert, no log noise.
func Ensure(ctx context.Context, exec firewall.Executor, alerter Alerter) {
	missing := Missing(ctx, exec, BasePackages...)
	if len(missing) == 0 {
		slog.Debug("dependências base presentes", "pacotes", BasePackages)
		return
	}

	if exec.IsDryRun() {
		slog.Info("dry-run: dependências base ausentes não serão instaladas", "pacotes", missing)
		return
	}

	slog.Warn("dependências base ausentes; o LinkGuard vai instalá-las", "pacotes", missing)
	err := InstallPackages(ctx, exec, missing...)
	if err != nil {
		// The most common first-boot failure is a machine whose apt index was
		// never fetched (or is stale enough that the versions on the mirror no
		// longer exist), which surfaces as "Unable to locate package". Refresh
		// and retry exactly once — a loop here would delay the panel forever
		// on a box that genuinely has no network.
		slog.Warn("falha ao instalar dependências base; atualizando o índice do apt e tentando outra vez", "err", err)
		if uerr := updateIndex(ctx, exec); uerr != nil {
			slog.Warn("apt-get update também falhou", "err", uerr)
		}
		err = InstallPackages(ctx, exec, missing...)
	}

	still := Missing(ctx, exec, missing...)
	if len(still) == 0 {
		detail := strings.Join(missing, ", ")
		slog.Info("dependências base instaladas pelo LinkGuard", "pacotes", missing)
		if alerter != nil {
			_ = alerter.BaseDepsOK(detail)
		}
		return
	}

	detail := describeMissing(still)
	slog.Error("o LinkGuard não conseguiu instalar dependências base; o appliance está incompleto",
		"faltando", still, "detalhe", detail, "err", err)
	if alerter != nil {
		_ = alerter.BaseDepsMissing(detail)
	}
}

// Missing returns, in the given order, the packages dpkg does not report as
// installed. Package state (not "is the binary on PATH") is the check on
// purpose: it is the same unit apt operates on, so what Missing reports is
// exactly what InstallPackages can act on.
func Missing(ctx context.Context, exec firewall.Executor, pkgs ...string) []string {
	var missing []string
	for _, pkg := range pkgs {
		if !installed(ctx, exec, pkg) {
			missing = append(missing, pkg)
		}
	}
	return missing
}

// installed reports whether dpkg has the package in the "install ok
// installed" state. Anything else — never installed (dpkg-query exits
// non-zero), unpacked but not configured, or purged leaving only config
// files — counts as not installed, because in every one of those states the
// program the package provides is unusable.
func installed(ctx context.Context, exec firewall.Executor, pkg string) bool {
	out, err := exec.ExecuteRead(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	if err != nil {
		return false
	}
	return strings.Contains(out, "ok installed")
}

// aptFlags are the apt-get options every install here runs with. Nobody is
// sitting at a terminal when these run, so an interactive prompt is not a
// question — it is a hang, or (with stdin at EOF, which is what --pipe gives)
// an aborted transaction that leaves the package half-configured.
//
// The conffile options are not defensive boilerplate: they were added after
// installing nftables on a bare box aborted with "end of file on stdin at
// conffile prompt". LinkGuard's own postinst creates /etc/nftables.conf so
// the service can start at all (see the unit's ReadWritePaths and that
// postinst's comment), so when the nftables package arrives later, dpkg finds
// a file it does not own and asks whom to believe. --force-confold answers
// it, and answers it the right way round: /etc/nftables.conf belongs to
// LinkGuard (README), and dpkg still leaves the maintainer's version next to
// it as .dpkg-dist. --force-confdef lets dpkg take the default silently
// wherever there is no local change to preserve.
var aptFlags = []string{
	"-y",
	"--no-install-recommends",
	"-o", "Dpkg::Options::=--force-confold",
	"-o", "Dpkg::Options::=--force-confdef",
}

// InstallPackages asks systemd to run apt-get in its own transient,
// unhardened unit — never inside this process's own sandbox, which would need
// ReadWritePaths widened across most of the package-management filesystem
// (/var/lib/dpkg, /var/cache/apt, /usr, ...) to work.
//
// This is the single apt-install call site in the codebase: timesync's
// InstallChrony delegates here, so the "how do we install a package" decision
// (transient unit, non-interactive flags) lives in exactly one place.
func InstallPackages(ctx context.Context, exec firewall.Executor, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	args := []string{"--pipe", "--wait", "--setenv=DEBIAN_FRONTEND=noninteractive",
		"--", "apt-get", "install"}
	args = append(args, aptFlags...)
	args = append(args, pkgs...)
	_, err := exec.Execute(ctx, "systemd-run", args...)
	return err
}

// updateIndex refreshes the apt package lists, same transient-unit reasoning
// as InstallPackages.
func updateIndex(ctx context.Context, exec firewall.Executor) error {
	_, err := exec.Execute(ctx, "systemd-run", "--pipe", "--wait",
		"--setenv=DEBIAN_FRONTEND=noninteractive", "--", "apt-get", "update")
	return err
}

// describeMissing renders the alert body: each package with what its absence
// breaks, plus the exact command an admin can run by hand once the box has
// network again.
func describeMissing(pkgs []string) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if c := consequences[p]; c != "" {
			parts = append(parts, p+" — "+c)
		} else {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "; ") +
		". Verifique a conexão com a internet e o repositório APT, ou instale à mão: apt-get install -y " +
		strings.Join(pkgs, " ")
}
