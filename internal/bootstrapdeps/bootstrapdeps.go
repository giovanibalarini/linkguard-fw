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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

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
//
// The on-demand entries below (kea-dhcp4-server, unbound, chrony) are not in
// BasePackages and are never installed at boot — they are brought in by
// EnsureInstalled when the admin turns the corresponding feature on. Their
// consequence text lives in the same map because the question the admin asks
// is identical ("what stops working?") and the sentence is rendered by the
// same describeMissing. TestEveryOnDemandPackageHasAConsequence guards them.
var consequences = map[string]string{
	"nftables":     "sem ele não existe filtro de pacote nenhum: o firewall não bloqueia, o NAT não é aplicado e nenhuma regra do painel tem efeito",
	"iproute2":     "sem ele o LinkGuard não lê nem escreve rotas: failover, balanceamento entre WANs e direcionamento por host param",
	"iptables":     "sem ele as regras legadas (compatibilidade e port forward antigo) não podem ser lidas nem aplicadas",
	"iputils-ping": "sem ele não há sonda de latência/perda: todo link WAN fica sem diagnóstico e o failover deixa de detectar queda",

	"kea-dhcp4-server": "sem ele não existe servidor DHCP: os hosts da LAN não recebem IP, gateway nem DNS automaticamente, e as reservas por MAC não valem",
	"unbound":          "sem ele não existe resolvedor DNS local: a LAN fica sem o DNS do próprio firewall, e o bloqueio de domínios e o log de consultas deixam de valer",
	"dns-root-data":    "sem ele o unbound nem sobe: falta a âncora DNSSEC da raiz (/var/lib/unbound/root.key) e o resolvedor aborta na inicialização, deixando a LAN sem DNS",
	"chrony":           "sem ele o relógio da máquina não sincroniza por NTP: logs, certificados e o próprio agendamento ficam sujeitos a desvio de horário",
	"wireguard-tools":  "sem ele a VPN WireGuard não pode criar a interface nem aplicar os peers configurados no painel",
	"qrencode":         "sem ele o painel não consegue gerar o QR code one-time para importar a configuração WireGuard no celular",
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
	// BaseDepsPresent silently clears it when the base turns out to be in
	// place and LinkGuard did not install anything — the admin fixed it by
	// hand. No recovery is announced: nobody has anything to announce.
	BaseDepsPresent()
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
//
// It returns whether there is nothing left to do: the base is in place, or
// (dry-run) nothing may be done about it. A false answer is the caller's cue
// to try again later — see RetryDelay. The single most common reason for a
// false right after boot is not a broken mirror but apt-daily/
// unattended-upgrades holding the dpkg lock, and the whole fix for that is
// to ask again in a few minutes.
func Ensure(ctx context.Context, exec firewall.Executor, alerter Alerter) bool {
	missing := Missing(ctx, exec, BasePackages...)
	if len(missing) == 0 {
		EnsureNftablesUnitEnabled(ctx, exec)
		slog.Debug("dependências base presentes", "pacotes", BasePackages)
		// Fecha um alerta que ficou aberto de uma tentativa anterior (ou de
		// um boot anterior) e que já não descreve a máquina. Sem isto, quem
		// instalasse à mão pelo SSH ficava com o alerta crítico para
		// sempre: o alerta só era mexido quando o PRÓPRIO LinkGuard
		// instalava algo. Não gera alerta de recuperação — não houve
		// recuperação nossa a anunciar.
		if alerter != nil {
			alerter.BaseDepsPresent()
		}
		return true
	}

	if exec.IsDryRun() {
		slog.Info("dry-run: dependências base ausentes não serão instaladas", "pacotes", missing)
		return true
	}

	slog.Warn("dependências base ausentes; o LinkGuard vai instalá-las", "pacotes", missing)
	// One apt at a time in this process — see aptMu.
	aptMu.Lock()
	defer aptMu.Unlock()
	err := installPackages(ctx, exec, missing...)
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
		err = installPackages(ctx, exec, missing...)
	}

	still := Missing(ctx, exec, missing...)
	EnsureNftablesUnitEnabled(ctx, exec)
	if len(still) == 0 {
		detail := strings.Join(missing, ", ")
		slog.Info("dependências base instaladas pelo LinkGuard", "pacotes", missing)
		if alerter != nil {
			_ = alerter.BaseDepsOK(detail)
		}
		return true
	}

	detail := describeMissing(still) + retryNotice
	slog.Error("o LinkGuard não conseguiu instalar dependências base; o appliance está incompleto",
		"faltando", still, "detalhe", detail, "err", err)
	if alerter != nil {
		_ = alerter.BaseDepsMissing(detail)
	}
	return false
}

// nftablesUnit é a unidade que carrega /etc/nftables.conf no boot — e também
// o nome do pacote que a fornece, que é por que o mesmo identificador serve
// para o dpkg-query e para o systemctl. O pacote do Debian entrega a unidade
// DESABILITADA de propósito (o README.Debian dele diz "you can optionally
// enable"): ela não faz nada até alguém habilitá-la.
const nftablesUnit = "nftables"

// EnsureNftablesUnitEnabled garante que a unidade do nftables está habilitada
// — habilitada, nunca iniciada.
//
// Por que isto virou responsabilidade do LinkGuard: enquanto a base estava em
// `Depends:`, o apt trazia o nftables e quem preparava a máquina habilitava a
// unidade. Na premissa nova o LinkGuard instala o nftables sozinho, e nesse
// caminho ninguém habilita nada. O resultado é uma máquina em que:
//
//   - Persist() reescreve /etc/nftables.conf a cada reconciliação e nada
//     nunca lê o arquivo — persistência que só existe no papel. Este é o
//     motivo PRINCIPAL, e é o que sozinho justifica a função;
//   - em todo reboot a tabela não existe, EnsureTable devolve true e o boot
//     cai no Restore(snapshot) — ou seja, o firewall da máquina passa a
//     depender do último snapshot gravado no banco em vez do arquivo de boot,
//     e o que não estiver nesse snapshot não volta;
//   - se esse Restore falhar, os named sets voltam vazios enquanto as linhas
//     de drop continuam na forward: o painel afirma "host bloqueado" com o
//     tráfego passando.
//
// Correção de 2026-08-13: o segundo item dizia que o Restore "começa com
// `flush ruleset`" e concluía que a regra de ouro do produto ("o LinkGuard só
// mexe na tabela dele", README) era violada uma vez por reboot, apagando toda
// tabela de terceiro criada depois do último snapshot. Isso deixou de ser
// verdade — nftables.Service.Restore é escopado à tabela `inet linkguard` desde
// o commit `4450769` e não toca em tabela de terceiro nenhuma. A função continua
// necessária pelos outros dois motivos, que não dependem daquele.
//
// Por que aqui, e não no postinst: o postinst roda no instante da instalação,
// quando o nftables normalmente ainda NÃO está instalado (é o próprio
// LinkGuard que o instala, minutos depois, já em execução) — ele cobriria
// justamente o caso que não precisa de cobertura. Aqui a verificação é feita
// em todo boot, cobre os três instaladores de uma vez e alcança também a
// máquina em que o pacote já estava instalado e a unidade continuava
// desabilitada.
//
// Habilitar sim, iniciar NÃO, e isso é decisão:
//
//  1. `systemctl start` roda `nft -f /etc/nftables.conf`, e nesse instante o
//     arquivo é no máximo o snapshot do boot anterior — carregá-lo por cima
//     do ruleset que o LinkGuard acabou de montar em memória não acrescenta
//     nada e pode reintroduzir estado velho;
//  2. o unit do Debian declara `ExecStop=/usr/sbin/nft flush ruleset`. Com a
//     unidade ATIVA, todo stop/restart posterior — e um `apt upgrade` do
//     próprio pacote nftables faz exatamente isso — apagaria o ruleset
//     inteiro da máquina, tabelas de terceiros incluídas, sem um reboot para
//     se recuperar. Ou seja: iniciar agora criaria, em pleno funcionamento, a
//     mesma violação da regra de ouro que este conserto existe para eliminar.
//
// A unidade só precisa estar habilitada: quem a executa é o próximo boot,
// onde ela é a única coisa carregando regras e o arquivo é a autoridade.
func EnsureNftablesUnitEnabled(ctx context.Context, exec firewall.Executor) {
	// Habilitar unidade é mexer na máquina; um dry-run não mexe.
	if exec.IsDryRun() {
		return
	}
	// Sem o pacote não existe unidade para habilitar. Tentar só produziria um
	// erro no log, no mesmo boot em que o admin já está vendo o alerta de
	// base ausente.
	if !installed(ctx, exec, nftablesUnit) {
		return
	}
	out, err := exec.ExecuteRead(ctx, "systemctl", "is-enabled", nftablesUnit)
	state := strings.TrimSpace(out)
	switch {
	case state == "enabled" || state == "enabled-runtime":
		// O caso comum de toda máquina já provisionada: nada a fazer, e nada
		// no log.
		return
	case state == "masked" || state == "masked-runtime":
		// Mascarar é decisão explícita de quem administra a máquina, e
		// `systemctl enable` numa unidade mascarada falha de qualquer jeito.
		// Não se insiste — mas também não se finge que está tudo bem.
		slog.Warn("a unidade nftables está mascarada: /etc/nftables.conf não será carregado no boot, "+
			"e a cada reinicialização o LinkGuard vai reconstruir o ruleset com um flush",
			"unidade", nftablesUnit)
		return
	case state == "":
		// Sem saída nenhuma o systemd está dizendo que não conhece a unidade
		// (pacote sem o unit file, máquina sem systemd, contêiner). Nada a
		// habilitar.
		slog.Debug("estado da unidade nftables indisponível", "err", err)
		return
	}

	slog.Info("a unidade nftables está desabilitada; o LinkGuard vai habilitá-la para que "+
		"/etc/nftables.conf seja carregado no boot (sem iniciá-la agora: isso recarregaria o "+
		"arquivo por cima do ruleset vivo)", "estado", state)
	if _, err := exec.Execute(ctx, "systemctl", "enable", nftablesUnit); err != nil {
		slog.Error("não foi possível habilitar a unidade nftables; a cada reboot o LinkGuard vai "+
			"reconstruir o ruleset com um flush, apagando tabelas de outros programas",
			"err", err)
		return
	}
	slog.Info("unidade nftables habilitada", "unidade", nftablesUnit)
}

// retryNotice is the sentence that turns this alert from a dead end into
// something with a way out. Two facts an operator cannot guess: LinkGuard
// keeps trying on its own (so "no WAN yet at boot" heals itself), and a
// manual install is noticed on the next attempt — this alert used to be
// re-evaluated ONLY at boot, so whoever fixed it by hand over SSH without
// restarting the service kept a red critical alert forever, with nothing on
// screen suggesting a restart or anything else.
const retryNotice = " O LinkGuard tenta de novo sozinho a cada poucos minutos: " +
	"se você instalar à mão, o alerta se fecha na tentativa seguinte, sem precisar reiniciar o serviço."

// retryDelays is the schedule for re-attempting the base install after a
// failure. It starts short because the likeliest cause is transient and
// self-clearing (apt-daily or unattended-upgrades holding the dpkg lock,
// routine in the first minutes after a boot) and settles at a quarter of an
// hour because the other likely cause is not (no WAN yet, dead mirror) and
// hammering apt buys nothing.
var retryDelays = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
	15 * time.Minute,
}

// RetryDelay is how long to wait before attempt+1, given that attempt failed.
func RetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= len(retryDelays) {
		return retryDelays[len(retryDelays)-1]
	}
	return retryDelays[attempt]
}

// EnsureInstalled is the on-demand sibling of Ensure: it guarantees the
// packages a feature needs at the moment the admin turns that feature on,
// synchronously, on the caller's goroutine — and, unlike Ensure (a boot-time
// best-effort that must never take the process down), it RETURNS the failure
// so the handler that is holding an HTTP request open can put it in front of
// the admin instead of a generic 500.
//
// This is what makes "os pacotes opcionais ficam sob demanda" (package doc,
// FEATURES.md) real rather than aspirational: before this existed, nothing in
// the codebase installed kea-dhcp4-server or unbound, so enabling DHCP on a
// bare box died with `open /etc/kea/kea-validate-*.conf: no such file or
// directory` — /etc/kea existing only because some human had run apt.
//
// It returns the packages it actually installed (empty when everything was
// already present, which is the common case on every apply after the first),
// so the caller can clear a previously-raised "missing" alert only on the
// transition, exactly as Ensure does with BaseDepsOK.
//
// The retry-after-apt-update is the same one Ensure does, for the same reason
// (a box whose apt index was never fetched answers "Unable to locate
// package"). The verdict is a re-detection, never apt's exit code: a partial
// install must report what is STILL missing.
//
// Dry-run installs nothing and reports success — a dry run must not modify
// the box, and must not invent a failure the admin cannot act on either.
func EnsureInstalled(ctx context.Context, exec firewall.Executor, pkgs ...string) ([]string, error) {
	missing := Missing(ctx, exec, pkgs...)
	if len(missing) == 0 {
		return nil, nil
	}
	if exec.IsDryRun() {
		slog.Info("dry-run: pacotes ausentes não serão instalados", "pacotes", missing)
		return nil, nil
	}

	// Serialize, then look again: the debounced auto-apply and the admin's
	// own "Aplicar agora" reach this within milliseconds of each other, and
	// whoever waited must not re-install what the other one just brought in.
	aptMu.Lock()
	defer aptMu.Unlock()
	if missing = Missing(ctx, exec, missing...); len(missing) == 0 {
		return nil, nil
	}

	slog.Warn("pacote(s) sob demanda ausentes; o LinkGuard vai instalá-los", "pacotes", missing)
	err := installPackages(ctx, exec, missing...)
	if err != nil {
		slog.Warn("falha ao instalar pacote sob demanda; atualizando o índice do apt e tentando outra vez", "pacotes", missing, "err", err)
		if uerr := updateIndex(ctx, exec); uerr != nil {
			slog.Warn("apt-get update também falhou", "err", uerr)
		}
		err = installPackages(ctx, exec, missing...)
	}

	still := Missing(ctx, exec, missing...)
	installed := installedNow(missing, still)
	if len(still) > 0 {
		slog.Error("o LinkGuard não conseguiu instalar pacote(s) sob demanda", "faltando", still, "err", err)
		return installed, errors.New(installFailureMessage(still, err))
	}
	slog.Info("pacote(s) instalados sob demanda pelo LinkGuard", "pacotes", installed)
	return installed, nil
}

// installedNow subtracts what is still missing from what was attempted,
// preserving order — the packages this run actually brought in.
func installedNow(attempted, still []string) []string {
	stillSet := make(map[string]bool, len(still))
	for _, p := range still {
		stillSet[p] = true
	}
	var got []string
	for _, p := range attempted {
		if !stillSet[p] {
			got = append(got, p)
		}
	}
	return got
}

// installFailureMessage is the sentence an admin reads on the panel when
// LinkGuard could not install what a feature needs. It answers, in order, the
// four questions that make the difference between an actionable message and
// "erro interno do servidor": which package, why apt failed (verbatim — "no
// space left on device" and "Temporary failure resolving deb.debian.org" call
// for very different actions), what stops working, and the exact command to
// run by hand.
func installFailureMessage(still []string, aptErr error) string {
	head := "o pacote " + still[0] + " não está instalado e o LinkGuard não conseguiu instalá-lo"
	if len(still) > 1 {
		head = "os pacotes " + strings.Join(still, ", ") + " não estão instalados e o LinkGuard não conseguiu instalá-los"
	}
	if reason := aptReason(aptErr); reason != "" {
		head += " (apt: " + reason + ")"
	}
	return head + ". " + describeMissing(still)
}

// aptReason extracts the part of an apt failure an admin can act on. What
// comes back from the executor is a transcript, not a message: on the test
// VM one unreachable mirror produced eleven "E: Failed to fetch" lines
// wrapped in systemd-run's own banner (invocation ID, runtime, CPU time,
// memory peak) — over two thousand characters headed for a banner on the
// DHCP page. apt puts everything worth reading on its `E:` lines, so those
// are what survives, capped at two; the whole transcript is still in the
// journal (the caller logs it), which is where a transcript belongs.
//
// When there is no `E:` line at all the fallback matters more than the happy
// path, because that is the most likely case in practice: an apt killed by
// its deadline prints no `E:` line. The naive fallback ("first line of the
// error") then produced the WORST possible sentence — internal/firewall
// formats its errors as `command "<the entire command line>" failed: ...`,
// so the admin got 253 characters of `systemd-run --collect --pipe --wait
// --setenv=... apt-get install -y ...` ending in "signal: killed", inside a
// ~980-character banner on the DHCP page. stripCommandEcho drops the echo,
// and a killed apt gets a sentence that says what actually happened and what
// to do — including the fact that the install may well still be running
// (the transient unit does not die with us).
func aptReason(err error) string {
	if err == nil {
		return ""
	}
	var errLines []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "E:") {
			errLines = append(errLines, line)
		}
	}
	if len(errLines) > 0 {
		extra := ""
		if len(errLines) > 2 {
			extra = fmt.Sprintf(" (+%d erros do apt no log do serviço)", len(errLines)-2)
			errLines = errLines[:2]
		}
		return truncateReason(strings.Join(errLines, "; ") + extra)
	}

	reason := stripCommandEcho(strings.TrimSpace(strings.Split(err.Error(), "\n")[0]))
	if killedByDeadline(reason) {
		return "o apt passou do prazo e foi interrompido; a instalação pode ainda estar em curso na máquina — espere alguns minutos e aplique de novo antes de mexer no apt à mão"
	}
	return truncateReason(reason)
}

// maxReasonLen keeps the panel banner readable. The whole transcript is in
// the journal (the caller logs it), which is where a transcript belongs.
const maxReasonLen = 300

func truncateReason(s string) string {
	if len(s) <= maxReasonLen {
		return s
	}
	return strings.TrimSpace(s[:maxReasonLen]) + "…"
}

// stripCommandEcho removes internal/firewall's `command "<command line>"
// failed: ` prefix, which is the command LinkGuard ran — never information
// the admin needs, and always long enough to bury whatever follows it.
func stripCommandEcho(s string) string {
	const marker = `" failed: `
	if strings.HasPrefix(s, `command "`) {
		if i := strings.Index(s, marker); i >= 0 {
			return strings.TrimSpace(s[i+len(marker):])
		}
	}
	return s
}

// killedByDeadline recognises an apt that did not fail but was cut short:
// exec.CommandContext kills the process on deadline, and what surfaces is
// "signal: killed" (or the context error itself).
func killedByDeadline(reason string) bool {
	return strings.Contains(reason, "signal: killed") ||
		strings.Contains(reason, "context deadline exceeded") ||
		strings.Contains(reason, "context canceled")
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
// conffile prompt". They are still required, and the reason is worth stating
// precisely, because the mechanism moved:
//
// /etc/nftables.conf has to exist before linkguard-fw.service starts (it is an
// unprefixed ReadWritePaths= entry; missing, the unit dies in 226/NAMESPACE).
// No INSTALLER creates it — the postinst deliberately does not, since creating
// a conffile of another package from inside the dpkg transaction is what made
// `apt install ./linkguard-fw_*.deb` stop at the prompt in the first place
// (see deploy/deb/postinst and sysprep.Stage). What creates it is the unit's
// own ExecStartPre=-+ `--prepare-system-at-start`, i.e. sysprep.Prepare with
// StageServiceStart, outside any dpkg transaction.
//
// That is EARLIER than this code runs: the file is on disk, owned by no
// package, by the time the service reaches an `apt install nftables` here. So
// dpkg still finds a conffile it did not write and still asks whom to believe
// — same prompt, one creator later. --force-confold answers it, and answers it
// the right way round: /etc/nftables.conf belongs to LinkGuard (README), and
// dpkg still leaves the maintainer's version next to it as .dpkg-dist.
// --force-confdef lets dpkg take the default silently wherever there is no
// local change to preserve.
//
// Removing these flags therefore needs more than "the postinst no longer
// creates the file": it needs /etc/nftables.conf to be absent when this runs,
// which the unit's pre-start guarantees it is not.
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
	aptMu.Lock()
	defer aptMu.Unlock()
	return installPackages(ctx, exec, pkgs...)
}

// aptMu serializes this process's package-manager runs. dpkg holds
// /var/lib/dpkg/lock-frontend for a whole transaction and a second apt does
// not queue behind it — it dies immediately with "Could not get lock ... is
// another process using it?".
//
// This is not hypothetical: on the test VM, saving the DHCP config (which
// arms the debounced auto-apply) and pressing "Aplicar agora" put two
// installs in flight at once; the loser failed on the lock AND burned the
// single retry that exists for the stale-index case, turning a working
// install into a spurious "não foi possível instalar" in front of the admin.
// It cannot serialize against apt runs from OTHER processes (unattended-
// upgrades, an admin on SSH) — nothing in a process can — which is what the
// retry-after-refresh above is for.
var aptMu sync.Mutex

// installPackages is InstallPackages without the lock, for callers that
// already hold aptMu across a detect/install/re-detect sequence.
func installPackages(ctx context.Context, exec firewall.Executor, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	args := append([]string{}, systemdRunFlags...)
	args = append(args, "--", "apt-get", "install")
	args = append(args, aptFlags...)
	args = append(args, pkgs...)
	_, err := exec.Execute(ctx, "systemd-run", args...)
	return err
}

// systemdRunFlags are the transient-unit flags every apt run here uses.
//
// --collect is not cosmetic: without it, systemd keeps a failed transient
// unit around ("run-u42.service"), and every aborted attempt — a timeout, a
// mirror that went away — leaves one more `run-*.service` in failed state
// forever. That is a real symptom on a real appliance: `systemctl
// --failed` is the first thing an operator looks at, and it would be
// showing garbage from an install that has long since been retried
// successfully. The existing `systemctl reset-failed` in keaunbound does
// NOT cover these: it clears kea-dhcp4-server/unbound, which are named
// units, not the anonymous transient ones systemd-run creates.
var systemdRunFlags = []string{
	"--collect",
	"--pipe",
	"--wait",
	"--setenv=DEBIAN_FRONTEND=noninteractive",
}

// updateIndex refreshes the apt package lists, same transient-unit reasoning
// as InstallPackages.
func updateIndex(ctx context.Context, exec firewall.Executor) error {
	args := append([]string{}, systemdRunFlags...)
	args = append(args, "--", "apt-get", "update")
	_, err := exec.Execute(ctx, "systemd-run", args...)
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
