package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	linkguardfw "github.com/giovanibalarini/linkguard-fw"
	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/balancer"
	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-fw/internal/config"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/keaunbound"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/sysprep"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
	"github.com/giovanibalarini/linkguard-fw/internal/tlscert"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

var version = "dev"

// pkgInstallTimeout is the deadline for a single apt-get run. Sized for a
// package download over a bad link, not for a local command: kea + unbound +
// dns-root-data are ~10 MB, and the measurement that motivated this was a
// first apply taking ~40s on a healthy office link — with a 30s executor
// underneath it.
//
// It is a ceiling for a hung apt, not an expectation. Nothing waits on it
// synchronously any more: the boot path runs it off the critical path (see
// the goroutine below) and the HTTP path runs it on a request whose context
// is deliberately detached from the client's.
const pkgInstallTimeout = 10 * time.Minute

func main() {
	os.Exit(run())
}

// ntpInputStateFrom lê o estado de "servir NTP para a LAN" da chave de
// settings "ntp_config" (dona: internal/api/handlers.NTPHandler) e é a ÚNICA
// leitura dela fora da camada HTTP: alimenta tanto a fonte ligada em
// nftables.SetInputChainSources quanto a reconciliação do boot, para que as
// duas nunca discordem sobre o que está configurado.
//
// NENHUM dos dois erros pode ser engolido (I-1 da revisão da Fase C2).
// db.GetSetting devolve ("", nil) só quando a chave não existe; qualquer outra
// falha (banco travado, IO) é erro de verdade, e um `_` ali transformava "não
// consegui ler" em "servir NTP está desligado" — o que faria a passada
// seguinte de ReconcileGroups dar flush na chain input e reescrevê-la só com
// os jumps, apagando do firewall vivo as duas linhas de udp/123 enquanto o
// painel continua mostrando o toggle ligado e o apply é reportado ok. JSON
// corrompido tem exatamente o mesmo efeito, e por isso também é erro.
//
// Recebe a leitura por parâmetro (e não o *storage.DB) para que o teste possa
// exercitar as quatro saídas sem inventar um banco quebrado.
func ntpInputStateFrom(getSetting func(string) (string, error)) ([]string, bool, error) {
	raw, err := getSetting("ntp_config")
	if err != nil {
		return nil, false, fmt.Errorf("ler a configuração de NTP do banco: %w", err)
	}
	if raw == "" {
		return nil, false, nil // nunca configurado: servir NTP nasce desligado
	}
	var c timesync.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, false, fmt.Errorf("interpretar a configuração de NTP gravada: %w", err)
	}
	return c.AllowedNetworks, c.ServeLAN, nil
}

func run() int {
	configPath := flag.String("config", "/etc/linkguard-fw/config.json", "Path to config file")
	addr := flag.String("addr", "", "Listen address override")
	port := flag.Int("port", 0, "Listen port override")
	dryRun := flag.Bool("dry-run", false, "Run in dry-run mode")
	debug := flag.Bool("debug", false, "Enable debug logs")
	showVersion := flag.Bool("version", false, "Print version and exit")
	notifyDown := flag.Bool("notify-down", false, "Send a 'service down' notification and exit (systemd OnFailure)")
	prepareSystem := flag.Bool("prepare-system", false, "Create the filesystem paths the systemd unit needs before it can start, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	// Chamado pelos TRÊS caminhos de instalação (postinst do .deb,
	// deploy/install.sh, `make install`) logo depois de copiar o binário,
	// para que os três deixem a máquina no MESMO estado. Ver
	// internal/sysprep: sem isso a unidade morre em 226/NAMESPACE, em loop
	// de restart, disparando o OnFailure a cada tentativa — e sem nunca
	// executar uma linha do binário que instalaria a base.
	if *prepareSystem {
		created, err := sysprep.Prepare("")
		for _, line := range created {
			fmt.Println("[INFO] criado: " + line)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "[ERRO] "+err.Error())
			return 1
		}
		return 0
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuração inválida", "err", err)
		return 1
	}

	if setFlags["addr"] {
		cfg.ListenAddr = *addr
	}
	if setFlags["port"] {
		cfg.Port = *port
	}
	if setFlags["dry-run"] {
		cfg.DryRun = *dryRun
	}
	if setFlags["debug"] {
		cfg.Debug = *debug
	}

	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	if *notifyDown {
		db, err := storage.Open(cfg.DBPath)
		if err == nil {
			defer db.Close()
			if orphanErr := secrets.CheckNotOrphaned("/etc/linkguard-fw/secret.key", db); orphanErr != nil {
				slog.Warn("notify-down: refusing to start", "err", orphanErr)
				return 1
			}
			key, keyErr := secrets.LoadOrGenerateKey("/etc/linkguard-fw/secret.key")
			if keyErr != nil {
				slog.Warn("notify-down: failed to load secret key", "err", keyErr)
				return 1
			}
			sec := secrets.NewService(db, key)
			for _, e := range notify.NewService(db, sec).SendNow("critical",
				"LinkGuard caiu", "O serviço linkguard-fw parou inesperadamente no firewall.") {
				if e != nil {
					slog.Warn("notify-down send failed", "err", e)
				}
			}
		}
		return 0
	}

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		slog.Error("failed to open database", "path", cfg.DBPath, "err", err)
		return 1
	}
	defer db.Close()

	if err := seedDefaultRoles(db); err != nil {
		slog.Error("failed to seed default roles", "err", err)
		return 1
	}

	if err := secrets.CheckNotOrphaned("/etc/linkguard-fw/secret.key", db); err != nil {
		slog.Error("refusing to start", "err", err)
		return 1
	}
	secretKey, err := secrets.LoadOrGenerateKey("/etc/linkguard-fw/secret.key")
	if err != nil {
		slog.Error("failed to load or generate secret key", "err", err)
		return 1
	}
	secretsSvc := secrets.NewService(db, secretKey)
	if err := storage.MigrateSettingsToSecrets(db, secretsSvc); err != nil {
		slog.Error("failed to migrate legacy secrets", "err", err)
		return 1
	}

	var exec firewall.Executor = firewall.NewRealExecutor(30 * time.Second)
	if cfg.DryRun {
		exec = firewall.NewDryRunExecutor()
	}

	// pkgExec is the executor for anything that runs a package manager. The
	// application's `exec` has a 30s deadline — right for `nft`, `ip` or
	// `systemctl`, far too short for an apt-get fetching packages, and worse
	// than too short: when the deadline fires, the apt does NOT die with it
	// (systemd-run's transient unit finishes the transaction), so LinkGuard
	// reports a failure that is not happening. Every apt path — the base at
	// boot, the on-demand DHCP/DNS install, chrony — uses this one.
	pkgExec := exec
	if !cfg.DryRun {
		pkgExec = firewall.NewRealExecutor(pkgInstallTimeout)
	}

	alertSvc := alerts.NewService(db)
	// Close state-derived alerts left open by a previous process before any
	// watcher starts observing again: the health state that gates whether a
	// condition is "new" lives only in memory, so every restart forgets
	// what was already true. Whatever is still genuinely wrong gets
	// re-raised within the first tick or two; whatever was fixed while the
	// service was down (three alerts had to be resolved by hand on
	// 2026-08-11 for exactly this reason) stays closed. Must run before the
	// collectors/schedulers below start, so a still-true condition is
	// re-raised by the first tick rather than racing this cleanup.
	alertSvc.ResolveStaleOnStartup()
	notifySvc := notify.NewService(db, secretsSvc)
	alertSvc.SetNotifier(notifySvc)
	authSvc := auth.NewService(db, cfg.JWTSecret, secretsSvc)
	linkSvc := links.NewService(db)
	iptSvc := iptables.NewService(exec)
	routeSvc := routes.NewService(exec)
	failoverSvc := failover.NewService(failover.Config{
		Enabled:          cfg.FailoverEnabled,
		DryRun:           cfg.DryRun,
		FailThreshold:    cfg.FailThreshold,
		RecoverThreshold: cfg.RecoverThreshold,
		CooldownSecs:     cfg.FailoverCooldownSecs,
	}, db, exec, routeSvc, alertSvc)
	nftSvc := nftables.NewService(exec)
	frSvc := firewallrules.NewService(db, nftSvc)
	// Bloqueio administrativo que não está mais na lista de grupos é motivo
	// para alcançar o operador onde ele estiver, não só para deixar a faixa
	// vermelha na tela do firewall.
	frSvc.SetAlerter(alertSvc)
	// A chain input tem um renderizador só (Fase C2): ela é reconstruída
	// inteira, com a proteção do NTP E os jumps dos grupos de escopo input,
	// venha a passada de onde vier. Quem reconcilia o NTP sabe o estado do
	// NTP e precisa dos grupos; quem reconcilia os grupos sabe os grupos e
	// precisa do estado do NTP — estas duas funções são o que fecha esse
	// círculo sem internal/nftables importar internal/storage.
	//
	// Ligado aqui, junto da construção, e não perto de um dos reconciles: sem
	// isto, salvar um grupo apagaria a proteção do NTP da chain input.
	// TestMainWiresTheInputChainSources guarda essa ligação contra deriva.
	//
	// O erro de leitura viaja junto e NÃO vira "servir NTP está desligado" —
	// ver ntpInputStateFrom.
	ntpInputState := func() ([]string, bool, error) { return ntpInputStateFrom(db.GetSetting) }
	nftSvc.SetInputChainSources(frSvc.StoredGroups, ntpInputState)
	balancerSvc := balancer.NewService(db, exec, linkSvc, alertSvc)
	keaSvc := keaunbound.NewService(exec)
	// O caminho sob demanda (o admin liga DHCP/DNS no painel) instala
	// kea + unbound + dns-root-data. Sem isto ele herdava o executor de 30s
	// e, ao estourar, mentia dizendo que não conseguiu instalar enquanto o
	// apt terminava a instalação com sucesso.
	keaSvc.SetInstallExecutor(pkgExec)
	var netSvc netsvc.Provider = keaSvc
	trafficSvc := hosttraffic.NewService(exec)
	hostSvc := hosts.NewService(exec, db, nftSvc, netSvc)
	netifSvc := netif.NewService(exec, db, linkSvc)
	netifSvc.SetAlertService(alertSvc)
	sysCollector := system.NewCollector()
	rrdSvc := tsdb.NewService(db)

	// Optional AI advisory layer (BYOK): disabled by default (ai.LoadConfig's
	// Enabled defaults to false), and swallows its own failures — wiring it in
	// unconditionally here does not change failover/balance behavior.
	aiBudget := ai.NewBudgetGuard(db)
	aiClient := ai.NewClient(secretsSvc, aiBudget, func() ai.Config { return ai.LoadConfig(db) })
	balancerSvc.SetAI(aiClient, rrdSvc)

	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
	journalSched := monitoring.NewJournalScheduler(metricsCollector)
	updatesSched := monitoring.NewUpdatesScheduler(metricsCollector)

	server := api.New(api.Config{
		Addr:    cfg.Addr(),
		DryRun:  cfg.DryRun,
		WebFS:   linkguardfw.WebFS,
		PromReg: promReg,
		Version: version,
		PkgExec: pkgExec,
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, balancerSvc, alertSvc, authSvc, hostSvc, netifSvc, nftSvc, frSvc, netSvc, notifySvc, trafficSvc, sysCollector, rrdSvc, promReg, metricsCollector, secretsSvc, aiClient, backupSched)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interval := time.Duration(cfg.MonitorInterval) * time.Second
	// The link health probe runs on its own (faster) cadence, decoupled from the
	// metrics collector, and sends several probes per host so packet loss/latency
	// are real averages instead of a single pass/fail.
	probeInterval := time.Duration(cfg.ProbeIntervalSeconds) * time.Second
	monitor := links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount, rrdSvc, appMetrics)
	// On a link state change, balance mode rebuilds the weighted multipath
	// default route; otherwise the legacy per-table failover handles it.
	monitor.OnStatusChange(func(link *storage.Link, oldStatus, newStatus string) {
		if balancerSvc.Active() {
			balancerSvc.OnLinkChange(link, oldStatus, newStatus)
			return
		}
		failoverSvc.HandleStatusChange(link, oldStatus, newStatus)
	})
	// A link that stays degraded past the admin-configured threshold triggers
	// active flow eviction (balance mode only; itself gated by a toggle). The
	// threshold is read live so UI changes take effect without a restart.
	monitor.SustainThreshold(func() int { return balancerSvc.LoadConfig().DegradedSustainSamples })
	monitor.OnDegradedSustained(func(link *storage.Link) {
		if balancerSvc.Active() {
			balancerSvc.EvictDegraded(ctx, link)
		}
	})

	// pendingCheckedOnce prende a verificação de boot do confirmar-ou-reverte
	// à PRIMEIRA passada de provisionSystem. provisionSystem é reexecutado
	// quando uma tentativa posterior de instalar a base finalmente dá certo —
	// e isso pode acontecer meia hora depois da subida, com o operador já no
	// painel. Sem esta trava, essa segunda passada reverteria uma janela de
	// confirmação que ele tivesse acabado de abrir, como se a máquina tivesse
	// reiniciado. "No boot" tem que querer dizer no boot.
	var pendingCheckedOnce sync.Once

	// provisionSystem é tudo o que o LinkGuard faz no boot que MEXE na
	// máquina: forwarding, policy routing, bootstrap/reconciliação do
	// nftables, accounting do conntrack, NTP e resolv.conf.
	//
	// Tudo isto depende de o `nft`/`ip` existirem, então continua vindo
	// DEPOIS de garantir a base — mas fora do caminho crítico da subida (ver
	// a goroutine logo abaixo). É idempotente de ponta a ponta, e por isso
	// pode ser chamado de novo quando uma tentativa posterior de instalar a
	// base finalmente der certo.
	provisionSystem := func() {
		// PRIMEIRA COISA, antes de qualquer reconciliação (Fase C2, spec
		// §5.1): se ficou uma mudança de firewall aplicada e não confirmada,
		// reverta — tenha ela expirado ou não.
		//
		// A ordem é a proteção, não uma preferência de organização. Reverter
		// DEPOIS de já ter reconciliado significaria aplicar mais uma vez, na
		// máquina que acabou de voltar, exatamente a regra que pode tê-la
		// derrubado — e regra de escopo input derruba o acesso do OPERADOR
		// (SSH, painel), numa máquina remota, sem conserto local.
		//
		// Reverter mesmo dentro do prazo é decisão registrada: o operador não
		// estava lá para confirmar, e um reboot dentro da janela normalmente
		// significa que a máquina caiu por causa da mudança. Ver
		// RevertPendingOnBoot.
		//
		// Erro aqui não derruba o boot: fica no journal e a mudança continua
		// pendente, com a faixa do painel pedindo confirmação ou reversão.
		pendingCheckedOnce.Do(func() {
			if err := frSvc.RevertPendingOnBoot(ctx); err != nil {
				slog.Error("não foi possível reverter no boot a mudança de firewall não confirmada", "err", err)
			}
		})

		// Enable IPv4 forwarding so the box can route between LAN and WAN; it
		// defaults to 0 on a fresh system and a firewall/router needs it on.
		routeSvc.EnsureForwarding()

		// Apply the WAN host-steering policy routing at startup (LinkGuard now owns
		// this; it previously came from /etc/network/linkguard-routing.sh via rc.local).
		balancerSvc.EnsureSteerRouting(ctx)

		// Bootstrap `table inet linkguard` if it doesn't exist yet — every other
		// nftables operation (block host, port forward, custom rule) assumes the
		// table is already there. On every install to date this table was created
		// by hand once; this makes a fresh install self-sufficient instead of
		// silently failing the first time an admin uses the Firewall screen.
		if configuredLinks, err := linkSvc.List(); err != nil {
			slog.Warn("could not load links for nftables bootstrap", "err", err)
		} else {
			wanInterfaces := make([]string, 0, len(configuredLinks))
			for _, l := range configuredLinks {
				wanInterfaces = append(wanInterfaces, l.Interface)
			}
			if nftSvc.EnsureTable(ctx, wanInterfaces) {
				// The table was just created empty — restore whatever was saved on
				// the last mutation (host_wan, blocklist, user rules, host blocks,
				// port forwards) so a from-scratch install with a restored database
				// comes back with the same firewall it had, not a blank one. Only
				// runs right after a bootstrap: reapplying a snapshot on every
				// ordinary restart would risk clobbering a running firewall with
				// stale state instead.
				if snapshot, _ := db.GetSetting(nftables.LiveSnapshotSettingKey); snapshot != "" {
					if _, err := nftSvc.Restore(ctx, snapshot); err != nil {
						slog.Warn("bootstrapped nftables table but could not restore the saved elements", "err", err)
					} else {
						slog.Info("restored saved nftables elements after bootstrap (host_wan/blocklist/user rules/port forwards)")
					}
				}
			}

			// Reconcile the masquerade rule on EVERY boot, not just when the table
			// had to be created. EnsureTable is a no-op on an already-provisioned
			// box, so before this the NAT rule kept whatever interface names it was
			// born with — in production a renamed NIC (enp4s0 -> enp5s0) silently
			// took WAN1's NAT down until an operator intervened by hand.
			enabledWANs := make([]string, 0, len(configuredLinks))
			for _, l := range configuredLinks {
				if l.Enabled && l.Interface != "" {
					enabledWANs = append(enabledWANs, l.Interface)
				}
			}
			if err := nftSvc.ReconcileMasquerade(ctx, enabledWANs); err != nil {
				slog.Warn("não foi possível reconciliar a regra de NAT no boot", "err", err)
			}

			// Reconcile the structural chain (mark_hosts) on every boot too.
			// Until this feature (2026-08-11, firewall page redesign spec §6)
			// it was only ever created once at EnsureTable/bootstrap and never
			// touched again — the gap that let a double-load of the ruleset
			// (2026-08-10 incident) leave every rule in it permanently
			// duplicated, since nothing ever flushed and rewrote it again. See
			// ReconcileStructuralChains' doc comment.
			//
			// The forward chain used to be reconciled here too; since rule
			// groups (Phase C1) it belongs to ReconcileGroups, called below via
			// frSvc.Reconcile — the only place that knows the admin's groups.
			if err := nftSvc.ReconcileStructuralChains(ctx); err != nil {
				slog.Warn("não foi possível reconciliar a chain estrutural (mark_hosts) no boot", "err", err)
			}

			// EnsureSystemGroups vem PRIMEIRO, antes de qualquer coisa que
			// reconcilie, e a ordem é o ponto: ele cria, uma única vez, as
			// duas linhas de grupo que representam os bloqueios (hosts e
			// destinos) nas posições 0 e 1, empurrando os grupos do admin
			// para depois. É a lista de grupos que passa a decidir se os
			// bloqueios existem na chain forward — e as duas migrações
			// abaixo reconciliam por dentro, então rodá-las antes desta
			// abriria uma janela em que a forward é reconstruída com a lista
			// ainda sem os bloqueios. A defesa de firewallrules recusa
			// exatamente esse estado (ver ensureSystemGroupsPresent): com a
			// ordem invertida, as duas migrações do boot de upgrade
			// falhariam em vez de migrar.
			//
			// Não depende de nenhuma das duas: só lê a própria trava e
			// insere as duas linhas, deslocando as posições existentes.
			// TestEnsureSystemGroupsRunsBeforeTheMigrationsThatReconcile
			// guarda essa ordem contra deriva.
			//
			// Um erro aqui não derruba o boot: os grupos não são criados, e
			// tudo que reconcilia a seguir se recusa a reconstruir a forward
			// (o firewall segue valendo com a última forward aplicada, que
			// tem os bloqueios dentro), com apply-status não-ok e alerta
			// crítico. A próxima inicialização tenta de novo.
			if err := frSvc.EnsureSystemGroups(ctx); err != nil {
				slog.Warn("não foi possível criar os grupos do sistema (hosts e destinos bloqueados)", "err", err)
			}

			// Phase B (firewall page redesign spec §4.1): the admin's own rules
			// now live in the DB, not just inside nft. On a box upgrading from
			// Phase A, ImportOnce brings whatever is in the live user_rules
			// chain into the DB exactly once (guarded by a settings flag, never
			// by "is the table empty" — see its doc comment for why that
			// distinction matters), preserving order; a fresh install has
			// nothing to import and just sets the guard.
			//
			// MigrateRulesIntoDefaultGroup runs right after: it adopts whatever
			// rules are still ungrouped — including whatever ImportOnce just
			// brought in — into the "Minhas regras" group, once, guarded the
			// same way. The order between these two is not arbitrary: inverting
			// them would make a box still on Phase A (nothing in the DB yet,
			// the real rules only living in the legacy user_rules chain) run
			// the group migration against an empty rule set, then have
			// ImportOnce bring the rules in afterwards as orphans nobody ever
			// adopts into a group.
			//
			// Reconcile (Fase C1) is what actually renders the forward chain
			// (blocks, then the group jumps) and every grp_ chain from the DB —
			// see its doc comment. It is called unconditionally last, on every
			// boot, same as the other reconciles above. This is not redundant
			// with the two calls above even though both of them also reconcile
			// internally when they do real work (MigrateRulesIntoDefaultGroup
			// must, to safely retire the legacy user_rules chain — see its doc
			// comment): on a box with nothing to migrate, that function returns
			// without reconciling at all, which would leave the forward chain
			// stuck on whatever was last written to /etc/nftables.conf.
			if err := frSvc.ImportOnce(ctx); err != nil {
				slog.Warn("não foi possível importar as regras existentes de user_rules para o banco", "err", err)
			}
			if err := frSvc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
				slog.Warn("não foi possível migrar as regras soltas para o grupo padrão", "err", err)
			}
			if err := frSvc.Reconcile(ctx); err != nil {
				slog.Warn("não foi possível reconciliar os grupos de regras (chain forward) a partir do banco no boot", "err", err)

				// m1 da revisão da Fase C2: frSvc.Reconcile → nftSvc.ReconcileGroups
				// já reconstrói a chain input INTEIRA (passo 3b, ver o doc-comment
				// de ReconcileGroups) a partir da mesma fonte de estado do NTP que
				// ntpInputState lê abaixo — no caminho feliz, chamar
				// nftSvc.ReconcileNTPInput de novo aqui só duplicava o trabalho.
				// Duplicar não é de graça: cada reconstrução da chain input abre uma
				// janela entre o `flush chain` e o `add rule` do bloqueio de udp/123
				// em que ela fica vazia com `policy accept` — NTP de qualquer origem
				// passaria nesse instante —, e dobrar a chamada dobra essa janela por
				// boot, além de duplicar o Persist() em /etc/nftables.conf.
				//
				// O valor que sobra é estreito mas real: se frSvc.Reconcile FALHOU
				// (por exemplo abortou em ensureSystemGroupsPresent, antes mesmo de
				// chamar ReconcileGroups), a chain input pode não ter sido tocada por
				// ele nesta passada — e é só este `if` que ainda garante que a
				// proteção do NTP suba no boot. Por isso a chamada fica presa a este
				// ramo de erro em vez de rodar solta como antes.
				// TestNTPInputIsReconciledAfterTheGroupChainsExist guarda isto.
				//
				// A ordem continua sendo o ponto (I-4 da revisão da Fase C2): desde a
				// Fase C2 a chain input carrega também um `jump` por grupo de escopo
				// input, e quem CRIA as chains grp_ é o passo 1 de ReconcileGroups,
				// chamado (com sucesso ou não) dentro de frSvc.Reconcile acima. Numa
				// máquina cujo ruleset foi recriado do zero por EnsureTable
				// (recuperação de desastre, como em 2026-08-10) e cujo banco tenha um
				// grupo de escopo input, emitir o jump antes disso falha com "No such
				// file or directory": a passada seguinte conserta, mas o log de boot
				// fica com um erro que não é erro — e log de boot de firewall é lido
				// em emergência.
				//
				// Erro de LEITURA não vira reconciliação: reconstruir a chain com
				// "servir NTP: desligado" que na verdade é "não consegui ler"
				// apagaria a proteção do serviço de hora do firewall vivo (I-1).
				if networks, serving, err := ntpInputState(); err != nil {
					slog.Warn("não foi possível ler a configuração de NTP no boot; a chain input não foi tocada nesta passada", "err", err)
				} else if err := nftSvc.ReconcileNTPInput(ctx, networks, serving); err != nil {
					slog.Warn("não foi possível reconciliar a chain de proteção do NTP no boot", "err", err)
				}
			}
		}

		// Enable conntrack byte accounting so per-host traffic (top talkers) can be
		// computed; without it /proc/net/nf_conntrack has no byte counters.
		trafficSvc.EnsureAccounting()

		// Enable NTP time sync (chrony) if it's installed — LinkGuard owns this
		// the same way it owns the three prerequisites above.
		timesync.EnsureEnabled(ctx, exec)

		// Relax /etc/kea's directory permissions so DHCP config validation/apply
		// doesn't fail under AppArmor (see EnsureKeaDirReadable's doc comment).
		keaSvc.EnsureKeaDirReadable()

		// Point /etc/resolv.conf at the local unbound and stop dhclient from
		// undoing it on lease renewal (see EnsureResolvConf's doc comment).
		keaSvc.EnsureResolvConf(ctx)
	}

	// O painel e o monitor de failover sobem PRIMEIRO; a base e o
	// provisionamento vão para segundo plano.
	//
	// Antes, bootstrapdeps.Ensure rodava síncrono aqui: com o executor de
	// pacote (10 min por comando) o pior caso era install + apt-get update +
	// install ≈ 30 minutos sem monitor de failover, sem balanceamento e sem
	// painel. E o cenário em que o apt trava devagar é justamente "a WAN
	// caiu" — exatamente quando o failover é a única coisa que importa. É o
	// padrão do incidente de 2026-07-24, em que uma migração sem transação
	// travou o boot desta aplicação por 50+ minutos numa máquina de
	// produção.
	//
	// Por que esta ordem e não simplesmente limitar o prazo total do Ensure:
	// um teto no Ensure escolhe entre "esperar menos" e "instalar a base" —
	// os dois importam, e num link ruim qualquer teto que caiba num boot
	// aceitável é curto demais para um apt honesto. Subir antes remove a
	// escolha: o painel aparece em milissegundos, o failover está de pé, e a
	// instalação tem todo o tempo de que precisa.
	//
	// Numa máquina já provisionada isto custa quatro dpkg-query e o
	// provisionamento roda igual, poucos milissegundos depois da subida.
	//
	// O laço existe porque Ensure roda uma vez por tentativa e o motivo mais
	// comum de falhar logo depois do boot é o apt-daily/unattended-upgrades
	// estar com o lock do dpkg — nada que uma segunda tentativa alguns
	// minutos depois não resolva. Sem ele, a base nunca era instalada nesse
	// boot. Cada tentativa bem-sucedida reprovisiona (é aí que o `nft`
	// finalmente existe para a reconciliação valer).
	go func() {
		for attempt := 0; ; attempt++ {
			done := bootstrapdeps.Ensure(ctx, pkgExec, alertSvc)
			if done || attempt == 0 {
				provisionSystem()
			}
			if done {
				return
			}
			delay := bootstrapdeps.RetryDelay(attempt)
			slog.Warn("base incompleta; o LinkGuard vai tentar instalar de novo", "em", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()

	// O timer em memória do confirmar-ou-reverte: enquanto o processo vive,
	// é ele que desfaz a mudança de firewall quando o prazo de 90 s termina
	// sem confirmação. A rede embaixo dele é a verificação de boot acima —
	// esta goroutine morre junto com o processo, e é justamente o processo
	// morrer dentro da janela o caso que não pode deixar a regra valendo.
	//
	// Cinco segundos: a contagem que o operador vê sai de expires_at (do
	// servidor), então isto é só a granularidade da reversão. Custa um SELECT
	// numa tabela de no máximo uma linha.
	go frSvc.WatchPending(ctx, 5*time.Second)

	go monitor.Run(ctx)
	go metricsCollector.Run(ctx, interval)
	go rrdSvc.Run(ctx)
	go balancerSvc.Run(ctx)
	go backupSched.Run(ctx)
	go journalSched.Run(ctx)
	go updatesSched.Run(ctx)
	go netifSvc.RunExpirySweep(ctx, 10*time.Second)
	go ai.RunDigest(ctx, aiClient, rrdSvc, alertSvc, db, func() []string {
		all, _ := db.GetLinks()
		names := make([]string, 0, len(all))
		for _, l := range all {
			if l.Enabled {
				names = append(names, l.Name)
			}
		}
		return names
	})

	httpServer := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown failed", "err", err)
		}
	}()

	slog.Info("linkguard-fw starting", "version", version, "addr", cfg.Addr(),
		"dry_run", cfg.DryRun, "tls", cfg.TLSEnabled)

	serve := httpServer.ListenAndServe
	if cfg.TLSEnabled {
		if err := tlscert.EnsureSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			slog.Error("tls certificate setup failed", "err", err)
			return 1
		}
		serve = func() error { return httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }
	}
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		return 1
	}
	slog.Info("linkguard-fw stopped")
	return 0
}

// seedDefaultRoles seeds the built-in RBAC roles (defined in the auth catalog)
// on first run, without overwriting any later admin customizations.
func seedDefaultRoles(db *storage.DB) error {
	seeds := make([]storage.RoleSeed, 0, len(auth.DefaultRoles))
	adminRoleID := ""
	for _, dr := range auth.DefaultRoles {
		perms := make([]string, len(dr.Permissions))
		for i, p := range dr.Permissions {
			perms[i] = string(p)
			if p == auth.PermUsersManage {
				adminRoleID = dr.ID
			}
		}
		seeds = append(seeds, storage.RoleSeed{
			ID:          dr.ID,
			Name:        dr.Name,
			Description: dr.Description,
			Permissions: perms,
			// Keep the admin role in sync with the catalog across upgrades.
			AlwaysSync: dr.ID == adminRoleID,
		})
	}
	return db.EnsureDefaultRoles(seeds, adminRoleID)
}
