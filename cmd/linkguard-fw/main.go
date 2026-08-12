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

func main() {
	os.Exit(run())
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
	balancerSvc := balancer.NewService(db, exec, linkSvc, alertSvc)
	keaSvc := keaunbound.NewService(exec)
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

	// Guarantee the base packages (nftables, iproute2, iptables,
	// iputils-ping) before anything below tries to use them. Installing the
	// LinkGuard is handing it the machine: on a bare box it brings in what it
	// cannot work without, instead of assuming somebody prepared the ground.
	//
	// This is what finishes the install: the .deb declares the base in
	// Recommends:, not Depends:, so `dpkg -i` on a machine with nothing on it
	// installs AND configures the package and the service actually starts
	// (with Depends: it stops at `iU` and there is no panel left to explain
	// anything). A package's own maintainer scripts cannot do this — dpkg
	// holds its lock for the whole run — but a running service can.
	//
	// Must come before EnsureForwarding/EnsureTable below, which need `ip`
	// and `nft` to exist. On an already-provisioned box it is one dpkg-query
	// per package and nothing else, so it does not slow down ordinary boots.
	// If apt cannot deliver (no network, dead mirror), it does not fail
	// silently: critical alert on the panel plus a log naming what is missing
	// and what stops working — and the boot carries on, so the operator has a
	// panel to read it on.
	//
	// It gets an executor of its own because the application's `exec` has a
	// 30s timeout: plenty for an `nft` or `ip` call, far too short for an
	// apt-get fetching packages over a bad link.
	depExec := exec
	if !cfg.DryRun {
		depExec = firewall.NewRealExecutor(10 * time.Minute)
	}
	bootstrapdeps.Ensure(ctx, depExec, alertSvc)

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

		// Reconcile the NTP-protection input chain on every boot too — same
		// self-healing reasoning as the masquerade rule above: a box upgraded
		// from before this feature (2026-08-11) has no input chain at all, and
		// EnsureTable/ReconcileNTPInput being no-ops on an already-provisioned
		// box means only an explicit reconcile keeps it in sync with the
		// admin's chosen networks and the serve-to-LAN toggle. Reads both
		// straight from the "ntp_config" settings key (owned by
		// internal/api/handlers.NTPHandler) since main wires the HTTP layer
		// after this point and has no handler instance yet. Reshaped
		// 2026-08-11 (spec §4): the chain is keyed on
		// timesync.Config.AllowedNetworks, not the WAN interface set — see
		// ReconcileNTPInput's doc comment.
		var ntpCfg timesync.Config
		if raw, _ := db.GetSetting("ntp_config"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &ntpCfg)
		}
		if err := nftSvc.ReconcileNTPInput(ctx, ntpCfg.AllowedNetworks, ntpCfg.ServeLAN); err != nil {
			slog.Warn("não foi possível reconciliar a chain de proteção do NTP no boot", "err", err)
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
