package main

import (
	"context"
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
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/balancer"
	"github.com/giovanibalarini/linkguard-fw/internal/config"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/keaunbound"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/tlscert"
	"github.com/giovanibalarini/linkguard-fw/internal/trafficrrd"
	"github.com/giovanibalarini/linkguard-fw/internal/wireguard"
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
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
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
			for _, e := range notify.NewService(db).SendNow("critical",
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

	var exec firewall.Executor = firewall.NewRealExecutor(30 * time.Second)
	if cfg.DryRun {
		exec = firewall.NewDryRunExecutor()
	}

	alertSvc := alerts.NewService(db)
	notifySvc := notify.NewService(db)
	alertSvc.SetNotifier(notifySvc)
	authSvc := auth.NewService(db, cfg.JWTSecret)
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
	balancerSvc := balancer.NewService(db, exec, linkSvc, alertSvc)
	var netSvc netsvc.Provider = keaunbound.NewService(exec)
	vpnSvc := wireguard.NewService(exec)
	trafficSvc := hosttraffic.NewService(exec)
	hostSvc := hosts.NewService(exec, db, nftSvc, netSvc)
	sysCollector := system.NewCollector()
	rrdSvc := trafficrrd.NewService(db)

	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec)

	server := api.New(api.Config{
		Addr:    cfg.Addr(),
		DryRun:  cfg.DryRun,
		WebFS:   linkguardfw.WebFS,
		PromReg: promReg,
		Version: version,
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, balancerSvc, alertSvc, authSvc, hostSvc, nftSvc, netSvc, vpnSvc, notifySvc, trafficSvc, sysCollector, rrdSvc, promReg, metricsCollector)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interval := time.Duration(cfg.MonitorInterval) * time.Second
	// The link health probe runs on its own (faster) cadence, decoupled from the
	// metrics collector, and sends several probes per host so packet loss/latency
	// are real averages instead of a single pass/fail.
	probeInterval := time.Duration(cfg.ProbeIntervalSeconds) * time.Second
	monitor := links.NewMonitor(db, linkSvc, probeInterval, cfg.ProbeCount)
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

	// Enable IPv4 forwarding so the box can route between LAN and WAN; it
	// defaults to 0 on a fresh system and a firewall/router needs it on.
	routeSvc.EnsureForwarding()

	// Apply the WAN host-steering policy routing at startup (LinkGuard now owns
	// this; it previously came from /etc/network/linkguard-routing.sh via rc.local).
	balancerSvc.EnsureSteerRouting(ctx)

	// Enable conntrack byte accounting so per-host traffic (top talkers) can be
	// computed; without it /proc/net/nf_conntrack has no byte counters.
	trafficSvc.EnsureAccounting()

	go monitor.Run(ctx)
	go metricsCollector.Run(ctx, interval)
	go rrdSvc.Run(ctx)
	go balancerSvc.Run(ctx)

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
