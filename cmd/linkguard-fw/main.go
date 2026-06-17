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
	"github.com/giovanibalarini/linkguard-fw/internal/config"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
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

	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		slog.Error("failed to open database", "path", cfg.DBPath, "err", err)
		return 1
	}
	defer db.Close()

	var exec firewall.Executor = firewall.NewRealExecutor(30 * time.Second)
	if cfg.DryRun {
		exec = firewall.NewDryRunExecutor()
	}

	alertSvc := alerts.NewService(db)
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
	sysCollector := system.NewCollector()

	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc)

	server := api.New(api.Config{
		Addr:    cfg.Addr(),
		DryRun:  cfg.DryRun,
		WebFS:   linkguardfw.WebFS,
		PromReg: promReg,
	}, db, exec, linkSvc, iptSvc, routeSvc, failoverSvc, alertSvc, authSvc, sysCollector, promReg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interval := time.Duration(cfg.MonitorInterval) * time.Second
	monitor := links.NewMonitor(db, linkSvc, interval)
	monitor.OnStatusChange(failoverSvc.HandleStatusChange)

	go monitor.Run(ctx)
	go metricsCollector.Run(ctx, interval)

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

	slog.Info("linkguard-fw starting", "version", version, "addr", cfg.Addr(), "dry_run", cfg.DryRun)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		return 1
	}
	slog.Info("linkguard-fw stopped")
	return 0
}
