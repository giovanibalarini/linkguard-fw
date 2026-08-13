// Package api provides the HTTP server and route registration for LinkGuard FW.
package api

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/balancer"
	"github.com/giovanibalarini/linkguard-fw/internal/dnslog"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/hosts"
	"github.com/giovanibalarini/linkguard-fw/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/stresstest"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
	"github.com/giovanibalarini/linkguard-fw/internal/updater"
)

// Server holds all dependencies needed to serve HTTP requests.
type Server struct {
	router      *chi.Mux
	db          *storage.DB
	exec        firewall.Executor
	linkSvc     *links.Service
	iptSvc      *iptables.Service
	routeSvc    *routes.Service
	failoverSvc *failover.Service
	balancerSvc *balancer.Service
	alertSvc    *alerts.Service
	authSvc     *auth.Service
	hostSvc     *hosts.Service
	netifSvc    *netif.Service
	nftSvc      *nftables.Service
	frSvc       *firewallrules.Service
	netSvc      netsvc.Provider
	notifySvc   *notify.Service
	trafficSvc  *hosttraffic.Service
	sysCol      *system.Collector
	rrdSvc      *tsdb.Service
	promReg     *prometheus.Registry
	mon         *monitoring.Collector
	sec         secrets.Secrets
	aiClient    *ai.Client
	backupSched *backup.Scheduler
	webFS       embed.FS
}

// Config holds server configuration.
type Config struct {
	Addr    string
	DryRun  bool
	WebFS   embed.FS
	PromReg *prometheus.Registry
	Version string
	// PkgExec is the executor for anything that runs a package manager
	// (today: the on-demand chrony install). Nil falls back to exec, which
	// is only right for tests — in production a 30s deadline on an apt-get
	// reports failures that are not happening. See
	// keaunbound.Service.installExec.
	PkgExec firewall.Executor
}

// New creates and wires up the HTTP server.
func New(cfg Config, db *storage.DB, exec firewall.Executor,
	linkSvc *links.Service, iptSvc *iptables.Service, routeSvc *routes.Service,
	failoverSvc *failover.Service, balancerSvc *balancer.Service, alertSvc *alerts.Service, authSvc *auth.Service,
	hostSvc *hosts.Service, netifSvc *netif.Service, nftSvc *nftables.Service, frSvc *firewallrules.Service, netSvc netsvc.Provider,
	notifySvc *notify.Service, trafficSvc *hosttraffic.Service,
	sysCol *system.Collector, rrdSvc *tsdb.Service, promReg *prometheus.Registry,
	mon *monitoring.Collector, sec secrets.Secrets, aiClient *ai.Client, backupSched *backup.Scheduler) *Server {

	s := &Server{
		db:          db,
		exec:        exec,
		linkSvc:     linkSvc,
		iptSvc:      iptSvc,
		routeSvc:    routeSvc,
		failoverSvc: failoverSvc,
		balancerSvc: balancerSvc,
		alertSvc:    alertSvc,
		authSvc:     authSvc,
		hostSvc:     hostSvc,
		netifSvc:    netifSvc,
		nftSvc:      nftSvc,
		frSvc:       frSvc,
		netSvc:      netSvc,
		notifySvc:   notifySvc,
		trafficSvc:  trafficSvc,
		sysCol:      sysCol,
		rrdSvc:      rrdSvc,
		promReg:     promReg,
		mon:         mon,
		sec:         sec,
		aiClient:    aiClient,
		backupSched: backupSched,
		webFS:       cfg.WebFS,
	}

	s.router = s.buildRouter(cfg)
	return s
}

// Handler returns the HTTP handler (for use in http.Server).
func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) buildRouter(cfg Config) *chi.Mux {
	r := chi.NewRouter()

	// Core middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(maxBodySize(2 << 20)) // 2MB — generoso pra qualquer corpo JSON desta API; backup/restore define seu próprio limite maior

	// CORS — restrict to localhost by default
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*", "http://127.0.0.1:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Prometheus metrics (no auth)
	r.Handle("/metrics", promhttp.HandlerFor(cfg.PromReg, promhttp.HandlerOpts{}))

	// Public auth endpoints
	authH := handlers.NewAuthHandler(s.authSvc, s.db)
	r.Post("/api/auth/login", authH.Login)

	// Health (no auth needed)
	healthH := handlers.NewHealthHandler(s.db, s.sysCol, cfg.Version)
	r.Get("/api/health", healthH.Health)

	// Protected API routes. Each route is gated by a feature permission
	// (RBAC); the user's effective permissions are resolved per request.
	r.Group(func(r chi.Router) {
		r.Use(s.authSvc.Middleware)
		require := s.authSvc.Require

		// Current user + effective permissions (authentication only)
		r.Get("/api/auth/me", authH.Me)

		// Two-factor (self-service; any authenticated user manages their own)
		r.Get("/api/auth/2fa", authH.TwoFAStatus)
		r.Post("/api/auth/2fa/setup", authH.TwoFASetup)
		r.Post("/api/auth/2fa/activate", authH.TwoFAActivate)
		r.Post("/api/auth/2fa/disable", authH.TwoFADisable)

		// Layout do painel (Fase B): os widgets que ESTE admin escolheu e onde
		// ele os pôs. É preferência pessoal, então o dono é sempre o usuário
		// autenticado — não existe rota para ler nem escrever o painel de
		// outro. O gate é dashboard.read (inclusive na escrita): quem não pode
		// abrir o painel não tem layout de painel para salvar.
		dashH := handlers.NewDashboardHandler(s.db)
		r.With(require(auth.PermDashboardRead)).Get("/api/dashboard/layout", dashH.GetLayout)
		r.With(require(auth.PermDashboardRead)).Put("/api/dashboard/layout", dashH.SaveLayout)
		r.With(require(auth.PermDashboardRead)).Delete("/api/dashboard/layout", dashH.ResetLayout)

		// System
		sysH := handlers.NewSystemHandler(s.sysCol, s.db, s.rrdSvc)
		r.With(require(auth.PermSystemRead)).Get("/api/system/status", sysH.Status)
		r.With(require(auth.PermSystemRead)).Get("/api/system/interface-aliases", sysH.ListInterfaceAliases)
		r.With(require(auth.PermSystemWrite)).Put("/api/system/interface-aliases", sysH.UpsertInterfaceAlias)
		r.With(require(auth.PermMonitoringRead)).Get("/api/system/traffic-history", sysH.TrafficHistory)
		r.With(require(auth.PermSystemRead)).Get("/api/system/traffic-retention", sysH.GetTrafficRetention)
		r.With(require(auth.PermSystemWrite)).Put("/api/system/traffic-retention", sysH.SetTrafficRetention)

		// Links
		linksH := handlers.NewLinksHandler(s.linkSvc, s.db, s.nftSvc)
		r.With(require(auth.PermLinksRead)).Get("/api/links", linksH.List)
		r.With(require(auth.PermLinksWrite)).Post("/api/links", linksH.Create)
		r.With(require(auth.PermLinksWrite)).Post("/api/links/auto-detect", linksH.AutoDetect)
		r.With(require(auth.PermLinksRead)).Get("/api/links/{id}", linksH.Get)
		r.With(require(auth.PermLinksWrite)).Put("/api/links/{id}", linksH.Update)
		r.With(require(auth.PermLinksWrite)).Delete("/api/links/{id}", linksH.Delete)

		// Routes
		routesH := handlers.NewRoutesHandler(s.routeSvc)
		r.With(require(auth.PermRoutesRead)).Get("/api/routes", routesH.List)
		r.With(require(auth.PermRoutesRead)).Get("/api/routes/rules", routesH.ListRules)
		r.With(require(auth.PermRoutesWrite)).Post("/api/routes", routesH.AddRoute)
		r.With(require(auth.PermRoutesWrite)).Put("/api/routes", routesH.UpdateRoute)
		r.With(require(auth.PermRoutesWrite)).Delete("/api/routes", routesH.DeleteRoute)
		r.With(require(auth.PermRoutesWrite)).Post("/api/routes/rules", routesH.AddRule)
		r.With(require(auth.PermRoutesWrite)).Put("/api/routes/rules", routesH.UpdateRule)
		r.With(require(auth.PermRoutesWrite)).Delete("/api/routes/rules", routesH.DeleteRule)

		// iptables / firewall
		iptH := handlers.NewIptablesHandler(s.iptSvc, s.db)
		r.With(require(auth.PermFirewallRead)).Get("/api/iptables/rules", iptH.ListAll)
		r.With(require(auth.PermFirewallRead)).Get("/api/iptables/nat", iptH.ListNat)
		r.With(require(auth.PermFirewallRead)).Get("/api/iptables/mangle", iptH.ListMangle)
		r.With(require(auth.PermFirewallRead)).Get("/api/iptables/filter", iptH.ListFilter)
		r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/preview", iptH.Preview)
		// POST /api/firewall/backup e POST /api/firewall/rollback FORAM REMOVIDAS
		// (2026-08-13, antes do deploy em produção). Eram do tempo do iptables e
		// nenhuma tela as chamava — o painel só usa /api/nftables/*. O que elas
		// eram, medido na revisão:
		//
		//   - o rollback legado NÃO tinha trava de janela de confirmação e NÃO
		//     reconciliava o banco depois, e lia AS MESMAS LINHAS da tabela
		//     `iptables_backups` que o botão do painel lê (esse já corrigido);
		//   - era inofensivo por acidente: o conteúdo gravado hoje é dump do
		//     `nft`, e o `iptables-restore` falha na linha 1 sem mudar nada;
		//   - mas o backup legado gravava saída de `iptables-save` na MESMA
		//     tabela, e uma linha nesse formato seria recusada com 400 pelo botão
		//     novo e APLICADA pela rota legada. `iptables-restore` sem `-n` dá
		//     flush em `ip filter/nat/mangle` — que são as chains do Docker.
		//
		// Ou seja: as duas juntas formavam um caminho para apagar as chains de
		// terceiros de uma máquina de produção, sem trava e sem tela, para quem
		// tivesse o token. Backup e rollback do firewall são
		// POST /api/nftables/backup e POST /api/nftables/rollback.
		r.With(require(auth.PermFirewallRead)).Get("/api/firewall/backups", iptH.ListBackups)
		r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/rules", iptH.CreateRule)
		r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/rules", iptH.UpdateRule)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/firewall/rules", iptH.DeleteRule)

		// nftables (native firewall management — replaces iptables)
		nftH := handlers.NewNftablesHandler(s.nftSvc, s.db, s.frSvc)
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/overview", nftH.Overview)
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/ruleset", nftH.Ruleset)
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/managed", nftH.Managed)
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/backups", nftH.ListBackups)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/backup", nftH.Backup)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/rollback", nftH.Rollback)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/wan-host", nftH.WanHost)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/nftables/wan-host", nftH.WanHost)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/blocklist", nftH.Blocklist)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/nftables/blocklist", nftH.Blocklist)
		// The admin's own rules (Phase B, design spec §4.1): id-based CRUD
		// against the DB, not nft's volatile handle — every mutation
		// reconciles user_rules immediately so nft never lags what the panel
		// shows.
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/rules", nftH.ListRules)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/rules", nftH.CreateRule)
		r.With(require(auth.PermFirewallWrite)).Put("/api/nftables/rules", nftH.UpdateRule)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/nftables/rules", nftH.DeleteRule)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/rules/reorder", nftH.ReorderRules)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/rules/toggle", nftH.ToggleRule)
		// Grupos de regras (Fase C1, design spec §2): cada grupo é uma chain
		// própria, alcançada por um jump condicional a partir da forward.
		// Ligar/desligar o grupo é pôr/tirar esse jump; reordenar é reescrever
		// a forward. Mesmo gating das regras — ler é PermFirewallRead,
		// qualquer mutação é PermFirewallWrite.
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/groups", nftH.ListGroups)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups", nftH.CreateGroup)
		r.With(require(auth.PermFirewallWrite)).Put("/api/nftables/groups", nftH.UpdateGroup)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/nftables/groups", nftH.DeleteGroup)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups/toggle", nftH.ToggleGroup)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups/reorder", nftH.ReorderGroups)
		// Confirmar-ou-reverte (Fase C2, spec §5): toda mutação que envolve um
		// grupo de escopo input é aplicada com prazo de 90 segundos para o
		// operador confirmar que ainda tem acesso; sem confirmação, o LinkGuard
		// reverte sozinho. O GET é o que o painel lê para desenhar a faixa com
		// a contagem regressiva, e os dois POSTs são as saídas da janela.
		//
		// Confirmar e reverter são PermFirewallWrite porque mudam o firewall
		// que vai valer daqui em diante; ler o pendente é PermFirewallRead,
		// como toda outra leitura de firewall. Ler não pode ser mais restrito
		// que isso: um operador que enxerga o painel precisa enxergar a faixa
		// que explica por que a edição está travada.
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/pending", nftH.PendingChange)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/pending/confirm", nftH.ConfirmPendingChange)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/pending/revert", nftH.RevertPendingChange)

		// Port forwarding (DNAT)
		pfH := handlers.NewPortForwardHandler(s.db, s.nftSvc)
		r.With(require(auth.PermFirewallRead)).Get("/api/portforward", pfH.List)
		r.With(require(auth.PermFirewallWrite)).Post("/api/portforward", pfH.Upsert)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/portforward", pfH.Delete)

		// Failover events
		failH := handlers.NewFailoverHandler(s.failoverSvc)
		r.With(require(auth.PermMonitoringRead)).Get("/api/failover/events", failH.ListEvents)

		// Multi-WAN balancing (weighted multipath default route + scheduling)
		routingH := handlers.NewRoutingHandler(s.balancerSvc, s.db)
		r.With(require(auth.PermRoutesRead)).Get("/api/routing/balance", routingH.Status)
		r.With(require(auth.PermRoutesWrite)).Put("/api/routing/balance", routingH.UpdateConfig)
		r.With(require(auth.PermRoutesWrite)).Post("/api/routing/balance/apply", routingH.Apply)
		r.With(require(auth.PermRoutesWrite)).Post("/api/routing/balance/confirm", routingH.Confirm)
		r.With(require(auth.PermRoutesWrite)).Post("/api/routing/balance/rollback", routingH.Rollback)

		// Link stress-test (on-demand fault injection: outage / degradation)
		stressH := handlers.NewStressTestHandler(stresstest.NewService(s.exec, s.linkSvc, s.alertSvc), s.db)
		r.With(require(auth.PermRoutesRead)).Get("/api/stresstest/status", stressH.Status)
		r.With(require(auth.PermRoutesWrite)).Post("/api/stresstest/start", stressH.Start)
		r.With(require(auth.PermRoutesWrite)).Post("/api/stresstest/stop", stressH.Stop)

		// Alerts
		alertsH := handlers.NewAlertsHandler(s.alertSvc)
		r.With(require(auth.PermMonitoringRead)).Get("/api/alerts", alertsH.List)
		r.With(require(auth.PermMonitoringRead)).Put("/api/alerts/{id}/resolve", alertsH.Resolve)

		// Monitoring (Vigia health snapshot + config)
		monH := handlers.NewMonitoringHandler(s.mon, s.db)
		timelineH := handlers.NewTimelineHandler(s.rrdSvc, s.alertSvc)
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/health", monH.Health)
		r.With(require(auth.PermSystemRead)).Get("/api/system/updates", monH.Updates)
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/config", monH.GetConfig)
		r.With(require(auth.PermSystemWrite)).Put("/api/monitoring/config", monH.SetConfig)
		r.With(require(auth.PermMonitoringRead)).Get("/api/monitoring/timeline", timelineH.Timeline)

		// Notification channels (webhook/Telegram/e-mail)
		notifyH := handlers.NewNotifyHandler(s.db, s.notifySvc)
		r.With(require(auth.PermSystemRead)).Get("/api/notifications", notifyH.Get)
		r.With(require(auth.PermSystemWrite)).Put("/api/notifications", notifyH.Update)
		r.With(require(auth.PermSystemWrite)).Post("/api/notifications/test", notifyH.Test)

		// Logs / Audit
		logsH := handlers.NewLogsHandler(s.db)
		r.With(require(auth.PermLogsRead)).Get("/api/logs", logsH.List)

		// Backup / restore (admin: system.write)
		backupH := handlers.NewBackupHandler(s.db, s.sec, cfg.Version, s.backupSched)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup", backupH.Export)
		r.With(require(auth.PermSystemWrite)).Post("/api/backup/restore", backupH.Restore)
		r.With(require(auth.PermSystemWrite)).Put("/api/backup/passphrase", backupH.PassphraseSet)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/passphrase/status", backupH.PassphraseStatus)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/schedule", backupH.ScheduleGet)
		r.With(require(auth.PermSystemWrite)).Put("/api/backup/schedule", backupH.ScheduleSet)
		r.With(require(auth.PermSystemWrite)).Post("/api/backup/send-now", backupH.SendNow)
		r.With(require(auth.PermSystemWrite)).Get("/api/backup/last-run", backupH.LastRun)

		// In-app update (admin: system.write)
		updateH := handlers.NewUpdateHandler(s.db, s.sec, updater.NewService(s.exec, cfg.Version,
			func() string {
				tok, err := s.sec.Get("github_update_token")
				if err != nil {
					slog.Warn("update: failed to read GitHub token from secrets vault", "err", err)
				}
				return tok
			}))
		r.With(require(auth.PermSystemRead)).Get("/api/system/update/check", updateH.Check)
		r.With(require(auth.PermSystemWrite)).Post("/api/system/update/apply", updateH.Apply)
		r.With(require(auth.PermSystemRead)).Get("/api/system/update/token", updateH.TokenStatus)
		r.With(require(auth.PermSystemWrite)).Put("/api/system/update/token", updateH.SetToken)

		// AI advisory layer (BYOK): token, config, report history (admin:
		// system.write for mutations; reports gated on monitoring.read since
		// they're diagnostic output, same tier as other monitoring views)
		aiH := handlers.NewAIHandler(s.db, s.sec, s.aiClient)
		r.With(require(auth.PermSystemRead)).Get("/api/ai/status", aiH.Status)
		r.With(require(auth.PermSystemWrite)).Put("/api/ai/token", aiH.SetToken)
		r.With(require(auth.PermSystemWrite)).Delete("/api/ai/token", aiH.DeleteToken)
		r.With(require(auth.PermSystemWrite)).Post("/api/ai/token/test", aiH.TestToken)
		r.With(require(auth.PermSystemWrite)).Put("/api/ai/config", aiH.SetConfig)
		r.With(require(auth.PermMonitoringRead)).Get("/api/ai/reports", aiH.ListReports)
		r.With(require(auth.PermMonitoringRead)).Get("/api/ai/reports/{id}", aiH.GetReport)

		// DHCP / DNS (Kea + unbound)
		netH := handlers.NewNetsvcHandler(s.db, s.netSvc, s.alertSvc)
		r.With(require(auth.PermDHCPRead)).Get("/api/dhcp", netH.GetDHCP)
		r.With(require(auth.PermDHCPWrite)).Put("/api/dhcp/config", netH.UpdateDHCPConfig)
		r.With(require(auth.PermDHCPWrite)).Post("/api/dhcp/reservations", netH.UpsertReservation)
		r.With(require(auth.PermDHCPWrite)).Delete("/api/dhcp/reservations", netH.DeleteReservation)
		r.With(require(auth.PermDNSRead)).Get("/api/dns", netH.GetDNS)
		r.With(require(auth.PermDNSWrite)).Put("/api/dns/config", netH.UpdateDNSConfig)
		r.With(require(auth.PermDNSWrite)).Post("/api/dns/blocklist", netH.AddBlocklist)
		r.With(require(auth.PermDNSWrite)).Delete("/api/dns/blocklist", netH.DeleteBlocklist)
		r.With(require(auth.PermDHCPRead)).Get("/api/netsvc/preview", netH.Preview)
		r.With(require(auth.PermDHCPWrite)).Post("/api/netsvc/apply", netH.Apply)

		// DNS query log (unbound journal; opt-in via DNS log_queries)
		dnsLogH := handlers.NewDNSLogHandler(dnslog.NewService(s.exec))
		r.With(require(auth.PermDNSRead)).Get("/api/dns/queries", dnsLogH.Recent)

		// NTP (chrony) — status, servidores customizados, timezone, instalar sob
		// demanda, e (2026-08-11) servir a LAN: nftSvc protege via a chain de
		// input, e a mudança do toggle reaplica o DHCP/DNS para anunciar (ou
		// deixar de anunciar) a opção ntp-servers.
		ntpSvc := timesync.NewService(s.exec)
		ntpSvc.SetInstallExecutor(cfg.PkgExec)
		ntpH := handlers.NewNTPHandler(s.db, ntpSvc, s.alertSvc, s.nftSvc)
		handlers.WireNTPDHCPReload(ntpH, netH)
		r.With(require(auth.PermNTPRead)).Get("/api/ntp", ntpH.GetNTP)
		r.With(require(auth.PermNTPWrite)).Put("/api/ntp/config", ntpH.UpdateNTPConfig)
		r.With(require(auth.PermNTPWrite)).Post("/api/ntp/apply", ntpH.Apply)
		r.With(require(auth.PermNTPWrite)).Post("/api/ntp/install-chrony", ntpH.InstallChrony)

		// Host inventory
		hostsH := handlers.NewHostsHandler(s.hostSvc, s.db)
		r.With(require(auth.PermHostsRead)).Get("/api/hosts", hostsH.List)
		trafficH := handlers.NewTrafficHandler(s.trafficSvc, s.db)
		r.With(require(auth.PermHostsRead)).Get("/api/hosts/traffic", trafficH.TopTalkers)
		r.With(require(auth.PermHostsBlock)).Put("/api/hosts/alias", hostsH.SetAlias)
		r.With(require(auth.PermHostsBlock)).Post("/api/hosts/block", hostsH.SetBlocked)

		// Interface inventory (read-only, Phase 1)
		netifH := handlers.NewNetifHandler(s.netifSvc, s.db)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces", netifH.List)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/drift", netifH.Drift)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/{name}/identify", netifH.Identify)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/preview", netifH.Preview)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/apply", netifH.Apply)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/confirm", netifH.Confirm)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/rollback", netifH.Rollback)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/pending", netifH.Pending)
		r.With(require(auth.PermInterfacesRead)).Get("/api/interfaces/stable-names", netifH.StableNames)
		r.With(require(auth.PermInterfacesWrite)).Post("/api/interfaces/stable-names/apply", netifH.ApplyStableNames)

		// User & role management (RBAC administration)
		usersH := handlers.NewUsersHandler(s.db)
		r.With(require(auth.PermUsersManage)).Get("/api/users", usersH.List)
		r.With(require(auth.PermUsersManage)).Post("/api/users", usersH.Create)
		r.With(require(auth.PermUsersManage)).Put("/api/users/{id}", usersH.Update)
		r.With(require(auth.PermUsersManage)).Delete("/api/users/{id}", usersH.Delete)

		rolesH := handlers.NewRolesHandler(s.db)
		r.With(require(auth.PermRolesManage)).Get("/api/permissions", rolesH.Catalog)
		r.With(require(auth.PermRolesManage)).Get("/api/roles", rolesH.List)
		r.With(require(auth.PermRolesManage)).Post("/api/roles", rolesH.Create)
		r.With(require(auth.PermRolesManage)).Put("/api/roles/{id}", rolesH.Update)
		r.With(require(auth.PermRolesManage)).Delete("/api/roles/{id}", rolesH.Delete)
	})

	// Serve embedded frontend for all other routes
	s.mountWebUI(r)

	return r
}

func (s *Server) mountWebUI(r *chi.Mux) {
	webDist, err := fs.Sub(s.webFS, "web/dist")
	if err != nil {
		slog.Warn("web UI not available", "err", err)
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Web UI not built. Run: make build-frontend", http.StatusNotFound)
		})
		return
	}
	fileServer := http.FileServer(http.FS(webDist))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		// If the requested asset is missing (SPA route), serve index.html.
		if st, err := fs.Stat(webDist, path); err != nil || st.IsDir() {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// backupRestorePath is exempt from the global maxBodySize cap: it manages
// its own, larger http.MaxBytesReader call (see BackupHandler.Restore).
// http.MaxBytesReader nests rather than replaces — a second call wraps
// whatever r.Body currently is, and reads still flow through the inner
// reader first, so the *smaller* of two nested limits always wins, not the
// most recently applied one. If the global middleware wrapped this route's
// body too, restore would be silently capped at the global 2MB instead of
// its intended 32MB. Skipping it here means Restore's own MaxBytesReader
// call is the only one that ever wraps this route's body.
const backupRestorePath = "/api/backup/restore"

// maxBodySize caps request bodies globally — the vast majority of this API's
// endpoints only ever receive small JSON bodies (a few KB at most). Backup
// restore is the one legitimate exception (see backupRestorePath) and is
// skipped here so its own, larger limit is the only one applied to it.
func maxBodySize(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == backupRestorePath {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration", time.Since(start))
	})
}
