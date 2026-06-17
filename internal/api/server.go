// Package api provides the HTTP server and route registration for LinkGuard FW.
package api

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/failover"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/iptables"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
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
	alertSvc    *alerts.Service
	authSvc     *auth.Service
	sysCol      *system.Collector
	promReg     *prometheus.Registry
	webFS       embed.FS
}

// Config holds server configuration.
type Config struct {
	Addr    string
	DryRun  bool
	WebFS   embed.FS
	PromReg *prometheus.Registry
}

// New creates and wires up the HTTP server.
func New(cfg Config, db *storage.DB, exec firewall.Executor,
	linkSvc *links.Service, iptSvc *iptables.Service, routeSvc *routes.Service,
	failoverSvc *failover.Service, alertSvc *alerts.Service, authSvc *auth.Service,
	sysCol *system.Collector, promReg *prometheus.Registry) *Server {

	s := &Server{
		db:          db,
		exec:        exec,
		linkSvc:     linkSvc,
		iptSvc:      iptSvc,
		routeSvc:    routeSvc,
		failoverSvc: failoverSvc,
		alertSvc:    alertSvc,
		authSvc:     authSvc,
		sysCol:      sysCol,
		promReg:     promReg,
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
	healthH := handlers.NewHealthHandler(s.db, s.sysCol)
	r.Get("/api/health", healthH.Health)

	// Protected API routes
	r.Group(func(r chi.Router) {
		r.Use(s.authSvc.Middleware)

		// System
		sysH := handlers.NewSystemHandler(s.sysCol)
		r.Get("/api/system/status", sysH.Status)

		// Links
		linksH := handlers.NewLinksHandler(s.linkSvc, s.db)
		r.Get("/api/links", linksH.List)
		r.Post("/api/links", linksH.Create)
		r.Get("/api/links/{id}", linksH.Get)
		r.Put("/api/links/{id}", linksH.Update)
		r.Delete("/api/links/{id}", linksH.Delete)

		// Routes
		routesH := handlers.NewRoutesHandler(s.routeSvc)
		r.Get("/api/routes", routesH.List)
		r.Get("/api/routes/rules", routesH.ListRules)

		// iptables
		iptH := handlers.NewIptablesHandler(s.iptSvc, s.db)
		r.Get("/api/iptables/rules", iptH.ListAll)
		r.Get("/api/iptables/nat", iptH.ListNat)
		r.Get("/api/iptables/mangle", iptH.ListMangle)
		r.Get("/api/iptables/filter", iptH.ListFilter)
		r.Post("/api/firewall/preview", iptH.Preview)
		r.Post("/api/firewall/backup", iptH.Backup)
		r.Post("/api/firewall/rollback", iptH.Rollback)
		r.Get("/api/firewall/backups", iptH.ListBackups)

		// Failover events
		failH := handlers.NewFailoverHandler(s.failoverSvc)
		r.Get("/api/failover/events", failH.ListEvents)

		// Alerts
		alertsH := handlers.NewAlertsHandler(s.alertSvc)
		r.Get("/api/alerts", alertsH.List)
		r.Put("/api/alerts/{id}/resolve", alertsH.Resolve)

		// Logs / Audit
		logsH := handlers.NewLogsHandler(s.db)
		r.Get("/api/logs", logsH.List)
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
		fileServer.ServeHTTP(w, r)
	})
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
