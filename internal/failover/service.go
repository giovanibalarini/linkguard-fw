// Package failover implements automatic failover logic for WAN links.
package failover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/routes"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Config holds failover tuning parameters.
type Config struct {
	Enabled          bool
	DryRun           bool
	FailThreshold    int
	RecoverThreshold int
	CooldownSecs     int
}

// Service orchestrates failover when links change state.
type Service struct {
	cfg      Config
	db       *storage.DB
	exec     firewall.Executor
	routeSvc *routes.Service
	alertSvc *alerts.Service

	mu       sync.Mutex
	cooldown map[string]time.Time // key = link ID
}

// NewService creates a new failover Service.
func NewService(cfg Config, db *storage.DB, exec firewall.Executor,
	routeSvc *routes.Service, alertSvc *alerts.Service) *Service {
	return &Service{
		cfg:      cfg,
		db:       db,
		exec:     exec,
		routeSvc: routeSvc,
		alertSvc: alertSvc,
		cooldown: make(map[string]time.Time),
	}
}

// HandleStatusChange is the callback invoked when a link changes state.
// It applies or removes routes as needed.
func (s *Service) HandleStatusChange(link *storage.Link, oldStatus, newStatus string) {
	if !s.cfg.Enabled {
		slog.Info("failover disabled, skipping", "link", link.Name)
		return
	}

	s.mu.Lock()
	coolUntil := s.cooldown[link.ID]
	s.mu.Unlock()

	if time.Now().Before(coolUntil) {
		slog.Info("failover cooldown active, skipping", "link", link.Name,
			"cooldown_until", coolUntil)
		return
	}

	slog.Info("failover: status change", "link", link.Name,
		"from", oldStatus, "to", newStatus, "dry_run", s.cfg.DryRun)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmds []string
	var err error

	switch newStatus {
	case links.StatusOffline:
		cmds, err = s.handleLinkDown(ctx, link)
		_ = s.alertSvc.LinkOffline(link.Name, link.ID)
		_ = s.alertSvc.Failover(link.Name, "link down")
	case links.StatusOnline:
		cmds, err = s.handleLinkUp(ctx, link)
		_ = s.alertSvc.LinkOnline(link.Name, link.ID)
	case links.StatusDegraded:
		_ = s.alertSvc.LinkDegraded(link.Name, link.ID)
	}

	if err != nil {
		slog.Error("failover error", "link", link.Name, "err", err)
		_ = s.alertSvc.RuleError(fmt.Sprintf("Failover for %s failed: %v", link.Name, err))
	}

	// Record the event
	event := &storage.FailoverEvent{
		LinkID:     link.ID,
		LinkName:   link.Name,
		FromStatus: oldStatus,
		ToStatus:   newStatus,
		Commands:   strings.Join(cmds, "\n"),
		DryRun:     s.cfg.DryRun,
	}
	if err != nil {
		event.Reason = err.Error()
	}
	if dbErr := s.db.CreateFailoverEvent(event); dbErr != nil {
		slog.Error("store failover event", "err", dbErr)
	}

	// Apply cooldown
	s.mu.Lock()
	s.cooldown[link.ID] = time.Now().Add(time.Duration(s.cfg.CooldownSecs) * time.Second)
	s.mu.Unlock()
}

func (s *Service) handleLinkDown(ctx context.Context, link *storage.Link) ([]string, error) {
	if link.Gateway == "" {
		slog.Warn("no gateway configured for link, skipping route removal", "link", link.Name)
		return nil, nil
	}

	var cmds []string
	tableStr := fmt.Sprintf("%d", link.TableID)

	// Remove default route from link's routing table
	out, err := s.routeSvc.DelRoute(ctx, "default", tableStr)
	cmds = append(cmds, fmt.Sprintf("ip route del default table %s → %s", tableStr, out))
	if err != nil && !strings.Contains(err.Error(), "No such process") {
		slog.Warn("remove default route", "table", tableStr, "err", err)
	}

	slog.Info("link down: routes removed", "link", link.Name, "dry_run", s.cfg.DryRun,
		"commands", cmds)
	return cmds, nil
}

func (s *Service) handleLinkUp(ctx context.Context, link *storage.Link) ([]string, error) {
	if link.Gateway == "" || link.Interface == "" {
		slog.Warn("incomplete link configuration, skipping route restoration", "link", link.Name)
		return nil, nil
	}

	var cmds []string
	tableStr := fmt.Sprintf("%d", link.TableID)

	// Restore default route in link's routing table
	out, err := s.routeSvc.AddRoute(ctx, "default", link.Gateway, link.Interface, tableStr)
	cmds = append(cmds, fmt.Sprintf("ip route add default via %s dev %s table %s → %s",
		link.Gateway, link.Interface, tableStr, out))
	if err != nil {
		return cmds, fmt.Errorf("restore default route: %w", err)
	}

	slog.Info("link up: routes restored", "link", link.Name, "dry_run", s.cfg.DryRun,
		"commands", cmds)
	return cmds, nil
}

// GetEvents returns recent failover events.
func (s *Service) GetEvents(limit int) ([]storage.FailoverEvent, error) {
	return s.db.GetFailoverEvents(limit)
}
