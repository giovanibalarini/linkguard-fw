// Package alerts manages system alerts generation and retrieval.
package alerts

import (
	"fmt"
	"log/slog"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const (
	TypeLinkOffline    = "link_offline"
	TypeLinkOnline     = "link_online"
	TypeLinkDegraded   = "link_degraded"
	TypeFailover       = "failover"
	TypeRouteChanged   = "route_changed"
	TypeRuleError      = "rule_error"
	TypeHighCPU        = "high_cpu"
	TypeHighMemory     = "high_memory"
	TypeGatewayDown    = "gateway_down"
	TypeServiceOffline = "service_offline"
	TypeServiceOnline  = "service_online"
	TypeDiskFull       = "disk_full"
	TypeAppDown        = "app_down"

	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Notifier delivers an alert to external channels (webhook/Telegram/e-mail).
// Implemented by internal/notify; kept as a local interface to avoid a cycle.
type Notifier interface {
	Notify(severity, title, message string)
	NotifyRecovery(title, message string)
}

// Service manages alert generation and retrieval.
type Service struct {
	db       *storage.DB
	notifier Notifier
}

// NewService creates a new alerts Service.
func NewService(db *storage.DB) *Service {
	return &Service{db: db}
}

// SetNotifier wires an external-delivery observer (best-effort, async).
func (s *Service) SetNotifier(n Notifier) {
	s.notifier = n
}

// Create creates a new alert.
func (s *Service) Create(alertType, severity, title, message, linkID string) error {
	a := &storage.Alert{
		Type:     alertType,
		Severity: severity,
		Title:    title,
		Message:  message,
		LinkID:   linkID,
	}
	if err := s.db.CreateAlert(a); err != nil {
		slog.Error("create alert", "err", err)
		return err
	}
	slog.Info("alert created", "type", alertType, "severity", severity, "title", title)
	if s.notifier != nil {
		s.notifier.Notify(severity, title, message)
	}
	return nil
}

// createRecovery is like Create but delivers via the recovery path (bypasses
// the min-severity gate) so "voltou" always reaches the user.
func (s *Service) createRecovery(alertType, title, message, linkID string) error {
	a := &storage.Alert{Type: alertType, Severity: SeverityInfo, Title: title, Message: message, LinkID: linkID}
	if err := s.db.CreateAlert(a); err != nil {
		slog.Error("create alert", "err", err)
		return err
	}
	slog.Info("alert created", "type", alertType, "severity", SeverityInfo, "title", title)
	if s.notifier != nil {
		s.notifier.NotifyRecovery(title, message)
	}
	return nil
}

// LinkOffline raises a critical alert when a link goes offline.
func (s *Service) LinkOffline(linkName, linkID string) error {
	return s.Create(TypeLinkOffline, SeverityCritical,
		"Link Offline: "+linkName,
		"WAN link "+linkName+" is no longer reachable.", linkID)
}

// LinkOnline raises an info alert when a link recovers, delivered via the
// recovery path so it bypasses the min-severity gate.
func (s *Service) LinkOnline(linkName, linkID string) error {
	s.AutoResolve(TypeLinkOffline, linkID)
	s.AutoResolve(TypeLinkDegraded, linkID)
	return s.createRecovery(TypeLinkOnline,
		"Link Online: "+linkName,
		"WAN link "+linkName+" has recovered and is reachable.", linkID)
}

// ServiceOffline raises a critical alert when a monitored service stops.
func (s *Service) ServiceOffline(name string) error {
	return s.Create(TypeServiceOffline, SeverityCritical,
		"Serviço offline: "+name,
		"O serviço "+name+" parou de responder.", "")
}

// ServiceOnline clears the offline alert and notifies recovery.
func (s *Service) ServiceOnline(name string) error {
	s.AutoResolve(TypeServiceOffline, "")
	return s.createRecovery(TypeServiceOnline,
		"Serviço recuperado: "+name,
		"O serviço "+name+" voltou a responder.", "")
}

// DiskFull raises a critical alert when disk usage crosses the threshold.
func (s *Service) DiskFull(pct float64) error {
	return s.Create(TypeDiskFull, SeverityCritical, "Disco cheio",
		fmt.Sprintf("Uso de disco em %.1f%%.", pct), "")
}

// DiskCleared notifies that disk usage dropped back below the threshold.
func (s *Service) DiskCleared(pct float64) error {
	s.AutoResolve(TypeDiskFull, "")
	return s.createRecovery(TypeDiskFull, "Disco normalizado",
		fmt.Sprintf("Uso de disco voltou a %.1f%%.", pct), "")
}

// AppDown raises a critical alert that the linkguard-fw service itself stopped
// (called from the --notify-down subcommand via systemd OnFailure).
func (s *Service) AppDown() error {
	return s.Create(TypeAppDown, SeverityCritical, "LinkGuard caiu",
		"O serviço linkguard-fw parou inesperadamente.", "")
}

// LinkDegraded raises a warning when a link is degraded.
func (s *Service) LinkDegraded(linkName, linkID string) error {
	return s.Create(TypeLinkDegraded, SeverityWarning,
		"Link Degraded: "+linkName,
		"WAN link "+linkName+" is experiencing high packet loss or latency.", linkID)
}

// Failover raises a warning when failover is triggered.
func (s *Service) Failover(linkName, direction string) error {
	return s.Create(TypeFailover, SeverityWarning,
		"Failover: "+linkName,
		"Failover triggered for WAN link "+linkName+". Direction: "+direction, "")
}

// RuleError raises a critical alert when a firewall rule fails.
func (s *Service) RuleError(detail string) error {
	return s.Create(TypeRuleError, SeverityCritical, "Firewall Rule Error", detail, "")
}

// HighCPU raises a warning when CPU usage exceeds a threshold.
func (s *Service) HighCPU(percent float64) error {
	return s.Create(TypeHighCPU, SeverityWarning, "High CPU Usage",
		fmt.Sprintf("CPU usage is at %.1f%%.", percent), "")
}

// HighMemory raises a warning when memory usage exceeds a threshold.
func (s *Service) HighMemory(percent float64) error {
	return s.Create(TypeHighMemory, SeverityWarning, "High Memory Usage",
		fmt.Sprintf("Memory usage is at %.1f%%.", percent), "")
}

// CPUNormal clears the high-CPU alert and notifies recovery.
func (s *Service) CPUNormal(percent float64) error {
	s.AutoResolve(TypeHighCPU, "")
	return s.createRecovery(TypeHighCPU, "CPU normalizada",
		fmt.Sprintf("Uso de CPU voltou a %.1f%%.", percent), "")
}

// MemoryNormal clears the high-memory alert and notifies recovery.
func (s *Service) MemoryNormal(percent float64) error {
	s.AutoResolve(TypeHighMemory, "")
	return s.createRecovery(TypeHighMemory, "Memória normalizada",
		fmt.Sprintf("Uso de memória voltou a %.1f%%.", percent), "")
}

// List returns recent alerts.
func (s *Service) List(unresolvedOnly bool, limit int) ([]storage.Alert, error) {
	return s.db.GetAlerts(unresolvedOnly, limit)
}

// Resolve marks an alert as resolved.
func (s *Service) Resolve(id string) error {
	return s.db.ResolveAlert(id)
}

// AutoResolve resolves open alerts of the given type for a specific link.
func (s *Service) AutoResolve(alertType, linkID string) {
	alerts, err := s.db.GetAlerts(true, 0)
	if err != nil {
		return
	}
	for _, a := range alerts {
		if a.Type == alertType && a.LinkID == linkID {
			_ = s.db.ResolveAlert(a.ID)
		}
	}
}
