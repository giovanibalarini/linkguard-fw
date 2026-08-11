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
	TypeBackupFailed   = "backup_failed"

	TypeNTPUnsynced       = "ntp_unsynced"
	TypeNTPSynced         = "ntp_synced"
	TypeDiskSMARTFail     = "disk_smart_fail"
	TypeDiskSMARTOK       = "disk_smart_ok"
	TypeDiskSMARTDegraded = "disk_smart_degraded"
	TypeDiskSMARTHot      = "disk_smart_hot"
	TypeSlowBoot          = "slow_boot"
	TypeJournalCorrupt    = "journal_corrupt"
	TypeJournalOK         = "journal_ok"

	TypeFirewallNATDrift       = "firewall_nat_drift"
	TypeFirewallNATOK          = "firewall_nat_ok"
	TypeWANInterfaceMissing    = "wan_interface_missing"
	TypeWANInterfaceOK         = "wan_interface_ok"
	TypeDNSResolverDrift       = "dns_resolver_drift"
	TypeDNSResolverOK          = "dns_resolver_ok"
	TypeSecurityUpdatesPending = "security_updates_pending"
	TypeSecurityUpdatesNone    = "security_updates_none"

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

// LinkDegraded raises a warning when a link is degraded. latencyMs and
// packetLossPct are the measurement that triggered the transition — embedding
// them in the message is what turns "is experiencing high packet loss or
// latency" (which forced every past investigation to go read the journal by
// hand) into something a human can act on without opening the timeline.
func (s *Service) LinkDegraded(linkName, linkID string, latencyMs, packetLossPct float64) error {
	return s.Create(TypeLinkDegraded, SeverityWarning,
		"Link Degraded: "+linkName,
		fmt.Sprintf("WAN link %s is experiencing high packet loss or latency (latency=%.1fms, loss=%.1f%%).",
			linkName, latencyMs, packetLossPct), linkID)
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

// BackupFailed raises a warning alert when the periodic (or manual "enviar
// agora") backup e-mail fails to send. Severity is warning, not critical —
// the server's own configuration didn't change, only the off-site copy is
// late; it's not a service outage.
func (s *Service) BackupFailed(detail string) error {
	return s.Create(TypeBackupFailed, SeverityWarning, "Falha ao enviar backup",
		"O backup automático não pôde ser enviado: "+detail, "")
}

// BackupSucceeded clears BackupFailed and notifies recovery.
func (s *Service) BackupSucceeded() error {
	s.AutoResolve(TypeBackupFailed, "")
	return s.createRecovery(TypeBackupFailed, "Backup enviado",
		"O backup automático voltou a ser enviado com sucesso.", "")
}

// NTPUnsynced raises a warning when the system clock is not NTP-synchronized
// — a silent degradation (logs, TLS, TOTP 2FA all depend on correct time),
// not a service outage, hence Warning not Critical.
func (s *Service) NTPUnsynced() error {
	return s.Create(TypeNTPUnsynced, SeverityWarning, "Relógio dessincronizado",
		"O relógio do sistema não está sincronizado via NTP.", "")
}

// NTPSynced clears NTPUnsynced and notifies recovery.
func (s *Service) NTPSynced() error {
	s.AutoResolve(TypeNTPUnsynced, "")
	return s.createRecovery(TypeNTPSynced, "Relógio sincronizado",
		"O relógio do sistema voltou a sincronizar via NTP.", "")
}

// DiskSMARTFail raises a critical alert when the disk's own S.M.A.R.T.
// self-assessment reports failure — the strongest signal this package
// raises, since the drive firmware itself is reporting trouble.
func (s *Service) DiskSMARTFail() error {
	return s.Create(TypeDiskSMARTFail, SeverityCritical, "Disco: falha no SMART",
		"O disco reporta falha no autodiagnóstico SMART — considere substituí-lo.", "")
}

// DiskSMARTOK clears DiskSMARTFail and notifies recovery.
func (s *Service) DiskSMARTOK() error {
	s.AutoResolve(TypeDiskSMARTFail, "")
	return s.createRecovery(TypeDiskSMARTOK, "Disco: SMART normalizado",
		"O disco voltou a passar no autodiagnóstico SMART.", "")
}

// DiskSMARTDegraded raises a warning when the disk's reallocated-sector count
// crosses the configured threshold — an earlier, softer signal than
// DiskSMARTFail. Signature matches Collector.checkResource's `high`
// callback.
func (s *Service) DiskSMARTDegraded(count float64) error {
	return s.Create(TypeDiskSMARTDegraded, SeverityWarning, "Disco: setores realocados",
		fmt.Sprintf("O disco reporta %.0f setor(es) realocado(s) via SMART.", count), "")
}

// DiskSMARTNormal clears DiskSMARTDegraded and notifies recovery. Signature
// matches Collector.checkResource's `normal` callback.
func (s *Service) DiskSMARTNormal(count float64) error {
	s.AutoResolve(TypeDiskSMARTDegraded, "")
	return s.createRecovery(TypeDiskSMARTDegraded, "Disco: setores realocados normalizados",
		fmt.Sprintf("Contagem de setores realocados voltou a %.0f.", count), "")
}

// DiskSMARTHot raises a warning when disk temperature crosses the configured
// threshold. Signature matches Collector.checkResource's `high` callback.
func (s *Service) DiskSMARTHot(tempC float64) error {
	return s.Create(TypeDiskSMARTHot, SeverityWarning, "Disco: temperatura alta",
		fmt.Sprintf("Temperatura do disco em %.0f°C.", tempC), "")
}

// DiskSMARTCool clears DiskSMARTHot and notifies recovery. Signature matches
// Collector.checkResource's `normal` callback.
func (s *Service) DiskSMARTCool(tempC float64) error {
	s.AutoResolve(TypeDiskSMARTHot, "")
	return s.createRecovery(TypeDiskSMARTHot, "Disco: temperatura normalizada",
		fmt.Sprintf("Temperatura do disco voltou a %.0f°C.", tempC), "")
}

// SlowBoot raises a one-time warning when the box takes longer than the
// configured threshold to reach its first monitoring tick. There is no
// recovery counterpart: a slow boot can't un-happen, only the next reboot
// can be fast.
func (s *Service) SlowBoot(seconds float64) error {
	return s.Create(TypeSlowBoot, SeverityWarning, "Boot lento",
		fmt.Sprintf("O sistema levou %.0fs para o LinkGuard ficar pronto neste boot.", seconds), "")
}

// JournalCorrupt raises a warning when a periodic `journalctl --verify` finds
// corruption — degrades observability, not an operational outage, hence
// Warning.
func (s *Service) JournalCorrupt(detail string) error {
	return s.Create(TypeJournalCorrupt, SeverityWarning, "Logs do sistema corrompidos",
		"journalctl --verify encontrou corrupção: "+detail, "")
}

// JournalOK clears JournalCorrupt and notifies recovery (a corrupted journal
// file rotating out of retention is enough to "heal" this on its own).
func (s *Service) JournalOK() error {
	s.AutoResolve(TypeJournalCorrupt, "")
	return s.createRecovery(TypeJournalOK, "Logs do sistema normalizados",
		"journalctl --verify não encontra mais corrupção nos logs.", "")
}

// FirewallNATDrift raises a critical alert when the live masquerade rule no
// longer matches the configured WAN links — the exact failure that took
// WAN1's NAT down in production on 2026-08-10 with no signal on the panel.
// Critical because, unlike a degraded disk, it means traffic is not being
// translated right now.
func (s *Service) FirewallNATDrift(detail string) error {
	return s.Create(TypeFirewallNATDrift, SeverityCritical, "Regra de NAT inconsistente",
		"A regra de NAT ativa não corresponde às WANs configuradas: "+detail, "")
}

// FirewallNATOK clears FirewallNATDrift and notifies recovery.
func (s *Service) FirewallNATOK() error {
	s.AutoResolve(TypeFirewallNATDrift, "")
	return s.createRecovery(TypeFirewallNATOK, "Regra de NAT consistente",
		"A regra de NAT voltou a corresponder às WANs configuradas.", "")
}

// WANInterfaceMissing raises a critical alert when a configured WAN link
// points at a network interface that does not exist on the box — typically
// after a NIC rename (PCI reshuffle), which is what happened in production.
func (s *Service) WANInterfaceMissing(detail string) error {
	return s.Create(TypeWANInterfaceMissing, SeverityCritical, "Interface WAN inexistente",
		"Um link WAN aponta para uma interface que não existe: "+detail, "")
}

// WANInterfaceOK clears WANInterfaceMissing and notifies recovery.
func (s *Service) WANInterfaceOK() error {
	s.AutoResolve(TypeWANInterfaceMissing, "")
	return s.createRecovery(TypeWANInterfaceOK, "Interfaces WAN consistentes",
		"Todos os links WAN apontam para interfaces existentes.", "")
}

// DNSResolverDrift raises a warning when the box is not using its own
// resolver — it still resolves names, so it is not an outage, but the DNS
// blocklist and query visibility are silently bypassed.
func (s *Service) DNSResolverDrift(detail string) error {
	return s.Create(TypeDNSResolverDrift, SeverityWarning, "Resolver DNS externo em uso",
		"O sistema não está usando o resolver local (unbound): "+detail, "")
}

// DNSResolverOK clears DNSResolverDrift and notifies recovery.
func (s *Service) DNSResolverOK() error {
	s.AutoResolve(TypeDNSResolverDrift, "")
	return s.createRecovery(TypeDNSResolverOK, "Resolver DNS local em uso",
		"O sistema voltou a usar o resolver local (unbound).", "")
}

// SecurityUpdatesPending raises a warning when security updates are waiting
// to be installed. Warning, not Critical: it is a maintenance signal, and
// crying Critical over routine patching trains the operator to ignore
// Critical alerts.
func (s *Service) SecurityUpdatesPending(detail string) error {
	return s.Create(TypeSecurityUpdatesPending, SeverityWarning, "Atualizações de segurança pendentes",
		"Há atualizações de segurança do sistema aguardando instalação: "+detail, "")
}

// SecurityUpdatesNone clears SecurityUpdatesPending and notifies recovery.
func (s *Service) SecurityUpdatesNone() error {
	s.AutoResolve(TypeSecurityUpdatesPending, "")
	return s.createRecovery(TypeSecurityUpdatesNone, "Sem atualizações de segurança pendentes",
		"Não há atualizações de segurança aguardando instalação.", "")
}
