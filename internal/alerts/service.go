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
	// TypeSelfUpdateFailed: a atualização pedida pelo painel não concluiu
	// (issue #101). Evento, não estado — como o backup_failed logo acima: não
	// existe "voltou ao normal" para uma tentativa que falhou, existe uma
	// próxima tentativa. Por isso não entra em stateAlertTypes nem tem par de
	// auto-resolve.
	TypeSelfUpdateFailed = "self_update_failed"

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
	TypeBaseDepsMissing        = "base_deps_missing"
	TypeBaseDepsOK             = "base_deps_ok"
	TypeNetsvcDepsMissing      = "netsvc_deps_missing"
	TypeNetsvcDepsOK           = "netsvc_deps_ok"

	TypeFirewallSystemGroupsMissing = "firewall_system_groups_missing"
	TypeFirewallSystemGroupsOK      = "firewall_system_groups_ok"

	// TypeFirewallGhostIface: alguma regra cita uma interface que não existe
	// mais na máquina (issue #83). Ela carrega no nft sem erro e nunca casa —
	// o painel mostra a regra ativa e ela não protege nada.
	TypeFirewallGhostIface = "firewall_ghost_iface"

	TypeFirewallChangeReverted = "firewall_change_reverted"

	TypeFirewallBootPersistFailed = "firewall_boot_persist_failed"
	TypeFirewallBootPersistOK     = "firewall_boot_persist_ok"

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

// stateAlertTypes are the problem types that represent an ongoing condition
// with a recovery counterpart that closes it — every type below is raised by
// one method and cleared by another's s.AutoResolve(type, ...) call
// (systemd unit back up, link back online, resource back under threshold,
// resolver back local, and so on). ResolveStaleOnStartup uses this list to
// decide what it is safe to close on a restart.
//
// TypeRuleError is deliberately excluded: it is a catch-all raised from
// seven unrelated call sites (failover, NTP apply, DHCP/DNS apply, and four
// in the balancer) with nothing that ever resolves it — see Create's doc
// comment for why. Clearing it at startup would silently discard a genuine
// unacknowledged failure that no watcher will ever re-raise on its own,
// since nothing observes a "rule_error fixed" transition.
//
// Also absent, and for the same underlying reason (no AutoResolve call
// anywhere resolves them): TypeSlowBoot ("a slow boot can't un-happen, only
// the next reboot can be fast" — see SlowBoot's doc comment), TypeFailover,
// and TypeAppDown. TypeGatewayDown and TypeRouteChanged are unused
// constants — nothing in this codebase raises them at all.
//
// TestStateAlertTypesMatchAutoResolveCallSites guards this list against
// drifting from service.go's actual AutoResolve call sites.
var stateAlertTypes = []string{
	TypeLinkOffline,
	TypeLinkDegraded,
	TypeServiceOffline,
	TypeDiskFull,
	TypeHighCPU,
	TypeHighMemory,
	TypeBackupFailed,
	TypeNTPUnsynced,
	TypeDiskSMARTFail,
	TypeDiskSMARTDegraded,
	TypeDiskSMARTHot,
	TypeJournalCorrupt,
	TypeFirewallNATDrift,
	TypeWANInterfaceMissing,
	TypeDNSResolverDrift,
	TypeSecurityUpdatesPending,
	TypeBaseDepsMissing,
	TypeNetsvcDepsMissing,
	TypeFirewallSystemGroupsMissing,
	TypeFirewallBootPersistFailed,
	TypeFirewallGhostIface,
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

// Create creates a new alert for an ongoing problem, unless one for the same
// (type, linkID) is already open.
//
// linkID identifica O QUE o alerta é sobre, e não necessariamente um link: é o
// id do link nos alertas de WAN, o nome da unidade nos de serviço
// (ServiceOffline), e "" nos que só podem existir uma vez por máquina (disco,
// CPU, relógio, NAT). O nome da coluna é herança de quando só os alertas de
// link a usavam; nada fora deste arquivo a lê — não há FK nem JOIN com
// links(id) e nenhuma tela a exibe. Passar "" para uma condição que pode
// existir mais de uma vez ao mesmo tempo é um bug: as instâncias colapsam numa
// vaga só e a recuperação de uma fecha o alerta das outras.
//
// (type, linkID) is already this package's identity for "an ongoing
// problem" — AutoResolve resolves every unresolved row matching that pair in
// one shot. A second unresolved row for the same pair carries no new
// information: it tells the operator nothing they don't already know, and
// re-notifying just trains them to ignore the channel. This is also what
// keeps the alert list stable across restarts: the health state that gates
// whether a condition is "new" (internal/monitoring's observe map) lives
// only in memory, so every restart or reboot re-evaluates every still-true
// condition from scratch and would otherwise re-fire it as if it were brand
// new. Once the earlier alert is resolved, though, the condition returning
// is genuinely new and must open a fresh row — so the check only looks at
// currently-unresolved alerts.
//
// TypeRuleError is the one deliberate exception to that identity, and is
// keyed by (type, linkID, message) instead. Every other type here has a
// recovery counterpart: it represents a *state* that opens and is later
// explicitly closed (AutoResolve / createRecovery), so (type, linkID) alone
// is a sound identity for it — there's exactly one open condition of that
// kind at a time. rule_error has no recovery path: it's a catch-all raised
// from seven unrelated call sites (failover, NTP apply, DHCP/DNS apply, and
// four in the balancer) with nothing to ever resolve it. Deduping it by type
// alone would mean the first rule_error ever recorded opens a row that never
// closes, permanently masking every later, unrelated Critical failure from
// any other subsystem — strictly worse than the pileup this dedupe exists to
// prevent. Keying it by message instead keeps the same restart-safety
// property (an identical repeated failure still collapses to one row) while
// letting a genuinely different failure stay visible.
func (s *Service) Create(alertType, severity, title, message, linkID string) error {
	alerts, err := s.db.GetAlerts(true, 0)
	if err != nil {
		slog.Error("create alert: check existing", "err", err)
		return err
	}
	for _, a := range alerts {
		if a.Type != alertType || a.LinkID != linkID {
			continue
		}
		if alertType == TypeRuleError && a.Message != message {
			continue
		}
		slog.Debug("alert suppressed: already open", "type", alertType, "linkID", linkID)
		return nil
	}

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
//
// The alert it stores is created already Resolved: a recovery alert
// announces a condition that has already ended ("link back online", "clock
// resynced", ...) — it is history the moment it is written, not an open
// condition to track. Leaving it unresolved (the pre-fix behavior) meant
// every recovery event permanently inflated the open-alert count with
// nothing left to ever resolve it — 114 of the 135 open alerts on the
// production box were exactly this: link_online rows that could never leave
// the unresolved bucket. It is still stored (so it shows in history) and
// still delivered via NotifyRecovery — only its "open" status changes.
func (s *Service) createRecovery(alertType, title, message, linkID string) error {
	a := &storage.Alert{Type: alertType, Severity: SeverityInfo, Title: title, Message: message, LinkID: linkID, Resolved: true}
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

// ServiceOffline abre o alerta crítico de que um serviço vigiado parou.
//
// O nome da unidade vai no campo de identidade (o mesmo que LinkOffline usa
// para o id do link) porque a identidade de um alerta em curso é
// (tipo, identificador) — sem ele, TODO service_offline dividia uma vaga só e
// o segundo serviço a cair era engolido pelo primeiro. Medido em VM (§14 da
// validação final): com um service_offline aberto para o nftables, o
// kea-dhcp4-server foi parado de verdade e nenhum alerta foi criado. Pior
// ainda, a volta de um serviço fechava o alerta do outro, e a tela passava a
// dizer que estava tudo bem com um serviço ainda caído — dado falso no painel,
// que é exatamente o que este projeto não admite.
//
// Sobre o nome do campo: a coluna se chama link_id por ter nascido servindo
// aos alertas de link, mas ela já não é um id de link há muito tempo — a
// maioria das chamadas de Create passa "" e nada no sistema a lê como
// chave estrangeira de links(id) (sem FK, sem JOIN, nenhuma tela a exibe).
// Quem a consome é só este arquivo: dedupe em Create, AutoResolve e
// ResolveStaleOnStartup, todos comparando string com string.
func (s *Service) ServiceOffline(name string) error {
	return s.Create(TypeServiceOffline, SeverityCritical,
		"Serviço offline: "+name,
		"O serviço "+name+" parou de responder.", name)
}

// ServiceOnline fecha o alerta DAQUELE serviço e anuncia a recuperação.
//
// O AutoResolve é por nome de serviço de propósito: fechar por "" varreria
// junto o alerta de qualquer outro serviço ainda caído.
//
// Alertas gravados por versões anteriores (com o identificador vazio) não
// ficam órfãos: service_offline está em stateAlertTypes, então o
// ResolveStaleOnStartup do primeiro boot depois do upgrade — e o postinst
// reinicia o serviço — fecha as linhas antigas lendo o identificador da
// própria linha. O que ainda estiver caído volta a ser levantado pelo vigia
// no ciclo seguinte, agora com o nome do serviço na chave. Por isso não há um
// AutoResolve(TypeServiceOffline, "") extra aqui: ele só teria efeito numa
// janela que não chega a existir, e reintroduziria justamente o acoplamento
// entre serviços que esta correção elimina.
func (s *Service) ServiceOnline(name string) error {
	s.AutoResolve(TypeServiceOffline, name)
	return s.createRecovery(TypeServiceOnline,
		"Serviço recuperado: "+name,
		"O serviço "+name+" voltou a responder.", name)
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

// GhostIface avisa que regras citam interfaces que não existem mais.
//
// A severidade depende de as regras órfãs BLOQUEAREM ou não, e a distinção não
// é cosmética: uma regra de accept que deixou de casar só faz o tráfego cair
// noutra linha; uma de drop que deixou de casar é uma proteção que sumiu, com o
// painel afirmando que ela continua lá.
//
// O texto nomeia as interfaces e diz quantas regras dependem de cada uma,
// porque a ação que o admin precisa tomar — reapontar ou apagar — exige saber
// exatamente onde mexer. "Uma interface não existe" mandaria ele procurar.
func (s *Service) GhostIface(detalhe string, bloqueando bool) error {
	sev := SeverityWarning
	titulo := "Regras apontam para uma interface que não existe mais"
	if bloqueando {
		sev = SeverityCritical
		titulo = "Um bloqueio do firewall não está em vigor: a interface não existe mais"
	}
	return s.Create(TypeFirewallGhostIface, sev, titulo, detalhe, "")
}

// GhostIfaceOK fecha o alerta quando nenhuma regra cita mais uma interface
// ausente — porque o admin reapontou, apagou a regra, ou a interface voltou.
//
// Fecha em SILÊNCIO (AutoResolve, sem linha de recuperação e sem notificação),
// e isso é deliberado: a condição some sozinha em casos banais, como uma
// interface USB reconectada. Anunciar "resolvido" a cada reconexão treinaria o
// operador a ignorar o canal — e é o mesmo tratamento que
// NetsvcDepsMissing já recebe quando o admin conserta por fora.
//
// Sem este método, o alerta ficaria vermelho para sempre depois de consertado.
// TestStateAlertTypesMatchAutoResolveCallSites existe exatamente para não
// deixar um alerta de estado nascer sem o par que o fecha.
func (s *Service) GhostIfaceOK() {
	s.AutoResolve(TypeFirewallGhostIface, "")
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

// ResolveStaleOnStartup closes state-derived alerts (stateAlertTypes) left
// open by a previous process. The health state that gates whether a
// condition is "new" (internal/monitoring's observe map, see Create's doc
// comment) lives only in memory, so a restart forgets which conditions were
// already true. Whatever is still genuinely wrong gets re-raised by the
// watchers within their next tick or two; whatever was fixed while the
// service was down — the exact situation that left three stale alerts open
// by hand on 2026-08-11 — stays closed instead of sitting red on the panel
// forever.
//
// This is bookkeeping, not an event worth pushing at the operator: it
// reuses AutoResolve directly, so it neither creates recovery rows nor
// notifies. Callers should invoke it once, early at startup, and before the
// collectors/schedulers start — otherwise a still-true condition raised (or
// re-raised) concurrently by an already-running watcher could race this
// cleanup and be resolved right back out from under it.
func (s *Service) ResolveStaleOnStartup() {
	open, err := s.db.GetAlerts(true, 0)
	if err != nil {
		slog.Error("resolve stale alerts on startup: list open alerts", "err", err)
		return
	}
	isStateType := make(map[string]bool, len(stateAlertTypes))
	for _, t := range stateAlertTypes {
		isStateType[t] = true
	}
	done := make(map[string]bool)
	for _, a := range open {
		if !isStateType[a.Type] {
			continue
		}
		key := a.Type + "\x00" + a.LinkID
		if done[key] {
			continue // AutoResolve already sweeps every row for this (type, linkID)
		}
		done[key] = true
		s.AutoResolve(a.Type, a.LinkID)
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

// FirewallBootPersistFailed abre o aviso de que o firewall vivo não está
// gravado no arquivo de boot: as regras valem AGORA e não sobreviveriam a um
// reboot. Medido em VM (§10 da validação final) com /etc imutável — o apply
// chega ao kernel, o painel responde, e a máquina voltaria de um reboot com um
// firewall diferente do que a tela mostrava.
//
// Warning, e não Critical, de propósito: nada está desprotegido neste instante,
// ao contrário da regra de NAT inconsistente (que é tráfego sem tradução agora).
// Gritar Critical por algo que só se materializa no próximo boot treina o
// operador a ignorar Critical — que é a razão pela qual este projeto já teve de
// corrigir um alerta crítico falso.
//
// A mensagem termina dizendo COMO SAIR, porque o alerta é lido por quem chega
// depois e não tem o contexto: devolver a permissão de escrita e REINICIAR o
// serviço. Medido em VM (cenário 5 da validação de 2026-08-13): uma mutação nova
// não resolve, por causa de `ProtectSystem=strict` +
// `ReadWritePaths=-/etc/nftables.conf` — ver nftables.Service.Persist.
func (s *Service) FirewallBootPersistFailed(detail string) error {
	return s.Create(TypeFirewallBootPersistFailed, SeverityWarning, "Regras não gravadas para o próximo boot",
		"O firewall em vigor não foi gravado no arquivo de boot; as regras valem agora, mas um reboot não as traria de volta: "+detail+
			". Para resolver: devolva a permissão de escrita em /etc/nftables.conf e reinicie o serviço (systemctl restart linkguard-fw). Aplicar outra regra NÃO resolve.", "")
}

// FirewallBootPersistOK fecha FirewallBootPersistFailed e anuncia a volta.
func (s *Service) FirewallBootPersistOK() error {
	s.AutoResolve(TypeFirewallBootPersistFailed, "")
	return s.createRecovery(TypeFirewallBootPersistOK, "Regras gravadas para o próximo boot",
		"O firewall em vigor voltou a ser gravado no arquivo de boot.", "")
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

// NetsvcDepsMissing raises the "the DHCP/DNS the admin asked for is not
// running" alert: the panel accepted the configuration, but the package that
// would serve it (kea-dhcp4-server, unbound) is not installed and LinkGuard
// could not install it either. Critical for the same reason BaseDepsMissing
// is: the box looks configured and is serving nothing, which is the false
// confidence this product exists to eliminate.
//
// It is deliberately NOT TypeRuleError (the catch-all the DHCP/DNS apply
// used to raise for every failure): "Firewall Rule Error" over a message
// about a missing package tells the admin to look in the wrong place, and
// nothing ever resolves a rule_error — while this condition does resolve,
// the moment the package gets installed.
func (s *Service) NetsvcDepsMissing(detail string) error {
	return s.Create(TypeNetsvcDepsMissing, SeverityCritical, "DHCP/DNS sem os pacotes necessários",
		detail, "")
}

// NetsvcDepsOK clears NetsvcDepsMissing and records that LinkGuard installed
// the DHCP/DNS packages itself. Raised only on the transition — an apply
// that had to install something — never on the routine applies that follow,
// which would turn the recovery into noise.
func (s *Service) NetsvcDepsOK(detail string) error {
	s.AutoResolve(TypeNetsvcDepsMissing, "")
	return s.createRecovery(TypeNetsvcDepsOK, "Pacotes do DHCP/DNS instalados",
		"O LinkGuard instalou sob demanda o que faltava para servir DHCP/DNS: "+detail, "")
}

// BaseDepsMissing raises the strongest alert this package has when LinkGuard
// could not install the packages it cannot work without (internal/bootstrapdeps).
// Critical, and deliberately the same severity as a NAT drift: the appliance is
// installed and the panel is up, but with nftables absent there is no packet
// filter at all — a box that looks alive and protects nothing is exactly the
// false confidence this product exists to eliminate. The detail carries the
// package names, what each one breaks, and the command to fix it by hand.
func (s *Service) BaseDepsMissing(detail string) error {
	return s.Create(TypeBaseDepsMissing, SeverityCritical, "Dependências base ausentes",
		"O LinkGuard não conseguiu instalar pacotes essenciais: "+detail, "")
}

// BaseDepsOK clears BaseDepsMissing and records that LinkGuard installed the
// base packages itself. Raised only on the transition (a boot that actually
// had to install something), never on every start — see bootstrapdeps.Ensure.
// BaseDepsPresent silently closes a stale "base ausente" alert. Nothing was
// installed by LinkGuard and there is no recovery to announce — the
// condition simply stopped being true, typically because the admin ran
// apt-get over SSH. Before this existed, that alert was only ever created
// or cleared by an install LinkGuard itself performed, so an admin who
// fixed it by hand kept a red critical alert until the next service
// restart. No-op when nothing is open.
func (s *Service) BaseDepsPresent() {
	s.AutoResolve(TypeBaseDepsMissing, "")
}

// FirewallSystemGroupsMissing raises the critical alert that says the two
// system groups (blocked hosts, blocked destinations) are no longer in the
// group list even though the migration that creates them has already run —
// which is why internal/firewallrules.Service.Reconcile refused to rebuild
// the forward chain. The firewall is still enforcing whatever was last
// applied; what is broken is the ability to apply anything new, and the
// reason is that applying it would drop the administrative blocks.
func (s *Service) FirewallSystemGroupsMissing(detail string) error {
	return s.Create(TypeFirewallSystemGroupsMissing, SeverityCritical,
		"Bloqueios fora da lista de grupos", detail, "")
}

// FirewallSystemGroupsOK closes the alert above once the list is whole
// again — and announces the recovery, but ONLY when something was actually
// open. Reconcile calls this on every successful pass (every boot and every
// rule mutation), so announcing unconditionally would file a recovery row
// each time and bury the alert list under history, the same pileup
// createRecovery's doc comment describes.
//
// A mensagem afirma que a chain forward foi reconstruída, então quem chama
// só pode chamar DEPOIS de o apply ter dado certo — a lista estar completa
// não reconstrói nada por si só. Ver o comentário no fim de
// firewallrules.Service.Reconcile.
func (s *Service) FirewallSystemGroupsOK() {
	open, err := s.db.GetAlerts(true, 0)
	if err != nil {
		return
	}
	found := false
	for _, a := range open {
		if a.Type == TypeFirewallSystemGroupsMissing && a.LinkID == "" {
			found = true
			break
		}
	}
	if !found {
		return
	}
	s.AutoResolve(TypeFirewallSystemGroupsMissing, "")
	_ = s.createRecovery(TypeFirewallSystemGroupsOK, "Bloqueios de volta na lista de grupos",
		"Os grupos do sistema voltaram a aparecer na lista e a chain forward foi reconstruída com os bloqueios.", "")
}

// FirewallChangeReverted registra que uma mudança de firewall aplicada e NÃO
// confirmada foi desfeita sozinha (Fase C2, spec §5): ou o prazo de 90
// segundos terminou sem ninguém confirmar, ou o LinkGuard reiniciou com a
// janela ainda aberta.
//
// É como o operador descobre, quando voltar, que a alteração dele não está
// mais valendo — e por quê. Sem isto a máquina desfaz sozinha em silêncio, e
// ele reencontra um firewall diferente do que deixou sem nada que explique a
// diferença: a pior forma de um firewall se comportar.
//
// Deliberadamente FORA de stateAlertTypes, pela mesma razão de TypeSlowBoot:
// não é uma condição em curso que alguma recuperação fecha — uma reversão que
// aconteceu não pode desacontecer. O operador resolve o alerta quando tiver
// lido, como faz com o de boot lento.
//
// Warning, não critical: a máquina está num estado bom e conhecido (o
// anterior). O que ele precisa é ficar sabendo, não ser acordado.
func (s *Service) FirewallChangeReverted(detail string) error {
	return s.Create(TypeFirewallChangeReverted, SeverityWarning,
		"Mudança de firewall revertida por falta de confirmação", detail, "")
}

func (s *Service) BaseDepsOK(detail string) error {
	s.AutoResolve(TypeBaseDepsMissing, "")
	return s.createRecovery(TypeBaseDepsOK, "Dependências base instaladas",
		"O LinkGuard instalou os pacotes essenciais que faltavam: "+detail, "")
}
