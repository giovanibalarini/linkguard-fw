// Package stresstest runs bounded, self-restoring fault-injection tests against
// a WAN link (bring it down, or degrade it with tc netem) while measuring
// connectivity continuity (ping + DNS) and watching the balancer react. It is
// how an admin validates multi-WAN failover on demand instead of waiting for a
// real outage.
//
// Safety: every test captures the prior route, arms a bounded watchdog that
// uses the same per-interface owner as QoS, refuses to stress the only healthy
// link, and restores on finish or abort.
package stresstest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// reIface constrains interface names passed to ip/tc and persisted in the
// crash-recovery lease.
var reIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

const (
	pingTarget     = "8.8.8.8"
	dnsTarget      = "google.com"
	sampleInterval = 2 * time.Second

	minDuration = 30
	maxDuration = 300
)

// Mode is the fault type.
type Mode string

const (
	ModeOutage  Mode = "outage"  // ip link set down
	ModeDegrade Mode = "degrade" // tc netem delay/loss
)

// Sample is one point on the continuity timeline.
type Sample struct {
	T     string `json:"t"`
	Route string `json:"route"`
	Ping  bool   `json:"ping"`
	DNS   bool   `json:"dns"`
	Phase string `json:"phase"` // baseline | fault | recovery
}

// Test is a single stress-test run and its live/final state.
type Test struct {
	ID          string   `json:"id"`
	LinkID      string   `json:"link_id"`
	LinkName    string   `json:"link_name"`
	Interface   string   `json:"interface"`
	Mode        Mode     `json:"mode"`
	DelayMs     int      `json:"delay_ms"`
	LossPct     int      `json:"loss_pct"`
	DurationSec int      `json:"duration_sec"`
	State       string   `json:"state"` // running | done | aborted | error
	Message     string   `json:"message"`
	StartedAt   string   `json:"started_at"`
	EndedAt     string   `json:"ended_at"`
	Samples     []Sample `json:"samples"`
	PingLossPct float64  `json:"ping_loss_pct"`
	DNSLossPct  float64  `json:"dns_loss_pct"`
	Restored    bool     `json:"restored"`
}

// Service runs one stress test at a time.
type Service struct {
	exec     firewall.Executor
	linkSvc  *links.Service
	alertSvc *alerts.Service
	qosSvc   qosCoordinator
	recovery recoveryStore

	mu             sync.Mutex
	active         *Test
	cancel         context.CancelFunc
	watchdogCancel context.CancelFunc
	watchdogAfter  func(time.Duration) <-chan time.Time
	nowFn          func() string // injectable for tests
	nextID         func() string
}

type qosCoordinator interface {
	WithInterfaceLock(context.Context, string, func(qos.InterfaceOperations) error) error
}

type recoveryStore interface {
	SaveStressRecoveryLease(*storage.StressRecoveryLease) error
	GetStressRecoveryLease() (*storage.StressRecoveryLease, error)
	ClearStressRecoveryLease(string) error
}

// NewService creates a stress-test Service.
func NewService(exec firewall.Executor, linkSvc *links.Service, alertSvc *alerts.Service) *Service {
	return &Service{
		exec:          exec,
		linkSvc:       linkSvc,
		alertSvc:      alertSvc,
		qosSvc:        qos.NewService(exec),
		watchdogAfter: time.After,
		nowFn:         func() string { return time.Now().Format("15:04:05") },
		nextID:        func() string { return time.Now().UTC().Format("20060102T150405") },
	}
}

// SetQosService wires the same per-interface owner used by the QoS API. The
// default private owner is safe for standalone uses; production replaces it
// with the shared instance before a stress test can start.
func (s *Service) SetQosService(service qosCoordinator) {
	if service != nil {
		s.qosSvc = service
	}
}

// SetRecoveryStore wires the durable lease used to recover a fault after a
// process or host crash. Start fails closed until this dependency is present.
func (s *Service) SetRecoveryStore(store recoveryStore) {
	if store != nil {
		s.recovery = store
	}
}

// StartParams describes a requested test.
type StartParams struct {
	LinkID      string `json:"link_id"`
	Mode        Mode   `json:"mode"`
	DelayMs     int    `json:"delay_ms"`
	LossPct     int    `json:"loss_pct"`
	DurationSec int    `json:"duration_sec"`
}

// Status returns a snapshot of the current or last test (nil if none ran).
// It returns a deep copy so callers (e.g. an HTTP handler that json.Marshals
// the result) never read Samples while the run goroutine appends to it.
func (s *Service) Status() *Test {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.active)
}

// snapshot deep-copies a Test (including its Samples slice) so the returned
// value is safe to read without s.mu. Callers must hold s.mu while calling it.
func snapshot(t *Test) *Test {
	if t == nil {
		return nil
	}
	cp := *t
	// Use make (not append to a nil slice) so an empty Samples stays a non-nil
	// empty slice: it must marshal to "samples":[] and never null, or the
	// frontend crashes dereferencing test.samples (black screen).
	cp.Samples = append(make([]Sample, 0, len(t.Samples)), t.Samples...)
	return &cp
}

// Stop aborts a running test (the run loop restores on its way out).
func (s *Service) Stop() {
	s.mu.Lock()
	c := s.cancel
	s.mu.Unlock()
	if c != nil {
		c()
	}
}

// Start validates and launches a test. Returns an error if one is already
// running, the link is unusable, or stressing it would kill the only WAN.
func (s *Service) Start(p StartParams) (*Test, error) {
	s.mu.Lock()
	if s.active != nil && s.active.State == "running" {
		s.mu.Unlock()
		return nil, fmt.Errorf("já existe um teste em andamento")
	}
	s.mu.Unlock()

	if p.Mode != ModeOutage && p.Mode != ModeDegrade {
		return nil, fmt.Errorf("modo inválido")
	}
	if p.DurationSec < minDuration {
		p.DurationSec = 90
	}
	if p.DurationSec > maxDuration {
		p.DurationSec = maxDuration
	}
	if p.Mode == ModeDegrade {
		if p.DelayMs <= 0 {
			p.DelayMs = 500
		}
		if p.LossPct < 0 || p.LossPct > 100 {
			p.LossPct = 20
		}
	}

	all, err := s.linkSvc.List()
	if err != nil {
		return nil, err
	}
	var tgt *linkInfo
	healthyOthers := 0
	for i := range all {
		l := all[i]
		if l.ID == p.LinkID {
			tgt = &linkInfo{id: l.ID, name: l.Name, iface: l.Interface, enabled: l.Enabled}
			continue
		}
		if l.Enabled && (l.Status == links.StatusOnline) {
			healthyOthers++
		}
	}
	if tgt == nil || !tgt.enabled || tgt.iface == "" {
		return nil, fmt.Errorf("link inválido ou desabilitado")
	}
	// Defense-in-depth: reject anything outside a strict interface charset even
	// though links are validated on creation. Recovery may replay this argv
	// after a restart, so the persisted identifier must remain self-validating.
	if !reIface.MatchString(tgt.iface) {
		return nil, fmt.Errorf("nome de interface inválido")
	}
	if healthyOthers == 0 {
		return nil, fmt.Errorf("não há outro link WAN saudável — testar este derrubaria a internet")
	}

	t := &Test{
		ID:          s.nextID(),
		LinkID:      tgt.id,
		LinkName:    tgt.name,
		Interface:   tgt.iface,
		Mode:        p.Mode,
		DelayMs:     p.DelayMs,
		LossPct:     p.LossPct,
		DurationSec: p.DurationSec,
		State:       "running",
		StartedAt:   s.nowFn(),
		Samples:     []Sample{},
	}
	if s.recovery == nil {
		return nil, errors.New("armazenamento de recuperação do stress test não configurado")
	}
	if err := s.recovery.SaveStressRecoveryLease(&storage.StressRecoveryLease{
		TestID: t.ID, LinkID: t.LinkID, Interface: t.Interface, Mode: string(t.Mode),
		DelayMs: t.DelayMs, LossPct: t.LossPct, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return nil, fmt.Errorf("registrar recuperação do stress test: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.active = t
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(ctx, t)

	// Return a snapshot: run() begins appending samples immediately, so handing
	// back the live *t would race the caller's json.Marshal.
	s.mu.Lock()
	out := snapshot(t)
	s.mu.Unlock()
	return out, nil
}

type linkInfo struct {
	id, name, iface string
	enabled         bool
}

// ─── run loop ────────────────────────────────────────────────────────────────

func (s *Service) run(ctx context.Context, t *Test) {
	origRoute := s.currentDefault()
	s.armWatchdog(t)

	s.appendSample(t, "baseline")
	if err := s.applyFault(t); err != nil {
		slog.Error("não foi possível aplicar a falha do stress test", "link_id", t.LinkID, "interface", t.Interface, "err", err)
		restoreErr := s.restore(t, origRoute)
		if restoreErr == nil {
			s.disarmWatchdog()
		} else {
			slog.Error("não foi possível reconciliar o stress test que falhou ao iniciar", "link_id", t.LinkID, "interface", t.Interface, "err", restoreErr)
		}
		s.finalizeError(t, errors.Join(err, restoreErr), restoreErr == nil)
		return
	}

	half := time.Duration(t.DurationSec/2) * time.Second
	total := time.Duration(t.DurationSec) * time.Second
	faultRemoved := false
	for elapsed := time.Duration(0); elapsed < total; elapsed += sampleInterval {
		if ctx.Err() != nil {
			break
		}
		if elapsed >= half && !faultRemoved {
			s.removeFault(t)
			faultRemoved = true
		}
		phase := "fault"
		if faultRemoved {
			phase = "recovery"
		}
		s.appendSample(t, phase)
		s.wait(ctx, sampleInterval)
	}
	if !faultRemoved {
		s.removeFault(t)
	}
	aborted := ctx.Err() != nil
	restoreErr := s.restore(t, origRoute)
	if restoreErr == nil {
		s.disarmWatchdog()
	} else {
		slog.Error("não foi possível restaurar interface/QoS após stress test", "link_id", t.LinkID, "interface", t.Interface, "err", restoreErr)
	}
	s.finalize(t, aborted, restoreErr == nil)
}

func (s *Service) wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// bg returns a fresh short-lived context so fault/restore commands run even
// after the test context was cancelled (abort).
func bg() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func (s *Service) applyFault(t *Test) error {
	ctx, cancel := bg()
	defer cancel()
	if s.alertSvc != nil {
		if t.Mode == ModeOutage {
			_ = s.alertSvc.LinkOffline(t.LinkName, t.LinkID)
		} else {
			_ = s.alertSvc.LinkDegraded(t.LinkName, t.LinkID, float64(t.DelayMs), float64(t.LossPct))
		}
	}
	return s.withQosLock(ctx, t.Interface, func(ops qos.InterfaceOperations) error {
		if t.Mode == ModeOutage {
			_, err := s.exec.Execute(ctx, "ip", "link", "set", t.Interface, "down")
			return err
		}
		return ops.ApplyNetem(ctx, qos.NetemFault{DelayMs: t.DelayMs, LossPct: t.LossPct})
	})
}

func (s *Service) removeFault(t *Test) {
	ctx, cancel := bg()
	defer cancel()
	if err := s.restoreInterface(ctx, t); err != nil {
		slog.Error("não foi possível remover a falha e reconciliar QoS", "link_id", t.LinkID, "interface", t.Interface, "err", err)
	}
}

// restore guarantees the link is up, an owned netem is cleared, persisted QoS
// is reapplied, and the prior default route is restored.
func (s *Service) restore(t *Test, origFlat string) error {
	ctx, cancel := bg()
	defer cancel()
	if err := s.restoreInterface(ctx, t); err != nil {
		return err
	}
	if err := s.clearRecoveryLease(t.ID); err != nil {
		return err
	}
	if origFlat != "" {
		args := append([]string{"route", "replace"}, strings.Fields(origFlat)...)
		_, _ = s.exec.Execute(ctx, "ip", args...)
	}
	if s.alertSvc != nil {
		_ = s.alertSvc.LinkOnline(t.LinkName, t.LinkID)
	}
	return nil
}

// RecoverInterrupted reconciles the singleton lease left by an interrupted
// process. It clears the lease only after the exact owned fault is safely
// removed and current persisted QoS has been reapplied.
func (s *Service) RecoverInterrupted(ctx context.Context) error {
	if s.recovery == nil {
		return errors.New("armazenamento de recuperação do stress test não configurado")
	}
	lease, err := s.recovery.GetStressRecoveryLease()
	if err != nil || lease == nil {
		return err
	}
	if !reIface.MatchString(lease.Interface) {
		return fmt.Errorf("lease de recuperação tem interface inválida %q", lease.Interface)
	}
	t := &Test{
		ID: lease.TestID, LinkID: lease.LinkID, Interface: lease.Interface,
		Mode: Mode(lease.Mode), DelayMs: lease.DelayMs, LossPct: lease.LossPct,
	}
	if t.Mode != ModeOutage && t.Mode != ModeDegrade {
		return fmt.Errorf("lease de recuperação tem modo inválido %q", lease.Mode)
	}
	if t.Mode == ModeDegrade {
		fault := qos.NetemFault{DelayMs: t.DelayMs, LossPct: t.LossPct}
		if fault.DelayMs <= 0 || fault.LossPct < 0 || fault.LossPct > 100 {
			return errors.New("lease de recuperação tem assinatura netem inválida")
		}
	}
	if err := s.restoreInterface(ctx, t); err != nil {
		return err
	}
	return s.clearRecoveryLease(t.ID)
}

func (s *Service) clearRecoveryLease(testID string) error {
	if s.recovery == nil {
		return errors.New("armazenamento de recuperação do stress test não configurado")
	}
	lease, err := s.recovery.GetStressRecoveryLease()
	if err != nil {
		return err
	}
	if lease == nil {
		return nil
	}
	if lease.TestID != testID {
		return fmt.Errorf("lease de recuperação pertence ao teste %q, não %q", lease.TestID, testID)
	}
	return s.recovery.ClearStressRecoveryLease(testID)
}

func (s *Service) restoreInterface(ctx context.Context, t *Test) error {
	return s.withQosLock(ctx, t.Interface, func(ops qos.InterfaceOperations) error {
		var linkErr error
		if t.Mode == ModeOutage {
			if _, err := s.exec.Execute(ctx, "ip", "link", "set", t.Interface, "up"); err != nil {
				return err
			}
		}
		cfg, err := s.loadEffectiveQoS(t.LinkID, t.Interface)
		if err != nil {
			linkErr = err
			cfg = qos.Config{Interface: t.Interface}
		}
		if t.Mode == ModeDegrade {
			_, err = ops.RestoreAfterNetem(ctx, cfg, qos.NetemFault{DelayMs: t.DelayMs, LossPct: t.LossPct})
		} else {
			_, err = ops.Apply(ctx, cfg)
		}
		return errors.Join(linkErr, err)
	})
}

func (s *Service) loadEffectiveQoS(linkID, iface string) (qos.Config, error) {
	cfg := qos.Config{Interface: iface}
	if s.linkSvc == nil || linkID == "" {
		return cfg, nil
	}
	link, err := s.linkSvc.Get(linkID)
	if err != nil {
		return cfg, err
	}
	if link.Interface != iface || !link.Enabled || !link.QoSEnabled {
		return cfg, nil
	}
	return qos.Config{
		Interface:    iface,
		Enabled:      true,
		UploadMbps:   link.QoSUploadMbps,
		DownloadMbps: link.QoSDownloadMbps,
		Interactive:  link.QoSInteractive,
	}, nil
}

func (s *Service) withQosLock(ctx context.Context, iface string, fn func(qos.InterfaceOperations) error) error {
	coordinator := s.qosSvc
	if coordinator == nil {
		coordinator = qos.NewService(s.exec)
	}
	return coordinator.WithInterfaceLock(ctx, iface, fn)
}

// armWatchdog schedules the same ownership-aware restore path used on normal
// completion. It never launches a shell or issues an unconditional qdisc
// delete, so a late watchdog cannot remove a root installed by another owner.
func (s *Service) armWatchdog(t *Test) {
	if !reIface.MatchString(t.Interface) {
		slog.Error("armWatchdog: interface inválida, watchdog não armado", "interface", t.Interface)
		return
	}
	watchdogCtx, cancel := context.WithCancel(context.Background())
	after := s.watchdogAfter
	if after == nil {
		after = time.After
	}
	s.mu.Lock()
	if s.watchdogCancel != nil {
		s.watchdogCancel()
	}
	s.watchdogCancel = cancel
	s.mu.Unlock()
	snapshot := *t
	deadline := time.Duration(t.DurationSec+60) * time.Second
	go func() {
		select {
		case <-watchdogCtx.Done():
			return
		case <-after(deadline):
		}
		ctx, cancel := bg()
		defer cancel()
		if err := s.restoreInterface(ctx, &snapshot); err != nil {
			slog.Error("watchdog não conseguiu restaurar interface/QoS", "link_id", snapshot.LinkID, "interface", snapshot.Interface, "err", err)
			return
		}
		if err := s.clearRecoveryLease(snapshot.ID); err != nil {
			slog.Error("watchdog restaurou a interface, mas não confirmou a lease", "link_id", snapshot.LinkID, "interface", snapshot.Interface, "err", err)
		}
	}()
}

func (s *Service) disarmWatchdog() {
	s.mu.Lock()
	cancel := s.watchdogCancel
	s.watchdogCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) currentDefault() string {
	ctx, cancel := bg()
	defer cancel()
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show", "default")
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(out), " ") // flatten multipath
}

func (s *Service) appendSample(t *Test, phase string) {
	route := s.currentDefault()
	ctx, cancel := bg()
	defer cancel()
	_, perr := s.exec.Execute(ctx, "ping", "-c1", "-W2", pingTarget)
	_, derr := s.exec.Execute(ctx, "getent", "hosts", dnsTarget)
	sample := Sample{T: s.nowFn(), Route: route, Ping: perr == nil, DNS: derr == nil, Phase: phase}
	s.mu.Lock()
	t.Samples = append(t.Samples, sample)
	s.mu.Unlock()
}

func (s *Service) finalize(t *Test, aborted, restored bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pingFail, dnsFail, n := 0, 0, 0
	for _, sm := range t.Samples {
		if sm.Phase == "baseline" {
			continue
		}
		n++
		if !sm.Ping {
			pingFail++
		}
		if !sm.DNS {
			dnsFail++
		}
	}
	if n > 0 {
		t.PingLossPct = float64(pingFail) / float64(n) * 100
		t.DNSLossPct = float64(dnsFail) / float64(n) * 100
	}
	t.Restored = restored
	t.EndedAt = s.nowFn()
	if !restored {
		t.State = "error"
		t.Message = "Teste encerrado, mas a restauração ficou pendente para o watchdog/boot."
		return
	}
	if aborted {
		t.State = "aborted"
		t.Message = "Teste abortado — link restaurado."
	} else {
		t.State = "done"
		t.Message = fmt.Sprintf("Concluído. Continuidade: ping %.0f%%, DNS %.0f%%.",
			100-t.PingLossPct, 100-t.DNSLossPct)
	}
}

func (s *Service) finalizeError(t *Test, err error, restored bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Restored = restored
	t.EndedAt = s.nowFn()
	t.State = "error"
	if restored {
		t.Message = "Falha ao aplicar o teste; o link foi reconciliado: " + err.Error()
	} else {
		t.Message = "Falha ao aplicar o teste; restauração pendente para o watchdog/boot: " + err.Error()
	}
}
