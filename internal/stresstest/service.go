// Package stresstest runs bounded, self-restoring fault-injection tests against
// a WAN link (bring it down, or degrade it with tc netem) while measuring
// connectivity continuity (ping + DNS) and watching the balancer react. It is
// how an admin validates multi-WAN failover on demand instead of waiting for a
// real outage.
//
// Safety: every test captures the prior state, arms an OS-level watchdog that
// force-restores the link after the deadline (so a crashed app can't strand a
// WAN down), refuses to stress the only healthy link, and restores on finish or
// abort.
package stresstest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
)

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
	exec    firewall.Executor
	linkSvc *links.Service

	mu     sync.Mutex
	active *Test
	cancel context.CancelFunc
	nowFn  func() string // injectable for tests
	nextID func() string
}

// NewService creates a stress-test Service.
func NewService(exec firewall.Executor, linkSvc *links.Service) *Service {
	return &Service{
		exec:    exec,
		linkSvc: linkSvc,
		nowFn:   func() string { return time.Now().Format("15:04:05") },
		nextID:  func() string { return time.Now().UTC().Format("20060102T150405") },
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

// Status returns the current or last test (nil if none ran).
func (s *Service) Status() *Test {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
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

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.active = t
	s.cancel = cancel
	s.mu.Unlock()

	go s.run(ctx, t)
	return t, nil
}

type linkInfo struct {
	id, name, iface string
	enabled         bool
}

// ─── run loop ────────────────────────────────────────────────────────────────

func (s *Service) run(ctx context.Context, t *Test) {
	origRoute := s.currentDefault()
	s.armWatchdog(t) // OS-level force-restore; survives an app crash

	s.appendSample(t, "baseline")
	s.applyFault(t)

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
	s.restore(t, origRoute)
	s.finalize(t, aborted)
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

func (s *Service) applyFault(t *Test) {
	ctx, cancel := bg()
	defer cancel()
	if t.Mode == ModeOutage {
		_, _ = s.exec.Execute(ctx, "ip", "link", "set", t.Interface, "down")
		return
	}
	_, _ = s.exec.Execute(ctx, "tc", "qdisc", "replace", "dev", t.Interface, "root",
		"netem", "delay", fmt.Sprintf("%dms", t.DelayMs), "loss", fmt.Sprintf("%d%%", t.LossPct))
}

func (s *Service) removeFault(t *Test) {
	ctx, cancel := bg()
	defer cancel()
	if t.Mode == ModeOutage {
		_, _ = s.exec.Execute(ctx, "ip", "link", "set", t.Interface, "up")
		return
	}
	_, _ = s.exec.Execute(ctx, "tc", "qdisc", "del", "dev", t.Interface, "root")
}

// restore guarantees the link is up, netem cleared, and the prior default route
// re-applied (the balancer keeps it thereafter).
func (s *Service) restore(t *Test, origFlat string) {
	ctx, cancel := bg()
	defer cancel()
	_, _ = s.exec.Execute(ctx, "ip", "link", "set", t.Interface, "up")
	_, _ = s.exec.Execute(ctx, "tc", "qdisc", "del", "dev", t.Interface, "root")
	if origFlat != "" {
		args := append([]string{"route", "replace"}, strings.Fields(origFlat)...)
		_, _ = s.exec.Execute(ctx, "ip", args...)
	}
}

// armWatchdog spawns a detached process that force-restores the link/tc after
// the deadline no matter what — even if this process dies mid-test.
func (s *Service) armWatchdog(t *Test) {
	ctx, cancel := bg()
	defer cancel()
	margin := t.DurationSec + 60
	restore := fmt.Sprintf("ip link set %s up; tc qdisc del dev %s root 2>/dev/null",
		t.Interface, t.Interface)
	cmd := fmt.Sprintf("setsid sh -c 'sleep %d; %s' </dev/null >/dev/null 2>&1 &", margin, restore)
	_, _ = s.exec.Execute(ctx, "sh", "-c", cmd)
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

func (s *Service) finalize(t *Test, aborted bool) {
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
	t.Restored = true
	t.EndedAt = s.nowFn()
	if aborted {
		t.State = "aborted"
		t.Message = "Teste abortado — link restaurado."
	} else {
		t.State = "done"
		t.Message = fmt.Sprintf("Concluído. Continuidade: ping %.0f%%, DNS %.0f%%.",
			100-t.PingLossPct, 100-t.DNSLossPct)
	}
}
