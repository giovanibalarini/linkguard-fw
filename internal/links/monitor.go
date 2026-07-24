package links

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// Health classification thresholds.
const (
	probeFailThreshold    = 3     // consecutive unreachable checks → offline
	probeRecoverThreshold = 2     // consecutive good checks → online
	degradedLossPct       = 25.0  // packet loss above this → degraded
	degradedLatencyMs     = 300.0 // average latency above this → degraded
)

// CheckResult holds the result of a single connectivity check.
type CheckResult struct {
	Host    string
	Latency time.Duration
	Success bool
	Error   string
}

// Monitor periodically checks link connectivity and updates link status.
type Monitor struct {
	db                  *storage.DB
	svc                 *Service
	interval            time.Duration
	probeCount          int
	rec                 tsdb.Recorder
	m                   *metrics.Metrics
	onStatusChange      func(link *storage.Link, oldStatus, newStatus string)
	onDegradedSustained func(link *storage.Link)
	sustainThreshold    func() int

	mu     sync.Mutex
	states map[string]*linkState // key = link ID
}

type linkState struct {
	consecutiveFails     int
	consecutiveSuccesses int
	consecutiveDegraded  int
	degradedEpisodeFired bool // true once a sustained episode has fired
	lastStatus           string
	cooldownUntil        time.Time
}

// NewMonitor creates a new Monitor. probeCount is how many connectivity probes
// are sent per host per tick (≥1); more probes yield finer packet-loss/latency.
// rec receives every measurement for the diagnostic timeline — pass nil to
// disable (used in tests that don't care about history).
func NewMonitor(db *storage.DB, svc *Service, interval time.Duration, probeCount int, rec tsdb.Recorder, m *metrics.Metrics) *Monitor {
	if probeCount < 1 {
		probeCount = 1
	}
	return &Monitor{
		db:         db,
		svc:        svc,
		interval:   interval,
		probeCount: probeCount,
		rec:        rec,
		m:          m,
		states:     make(map[string]*linkState),
	}
}

// OnStatusChange registers a callback invoked when a link changes status.
func (m *Monitor) OnStatusChange(fn func(link *storage.Link, oldStatus, newStatus string)) {
	m.onStatusChange = fn
}

// OnDegradedSustained registers an edge-triggered callback invoked once per
// degradation episode, when a link has been continuously degraded for
// SustainThreshold() consecutive checks. Used to trigger active flow eviction.
func (m *Monitor) OnDegradedSustained(fn func(link *storage.Link)) {
	m.onDegradedSustained = fn
}

// SustainThreshold sets the provider for the number of consecutive degraded
// checks required before OnDegradedSustained fires. Read at evaluation time so
// the value always reflects the admin's current setting. A nil provider (or a
// value ≤ 0) is treated as 1.
func (m *Monitor) SustainThreshold(fn func() int) {
	m.sustainThreshold = fn
}

func (m *Monitor) sustainN() int {
	if m.sustainThreshold == nil {
		return 1
	}
	return m.sustainThreshold()
}

// summarize computes average latency (ms, over successful probes only) and
// packet loss (%) across all probe samples. Zero samples or all-failures yield
// 0 latency and 100% loss.
func summarize(results []CheckResult) (avgLatencyMs, packetLossPct float64) {
	if len(results) == 0 {
		return 0, 100.0
	}
	var total time.Duration
	success := 0
	for _, r := range results {
		if r.Success {
			success++
			total += r.Latency
		}
	}
	if success == 0 {
		return 0, 100.0
	}
	avg := float64(total/time.Duration(success)) / float64(time.Millisecond)
	loss := float64(len(results)-success) / float64(len(results)) * 100
	return avg, loss
}

// advance feeds one sample's classification into the link's state machine and
// returns the resulting status plus whether a sustained-degradation episode was
// just triggered (edge-triggered: once per episode, when consecutiveDegraded
// first reaches sustainThreshold). A sustainThreshold ≤ 0 is treated as 1.
func (st *linkState) advance(reachable, degradedNow bool, prevStatus string, sustainThreshold int) (newStatus string, fireSustained bool) {
	if sustainThreshold < 1 {
		sustainThreshold = 1
	}

	switch {
	case !reachable:
		st.consecutiveFails++
		st.consecutiveSuccesses = 0
		st.consecutiveDegraded = 0
		st.degradedEpisodeFired = false
	case degradedNow:
		st.consecutiveFails = 0
		st.consecutiveSuccesses = 0
		st.consecutiveDegraded++
	default:
		st.consecutiveFails = 0
		st.consecutiveSuccesses++
		st.consecutiveDegraded = 0
		st.degradedEpisodeFired = false
	}

	if degradedNow && st.consecutiveDegraded >= sustainThreshold && !st.degradedEpisodeFired {
		st.degradedEpisodeFired = true
		fireSustained = true
	}

	switch {
	case st.consecutiveFails >= probeFailThreshold:
		newStatus = StatusOffline
	case degradedNow && st.consecutiveDegraded >= sustainThreshold:
		newStatus = StatusDegraded
	case st.consecutiveSuccesses >= probeRecoverThreshold:
		newStatus = StatusOnline
	default:
		newStatus = prevStatus
		if newStatus == "" {
			newStatus = StatusUnknown
		}
	}
	return newStatus, fireSustained
}

// Run starts the monitoring loop and blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	slog.Info("link monitor started", "interval", m.interval)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Initial check right away
	m.checkAll(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("link monitor stopped")
			return
		case <-ticker.C:
			m.checkAll(ctx)
		}
	}
}

// RunOnceForTest runs a single checkAll pass synchronously. Test-only.
func (m *Monitor) RunOnceForTest(ctx context.Context) {
	m.checkAll(ctx)
}

func (m *Monitor) checkAll(ctx context.Context) {
	links, err := m.db.GetLinks()
	if err != nil {
		slog.Error("monitor: get links", "err", err)
		return
	}

	var wg sync.WaitGroup
	for i := range links {
		if !links[i].Enabled {
			continue
		}
		wg.Add(1)
		go func(l storage.Link) {
			defer wg.Done()
			m.checkLink(ctx, l)
		}(links[i])
	}
	wg.Wait()
}

func (m *Monitor) checkLink(ctx context.Context, l storage.Link) {
	hosts := parseHosts(l.MonitorHosts)
	if len(hosts) == 0 {
		hosts = []string{l.DNSTest}
	}

	// Send probeCount probes per host per tick, so packet loss and latency are
	// real averages over len(hosts)×probeCount samples instead of a single
	// pass/fail per host. Finer sampling catches short jitter/loss bursts that a
	// lone probe would miss (a flukey success masking a bad link).
	results := make([]CheckResult, 0, len(hosts)*m.probeCount)
	for _, host := range hosts {
		for i := 0; i < m.probeCount; i++ {
			results = append(results, tcpCheck(ctx, host, l.Interface, 5*time.Second))
		}
	}
	avgLatency, packetLoss := summarize(results)

	m.mu.Lock()
	state, ok := m.states[l.ID]
	if !ok {
		state = &linkState{lastStatus: l.Status}
		m.states[l.ID] = state
	}
	m.mu.Unlock()

	// Classify this sample. "Degraded" = reachable but lossy/slow — a STABLE
	// state: a consistently degraded link must NOT escalate to offline, so the
	// balancer can keep it as a last resort and switch back when it recovers.
	// "Offline" = no host answered for several consecutive checks.
	reachable := packetLoss < 100.0
	degradedNow := reachable && (packetLoss > degradedLossPct || avgLatency > degradedLatencyMs)

	newStatus, fireSustained := state.advance(reachable, degradedNow, l.Status, m.sustainN())

	if m.rec != nil {
		m.rec.Gauge("link.latency_ms", l.Name, avgLatency)
		m.rec.Gauge("link.loss_pct", l.Name, packetLoss)
		m.rec.State("link", l.Name, newStatus)
	}
	if m.m != nil {
		m.m.LinkStatus.WithLabelValues(l.Name, l.Interface).Set(metrics.LinkStatusValue(newStatus))
		m.m.LinkLatency.WithLabelValues(l.Name, l.Interface).Set(avgLatency)
		m.m.LinkLoss.WithLabelValues(l.Name, l.Interface).Set(packetLoss)
	}

	// Update the link in DB
	if err := m.svc.UpdateStatus(l.ID, newStatus, avgLatency, packetLoss); err != nil {
		slog.Error("monitor: update status", "link", l.Name, "err", err)
		return
	}

	// Fire callback on status change
	if newStatus != state.lastStatus && m.onStatusChange != nil {
		updated := l
		updated.Status = newStatus
		m.onStatusChange(&updated, state.lastStatus, newStatus)
		state.lastStatus = newStatus
	}

	// Edge-triggered: a link that has been degraded for the sustained threshold
	// fires once so the balancer can actively evict its in-flight flows.
	if fireSustained && m.onDegradedSustained != nil {
		updated := l
		updated.Status = newStatus
		m.onDegradedSustained(&updated)
	}

	slog.Debug("link check", "link", l.Name, "status", newStatus,
		"latency_ms", fmt.Sprintf("%.1f", avgLatency), "packet_loss", fmt.Sprintf("%.1f%%", packetLoss))
}

// ─── Connectivity checks ─────────────────────────────────────────────────────

// tcpCheck tries a TCP connection to determine if a host is reachable THROUGH a
// specific link. Binding the probe to the link's interface (SO_BINDTODEVICE) is
// what makes per-link health work in balance mode: without it, a generic probe
// egresses via whichever WAN is alive in the multipath default and always
// succeeds, so a single link's failure (especially a "soft" ISP outage where the
// interface stays up) would go undetected. It tries common ports (443, 80, 53).
func tcpCheck(ctx context.Context, host, device string, timeout time.Duration) CheckResult {
	dialer := bindDialer(device, timeout)
	ports := []string{"443", "80", "53"}
	for _, port := range ports {
		start := time.Now()
		addr := net.JoinHostPort(host, port)
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return CheckResult{Host: host, Latency: time.Since(start), Success: true}
		}
	}
	return CheckResult{Host: host, Success: false, Error: "all ports unreachable"}
}

// bindDialer builds a TCP dialer that forces egress through the given interface
// via SO_BINDTODEVICE (Linux; requires CAP_NET_RAW — the service runs as root).
// An empty device yields a plain dialer (default routing).
func bindDialer(device string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if device == "" {
		return d
	}
	d.Control = func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return serr
	}
	return d
}

func parseHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
