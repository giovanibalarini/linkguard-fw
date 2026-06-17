package links

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// CheckResult holds the result of a single connectivity check.
type CheckResult struct {
	Host      string
	Latency   time.Duration
	Success   bool
	Error     string
}

// Monitor periodically checks link connectivity and updates link status.
type Monitor struct {
	db         *storage.DB
	svc        *Service
	interval   time.Duration
	onStatusChange func(link *storage.Link, oldStatus, newStatus string)

	mu     sync.Mutex
	states map[string]*linkState // key = link ID
}

type linkState struct {
	consecutiveFails    int
	consecutiveSuccesses int
	lastStatus          string
	cooldownUntil       time.Time
}

// NewMonitor creates a new Monitor.
func NewMonitor(db *storage.DB, svc *Service, interval time.Duration) *Monitor {
	return &Monitor{
		db:       db,
		svc:      svc,
		interval: interval,
		states:   make(map[string]*linkState),
	}
}

// OnStatusChange registers a callback invoked when a link changes status.
func (m *Monitor) OnStatusChange(fn func(link *storage.Link, oldStatus, newStatus string)) {
	m.onStatusChange = fn
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

	var totalLatency time.Duration
	successCount := 0
	for _, host := range hosts {
		r := tcpCheck(ctx, host, 5*time.Second)
		if r.Success {
			successCount++
			totalLatency += r.Latency
		}
	}

	var avgLatency float64
	packetLoss := 100.0
	if successCount > 0 {
		avgLatency = float64(totalLatency/time.Duration(successCount)) / float64(time.Millisecond)
		packetLoss = float64(len(hosts)-successCount) / float64(len(hosts)) * 100
	}

	m.mu.Lock()
	state, ok := m.states[l.ID]
	if !ok {
		state = &linkState{lastStatus: l.Status}
		m.states[l.ID] = state
	}
	m.mu.Unlock()

	// Determine new status
	var newStatus string
	if successCount == 0 {
		state.consecutiveFails++
		state.consecutiveSuccesses = 0
	} else if packetLoss > 25 {
		state.consecutiveFails++
		state.consecutiveSuccesses = 0
	} else {
		state.consecutiveFails = 0
		state.consecutiveSuccesses++
	}

	switch {
	case state.consecutiveFails >= 3:
		newStatus = StatusOffline
	case packetLoss > 25 && successCount > 0:
		newStatus = StatusDegraded
	case state.consecutiveSuccesses >= 2:
		newStatus = StatusOnline
	default:
		newStatus = l.Status
		if newStatus == "" {
			newStatus = StatusUnknown
		}
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

	slog.Debug("link check", "link", l.Name, "status", newStatus,
		"latency_ms", fmt.Sprintf("%.1f", avgLatency), "packet_loss", fmt.Sprintf("%.1f%%", packetLoss))
}

// ─── Connectivity checks ─────────────────────────────────────────────────────

// tcpCheck tries a TCP connection to determine if a host is reachable.
// It tries common ports (443, 80, 53) to maximise success chance.
func tcpCheck(ctx context.Context, host string, timeout time.Duration) CheckResult {
	ports := []string{"443", "80", "53"}
	for _, port := range ports {
		start := time.Now()
		addr := net.JoinHostPort(host, port)
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return CheckResult{Host: host, Latency: time.Since(start), Success: true}
		}
	}
	return CheckResult{Host: host, Success: false, Error: "all ports unreachable"}
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
