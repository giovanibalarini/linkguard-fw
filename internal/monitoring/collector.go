// Package monitoring collects and updates metrics from links and system.
package monitoring

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

// Collector gathers system and link metrics and updates Prometheus gauges.
type Collector struct {
	db        *storage.DB
	sysCol    *system.Collector
	m         *metrics.Metrics
	alertSvc  *alerts.Service
	exec      firewall.Executor
	rec       tsdb.Recorder
	startTime time.Time

	healthMu sync.Mutex
	health   map[string]*itemState
	nowFn    func() int64
}

// NewCollector creates a monitoring Collector. rec receives every measurement
// for the diagnostic timeline — pass nil to disable (used in tests that don't
// care about history).
func NewCollector(db *storage.DB, m *metrics.Metrics, alertSvc *alerts.Service, exec firewall.Executor, rec tsdb.Recorder) *Collector {
	return &Collector{
		db:        db,
		sysCol:    system.NewCollector(),
		m:         m,
		alertSvc:  alertSvc,
		exec:      exec,
		rec:       rec,
		startTime: time.Now(),
		health:    map[string]*itemState{},
		nowFn:     func() int64 { return time.Now().Unix() },
	}
}

// Run starts the collection loop and blocks until ctx is done.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	slog.Info("metrics collector started", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	c.collect()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) collect() {
	cfg := LoadConfig(c.db)

	// Service uptime
	c.m.ServiceUptime.Set(time.Since(c.startTime).Seconds())

	// System metrics
	sys, err := c.sysCol.Collect()
	if err != nil {
		slog.Warn("system metrics collection error", "err", err)
	} else {
		c.m.CPUPercent.Set(sys.CPUPercent)
		c.m.MemPercent.Set(sys.MemPercent)
		c.m.DiskPercent.Set(sys.DiskPercent)
		c.m.UptimeSeconds.Set(sys.UptimeSeconds)

		if c.rec != nil {
			c.rec.Gauge("sys.cpu_pct", "", sys.CPUPercent)
			c.rec.Gauge("sys.mem_pct", "", sys.MemPercent)
			c.rec.Gauge("sys.disk_pct", "", sys.DiskPercent)
		}

		for _, iface := range sys.Interfaces {
			c.m.InterfaceRxBytes.WithLabelValues(iface.Name).Set(float64(iface.RxBytes))
			c.m.InterfaceTxBytes.WithLabelValues(iface.Name).Set(float64(iface.TxBytes))
			c.m.InterfaceRxPkts.WithLabelValues(iface.Name).Set(float64(iface.RxPackets))
			c.m.InterfaceTxPkts.WithLabelValues(iface.Name).Set(float64(iface.TxPackets))
		}

		// Resource threshold alerts — transition-based with anti-flap (fire once
		// on crossing, recover once, transient spikes suppressed) instead of
		// re-firing every tick while over the threshold.
		//
		// Gated by cfg.Enabled — the "Me avise de qualquer queda" master toggle.
		// By product decision it is a single switch: turning it off silences ALL
		// alerts (services, links AND the box's own cpu/mem/disk), for the
		// simplest mental model. Default is on.
		if cfg.Enabled {
			c.checkResource("resource:cpu", "CPU", sys.CPUPercent, 90, c.alertSvc.HighCPU, c.alertSvc.CPUNormal)
			c.checkResource("resource:mem", "Memória", sys.MemPercent, 90, c.alertSvc.HighMemory, c.alertSvc.MemoryNormal)
			c.checkResource("resource:disk", "Disco", sys.DiskPercent, cfg.DiskThresholdPct, c.alertSvc.DiskFull, c.alertSvc.DiskCleared)
		}
	}

	if cfg.Enabled {
		c.checkServices(cfg)
	}

	// Link metrics
	links, err := c.db.GetLinks()
	if err != nil {
		slog.Warn("fetch links for metrics", "err", err)
		return
	}

	for _, l := range links {
		statusVal := metrics.LinkStatusValue(l.Status)
		c.m.LinkStatus.WithLabelValues(l.Name, l.Interface).Set(statusVal)
		c.m.LinkLatency.WithLabelValues(l.Name, l.Interface).Set(l.LatencyMs)
		c.m.LinkLoss.WithLabelValues(l.Name, l.Interface).Set(l.PacketLoss)
	}

	// Unresolved alerts
	n, _ := c.db.CountAlerts()
	c.m.AlertsTotal.Set(float64(n))

	if cfg.Enabled {
		c.trackLinks()
	}
}
