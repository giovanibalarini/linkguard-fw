// Package monitoring collects and updates metrics from links and system.
package monitoring

import (
	"context"
	"log/slog"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/metrics"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/system"
)

// Collector gathers system and link metrics and updates Prometheus gauges.
type Collector struct {
	db        *storage.DB
	sysCol    *system.Collector
	m         *metrics.Metrics
	alertSvc  *alerts.Service
	startTime time.Time
}

// NewCollector creates a monitoring Collector.
func NewCollector(db *storage.DB, m *metrics.Metrics, alertSvc *alerts.Service) *Collector {
	return &Collector{
		db:       db,
		sysCol:   system.NewCollector(),
		m:        m,
		alertSvc: alertSvc,
		startTime: time.Now(),
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

		for _, iface := range sys.Interfaces {
			c.m.InterfaceRxBytes.WithLabelValues(iface.Name).Set(float64(iface.RxBytes))
			c.m.InterfaceTxBytes.WithLabelValues(iface.Name).Set(float64(iface.TxBytes))
			c.m.InterfaceRxPkts.WithLabelValues(iface.Name).Set(float64(iface.RxPackets))
			c.m.InterfaceTxPkts.WithLabelValues(iface.Name).Set(float64(iface.TxPackets))
		}

		// Threshold alerts
		if sys.CPUPercent > 90 {
			_ = c.alertSvc.HighCPU(sys.CPUPercent)
		}
		if sys.MemPercent > 90 {
			_ = c.alertSvc.HighMemory(sys.MemPercent)
		}
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
}
