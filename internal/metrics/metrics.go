// Package metrics exposes Prometheus metrics for LinkGuard FW.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric collectors.
type Metrics struct {
	// Link metrics
	LinkStatus  *prometheus.GaugeVec
	LinkLatency *prometheus.GaugeVec
	LinkLoss    *prometheus.GaugeVec

	// Interface traffic
	InterfaceRxBytes *prometheus.GaugeVec
	InterfaceTxBytes *prometheus.GaugeVec
	InterfaceRxPkts  *prometheus.GaugeVec
	InterfaceTxPkts  *prometheus.GaugeVec

	// System
	CPUPercent    prometheus.Gauge
	MemPercent    prometheus.Gauge
	DiskPercent   prometheus.Gauge
	UptimeSeconds prometheus.Gauge

	// Failover
	FailoverEvents prometheus.Counter

	// Service
	ServiceUptime prometheus.Gauge
	AlertsTotal   prometheus.Gauge
}

// New registers and returns all Prometheus metrics.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)

	return &Metrics{
		LinkStatus: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "link_status",
			Help:      "WAN link status: 1=online, 0=offline, 0.5=degraded",
		}, []string{"link", "interface"}),

		LinkLatency: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "link_latency_ms",
			Help:      "WAN link average latency in milliseconds",
		}, []string{"link", "interface"}),

		LinkLoss: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "link_packet_loss_percent",
			Help:      "WAN link packet loss percentage",
		}, []string{"link", "interface"}),

		InterfaceRxBytes: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_rx_bytes_total",
			Help:      "Total bytes received on the interface",
		}, []string{"interface"}),

		InterfaceTxBytes: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_tx_bytes_total",
			Help:      "Total bytes transmitted on the interface",
		}, []string{"interface"}),

		InterfaceRxPkts: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_rx_packets_total",
			Help:      "Total packets received on the interface",
		}, []string{"interface"}),

		InterfaceTxPkts: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_tx_packets_total",
			Help:      "Total packets transmitted on the interface",
		}, []string{"interface"}),

		CPUPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_cpu_percent",
			Help:      "Current CPU usage percentage",
		}),

		MemPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_memory_percent",
			Help:      "Current memory usage percentage",
		}),

		DiskPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_disk_percent",
			Help:      "Current disk usage percentage (root filesystem)",
		}),

		UptimeSeconds: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_uptime_seconds",
			Help:      "System uptime in seconds",
		}),

		FailoverEvents: f.NewCounter(prometheus.CounterOpts{
			Namespace: "linkguard",
			Name:      "failover_events_total",
			Help:      "Total number of failover events recorded",
		}),

		ServiceUptime: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "service_uptime_seconds",
			Help:      "LinkGuard FW service uptime in seconds",
		}),

		AlertsTotal: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "alerts_unresolved_total",
			Help:      "Number of unresolved alerts",
		}),
	}
}

// LinkStatusValue converts a status string to a numeric gauge value.
func LinkStatusValue(status string) float64 {
	switch status {
	case "online":
		return 1
	case "degraded":
		return 0.5
	default:
		return 0
	}
}
