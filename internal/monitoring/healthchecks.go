package monitoring

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/giovanibalarini/linkguard-fw/internal/disksmart"
	"github.com/giovanibalarini/linkguard-fw/internal/timesync"
)

type transition int

const (
	transNone transition = iota
	transDown
	transUp
)

// downConfirm is the number of consecutive "down" observations required before
// declaring an outage (anti-flap). With a 30s tick this debounces ~30–60s.
const downConfirm = 2

type itemState struct {
	name      string
	kind      string // "service" | "link" | "resource"
	up        bool
	since     int64
	failCount int
	known     bool
}

// serviceNameRe guards shell-embedded service names (defense-in-depth).
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]+$`)

// observe folds a raw up/down reading into the item's state and returns whether
// this reading is a real transition. Down transitions require downConfirm
// consecutive failures; up transitions are immediate.
func (c *Collector) observe(key string, up bool, now int64) transition {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		if !up {
			// Born down (e.g. service dead at startup): seed as up with one failure
			// so the next confirming tick fires the outage, instead of silently
			// treating "already down" as steady state and never alerting.
			c.health[key] = &itemState{up: true, since: now, failCount: 1, known: true}
			return transNone
		}
		c.health[key] = &itemState{up: up, since: now, known: true}
		return transNone
	}
	if up {
		st.failCount = 0
		if !st.up {
			st.up = true
			st.since = now
			return transUp
		}
		return transNone
	}
	// down reading
	if !st.up {
		return transNone // already down
	}
	st.failCount++
	if st.failCount >= downConfirm {
		st.up = false
		st.since = now
		return transDown
	}
	return transNone
}

// Snapshot returns the current health of every tracked item (services, links,
// resources) for the dashboard.
func (c *Collector) Snapshot() []HealthItem {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	out := make([]HealthItem, 0, len(c.health))
	for _, st := range c.health {
		out = append(out, HealthItem{Name: st.name, Kind: st.kind, Up: st.up, Since: st.since})
	}
	return out
}

// HealthItem is one row of the dashboard health panel.
type HealthItem struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Up    bool   `json:"up"`
	Since int64  `json:"since"`
}

// checkServices polls each configured service via systemctl and raises/clears
// alerts on confirmed transitions.
func (c *Collector) checkServices(cfg Config) {
	now := c.nowFn()
	for _, svc := range cfg.Services {
		up := c.isActive(svc)
		key := "service:" + svc
		tr := c.observe(key, up, now)
		c.ensureMeta(key, svc, "service")
		if c.rec != nil {
			state := "down"
			if up {
				state = "up"
			}
			c.rec.State("service", svc, state)
		}
		switch tr {
		case transDown:
			_ = c.alertSvc.ServiceOffline(svc)
		case transUp:
			_ = c.alertSvc.ServiceOnline(svc)
		}
	}
}

// checkResource applies transition + anti-flap alerting to a host resource
// (cpu / memory / disk). "up" means healthy (below the threshold); crossing the
// threshold fires `high` once, and dropping back below fires `normal`. Because
// observe() requires two consecutive over-threshold readings, a one-tick spike
// (e.g. the CPU burst during boot) is suppressed instead of spamming.
func (c *Collector) checkResource(key, name string, pct float64, thresholdPct int, high, normal func(float64) error) {
	now := c.nowFn()
	tr := c.observe(key, pct < float64(thresholdPct), now)
	c.ensureMeta(key, name, "resource")
	switch tr {
	case transDown:
		_ = high(pct)
	case transUp:
		_ = normal(pct)
	}
}

// trackLinks reflects link status into the health map for the dashboard. Link
// UP/DOWN alerts stay owned by the monitor's OnStatusChange path (Task 9).
func (c *Collector) trackLinks() {
	links, err := c.db.GetLinks()
	if err != nil {
		return
	}
	now := c.nowFn()
	for _, l := range links {
		key := "link:" + l.ID
		c.observe(key, l.Status == "online", now)
		c.ensureMeta(key, l.Name, "link")
	}
}

// ensureMeta sets the display name/kind on an item the first time we see it.
func (c *Collector) ensureMeta(key, name, kind string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if st := c.health[key]; st != nil {
		if st.name == "" {
			st.name = name
		}
		if st.kind == "" {
			st.kind = kind
		}
	}
}

// isActive reports whether a systemd unit is active. The service name is
// validated against serviceNameRe before reaching the shell (defense-in-depth).
func (c *Collector) isActive(svc string) bool {
	if !serviceNameRe.MatchString(svc) {
		return false
	}
	_, err := c.exec.ExecuteRead(context.Background(), "systemctl", "is-active", svc)
	return err == nil
}

// checkNTP verifies the system clock is NTP-synchronized and raises/clears
// alerts.TypeNTPUnsynced on a confirmed transition.
func (c *Collector) checkNTP() {
	up := timesync.IsSynced(context.Background(), c.exec)
	now := c.nowFn()
	tr := c.observe("ntp:sync", up, now)
	c.ensureMeta("ntp:sync", "ntp-sync", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.NTPUnsynced()
	case transUp:
		_ = c.alertSvc.NTPSynced()
	}
}

// checkSMART reads the root disk's SMART status once and applies three
// checks from that single reading: overall health (boolean, via observe()
// directly), reallocated sector count and temperature (both threshold-based,
// routed through the existing checkResource — same "lower is healthier"
// polarity as CPU/mem/disk). A read failure (tool missing, disk not found)
// is treated as "unknown for this tick" and skipped entirely, rather than
// raising a false SMART-fail alert — see the design spec's Casos de borda.
func (c *Collector) checkSMART(cfg Config) {
	ctx := context.Background()
	device, err := disksmart.DetectRootDisk(ctx, c.exec)
	if err != nil {
		slog.Warn("smart: could not detect root disk", "err", err)
		return
	}
	report, err := disksmart.Read(ctx, c.exec, device)
	if err != nil {
		slog.Warn("smart: read failed", "device", device, "err", err)
		return
	}

	now := c.nowFn()
	tr := c.observe("smart:health", report.Passed, now)
	c.ensureMeta("smart:health", "smart-health", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DiskSMARTFail()
	case transUp:
		_ = c.alertSvc.DiskSMARTOK()
	}

	if c.rec != nil {
		c.rec.Gauge("smart.reallocated", "", float64(report.ReallocatedSectors))
		c.rec.Gauge("smart.temp_c", "", float64(report.TemperatureC))
	}

	// checkResource's polarity is `pct < thresholdPct` (strictly less-than).
	// SMARTReallocatedThreshold defaults to 0 meaning "any reallocated sector
	// at all is a problem" — passing threshold+1 turns the strict "<" into
	// the intended "<= threshold is healthy" without changing
	// checkResource's shared comparison logic.
	c.checkResource("smart:realloc", "Setores realocados", float64(report.ReallocatedSectors),
		cfg.SMARTReallocatedThreshold+1, c.alertSvc.DiskSMARTDegraded, c.alertSvc.DiskSMARTNormal)
	c.checkResource("smart:temp", "Temperatura do disco", float64(report.TemperatureC),
		cfg.SMARTTempThresholdC, c.alertSvc.DiskSMARTHot, c.alertSvc.DiskSMARTCool)
}

// checkBootTime runs at most once per process lifetime (guarded by
// c.bootChecked — /proc/uptime only grows, so re-checking on a later tick
// would measure "how long the process has been running", not "how long the
// boot took"). uptimeSeconds is the system uptime at the moment this first
// tick fires (caller passes sys.UptimeSeconds from the same collect() pass).
//
// Unlike every other check in this file, the alert here is fired directly
// from the freshly-computed `up` value, NOT from observe()'s returned
// transition — observe()'s anti-flap model requires a SECOND confirming
// reading before a first-ever "down" fires, which never happens for a check
// that only ever runs once. observe()/ensureMeta() are still called so the
// item shows up on the dashboard panel and is bookkept consistently with
// every other item.
//
// cfg.Enabled gates the ALERT, but not the measurement/bookkeeping above it:
// gating the whole function would let a later re-enable of monitoring fire
// this using a stale (much larger) uptime reading instead of the real boot
// duration. The caller (collect(), Task 6) calls this unconditionally.
func (c *Collector) checkBootTime(uptimeSeconds float64, cfg Config) {
	c.healthMu.Lock()
	if c.bootChecked {
		c.healthMu.Unlock()
		return
	}
	c.bootChecked = true
	c.healthMu.Unlock()

	up := uptimeSeconds < float64(cfg.BootTimeThresholdSec)
	c.observe("boot:time", up, c.nowFn())
	c.ensureMeta("boot:time", "boot-time", "resource")
	if c.rec != nil {
		c.rec.Gauge("boot.seconds", "", uptimeSeconds)
	}
	if !up && cfg.Enabled {
		_ = c.alertSvc.SlowBoot(uptimeSeconds)
	}
}
