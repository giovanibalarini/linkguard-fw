package monitoring

import (
	"context"
	"regexp"
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
		switch tr {
		case transDown:
			_ = c.alertSvc.ServiceOffline(svc)
		case transUp:
			_ = c.alertSvc.ServiceOnline(svc)
		}
	}
}

// checkDisk observes disk usage against the configured threshold and
// raises/clears alerts on confirmed transitions.
func (c *Collector) checkDisk(cfg Config, pct float64) {
	now := c.nowFn()
	key := "resource:disk"
	up := pct < float64(cfg.DiskThresholdPct) // "up" == healthy
	tr := c.observe(key, up, now)
	c.ensureMeta(key, "Disco", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DiskFull(pct)
	case transUp:
		_ = c.alertSvc.DiskCleared(pct)
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
