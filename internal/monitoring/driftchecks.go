package monitoring

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Config drift watchers.
//
// Why this file exists: on 2026-08-10 a NIC rename left a WAN link pointing
// at an interface that no longer existed and the firewall's masquerade rule
// stranded on the old name. Every existing health check stayed green —
// `systemctl is-active nftables` was perfectly happy serving a stale rule —
// so the operator only found it by SSHing in. These checks close that blind
// spot: they compare what LinkGuard APPLIED against what the system
// actually LOOKS LIKE, which no other check in this package does.
//
// All three are read-only and cheap enough for the 30s collector tick.

// defaultResolvConfPath is the file checkDNSResolver reads; overridden in tests.
const defaultResolvConfPath = "/etc/resolv.conf"

// enabledWANInterfaces returns the interfaces of every enabled WAN link —
// the source of truth both checkWANInterfaces and checkFirewallNAT compare
// reality against.
func (c *Collector) enabledWANInterfaces() []string {
	ls, err := c.db.GetLinks()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			out = append(out, l.Interface)
		}
	}
	return out
}

// interfaceExists reports whether the kernel currently has this interface.
// Uses /sys/class/net directly (no exec) — a rename shows up immediately.
func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// checkWANInterfaces verifies every enabled WAN link points at an interface
// the kernel actually has. This is the watcher that would have caught the
// 2026-08-10 incident the moment the box came up.
func (c *Collector) checkWANInterfaces() {
	ls, err := c.db.GetLinks()
	if err != nil {
		return // cannot evaluate this tick; don't invent a verdict
	}
	exists := c.ifaceExists
	if exists == nil {
		exists = interfaceExists
	}

	var missing []string
	for _, l := range ls {
		if !l.Enabled || l.Interface == "" {
			continue
		}
		if !exists(l.Interface) {
			missing = append(missing, fmt.Sprintf("%s -> %s", l.Name, l.Interface))
		}
	}

	tr := c.observe("wan:interface", len(missing) == 0, c.nowFn())
	c.ensureMeta("wan:interface", "wan-interface", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.WANInterfaceMissing(strings.Join(missing, ", "))
	case transUp:
		_ = c.alertSvc.WANInterfaceOK()
	}
}

// checkFirewallNAT verifies the LIVE masquerade rule covers exactly the
// configured WAN interfaces. `systemctl is-active nftables` cannot see this:
// the service is happily active while the rule inside it is stale.
func (c *Collector) checkFirewallNAT() {
	wans := c.enabledWANInterfaces()
	if len(wans) == 0 {
		return // nothing configured to verify against
	}
	out, err := c.exec.ExecuteRead(context.Background(), "nft", "list", "chain",
		nftables.Family, nftables.Table, "postrouting")
	if err != nil {
		return // table/chain unreadable this tick — no verdict rather than a false one
	}

	var missing []string
	for _, iface := range wans {
		if !strings.Contains(out, `"`+iface+`"`) {
			missing = append(missing, iface)
		}
	}
	detail := ""
	if len(missing) > 0 {
		detail = "faltando na regra: " + strings.Join(missing, ", ")
	}

	tr := c.observe("firewall:nat", len(missing) == 0, c.nowFn())
	c.ensureMeta("firewall:nat", "firewall-nat", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.FirewallNATDrift(detail)
	case transUp:
		_ = c.alertSvc.FirewallNATOK()
	}
}

// checkDNSResolver verifies the box resolves through its own unbound rather
// than the ISP's servers — the drift found in production, caused by
// dhclient rewriting resolv.conf on lease renewal.
func (c *Collector) checkDNSResolver() {
	path := c.resolvConfPath
	if path == "" {
		path = defaultResolvConfPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return // unreadable this tick; no verdict
	}

	local := false
	var external []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		addr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		if addr == "127.0.0.1" || addr == "::1" {
			local = true
		} else if addr != "" {
			external = append(external, addr)
		}
	}

	tr := c.observe("dns:resolver", local && len(external) == 0, c.nowFn())
	c.ensureMeta("dns:resolver", "dns-resolver", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DNSResolverDrift(strings.Join(external, ", "))
	case transUp:
		_ = c.alertSvc.DNSResolverOK()
	}
}
