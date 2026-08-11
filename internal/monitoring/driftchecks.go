package monitoring

import (
	"context"
	"fmt"
	"os"
	"regexp"
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

// masqueradeRuleRe finds the line carrying the masquerade verdict inside
// `nft list chain` output (the ruleset ReconcileMasquerade writes always
// keeps `oifname { ... } masquerade` together on one line — see
// internal/nftables/reconcile.go).
var masqueradeRuleRe = regexp.MustCompile(`(?m)^.*\bmasquerade\b.*$`)

// quotedInterfaceRe pulls interface names out of an nft `{ "a", "b" }` set
// (also matches the unbracketed single-interface form nft can print).
var quotedInterfaceRe = regexp.MustCompile(`"([^"]+)"`)

// parseMasqueradeInterfaces extracts the interface names referenced by the
// masquerade rule in `nft list chain` output. found is false when the chain
// has no masquerade rule at all (NAT is off), as distinct from an empty
// interface set.
func parseMasqueradeInterfaces(chainText string) (ifaces []string, found bool) {
	line := masqueradeRuleRe.FindString(chainText)
	if line == "" {
		return nil, false
	}
	for _, m := range quotedInterfaceRe.FindAllStringSubmatch(line, -1) {
		ifaces = append(ifaces, m[1])
	}
	return ifaces, true
}

// checkFirewallNAT verifies the LIVE masquerade rule references EXACTLY the
// configured WAN interfaces, and that every interface it references exists
// in the kernel. `systemctl is-active nftables` cannot see any of this: the
// service is happily active while the rule inside it is stale.
//
// Replays the 2026-08-10 incident directly: the DB still said enp4s0,
// reconciliation faithfully wrote `oifname { "enp4s0" }`, NAT was down — and
// a check that only tests "every configured WAN appears somewhere in the
// rule" sees "enp4s0" present and reports green on a tile literally named
// "Regra de NAT", during the exact scenario it exists to catch. Comparing
// both directions (configured ⊆ rule AND rule ⊆ configured) also catches a
// stale extra interface left behind by a partial reconcile, and checking
// existence catches the rule referencing an interface the kernel no longer
// has at all.
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

	exists := c.ifaceExists
	if exists == nil {
		exists = interfaceExists
	}

	ruleIfaces, found := parseMasqueradeInterfaces(out)
	if !found {
		// No masquerade rule at all is a problem state (NAT is off), not an
		// unknown — we DID read the chain successfully.
		tr := c.observe("firewall:nat", false, c.nowFn())
		c.ensureMeta("firewall:nat", "firewall-nat", "resource")
		if tr == transDown {
			_ = c.alertSvc.FirewallNATDrift("nenhuma regra de masquerade encontrada na chain postrouting (NAT desligado)")
		}
		return
	}

	configured := make(map[string]bool, len(wans))
	for _, w := range wans {
		configured[w] = true
	}
	inRule := make(map[string]bool, len(ruleIfaces))
	for _, i := range ruleIfaces {
		inRule[i] = true
	}

	var missing, stale, absentFromKernel []string
	for _, w := range wans {
		if !inRule[w] {
			missing = append(missing, w)
		}
	}
	for _, i := range ruleIfaces {
		if !configured[i] {
			stale = append(stale, i)
		}
		if !exists(i) {
			absentFromKernel = append(absentFromKernel, i)
		}
	}

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "WAN configurada mas ausente da regra: "+strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		parts = append(parts, "interface na regra que não é uma WAN configurada: "+strings.Join(stale, ", "))
	}
	if len(absentFromKernel) > 0 {
		parts = append(parts, "interface na regra que não existe no kernel: "+strings.Join(absentFromKernel, ", "))
	}

	tr := c.observe("firewall:nat", len(parts) == 0, c.nowFn())
	c.ensureMeta("firewall:nat", "firewall-nat", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.FirewallNATDrift(strings.Join(parts, "; "))
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
