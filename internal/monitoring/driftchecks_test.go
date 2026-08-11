package monitoring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// driftExec answers the specific read commands the drift checks issue,
// keyed by the full command line, and reports which interfaces "exist".
type driftExec struct {
	responses map[string]string
	err       error
}

func (e *driftExec) Execute(_ context.Context, _ string, _ ...string) (string, error) {
	return "", nil
}
func (e *driftExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if e.err != nil {
		return "", e.err
	}
	return e.responses[strings.Join(append([]string{cmd}, args...), " ")], nil
}
func (e *driftExec) IsDryRun() bool { return false }

// TestCheckWANInterfacesFlagsMissingInterface is the regression test for the
// 2026-08-10 incident: a WAN link kept pointing at enp4s0 after the NIC was
// renamed to enp5s0, and nothing on the panel said so. This watcher is what
// would have caught it at boot.
func TestCheckWANInterfacesFlagsMissingInterface(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp4s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" }

	c.checkWANInterfaces()
	c.checkWANInterfaces() // downConfirm=2: the outage is declared on the confirming tick

	if up := c.healthUp("wan:interface"); up {
		t.Error("wan:interface should be down when a link points at a missing interface")
	}
}

func TestCheckWANInterfacesHealthyWhenAllPresent(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" }

	c.checkWANInterfaces()

	if up := c.healthUp("wan:interface"); !up {
		t.Error("wan:interface should be up when every link's interface exists")
	}
}

// A disabled link is not a live WAN — it must not raise an alert.
func TestCheckWANInterfacesIgnoresDisabledLinks(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VELHA", "enp9s0", false)
	c.ifaceExists = func(name string) bool { return false }

	c.checkWANInterfaces()
	c.checkWANInterfaces()

	if up := c.healthUp("wan:interface"); !up {
		t.Error("a disabled link must not mark wan:interface as down")
	}
}

// TestCheckFirewallNATFlagsStaleRule: the live rule still references the old
// interface while the configured link moved on — precisely the state
// production was left in.
func TestCheckFirewallNATFlagsStaleRule(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `table inet linkguard {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname { "enp2s0", "enp4s0" } masquerade
	}
}`,
	}}

	c.checkFirewallNAT()
	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); up {
		t.Error("firewall:nat should be down when the live rule omits a configured WAN")
	}
}

func TestCheckFirewallNATHealthyWhenRuleMatches(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" }
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `		oifname { "enp5s0" } masquerade`,
	}}

	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); !up {
		t.Error("firewall:nat should be up when the live rule covers exactly every configured WAN and every interface it references exists")
	}
}

// TestCheckFirewallNATFlagsStaleExtraInterface: the live rule references
// every configured WAN but ALSO an extra interface no longer configured
// (e.g. a WAN that was deleted but whose masquerade entry survived a
// partial reconcile). The old check only tested "every configured WAN is
// present somewhere in the rule" and would have missed this.
func TestCheckFirewallNATFlagsStaleExtraInterface(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.ifaceExists = func(name string) bool { return true }
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `oifname { "enp5s0", "enp9s0" } masquerade`,
	}}

	c.checkFirewallNAT()
	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); up {
		t.Error("firewall:nat should be down when the live rule references an interface that is not a configured WAN")
	}
}

// TestCheckFirewallNATFlagsRuleInterfaceMissingFromKernel replays the
// 2026-08-10 incident directly: the DB still says enp4s0, reconciliation
// faithfully wrote `oifname { "enp4s0" }`, NAT is down — and the OLD check
// saw "enp4s0" present in the rule text and reported green, because it never
// checked whether that interface actually exists. This is the exact
// scenario the check exists for.
func TestCheckFirewallNATFlagsRuleInterfaceMissingFromKernel(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp4s0", true)
	c.ifaceExists = func(name string) bool { return name == "enp5s0" } // kernel only has enp5s0
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `oifname { "enp4s0" } masquerade`,
	}}

	c.checkFirewallNAT()
	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); up {
		t.Error("firewall:nat should be down when the rule's interface no longer exists in the kernel (2026-08-10 incident replay)")
	}
}

// TestCheckFirewallNATFlagsMissingMasqueradeRule: no masquerade rule at all
// is a problem state (NAT is off), not an "unknown" — unlike the
// unreadable-chain case, we DID read the chain successfully, and it simply
// has no masquerade rule in it.
func TestCheckFirewallNATFlagsMissingMasqueradeRule(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `table inet linkguard {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}`,
	}}

	c.checkFirewallNAT()
	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); up {
		t.Error("firewall:nat should be down when no masquerade rule exists at all")
	}
}

// No configured WANs means there is nothing to verify — the watcher must not
// invent a problem (and must not claim health either; it simply stays out of
// the way).
func TestCheckFirewallNATSkipsWhenNoWANsConfigured(t *testing.T) {
	c := newDriftTestCollector(t)
	c.exec = &driftExec{responses: map[string]string{}}

	c.checkFirewallNAT()

	if _, known := c.healthState("firewall:nat"); known {
		t.Error("firewall:nat must not be reported at all when no WAN is configured")
	}
}

// succeedingDNSProbe stands in for a healthy resolver in tests that want to
// isolate the resolv.conf config check from the functional probe.
func succeedingDNSProbe() error { return nil }

func TestCheckDNSResolverFlagsExternalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 189.40.0.1\n")
	c.dnsProbe = succeedingDNSProbe

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf points at an external server")
	}
}

func TestCheckDNSResolverHealthyOnLocalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "# managed by linkguard\nnameserver 127.0.0.1\n")
	c.dnsProbe = succeedingDNSProbe

	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); !up {
		t.Error("dns:resolver should be up when resolv.conf points at 127.0.0.1 and the probe succeeds")
	}
}

// TestCheckDNSResolverFlagsProbeRefused is the regression test for the
// 2026-08-11 incident: resolv.conf pointed at 127.0.0.1 (config check green)
// while the box's own loopback DNS queries were arriving at unbound with a
// rewritten (WAN) source address and being correctly REFUSED by its
// access-control. The config-only check stayed green through all of it; this
// probe is what would have caught it.
func TestCheckDNSResolverFlagsProbeRefused(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 127.0.0.1\n")
	c.dnsProbe = func() error { return errors.New("REFUSED") }

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf is correct but the probe is REFUSED")
	}
}

func TestCheckDNSResolverFlagsProbeTimeout(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 127.0.0.1\n")
	c.dnsProbe = func() error { return errors.New("timeout") }

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf is correct but the probe times out")
	}
}

// TestCheckDNSResolverDoesNotJudgeWhenProbeUnavailable verifies the
// no-fake-data contract for the probe itself: if the probe could not even
// attempt the query (e.g. socket creation failed), that is not a verdict
// about the resolver's health — the item must not appear in the health map
// at all, exactly like the file's other "unreadable this tick" early
// returns.
func TestCheckDNSResolverDoesNotJudgeWhenProbeUnavailable(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 127.0.0.1\n")
	c.dnsProbe = func() error { return &dnsProbeUnavailableError{errors.New("socket: too many open files")} }

	c.checkDNSResolver()
	c.checkDNSResolver()

	if _, known := c.healthState("dns:resolver"); known {
		t.Error("dns:resolver must not be reported when the probe itself could not run")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

// newDriftTestCollector builds a real Collector backed by a temp sqlite db —
// no existing helper in this package wires up db+exec+alertSvc together (the
// package's other newTestCollector() only sets up the bare health map for
// observe()-only tests), so this is the brief's fallback.
func newDriftTestCollector(t *testing.T) *Collector {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	c := NewCollector(db, nil, alerts.NewService(db), &driftExec{responses: map[string]string{}}, nil)
	c.nowFn = func() int64 { return 1 }
	return c
}

func seedLink(t *testing.T, c *Collector, name, iface string, enabled bool) {
	t.Helper()
	if err := c.db.CreateLink(&storage.Link{ID: name, Name: name, Interface: iface, Weight: 1, Enabled: enabled}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
}

// healthUp reports the item's current up/down state; healthState also
// reports whether the item exists at all.
func (c *Collector) healthUp(key string) bool {
	up, _ := c.healthState(key)
	return up
}

func (c *Collector) healthState(key string) (up, known bool) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		return false, false
	}
	return st.up, true
}

// TestCheckFirewallNATDoesNotJudgeWhenNftUnreadable verifies the no-fake-data
// contract: when the drift watcher cannot read the live firewall state, it must
// not emit a verdict at all (neither "ok" nor "problem"), because a false "ok"
// would give the operator false confidence in their firewall. The item must not
// appear in the health map at all.
func TestCheckFirewallNATDoesNotJudgeWhenNftUnreadable(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)
	c.exec = &driftExec{err: context.DeadlineExceeded} // ExecuteRead will fail

	c.checkFirewallNAT()
	c.checkFirewallNAT() // call twice to ensure repeated failures never produce a verdict

	if _, known := c.healthState("firewall:nat"); known {
		t.Error("firewall:nat must not be reported when nft list chain fails")
	}
}

// TestCheckDNSResolverDoesNotJudgeWhenResolvConfUnreadable verifies the
// no-fake-data contract: when the drift watcher cannot read resolv.conf, it
// must not emit a verdict (not a false "ok", not a false "problem"). The item
// must not appear in the health map at all, so the operator knows the check
// could not run, not that resolution is healthy.
func TestCheckDNSResolverDoesNotJudgeWhenResolvConfUnreadable(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = filepath.Join(t.TempDir(), "nonexistent.conf")

	c.checkDNSResolver()
	c.checkDNSResolver() // call twice to ensure repeated failures never produce a verdict

	if _, known := c.healthState("dns:resolver"); known {
		t.Error("dns:resolver must not be reported when resolv.conf is unreadable")
	}
}

// TestCheckDNSResolverFlagsMixedLocalAndExternal verifies that a lingering
// external fallback is flagged as down. The configured state is local-only
// resolution via unbound, but if an external nameserver is still listed in
// resolv.conf (even alongside 127.0.0.1), a leak is possible: a client query
// to 127.0.0.1 could fail and the OS resolver could silently fall back to the
// external server, bypassing the local policy engine entirely. This is the
// exact silent bypass the drift watchers exist to catch, so mixed local+external
// must be reported as down, not healthy.
func TestCheckDNSResolverFlagsMixedLocalAndExternal(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 127.0.0.1\nnameserver 8.8.8.8\n")
	c.dnsProbe = succeedingDNSProbe

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf contains both local and external resolvers")
	}
}

// TestCheckWANInterfacesDoesNotJudgeWhenLinksUnreadable verifies the
// no-fake-data contract: when the drift watcher cannot read the configured WAN
// links from the database, it must not emit a verdict. The item must not appear
// in the health map at all, so the operator knows the check could not run.
func TestCheckWANInterfacesDoesNotJudgeWhenLinksUnreadable(t *testing.T) {
	c := newDriftTestCollector(t)
	seedLink(t, c, "WAN VIVO", "enp5s0", true)

	// Close the database connection to make GetLinks() fail on the next query.
	c.db.Close()

	c.checkWANInterfaces()
	c.checkWANInterfaces() // call twice to ensure repeated failures never produce a verdict

	if _, known := c.healthState("wan:interface"); known {
		t.Error("wan:interface must not be reported when GetLinks() fails")
	}
}
