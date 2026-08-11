package monitoring

import (
	"context"
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
	c.exec = &driftExec{responses: map[string]string{
		"nft list chain inet linkguard postrouting": `		oifname { "enp5s0" } masquerade`,
	}}

	c.checkFirewallNAT()

	if up := c.healthUp("firewall:nat"); !up {
		t.Error("firewall:nat should be up when the live rule covers every configured WAN")
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

func TestCheckDNSResolverFlagsExternalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "nameserver 189.40.0.1\n")

	c.checkDNSResolver()
	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); up {
		t.Error("dns:resolver should be down when resolv.conf points at an external server")
	}
}

func TestCheckDNSResolverHealthyOnLocalResolver(t *testing.T) {
	c := newDriftTestCollector(t)
	c.resolvConfPath = writeTempFile(t, "# managed by linkguard\nnameserver 127.0.0.1\n")

	c.checkDNSResolver()

	if up := c.healthUp("dns:resolver"); !up {
		t.Error("dns:resolver should be up when resolv.conf points at 127.0.0.1")
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
