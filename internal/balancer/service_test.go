package balancer

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestNormalizeWeights(t *testing.T) {
	tests := []struct {
		name string
		raw  []int
		want []int
	}{
		{"equal", []int{100, 100}, []int{256, 256}},
		{"all zero -> equal split", []int{0, 0}, []int{1, 1}},
		{"ratio preserved", []int{700, 300}, []int{256, 110}},
		{"single", []int{5}, []int{256}},
		{"clamps to >=1", []int{1000, 1}, []int{256, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nhs := make([]Nexthop, len(tt.raw))
			for i, w := range tt.raw {
				nhs[i] = Nexthop{RawWeight: w}
			}
			normalizeWeights(nhs)
			for i := range nhs {
				if nhs[i].Weight != tt.want[i] {
					t.Errorf("idx %d: got weight %d, want %d", i, nhs[i].Weight, tt.want[i])
				}
			}
		})
	}
}

func TestBuildReplaceArgs(t *testing.T) {
	nhs := []Nexthop{
		{Gateway: "192.168.15.1", Interface: "enp5s0", Weight: 3},
		{Gateway: "192.168.18.1", Interface: "enp3s0", Weight: 1},
	}
	args := buildReplaceArgs("main", nhs)
	got := "ip " + strings.Join(args, " ")
	want := "ip route replace default table main " +
		"nexthop via 192.168.15.1 dev enp5s0 weight 3 onlink " +
		"nexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	if buildReplaceArgs("main", nil) != nil {
		t.Error("expected nil args for empty nexthops")
	}

	// Single nexthop is still valid multipath.
	single := buildReplaceArgs("main", nhs[:1])
	if !strings.Contains(strings.Join(single, " "), "nexthop via 192.168.15.1") {
		t.Errorf("single nexthop missing: %v", single)
	}
}

func TestRestoreArgsFromShow_SinglePath(t *testing.T) {
	// Mirrors the production WAN1 default route.
	show := "default via 192.168.15.1 dev enp5s0 onlink"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main via 192.168.15.1 dev enp5s0 onlink"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRestoreArgsFromShow_SinglePathNoOnlink(t *testing.T) {
	show := "default via 192.168.18.1 dev enp3s0"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main via 192.168.18.1 dev enp3s0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Contains(got, "onlink") {
		t.Error("must not invent onlink when absent")
	}
}

func TestRestoreArgsFromShow_Multipath(t *testing.T) {
	// `ip route show` prints multipath across lines; we collapse whitespace.
	show := "default proto static \n\tnexthop via 192.168.15.1 dev enp5s0 weight 3 onlink \n\tnexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main " +
		"nexthop via 192.168.15.1 dev enp5s0 weight 3 onlink " +
		"nexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRestoreArgsFromShow_Empty(t *testing.T) {
	if restoreArgsFromShow("", "main") != nil {
		t.Error("expected nil for empty show output")
	}
}

func TestSelectNexthops(t *testing.T) {
	link := func(name, iface, gw, status string, loss, lat float64) storage.Link {
		return storage.Link{Name: name, Interface: iface, Gateway: gw, Weight: 100,
			Enabled: true, Status: status, PacketLoss: loss, LatencyMs: lat}
	}
	names := func(nhs []Nexthop) []string {
		out := []string{}
		for _, n := range nhs {
			out = append(out, n.Name)
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	allUp := map[string]bool{"eth0": true, "eth1": true}

	t.Run("both online -> balance both", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "online", 0, 12),
		}, allUp)
		if !eq(names(c), []string{"A", "B"}) {
			t.Errorf("chosen=%v, want [A B]", names(c))
		}
	})

	t.Run("one degraded -> use only healthy", func(t *testing.T) {
		c, ex := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "degraded", 40, 500),
		}, allUp)
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A] (degraded B must sit out)", names(c))
		}
		if !eq(names(ex), []string{"B"}) {
			t.Errorf("excluded=%v, want [B]", names(ex))
		}
	})

	t.Run("both degraded -> least degraded by loss", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "degraded", 60, 200),
			link("B", "eth1", "10.0.1.1", "degraded", 30, 400),
		}, allUp)
		if !eq(names(c), []string{"B"}) { // B has less loss
			t.Errorf("chosen=%v, want [B] (lowest loss)", names(c))
		}
	})

	t.Run("both degraded equal loss -> least latency", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "degraded", 30, 600),
			link("B", "eth1", "10.0.1.1", "degraded", 30, 250),
		}, allUp)
		if !eq(names(c), []string{"B"}) { // equal loss, B lower latency
			t.Errorf("chosen=%v, want [B] (lowest latency)", names(c))
		}
	})

	t.Run("offline excluded when a healthy link exists", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "offline", 100, 0),
		}, allUp)
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A]", names(c))
		}
	})

	t.Run("interface down is never a nexthop", func(t *testing.T) {
		// B is 'online' per the probe but its interface is physically down.
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "online", 0, 10),
		}, map[string]bool{"eth0": true}) // eth1 down
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A] (eth1 down)", names(c))
		}
	})

	t.Run("safety net: up interface, failing probe -> still used, never empty", func(t *testing.T) {
		// Probe says offline, but the interface is up: use it rather than leave
		// an empty default route (the bug that black-holed traffic + DNS).
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "offline", 100, 0),
		}, map[string]bool{"eth0": true})
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A] (safety net, must not be empty)", names(c))
		}
	})
}

func TestParseUpInterfaces(t *testing.T) {
	out := "lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n" +
		"enp5s0           UP             b8:ca:3a:fc:d6:03 <BROADCAST,MULTICAST,UP,LOWER_UP>\n" +
		"enp3s0           DOWN           f4:f2:6d:05:e2:f0 <BROADCAST,MULTICAST>"
	up := parseUpInterfaces(out)
	if !up["enp5s0"] {
		t.Error("enp5s0 should be up")
	}
	if up["enp3s0"] {
		t.Error("enp3s0 is DOWN, must not be up")
	}
	if up["lo"] {
		t.Error("lo state is UNKNOWN, must not count as up")
	}
}

func TestConfigNormalize(t *testing.T) {
	c := Config{}
	c.normalize()
	if c.Mode != ModeFailover {
		t.Errorf("default mode = %q, want %q", c.Mode, ModeFailover)
	}
	if c.Table != defaultTable {
		t.Errorf("default table = %q, want %q", c.Table, defaultTable)
	}
	if c.ArmSeconds != defaultArmSecs {
		t.Errorf("default arm = %d, want %d", c.ArmSeconds, defaultArmSecs)
	}
	// Regression: Schedules must never be nil, or it marshals to JSON null and
	// crashes the Links page (schedules.length on null).
	if c.Schedules == nil {
		t.Error("normalize must leave Schedules as a non-nil slice")
	}

	c2 := Config{Mode: "bogus"}
	c2.normalize()
	if c2.Mode != ModeFailover {
		t.Errorf("bogus mode should fall back to failover, got %q", c2.Mode)
	}
}
