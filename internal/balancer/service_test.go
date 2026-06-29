package balancer

import (
	"strings"
	"testing"
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
