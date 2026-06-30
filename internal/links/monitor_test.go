package links

import (
	"testing"
	"time"
)

func TestBindDialer(t *testing.T) {
	// No device → plain dialer (default routing), no Control hook.
	d := bindDialer("", 5*time.Second)
	if d.Control != nil {
		t.Error("empty device must not install a Control hook")
	}
	if d.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", d.Timeout)
	}

	// With a device → a Control hook is installed so the probe binds to that
	// interface (SO_BINDTODEVICE), giving per-link health detection.
	d2 := bindDialer("enp5s0", 3*time.Second)
	if d2.Control == nil {
		t.Error("a device must install a Control hook (SO_BINDTODEVICE)")
	}
}

func TestParseHosts(t *testing.T) {
	got := parseHosts(" 1.1.1.1, 8.8.8.8 ,, 9.9.9.9 ")
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("got %d hosts, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("host[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(parseHosts("")) != 0 {
		t.Error("empty string should yield no hosts")
	}
}
