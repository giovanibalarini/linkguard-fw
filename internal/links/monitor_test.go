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

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.001
}

func TestSummarize(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	tests := []struct {
		name     string
		results  []CheckResult
		wantLat  float64
		wantLoss float64
	}{
		{"no samples -> full loss", nil, 0, 100},
		{"all success", []CheckResult{{Success: true, Latency: ms(10)}, {Success: true, Latency: ms(20)}}, 15, 0},
		{"half loss averages only successes", []CheckResult{{Success: true, Latency: ms(10)}, {Success: false}, {Success: true, Latency: ms(30)}, {Success: false}}, 20, 50},
		{"all fail -> full loss", []CheckResult{{Success: false}, {Success: false}}, 0, 100},
		{"one of three -> ~66% loss", []CheckResult{{Success: true, Latency: ms(9)}, {Success: false}, {Success: false}}, 9, 66.6667},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lat, loss := summarize(tt.results)
			if !approx(lat, tt.wantLat) {
				t.Errorf("latency = %v, want %v", lat, tt.wantLat)
			}
			if !approx(loss, tt.wantLoss) {
				t.Errorf("loss = %v, want %v", loss, tt.wantLoss)
			}
		})
	}
}

// TestAdvanceDebounce verifies the sustained-degradation episode is edge-triggered:
// it fires exactly once when the consecutive-degraded count crosses the threshold,
// stays silent while the link remains degraded, and re-arms after recovery.
func TestAdvanceDebounce(t *testing.T) {
	st := &linkState{}
	// Two degraded samples below threshold(3) → no fire yet.
	for i := 0; i < 2; i++ {
		if _, fired := st.advance(true, true, StatusOnline, 3); fired {
			t.Fatalf("sample %d: fired before reaching threshold", i+1)
		}
	}
	// Third degraded sample → crosses threshold → fires once.
	status, fired := st.advance(true, true, StatusDegraded, 3)
	if !fired {
		t.Fatal("third degraded sample must fire sustained episode")
	}
	if status != StatusDegraded {
		t.Errorf("status = %q, want degraded", status)
	}
	// Further degraded samples must NOT re-fire the same episode.
	if _, fired := st.advance(true, true, StatusDegraded, 3); fired {
		t.Error("must not re-fire within the same degraded episode")
	}
	// Recover (good sample) then degrade again → a NEW episode may fire.
	st.advance(true, false, StatusDegraded, 3)
	for i := 0; i < 2; i++ {
		st.advance(true, true, StatusOnline, 3)
	}
	if _, fired := st.advance(true, true, StatusDegraded, 3); !fired {
		t.Error("a fresh degraded episode after recovery must fire again")
	}
}

func TestAdvanceThresholdFloor(t *testing.T) {
	// A threshold ≤ 0 is treated as 1: a single degraded sample fires.
	st := &linkState{}
	if _, fired := st.advance(true, true, StatusOnline, 0); !fired {
		t.Error("threshold 0 must be floored to 1 and fire on first degraded sample")
	}
}

func TestAdvanceOfflineAndOnline(t *testing.T) {
	// probeFailThreshold consecutive unreachable samples → offline.
	st := &linkState{}
	var status string
	for i := 0; i < probeFailThreshold; i++ {
		status, _ = st.advance(false, false, StatusOnline, 3)
	}
	if status != StatusOffline {
		t.Errorf("after %d fails, status = %q, want offline", probeFailThreshold, status)
	}
	// probeRecoverThreshold consecutive good samples → online.
	for i := 0; i < probeRecoverThreshold; i++ {
		status, _ = st.advance(true, false, StatusOffline, 3)
	}
	if status != StatusOnline {
		t.Errorf("after %d good samples, status = %q, want online", probeRecoverThreshold, status)
	}
}
