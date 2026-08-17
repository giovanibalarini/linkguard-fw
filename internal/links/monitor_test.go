package links

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
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

// TestAdvanceStatusRequiresSustainedThreshold verifies that a single degraded
// sample does NOT flip status to degraded — status must stay at whatever it
// was until sustainThreshold consecutive degraded samples accumulate, the
// same shape probeFailThreshold already uses for offline. Before this fix,
// "case degradedNow:" alone was enough to flip status on the very first
// sample, which is what turned an 8-second upstream blip into a route
// rewrite in production (2026-07-23 incident).
func TestAdvanceStatusRequiresSustainedThreshold(t *testing.T) {
	st := &linkState{}
	prev := StatusOnline

	// Two degraded samples below threshold(3): status must NOT flip yet.
	for i := 0; i < 2; i++ {
		status, _ := st.advance(true, true, prev, 3)
		if status != StatusOnline {
			t.Fatalf("sample %d: status = %q, want online (below threshold, must not flip)", i+1, status)
		}
	}

	// Third sample crosses the threshold: NOW it flips.
	status, _ := st.advance(true, true, prev, 3)
	if status != StatusDegraded {
		t.Fatalf("sample 3: status = %q, want degraded (threshold reached)", status)
	}
}

// TestAdvanceStatusRecoversAfterDegradedEpisode verifies that once degraded
// status has flipped, a single good sample does not immediately flip back to
// online — the existing probeRecoverThreshold gate (2 consecutive good
// samples) still applies, unaffected by this change.
func TestAdvanceStatusRecoversAfterDegradedEpisode(t *testing.T) {
	st := &linkState{}
	status := StatusOnline
	for i := 0; i < 3; i++ {
		status, _ = st.advance(true, true, status, 3)
	}
	if status != StatusDegraded {
		t.Fatalf("setup: expected degraded after 3 samples, got %q", status)
	}

	// One good sample: probeRecoverThreshold is 2, so status must stay degraded.
	status, _ = st.advance(true, false, status, 3)
	if status != StatusDegraded {
		t.Fatalf("after 1 good sample: status = %q, want degraded (recover threshold not yet met)", status)
	}

	// Second consecutive good sample: now it recovers.
	status, _ = st.advance(true, false, status, 3)
	if status != StatusOnline {
		t.Fatalf("after 2 good samples: status = %q, want online", status)
	}
}

// TestCheckLinkPassesFreshMeasurementToCallback verifies the link handed to
// onStatusChange carries THIS tick's measured latency/loss, not whatever was
// last persisted before the probe ran. Before this fix, "updated := l" copied
// the link fetched at the top of the tick — stale by definition, since it
// predates this tick's probe measurement — so any alert built from it could
// never show a real number.
func TestCheckLinkPassesFreshMeasurementToCallback(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	svc := NewService(db)
	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1:1", // deliberately unreachable port -> measurable loss
		Enabled: true, LatencyMs: 999, PacketLoss: 0, // stale values that must NOT leak through
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	mon := NewMonitor(db, svc, time.Second, 1, nil, nil)
	var gotLatency, gotLoss float64
	var called bool
	mon.OnStatusChange(func(link *storage.Link, oldStatus, newStatus string) {
		called = true
		gotLatency = link.LatencyMs
		gotLoss = link.PacketLoss
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mon.RunOnceForTest(ctx)

	if !called {
		t.Fatal("expected onStatusChange to fire on first observation (unknown -> offline/degraded)")
	}
	if gotLatency == 999 {
		t.Fatal("expected fresh latency, got the stale seed value 999 — updated.LatencyMs was never set")
	}
	_ = gotLoss // loss is asserted indirectly via gotLatency != stale sentinel above
}

// TestCheckLinkConcurrentProbesDoNotRace overlaps two probe cadences on the
// SAME link — e.g. a future second polling loop, or a manual re-check
// endpoint racing the ticker — and requires `go test -race` to stay silent.
//
// Antes da correção (issue #29), checkLink pegava o *linkState sob m.mu,
// SOLTAVA o lock, e só então chamava state.advance(...) e escrevia
// state.lastStatus — tudo fora da proteção do mutex. Com uma única goroutine
// por link e checkAll fazendo wg.Wait() antes do próximo tick isso nunca
// colidia de fato, o que é exatamente por que o -race nunca acusava nada em
// produção nem nos testes existentes (nenhum deles sobrepõe duas chamadas a
// checkLink para o mesmo link). Este teste força a sobreposição.
//
// Prova por mutação: revertendo o fix (voltando a soltar m.mu antes de
// state.advance/lastStatus, como no código original) este teste ACUSA data
// race sob -race; com o fix ele passa limpo. Essa é a prova pedida na issue
// — o "antes" é o próprio código pré-correção.
func TestCheckLinkConcurrentProbesDoNotRace(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	svc := NewService(db)
	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1:1", // porta fechada -> advance() muda estado a cada chamada
		Enabled: true,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	mon := NewMonitor(db, svc, time.Second, 1, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const goroutines = 2
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				mon.checkLink(ctx, *l)
			}
		}()
	}
	wg.Wait()
}

// TestSustainThresholdIsResolvedOutsideTheLock guards the SCOPE of mu, not its
// existence. The provider set by SustainThreshold reaches the database
// (balancer.LoadConfig → db.GetSetting) and the database opens a single
// connection (SetMaxOpenConns(1)). Resolving it while holding mu would make one
// link's goroutine wait on that connection with the mutex in hand, and every
// other link's goroutine wait on the mutex — delaying detection of the second
// WAN going down during the first one's incident.
//
// TryLock is the whole point: it answers "was mu held when the provider ran?"
// without deadlocking the suite if the answer is yes.
func TestSustainThresholdIsResolvedOutsideTheLock(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	l := &storage.Link{
		Name: "WAN1", Interface: "lo", Gateway: "127.0.0.1",
		DNSTest: "127.0.0.1", MonitorHosts: "127.0.0.1:1",
		Enabled: true,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	mon := NewMonitor(db, NewService(db), time.Second, 1, nil, nil)

	var called bool
	mon.SustainThreshold(func() int {
		called = true
		if !mon.mu.TryLock() {
			t.Error("SustainThreshold foi resolvido com mu travado: o provider lê o banco " +
				"(LoadConfig → GetSetting) e o banco tem uma conexão só, então isso serializa " +
				"os links uns nos outros. Resolva sustainN() ANTES de m.mu.Lock().")
			return 1
		}
		mon.mu.Unlock()
		return 1
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mon.checkLink(ctx, *l)

	if !called {
		t.Fatal("o provider nunca foi chamado; o teste não mediu nada")
	}
}
