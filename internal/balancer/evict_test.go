package balancer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// recExec records write commands and serves canned read output so the balancer's
// Rebuild/interfaceIPv4 calls succeed during eviction tests.
type recExec struct {
	linkOut string            // `ip -br link show` output
	ipv4    map[string]string // iface -> `ip -o -4 addr show dev <iface>` output
	writes  []string
}

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.writes = append(e.writes, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (e *recExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "-4 addr show"):
		for iface, out := range e.ipv4 {
			if strings.Contains(joined, "dev "+iface) {
				return out, nil
			}
		}
		return "", nil
	case strings.Contains(joined, "link show"):
		return e.linkOut, nil
	}
	return "", nil
}

func (e *recExec) IsDryRun() bool                              { return false }
func (_ *recExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *recExec) conntrackCalls() []string {
	var out []string
	for _, w := range e.writes {
		if strings.HasPrefix(w, "conntrack ") {
			out = append(out, w)
		}
	}
	return out
}

func newEvictService(t *testing.T, exec *recExec, evictOn bool, links_ []storage.Link) *Service {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for i := range links_ {
		l := links_[i]
		if err := db.CreateLink(&l); err != nil {
			t.Fatalf("create link: %v", err)
		}
	}
	svc := NewService(db, exec, links.NewService(db), alerts.NewService(db))
	if err := svc.SaveConfig(Config{Mode: ModeBalance, EvictOnDegrade: evictOn}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return svc
}

func TestNormalizeEvictDefaults(t *testing.T) {
	var c Config
	c.normalize()
	if c.DegradedSustainSamples != 3 {
		t.Errorf("DegradedSustainSamples = %d, want 3", c.DegradedSustainSamples)
	}
	if c.EvictCooldownSecs != 120 {
		t.Errorf("EvictCooldownSecs = %d, want 120", c.EvictCooldownSecs)
	}
	if c.EvictOnDegrade {
		t.Error("EvictOnDegrade must default to false")
	}
}

func TestParseInterfaceIPv4(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"typical", "3: enp5s0    inet 192.168.15.20/24 brd 192.168.15.255 scope global enp5s0\\       valid_lft forever", "192.168.15.20"},
		{"empty", "", ""},
		{"no inet", "3: enp5s0    inet6 fe80::1/64 scope link", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInterfaceIPv4(tt.out); got != tt.want {
				t.Errorf("parseInterfaceIPv4(%q) = %q, want %q", tt.out, got, tt.want)
			}
		})
	}
}

func TestEvictDecision(t *testing.T) {
	degraded := storage.Link{ID: "a", Enabled: true, Status: links.StatusDegraded}
	onlineAlt := storage.Link{ID: "b", Enabled: true, Status: links.StatusOnline}
	offlineAlt := storage.Link{ID: "b", Enabled: true, Status: links.StatusOffline}
	now := time.Now()

	tests := []struct {
		name          string
		cfg           Config
		all           []storage.Link
		cooldownUntil time.Time
		wantProceed   bool
	}{
		{"disabled", Config{EvictOnDegrade: false}, []storage.Link{degraded, onlineAlt}, time.Time{}, false},
		{"no healthy alternative", Config{EvictOnDegrade: true}, []storage.Link{degraded, offlineAlt}, time.Time{}, false},
		{"cooldown active", Config{EvictOnDegrade: true}, []storage.Link{degraded, onlineAlt}, now.Add(time.Minute), false},
		{"proceeds", Config{EvictOnDegrade: true}, []storage.Link{degraded, onlineAlt}, time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evictDecision(tt.cfg, degraded, tt.all, tt.cooldownUntil, now)
			if got != tt.wantProceed {
				t.Errorf("evictDecision proceed = %v, want %v", got, tt.wantProceed)
			}
		})
	}
}

func TestEvictDegradedHappyPath(t *testing.T) {
	exec := &recExec{
		linkOut: "enp5s0 UP\nenp3s0 UP",
		ipv4:    map[string]string{"enp5s0": "3: enp5s0 inet 192.168.15.20/24 scope global enp5s0"},
	}
	degraded := storage.Link{ID: "a", Name: "WAN1", Interface: "enp5s0", Gateway: "192.168.15.1", Weight: 100, Enabled: true, Status: links.StatusDegraded}
	healthy := storage.Link{ID: "b", Name: "WAN2", Interface: "enp3s0", Gateway: "192.168.18.1", Weight: 100, Enabled: true, Status: links.StatusOnline}
	svc := newEvictService(t, exec, true, []storage.Link{degraded, healthy})

	svc.EvictDegraded(context.Background(), &degraded)

	calls := exec.conntrackCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 conntrack call, got %d: %v", len(calls), calls)
	}
	if calls[0] != "conntrack -D -q 192.168.15.20" {
		t.Errorf("conntrack call = %q, want %q", calls[0], "conntrack -D -q 192.168.15.20")
	}

	// Cooldown armed: an immediate second call must NOT flush again.
	svc.EvictDegraded(context.Background(), &degraded)
	if got := len(exec.conntrackCalls()); got != 1 {
		t.Errorf("cooldown not honored: %d conntrack calls total, want 1", got)
	}
}

func TestEvictDegradedDisabledNoFlush(t *testing.T) {
	exec := &recExec{ipv4: map[string]string{"enp5s0": "inet 192.168.15.20/24 scope global"}}
	degraded := storage.Link{ID: "a", Interface: "enp5s0", Enabled: true, Status: links.StatusDegraded}
	healthy := storage.Link{ID: "b", Interface: "enp3s0", Enabled: true, Status: links.StatusOnline}
	svc := newEvictService(t, exec, false, []storage.Link{degraded, healthy})

	svc.EvictDegraded(context.Background(), &degraded)
	if got := len(exec.conntrackCalls()); got != 0 {
		t.Errorf("eviction disabled but %d conntrack calls made", got)
	}
}

func TestEvictDegradedNoHealthyNoFlush(t *testing.T) {
	exec := &recExec{ipv4: map[string]string{"enp5s0": "inet 192.168.15.20/24 scope global"}}
	degraded := storage.Link{ID: "a", Interface: "enp5s0", Enabled: true, Status: links.StatusDegraded}
	alsoBad := storage.Link{ID: "b", Interface: "enp3s0", Enabled: true, Status: links.StatusOffline}
	svc := newEvictService(t, exec, true, []storage.Link{degraded, alsoBad})

	svc.EvictDegraded(context.Background(), &degraded)
	if got := len(exec.conntrackCalls()); got != 0 {
		t.Errorf("no healthy alternative but %d conntrack calls made", got)
	}
}
