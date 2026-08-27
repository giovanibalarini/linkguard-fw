package stresstest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestFinalizeSummary(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{
		Samples: []Sample{
			{Phase: "baseline", Ping: true, DNS: true}, // excluded from summary
			{Phase: "fault", Ping: true, DNS: true},
			{Phase: "fault", Ping: false, DNS: true},    // 1 ping loss
			{Phase: "recovery", Ping: true, DNS: false}, // 1 dns loss
			{Phase: "recovery", Ping: true, DNS: true},
		},
	}
	s.finalize(test, false, true)

	// 4 non-baseline samples; 1 ping fail = 25%, 1 dns fail = 25%.
	if test.PingLossPct != 25 {
		t.Errorf("ping loss = %.0f, want 25", test.PingLossPct)
	}
	if test.DNSLossPct != 25 {
		t.Errorf("dns loss = %.0f, want 25", test.DNSLossPct)
	}
	if test.State != "done" || !test.Restored {
		t.Errorf("state=%q restored=%v, want done/true", test.State, test.Restored)
	}
}

func TestFinalizeAborted(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{Samples: []Sample{{Phase: "fault", Ping: true, DNS: true}}}
	s.finalize(test, true, true)
	if test.State != "aborted" {
		t.Errorf("state=%q, want aborted", test.State)
	}
}

// TestSnapshotEmptySamplesNotNil guards the black-screen regression: snapshot of
// a freshly-started test (empty Samples) must marshal to "samples":[] not null,
// or the frontend crashes dereferencing test.samples.
func TestSnapshotEmptySamplesNotNil(t *testing.T) {
	cp := snapshot(&Test{State: "running", Samples: []Sample{}})
	if cp.Samples == nil {
		t.Fatal("snapshot nil-ed an empty Samples slice (JSON would be null)")
	}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"samples":[]`) {
		t.Errorf(`expected "samples":[] in JSON, got: %s`, b)
	}
}

func newTestServiceWithAlerts(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Service{exec: firewall.NewDryRunExecutor(), linkSvc: links.NewService(db), alertSvc: alerts.NewService(db)}
	s.SetRecoveryStore(db)
	s.SetQosService(newRecordingQosCoordinator())
	return s, db
}

func countAlertsOfType(alerts []storage.Alert, typ string) int {
	n := 0
	for _, a := range alerts {
		if a.Type == typ {
			n++
		}
	}
	return n
}

func TestApplyFaultRaisesOutageAlert(t *testing.T) {
	s, db := newTestServiceWithAlerts(t)
	t2 := &Test{Mode: ModeOutage, LinkName: "WAN VIVO", LinkID: "id1", Interface: "eth0"}
	if err := db.CreateLink(&storage.Link{ID: t2.LinkID, Name: t2.LinkName, Interface: t2.Interface, Enabled: true}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	s.applyFault(t2)

	got, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkOffline); n != 1 {
		t.Errorf("link_offline alerts = %d, want 1 (all: %+v)", n, got)
	}

	if err := s.restore(t2, ""); err != nil {
		t.Fatalf("restore: %v", err)
	}

	got, err = db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkOnline); n != 1 {
		t.Errorf("link_online alerts = %d, want 1 (all: %+v)", n, got)
	}
}

type spyExecutor struct {
	calls     []string
	onExecute func(string, []string)
}

func (f *spyExecutor) Execute(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))
	if f.onExecute != nil {
		f.onExecute(name, append([]string(nil), args...))
	}
	return "", nil
}
func (f *spyExecutor) ExecuteRead(ctx context.Context, name string, args ...string) (string, error) {
	return "", nil
}
func (f *spyExecutor) IsDryRun() bool                              { return true }
func (_ *spyExecutor) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestArmWatchdogSkipsMalformedInterface(t *testing.T) {
	spy := &spyExecutor{}
	fired := make(chan time.Time, 1)
	coord := newRecordingQosCoordinator()
	s := &Service{exec: spy, qosSvc: coord, watchdogAfter: func(time.Duration) <-chan time.Time { return fired }}
	s.armWatchdog(&Test{Interface: `eth0; rm -rf /`, DurationSec: 30})
	fired <- time.Now()
	select {
	case <-coord.restoreDone:
		t.Fatal("malformed interface armed a QoS watchdog")
	case <-time.After(20 * time.Millisecond):
	}
	if len(spy.calls) != 0 {
		t.Fatalf("expected armWatchdog to skip executor for a malformed interface, got %v", spy.calls)
	}
}

func TestArmWatchdogRestoresThroughSharedQoSCoordinatorWithoutShell(t *testing.T) {
	spy := &spyExecutor{}
	fired := make(chan time.Time, 1)
	coord := newRecordingQosCoordinator()
	s := &Service{exec: spy, qosSvc: coord, watchdogAfter: func(time.Duration) <-chan time.Time { return fired }}
	s.armWatchdog(&Test{Interface: "enp3s0", Mode: ModeDegrade, DurationSec: 30})
	fired <- time.Now()
	select {
	case <-coord.restoreDone:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not restore through the QoS coordinator")
	}
	for _, call := range spy.calls {
		if strings.HasPrefix(call, "sh ") || strings.Contains(call, " sh ") {
			t.Fatalf("watchdog invoked a shell: %v", spy.calls)
		}
	}
}

func TestApplyFaultDegradeRaisesDegradedAlert(t *testing.T) {
	s, db := newTestServiceWithAlerts(t)
	t2 := &Test{Mode: ModeDegrade, LinkName: "WAN Claro", LinkID: "id2", Interface: "eth1"}

	s.applyFault(t2)

	got, err := db.GetAlerts(false, 0)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if n := countAlertsOfType(got, alerts.TypeLinkDegraded); n != 1 {
		t.Errorf("link_degraded alerts = %d, want 1 (all: %+v)", n, got)
	}
}

func TestRemoveFaultReappliesFreshPersistedQoSUnderInterfaceLock(t *testing.T) {
	s, db := newTestServiceWithAlerts(t)
	link := &storage.Link{Name: "WAN QoS", Interface: "eth1", Enabled: true, QoSEnabled: true, QoSUploadMbps: 40, QoSDownloadMbps: 300, QoSInteractive: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	coord := newRecordingQosCoordinator()
	s.SetQosService(coord)
	test := &Test{LinkID: link.ID, LinkName: link.Name, Interface: link.Interface, Mode: ModeDegrade, DelayMs: 500, LossPct: 20}

	s.removeFault(test)

	if coord.lockCount() == 0 {
		t.Fatal("removeFault did not use the shared QoS interface lock")
	}
	got := coord.restoredConfig()
	if !got.Enabled || got.Interface != link.Interface || got.UploadMbps != 40 || got.DownloadMbps != 300 || !got.Interactive {
		t.Fatalf("removeFault did not reapply persisted QoS under the lock: %+v", got)
	}
}

func TestApplyFaultDegradeUsesSharedQoSLockAndDeterministicNetem(t *testing.T) {
	s, _ := newTestServiceWithAlerts(t)
	coord := newRecordingQosCoordinator()
	s.SetQosService(coord)
	test := &Test{Interface: "eth1", Mode: ModeDegrade, DelayMs: 450, LossPct: 15}

	s.applyFault(test)

	delay, loss := coord.netem()
	if coord.lockCount() == 0 || delay != 450 || loss != 15 {
		t.Fatalf("applyFault did not install netem through the shared owner: locks=%d delay=%d loss=%d", coord.lockCount(), delay, loss)
	}
}

type recordingQosCoordinator struct {
	mu           sync.Mutex
	locks        int
	delayMs      int
	lossPct      int
	restored     qos.Config
	restoreFault qos.NetemFault
	restoreDone  chan struct{}
}

func newRecordingQosCoordinator() *recordingQosCoordinator {
	return &recordingQosCoordinator{restoreDone: make(chan struct{}, 1)}
}

func (c *recordingQosCoordinator) WithInterfaceLock(_ context.Context, _ string, fn func(qos.InterfaceOperations) error) error {
	c.mu.Lock()
	c.locks++
	c.mu.Unlock()
	return fn(recordingQosOperations{coordinator: c})
}

type recordingQosOperations struct {
	coordinator *recordingQosCoordinator
}

func (o recordingQosOperations) Apply(_ context.Context, cfg qos.Config) (qos.State, error) {
	o.coordinator.recordRestore(cfg)
	return qos.State{}, nil
}

func (o recordingQosOperations) ApplyNetem(_ context.Context, fault qos.NetemFault) error {
	o.coordinator.mu.Lock()
	o.coordinator.delayMs = fault.DelayMs
	o.coordinator.lossPct = fault.LossPct
	o.coordinator.mu.Unlock()
	return nil
}

func (o recordingQosOperations) RestoreAfterNetem(_ context.Context, cfg qos.Config, fault qos.NetemFault) (qos.State, error) {
	o.coordinator.mu.Lock()
	o.coordinator.restoreFault = fault
	o.coordinator.mu.Unlock()
	o.coordinator.recordRestore(cfg)
	return qos.State{}, nil
}

func (c *recordingQosCoordinator) recordRestore(cfg qos.Config) {
	c.mu.Lock()
	c.restored = cfg
	c.mu.Unlock()
	select {
	case c.restoreDone <- struct{}{}:
	default:
	}
}

func (c *recordingQosCoordinator) lockCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.locks
}

func (c *recordingQosCoordinator) restoredConfig() qos.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restored
}

func (c *recordingQosCoordinator) netem() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delayMs, c.lossPct
}

func (c *recordingQosCoordinator) restoredNetem() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restoreFault.DelayMs, c.restoreFault.LossPct
}
