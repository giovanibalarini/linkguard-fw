package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/stresstest"
)

type bootQosExec struct {
	failOn      string
	events      []string
	readOutputs map[string]string
	realWrites  bool
}

func (e *bootQosExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	event := cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if e.failOn != "" && strings.Contains(event, e.failOn) {
		return "", errors.New("simulated QoS failure")
	}
	if e.realWrites && cmd == "ip" && len(args) == 4 && args[0] == "link" && args[1] == "set" && args[3] == "up" {
		if e.readOutputs == nil {
			e.readOutputs = make(map[string]string)
		}
		e.readOutputs["ip link show dev "+args[2]] = "2: " + args[2] + ": <BROADCAST,UP> mtu 1500 state UP"
	}
	return "", nil
}

func (e *bootQosExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	key := cmd + " " + strings.Join(args, " ")
	if output, ok := e.readOutputs[key]; ok {
		return output, nil
	}
	return "", nil
}

func (e *bootQosExec) IsDryRun() bool { return !e.realWrites }

func (*bootQosExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestReconcileQoSOnBootAppliesOnlyEnabledQoSAndDisablesStale(t *testing.T) {
	exec := &bootQosExec{}
	configureBootManagedObjects(exec, "wan1", "wan2")
	service := qos.NewService(exec)
	links := []storage.Link{
		{ID: "enabled", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
		{ID: "qos-off", Interface: "wan1", Enabled: true, QoSEnabled: false, QoSUploadMbps: -99, QoSDownloadMbps: -99},
		{ID: "link-off", Interface: "wan2", Enabled: false, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
	}

	reconcileQoSOnBoot(context.Background(), service, func() ([]storage.Link, error) { return links, nil })

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan0 root handle cafe: cake bandwidth 50mbit") {
		t.Errorf("enabled QoS link was not applied: %v", exec.events)
	}
	for _, iface := range []string{"wan1", "wan2"} {
		if !containsBootQosEvent(exec.events, "tc filter del dev "+iface+" ingress pref 49152") {
			t.Errorf("stale QoS for %s was not disabled: %v", iface, exec.events)
		}
		if containsBootQosEvent(exec.events, "tc qdisc replace dev "+iface+" root handle cafe: cake") {
			t.Errorf("disabled QoS for %s was applied: %v", iface, exec.events)
		}
	}
}

func TestReconcileQoSOnBootLogsAndContinuesAfterApplyFailure(t *testing.T) {
	exec := &bootQosExec{failOn: "dev wan-fail"}
	service := qos.NewService(exec)
	links := []storage.Link{
		{ID: "fail", Interface: "wan-fail", Enabled: true, QoSEnabled: true, QoSUploadMbps: 10, QoSDownloadMbps: 20},
		{ID: "ok", Interface: "wan-ok", Enabled: true, QoSEnabled: true, QoSUploadMbps: 30, QoSDownloadMbps: 40},
	}

	reconcileQoSOnBoot(context.Background(), service, func() ([]storage.Link, error) { return links, nil })

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan-ok root handle cafe: cake bandwidth 30mbit") {
		t.Errorf("boot reconciliation stopped after one failure: %v", exec.events)
	}
}

func TestReconcileQoSOnBootUsesFreshPersistedSnapshotBeforeApply(t *testing.T) {
	exec := &bootQosExec{}
	service := qos.NewService(exec)
	initial := []storage.Link{{ID: "wan-1", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 10, QoSDownloadMbps: 20}}
	fresh := []storage.Link{{ID: "wan-1", Interface: "wan0", Enabled: true, QoSEnabled: true, QoSUploadMbps: 30, QoSDownloadMbps: 40}}
	loads := 0
	load := func() ([]storage.Link, error) {
		loads++
		if loads == 1 {
			return initial, nil
		}
		return fresh, nil
	}

	reconcileQoSOnBoot(context.Background(), service, load)

	if !containsBootQosEvent(exec.events, "tc qdisc replace dev wan0 root handle cafe: cake bandwidth 30mbit") {
		t.Fatalf("boot applied stale snapshot instead of fresh persisted QoS: %v", exec.events)
	}
}

func configureBootManagedObjects(exec *bootQosExec, interfaces ...string) {
	if exec.readOutputs == nil {
		exec.readOutputs = make(map[string]string)
	}
	for _, iface := range interfaces {
		ifb := qos.IFBName(iface)
		exec.readOutputs["ip link show dev "+ifb] = "6: " + ifb + ": <BROADCAST>"
		exec.readOutputs["tc qdisc show dev "+iface] = "qdisc cake cafe: root bandwidth 50mbit besteffort nat dual-srchost"
		exec.readOutputs["tc qdisc show dev "+ifb] = "qdisc cake caff: root bandwidth 200mbit besteffort nat dual-dsthost ingress"
		exec.readOutputs["tc filter show dev "+iface+" ingress pref 49152"] = "filter protocol all pref 49152 matchall\n action order 1: mirred egress redirect dev " + ifb
	}
}

func TestReconcileQoSOnBootPreservesForeignCakeOneRoots(t *testing.T) {
	exec := &bootQosExec{readOutputs: map[string]string{
		"tc qdisc show dev wan-enabled":  "qdisc cake 1: root bandwidth 50mbit besteffort dual-srchost",
		"tc qdisc show dev wan-disabled": "qdisc cake 1: root bandwidth 75mbit diffserv4 dual-srchost",
	}}
	service := qos.NewService(exec)
	links := []storage.Link{
		{ID: "enabled", Interface: "wan-enabled", Enabled: true, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
		{ID: "disabled", Interface: "wan-disabled", Enabled: true, QoSEnabled: false},
	}

	reconcileQoSOnBoot(context.Background(), service, func() ([]storage.Link, error) { return links, nil })

	if len(exec.events) != 0 {
		t.Fatalf("boot reconciliation mutated foreign cake 1: roots: %v", exec.events)
	}
}

func TestReconcileQoSOnBootPreservesCompleteForeignCakeOneChains(t *testing.T) {
	exec := &bootQosExec{readOutputs: make(map[string]string)}
	links := []storage.Link{
		{ID: "enabled", Interface: "wan-enabled", Enabled: true, QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200},
		{ID: "disabled", Interface: "wan-disabled", Enabled: true, QoSEnabled: false},
	}
	for _, link := range links {
		ifb := qos.IFBName(link.Interface)
		exec.readOutputs["ip link show dev "+ifb] = "6: " + ifb + ": <BROADCAST,UP>"
		exec.readOutputs["tc qdisc show dev "+link.Interface] = "qdisc cake 1: root bandwidth 50mbit besteffort dual-srchost\nqdisc clsact ffff: parent ffff:fff1\n"
		exec.readOutputs["tc qdisc show dev "+ifb] = "qdisc cake 1: root bandwidth 200mbit besteffort dual-dsthost\n"
		exec.readOutputs["tc filter show dev "+link.Interface+" ingress pref 49152"] = "filter protocol all pref 49152 matchall\n action order 1: mirred egress redirect dev " + ifb
	}

	reconcileQoSOnBoot(context.Background(), qos.NewService(exec), func() ([]storage.Link, error) { return links, nil })

	if len(exec.events) != 0 {
		t.Fatalf("boot reconciliation mutated complete foreign CAKE 1: chains: %v", exec.events)
	}
}

func TestRecoverStressTestOnBootRestoresOutageAndClearsLease(t *testing.T) {
	db := openBootQosDB(t)
	link := &storage.Link{ID: "wan-outage", Name: "WAN outage", Interface: "wan0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	lease := &storage.StressRecoveryLease{TestID: "stress-outage", LinkID: link.ID, Interface: link.Interface, Mode: string(stresstest.ModeOutage), CreatedAt: time.Now().UTC()}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	exec := &bootQosExec{realWrites: true}
	qosSvc := qos.NewService(exec)
	stressSvc := stresstest.NewService(exec, links.NewService(db), nil)
	stressSvc.SetQosService(qosSvc)
	stressSvc.SetRecoveryStore(db)

	recoverStressTestOnBoot(context.Background(), stressSvc)

	if !containsBootQosEvent(exec.events, "ip link set wan0 up") {
		t.Fatalf("boot recovery did not bring outage interface up: %v", exec.events)
	}
	if lease, err := db.GetStressRecoveryLease(); err != nil || lease != nil {
		t.Fatalf("boot outage lease after recovery = %+v, %v; want nil, nil", lease, err)
	}
}

func TestRecoverStressTestOnBootPreservesForeignCakeOneAndLease(t *testing.T) {
	db := openBootQosDB(t)
	link := &storage.Link{ID: "wan-degrade", Name: "WAN degrade", Interface: "wan0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	lease := &storage.StressRecoveryLease{
		TestID: "stress-degrade", LinkID: link.ID, Interface: link.Interface, Mode: string(stresstest.ModeDegrade),
		DelayMs: 500, LossPct: 20, CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	ifb := qos.IFBName("wan0")
	exec := &bootQosExec{realWrites: true, readOutputs: map[string]string{
		"ip link show dev " + ifb:                    "6: " + ifb + ": <BROADCAST,UP>",
		"tc qdisc show dev wan0":                     "qdisc cake 1: root bandwidth 50mbit besteffort dual-srchost\nqdisc clsact ffff: parent ffff:fff1\n",
		"tc qdisc show dev " + ifb:                   "qdisc cake 1: root bandwidth 200mbit besteffort dual-dsthost\n",
		"tc filter show dev wan0 ingress pref 49152": "filter protocol all pref 49152 matchall\n action order 1: mirred egress redirect dev " + ifb,
		"tc filter show dev " + ifb + " ingress":     "",
		"tc filter show dev " + ifb + " egress":      "",
	}}
	qosSvc := qos.NewService(exec)
	stressSvc := stresstest.NewService(exec, links.NewService(db), nil)
	stressSvc.SetQosService(qosSvc)
	stressSvc.SetRecoveryStore(db)

	recoverStressTestOnBoot(context.Background(), stressSvc)

	if len(exec.events) != 0 {
		t.Fatalf("boot stress recovery mutated foreign cake 1: root: %v", exec.events)
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("boot collision discarded recovery lease: got=%+v err=%v", got, err)
	}
}

func TestRecoverStressTestOnBootDoesNotConsumeLiveActiveLease(t *testing.T) {
	db := openBootQosDB(t)
	target := &storage.Link{ID: "wan-live", Name: "WAN live", Interface: "wan0", Enabled: true, Status: links.StatusOnline}
	other := &storage.Link{ID: "wan-backup", Name: "WAN backup", Interface: "wan1", Enabled: true, Status: links.StatusOnline}
	for _, link := range []*storage.Link{target, other} {
		if err := db.CreateLink(link); err != nil {
			t.Fatalf("CreateLink(%s): %v", link.ID, err)
		}
	}

	exec := newLiveStressExec()
	stressSvc := stresstest.NewService(exec, links.NewService(db), nil)
	stressSvc.SetQosService(qos.NewService(exec))
	stressSvc.SetRecoveryStore(db)
	started, err := stressSvc.Start(stresstest.StartParams{LinkID: target.ID, Mode: stresstest.ModeOutage, DurationSec: 30})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-exec.faultApplied:
	case <-time.After(time.Second):
		t.Fatal("live stress test did not apply its outage")
	}

	recoverStressTestOnBoot(context.Background(), stressSvc)
	lease, leaseErr := db.GetStressRecoveryLease()
	upWrites := exec.upWriteCount()
	status := stressSvc.Status()
	stressSvc.Stop()
	waitForBootStressCompletion(t, stressSvc)

	if leaseErr != nil || lease == nil || lease.TestID != started.ID {
		t.Fatalf("provisioning retry consumed live lease: got=%+v err=%v want=%q", lease, leaseErr, started.ID)
	}
	if upWrites != 0 {
		t.Fatalf("provisioning retry restored a live stress test %d time(s)", upWrites)
	}
	if status == nil || status.ID != started.ID || status.State != "running" {
		t.Fatalf("live test after provisioning retry = %+v; want running %q", status, started.ID)
	}
}

type liveStressExec struct {
	mu           sync.Mutex
	interfaceUp  bool
	upWrites     int
	faultApplied chan struct{}
	faultOnce    sync.Once
}

func newLiveStressExec() *liveStressExec {
	return &liveStressExec{interfaceUp: true, faultApplied: make(chan struct{})}
}

func (e *liveStressExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ip" && len(args) == 4 && args[0] == "link" && args[1] == "set" && args[2] == "wan0" {
		e.mu.Lock()
		switch args[3] {
		case "down":
			e.interfaceUp = false
			e.faultOnce.Do(func() { close(e.faultApplied) })
		case "up":
			e.interfaceUp = true
			e.upWrites++
		}
		e.mu.Unlock()
	}
	return "", nil
}

func (e *liveStressExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ip" && len(args) == 4 && args[0] == "link" && args[1] == "show" && args[2] == "dev" && args[3] == "wan0" {
		e.mu.Lock()
		up := e.interfaceUp
		e.mu.Unlock()
		if up {
			return "2: wan0: <BROADCAST,UP> mtu 1500 state UP", nil
		}
		return "2: wan0: <BROADCAST> mtu 1500 state DOWN", nil
	}
	return "", nil
}

func (*liveStressExec) IsDryRun() bool { return false }

func (*liveStressExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func (e *liveStressExec) upWriteCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.upWrites
}

func waitForBootStressCompletion(t *testing.T, svc *stresstest.Service) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		status := svc.Status()
		if status != nil && status.State != "running" {
			return
		}
		select {
		case <-deadline:
			t.Fatal("stress test did not finish after Stop")
		case <-time.After(time.Millisecond):
		}
	}
}

func openBootQosDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "qos-boot.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func containsBootQosEvent(events []string, want string) bool {
	for _, event := range events {
		if strings.Contains(event, want) {
			return true
		}
	}
	return false
}
