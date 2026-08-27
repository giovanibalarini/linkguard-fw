package stresstest

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestStartPersistsRecoveryLeaseBeforeApplyingOutage(t *testing.T) {
	db := openRecoveryDB(t)
	target := &storage.Link{ID: "target", Name: "Target", Interface: "eth0", Enabled: true, Status: links.StatusOnline}
	other := &storage.Link{ID: "other", Name: "Other", Interface: "eth1", Enabled: true, Status: links.StatusOnline}
	for _, link := range []*storage.Link{target, other} {
		if err := db.CreateLink(link); err != nil {
			t.Fatalf("CreateLink(%s): %v", link.ID, err)
		}
	}
	leaseBeforeFault := make(chan bool, 1)
	exec := &spyExecutor{}
	exec.onExecute = func(name string, args []string) {
		if name != "ip" || len(args) != 4 || args[0] != "link" || args[1] != "set" || args[2] != "eth0" || args[3] != "down" {
			return
		}
		lease, err := db.GetStressRecoveryLease()
		leaseBeforeFault <- err == nil && lease != nil && lease.Interface == "eth0" && lease.Mode == string(ModeOutage)
	}
	coord := newRecordingQosCoordinator()
	svc := NewService(exec, links.NewService(db), nil)
	svc.SetQosService(coord)
	svc.SetRecoveryStore(db)

	if _, err := svc.Start(StartParams{LinkID: target.ID, Mode: ModeOutage, DurationSec: 30}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case persisted := <-leaseBeforeFault:
		if !persisted {
			t.Fatal("outage command ran before its durable recovery lease existed")
		}
	case <-time.After(time.Second):
		t.Fatal("stress test did not apply outage")
	}
	svc.Stop()
	select {
	case <-coord.restoreDone:
	case <-time.After(time.Second):
		t.Fatal("stopped stress test did not start restoration")
	}
	deadline := time.After(time.Second)
	for {
		status := svc.Status()
		if status != nil && status.State != "running" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stopped stress test did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestRecoverInterruptedOutageBringsInterfaceUpAndClearsDurableLease(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-outage", Interface: "eth0", Mode: string(ModeOutage), CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	exec := &spyExecutor{}
	coord := newRecordingQosCoordinator()
	svc := NewService(exec, nil, nil)
	svc.SetQosService(coord)
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); err != nil {
		t.Fatalf("RecoverInterrupted: %v", err)
	}
	if !containsCall(exec.calls, "ip link set eth0 up") {
		t.Fatalf("outage recovery did not bring eth0 up: %v", exec.calls)
	}
	if coord.lockCount() != 1 || coord.restoredConfig().Interface != "eth0" {
		t.Fatalf("outage recovery did not reconcile QoS under the shared lock: locks=%d cfg=%+v", coord.lockCount(), coord.restoredConfig())
	}
	assertNoRecoveryLease(t, db)
}

func TestRecoverInterruptedOwnedNetemUsesPersistedSignatureAndClearsLease(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-netem", Interface: "eth1", Mode: string(ModeDegrade),
		DelayMs: 640, LossPct: 17, CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	coord := newRecordingQosCoordinator()
	svc := NewService(&spyExecutor{}, nil, nil)
	svc.SetQosService(coord)
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); err != nil {
		t.Fatalf("RecoverInterrupted: %v", err)
	}
	delay, loss := coord.restoredNetem()
	if delay != 640 || loss != 17 {
		t.Fatalf("recovery netem signature = %dms/%d%%; want 640ms/17%%", delay, loss)
	}
	assertNoRecoveryLease(t, db)
}

func TestRecoverInterruptedNetemCollisionPreservesLeaseForRetry(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-collision", Interface: "eth2", Mode: string(ModeDegrade),
		DelayMs: 500, LossPct: 20, CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	svc := NewService(&spyExecutor{}, nil, nil)
	svc.SetQosService(rejectingRecoveryCoordinator{})
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); !errors.Is(err, qos.ErrOwnershipNotEstablished) {
		t.Fatalf("RecoverInterrupted collision error = %v; want ErrOwnershipNotEstablished", err)
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("collision discarded durable recovery lease: got=%+v err=%v", got, err)
	}
}

func openRecoveryDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "recovery.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func assertNoRecoveryLease(t *testing.T, db *storage.DB) {
	t.Helper()
	lease, err := db.GetStressRecoveryLease()
	if err != nil || lease != nil {
		t.Fatalf("recovery lease after success = %+v, %v; want nil, nil", lease, err)
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

type rejectingRecoveryCoordinator struct{}

func (rejectingRecoveryCoordinator) WithInterfaceLock(ctx context.Context, _ string, fn func(qos.InterfaceOperations) error) error {
	return fn(rejectingRecoveryOperations{})
}

type rejectingRecoveryOperations struct{}

func (rejectingRecoveryOperations) Apply(context.Context, qos.Config) (qos.State, error) {
	return qos.State{}, nil
}

func (rejectingRecoveryOperations) ApplyNetem(context.Context, qos.NetemFault) error {
	return nil
}

func (rejectingRecoveryOperations) RestoreAfterNetem(context.Context, qos.Config, qos.NetemFault) (qos.State, error) {
	return qos.State{}, qos.ErrOwnershipNotEstablished
}
