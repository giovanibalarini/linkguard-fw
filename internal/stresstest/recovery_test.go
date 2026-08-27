package stresstest

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestRecoverInterruptedWaitsForStartToPublishActiveLease(t *testing.T) {
	db := openRecoveryDB(t)
	target := &storage.Link{ID: "target-race", Name: "Target", Interface: "eth0", Enabled: true, Status: links.StatusOnline}
	other := &storage.Link{ID: "other-race", Name: "Other", Interface: "eth1", Enabled: true, Status: links.StatusOnline}
	for _, link := range []*storage.Link{target, other} {
		if err := db.CreateLink(link); err != nil {
			t.Fatalf("CreateLink(%s): %v", link.ID, err)
		}
	}

	store := newSaveBarrierRecoveryStore(db)
	svc := NewService(&spyExecutor{interfaceUp: map[string]bool{"eth0": true}}, links.NewService(db), nil)
	svc.SetQosService(newRecordingQosCoordinator())
	svc.SetRecoveryStore(store)
	svc.nextID = func() string { return "stress-pre-publication" }

	type startResult struct {
		test *Test
		err  error
	}
	startDone := make(chan startResult, 1)
	go func() {
		test, err := svc.Start(StartParams{LinkID: target.ID, Mode: ModeOutage, DurationSec: 30})
		startDone <- startResult{test: test, err: err}
	}()

	select {
	case <-store.saved:
	case <-time.After(time.Second):
		t.Fatal("Start did not persist the recovery lease")
	}

	recoverDone := make(chan error, 1)
	go func() { recoverDone <- svc.RecoverInterrupted(context.Background()) }()

	var earlyRecovery error
	recoveredBeforePublication := false
	select {
	case earlyRecovery = <-recoverDone:
		recoveredBeforePublication = true
	case <-time.After(100 * time.Millisecond):
	}
	close(store.release)

	var started startResult
	select {
	case started = <-startDone:
	case <-time.After(time.Second):
		t.Fatal("Start did not publish the active test after releasing the lease barrier")
	}
	if started.err != nil {
		t.Fatalf("Start: %v", started.err)
	}
	if !recoveredBeforePublication {
		select {
		case earlyRecovery = <-recoverDone:
		case <-time.After(time.Second):
			t.Fatal("RecoverInterrupted remained blocked after Start published active state")
		}
	}

	lease, leaseErr := db.GetStressRecoveryLease()
	status := svc.Status()
	svc.Stop()
	waitForStressCompletion(t, svc)

	if recoveredBeforePublication {
		t.Fatalf("RecoverInterrupted completed before Start published active state: %v", earlyRecovery)
	}
	if earlyRecovery != nil {
		t.Fatalf("RecoverInterrupted: %v", earlyRecovery)
	}
	if leaseErr != nil || lease == nil || lease.TestID != started.test.ID {
		t.Fatalf("live lease after serialized recovery = %+v, %v; want %q", lease, leaseErr, started.test.ID)
	}
	if status == nil || status.ID != started.test.ID || status.State != "running" {
		t.Fatalf("active test after serialized recovery = %+v; want running %q", status, started.test.ID)
	}
}

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

func TestStartDryRunDoesNotCreateDurableRecoveryLease(t *testing.T) {
	db := openRecoveryDB(t)
	target := &storage.Link{ID: "target-dry", Name: "Target", Interface: "eth0", Enabled: true, Status: links.StatusOnline}
	other := &storage.Link{ID: "other-dry", Name: "Other", Interface: "eth1", Enabled: true, Status: links.StatusOnline}
	for _, link := range []*storage.Link{target, other} {
		if err := db.CreateLink(link); err != nil {
			t.Fatalf("CreateLink(%s): %v", link.ID, err)
		}
	}
	exec := &spyExecutor{dryRun: true}
	coord := newRecordingQosCoordinator()
	svc := NewService(exec, links.NewService(db), nil)
	svc.SetQosService(coord)
	svc.SetRecoveryStore(db)

	if _, err := svc.Start(StartParams{LinkID: target.ID, Mode: ModeOutage, DurationSec: 30}); err != nil {
		t.Fatalf("Start dry-run: %v", err)
	}
	lease, err := db.GetStressRecoveryLease()
	if err != nil || lease != nil {
		t.Fatalf("dry-run Start persisted recovery lease = %+v, %v; want nil, nil", lease, err)
	}
	svc.Stop()
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

func TestRecoverInterruptedDryRunPreservesRealLeaseWithoutHostWrites(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-dry-run", Interface: "eth0", Mode: string(ModeOutage), CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	exec := &spyExecutor{dryRun: true, interfaceUp: map[string]bool{"eth0": false}}
	coord := newRecordingQosCoordinator()
	svc := NewService(exec, nil, nil)
	svc.SetQosService(coord)
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); err == nil {
		t.Fatal("RecoverInterrupted() error = nil in dry-run; want deferred recovery")
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("dry-run recovery consumed durable lease: got=%+v err=%v", got, err)
	}
	if exec.interfaceUp["eth0"] {
		t.Fatal("dry-run recovery changed the observed host state")
	}
	if len(exec.calls) != 0 || coord.lockCount() != 0 {
		t.Fatalf("dry-run recovery reached host/QoS mutations: calls=%v locks=%d", exec.calls, coord.lockCount())
	}
}

func TestRecoverInterruptedOutagePreservesLeaseWhenInterfaceStillDown(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-still-down", Interface: "eth0", Mode: string(ModeOutage), CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	exec := &spyExecutor{ignoreLinkWrites: true, interfaceUp: map[string]bool{"eth0": false}}
	svc := NewService(exec, nil, nil)
	svc.SetQosService(newRecordingQosCoordinator())
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); err == nil {
		t.Fatal("RecoverInterrupted() error = nil while interface remained down")
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("failed outage postcondition consumed durable lease: got=%+v err=%v", got, err)
	}
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

func TestRecoveryRetiresLeaseForAuthoritativeDeletedOrMovedLink(t *testing.T) {
	paths := []struct {
		name string
		run  func(*Service, *Test) error
	}{
		{name: "normal completion", run: func(svc *Service, test *Test) error { return svc.restore(test, "") }},
		{name: "restart", run: func(svc *Service, _ *Test) error { return svc.RecoverInterrupted(context.Background()) }},
	}
	mutations := []struct {
		name   string
		mutate func(*testing.T, *storage.DB, *storage.Link)
	}{
		{name: "deleted", mutate: func(t *testing.T, db *storage.DB, link *storage.Link) {
			t.Helper()
			if err := db.DeleteLink(link.ID); err != nil {
				t.Fatalf("DeleteLink: %v", err)
			}
		}},
		{name: "moved", mutate: func(t *testing.T, db *storage.DB, link *storage.Link) {
			t.Helper()
			link.Interface = "eth9"
			if err := db.UpdateLinkNonQoS(link); err != nil {
				t.Fatalf("UpdateLinkNonQoS: %v", err)
			}
		}},
	}

	for _, path := range paths {
		for _, mode := range []Mode{ModeOutage, ModeDegrade} {
			for _, mutation := range mutations {
				name := path.name + "/" + string(mode) + "/" + mutation.name
				t.Run(name, func(t *testing.T) {
					db := openRecoveryDB(t)
					link := &storage.Link{
						ID: "target", Name: "Target", Interface: "eth0", Enabled: true,
						QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200,
					}
					if err := db.CreateLink(link); err != nil {
						t.Fatalf("CreateLink: %v", err)
					}
					lease := &storage.StressRecoveryLease{
						TestID: "stress-lifecycle", LinkID: link.ID, Interface: "eth0", Mode: string(mode),
						DelayMs: 500, LossPct: 20, CreatedAt: time.Now().UTC(),
					}
					if err := db.SaveStressRecoveryLease(lease); err != nil {
						t.Fatalf("SaveStressRecoveryLease: %v", err)
					}
					mutation.mutate(t, db, link)

					exec := &spyExecutor{interfaceUp: map[string]bool{"eth0": false}}
					coord := newRecordingQosCoordinator()
					svc := NewService(exec, links.NewService(db), nil)
					svc.SetQosService(coord)
					svc.SetRecoveryStore(db)
					test := &Test{
						ID: lease.TestID, LinkID: lease.LinkID, Interface: lease.Interface,
						Mode: mode, DelayMs: lease.DelayMs, LossPct: lease.LossPct,
					}

					if err := path.run(svc, test); err != nil {
						t.Fatalf("recovery error = %v; want safe disabled fallback", err)
					}
					got := coord.restoredConfig()
					if got.Interface != "eth0" || got.Enabled {
						t.Fatalf("recovery config = %+v; want disabled intent on recorded eth0", got)
					}
					assertNoRecoveryLease(t, db)
				})
			}
		}
	}
}

func TestRecoverInterruptedPreservesLeaseOnLinkStorageError(t *testing.T) {
	leaseDB := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-storage-error", LinkID: "target", Interface: "eth0", Mode: string(ModeOutage), CreatedAt: time.Now().UTC(),
	}
	if err := leaseDB.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	closedDB := openRecoveryDB(t)
	if err := closedDB.Close(); err != nil {
		t.Fatalf("Close link DB: %v", err)
	}
	exec := &spyExecutor{interfaceUp: map[string]bool{"eth0": false}}
	svc := NewService(exec, links.NewService(closedDB), nil)
	svc.SetQosService(newRecordingQosCoordinator())
	svc.SetRecoveryStore(leaseDB)

	if err := svc.RecoverInterrupted(context.Background()); err == nil {
		t.Fatal("RecoverInterrupted() error = nil for link storage failure")
	}
	got, err := leaseDB.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("link storage failure consumed durable lease: got=%+v err=%v", got, err)
	}
}

func TestRecoverInterruptedPreservesLeaseWhenLinkLoaderIsUnavailable(t *testing.T) {
	db := openRecoveryDB(t)
	lease := &storage.StressRecoveryLease{
		TestID: "stress-no-loader", LinkID: "target", Interface: "eth0", Mode: string(ModeOutage), CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	exec := &spyExecutor{interfaceUp: map[string]bool{"eth0": false}}
	svc := NewService(exec, nil, nil)
	svc.SetQosService(newRecordingQosCoordinator())
	svc.SetRecoveryStore(db)

	if err := svc.RecoverInterrupted(context.Background()); err == nil {
		t.Fatal("RecoverInterrupted() error = nil without a link loader")
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got == nil || got.TestID != lease.TestID {
		t.Fatalf("missing link loader consumed durable lease: got=%+v err=%v", got, err)
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

func waitForStressCompletion(t *testing.T, svc *Service) {
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

type saveBarrierRecoveryStore struct {
	delegate recoveryStore
	saved    chan struct{}
	release  chan struct{}
	once     sync.Once
}

func newSaveBarrierRecoveryStore(delegate recoveryStore) *saveBarrierRecoveryStore {
	return &saveBarrierRecoveryStore{
		delegate: delegate,
		saved:    make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (s *saveBarrierRecoveryStore) SaveStressRecoveryLease(lease *storage.StressRecoveryLease) error {
	if err := s.delegate.SaveStressRecoveryLease(lease); err != nil {
		return err
	}
	s.once.Do(func() { close(s.saved) })
	<-s.release
	return nil
}

func (s *saveBarrierRecoveryStore) GetStressRecoveryLease() (*storage.StressRecoveryLease, error) {
	return s.delegate.GetStressRecoveryLease()
}

func (s *saveBarrierRecoveryStore) ClearStressRecoveryLease(testID string) error {
	return s.delegate.ClearStressRecoveryLease(testID)
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
