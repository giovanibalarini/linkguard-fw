package qos_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestApplyRecoversAfterRestartAtEveryJournalBoundary(t *testing.T) {
	for _, boundary := range recoveryBoundaries(6) {
		t.Run(boundary.name, func(t *testing.T) {
			kernel := newRestartKernel()
			db, service := restartService(t, kernel, boundary)
			cfg := qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
			mustCrash(t, func() {
				_, _ = service.ApplyAndPersist(context.Background(), cfg, qos.Config{Interface: "wan0"}, func(string) error {
					t.Fatal("persistence callback reached before simulated crash")
					return nil
				})
			})
			recoverAfterReopen(t, db, kernel)
			state, err := qos.NewService(kernel).Observe(context.Background(), "wan0")
			if err != nil || state.Enabled || kernel.hasManagedObjects() {
				t.Fatalf("recovered Apply state = %+v, err=%v, kernel=%+v; want prior disabled state", state, err, kernel)
			}
		})
	}
}

func TestDisableRecoversAfterRestartAtEveryJournalBoundary(t *testing.T) {
	for _, boundary := range recoveryBoundaries(4) {
		t.Run(boundary.name, func(t *testing.T) {
			kernel := newRestartKernel()
			cfg := qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
			if _, err := qos.NewService(kernel).Apply(context.Background(), cfg); err != nil {
				t.Fatalf("seed managed QoS: %v", err)
			}
			kernel.resetWrites()
			db, service := restartService(t, kernel, boundary)
			mustCrash(t, func() {
				_, _ = service.ApplyAndPersist(context.Background(), qos.Config{Interface: "wan0"}, cfg, func(string) error {
					t.Fatal("persistence callback reached before simulated crash")
					return nil
				})
			})
			recoverAfterReopen(t, db, kernel)
			state, err := qos.NewService(kernel).Observe(context.Background(), "wan0")
			if err != nil || !state.Enabled {
				t.Fatalf("recovered Disable state = %+v, err=%v, kernel=%+v; want prior enabled state", state, err, kernel)
			}
		})
	}
}

func TestStandaloneApplyCompletesAfterRestartAtEveryKernelBoundary(t *testing.T) {
	for write := 1; write <= 6; write++ {
		t.Run(fmt.Sprintf("after_kernel_write_%d", write), func(t *testing.T) {
			kernel := newRestartKernel()
			db, service := restartService(t, kernel, recoveryBoundary{panicWrite: write})
			cfg := qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
			mustCrash(t, func() { _, _ = service.Apply(context.Background(), cfg) })
			recoverAfterReopen(t, db, kernel)
			state, err := qos.NewService(kernel).Observe(context.Background(), cfg.Interface)
			if err != nil || !state.Enabled {
				t.Fatalf("standalone Apply recovery = %+v, %v; want completed enabled state", state, err)
			}
		})
	}
}

func TestStandaloneDisableCompletesAfterRestartAtEveryKernelBoundary(t *testing.T) {
	for write := 1; write <= 4; write++ {
		t.Run(fmt.Sprintf("after_kernel_write_%d", write), func(t *testing.T) {
			kernel := newRestartKernel()
			cfg := qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
			if _, err := qos.NewService(kernel).Apply(context.Background(), cfg); err != nil {
				t.Fatalf("seed managed QoS: %v", err)
			}
			kernel.resetWrites()
			db, service := restartService(t, kernel, recoveryBoundary{panicWrite: write})
			mustCrash(t, func() { _, _ = service.Disable(context.Background(), cfg.Interface) })
			recoverAfterReopen(t, db, kernel)
			state, err := qos.NewService(kernel).Observe(context.Background(), cfg.Interface)
			if err != nil || state.Enabled || kernel.hasManagedObjects() {
				t.Fatalf("standalone Disable recovery = %+v, %v, kernel=%+v; want completed disabled state", state, err, kernel)
			}
		})
	}
}

func TestRestartRecoveryPreservesUnrecordedRootAndLease(t *testing.T) {
	kernel := newRestartKernel()
	kernel.egress = "qdisc cake 1: root bandwidth 99mbit besteffort nat dual-srchost\n"
	path := filepath.Join(t.TempDir(), "foreign.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lease := &qos.OperationLease{
		ID: "qos-op-foreign", Interface: "wan0", Intent: qos.OperationApply,
		Target:   qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200},
		Recovery: qos.Config{Interface: "wan0"},
	}
	if err := db.SaveQoSOperationLease(lease); err != nil {
		t.Fatalf("SaveQoSOperationLease: %v", err)
	}
	service := qos.NewService(kernel)
	service.SetOperationStore(db)

	err = service.RecoverInterrupted(context.Background())
	if !errors.Is(err, qos.ErrOwnershipNotEstablished) {
		t.Fatalf("RecoverInterrupted error = %v; want ErrOwnershipNotEstablished", err)
	}
	if kernel.egress != "qdisc cake 1: root bandwidth 99mbit besteffort nat dual-srchost\n" || kernel.writes != 0 {
		t.Fatalf("recovery mutated foreign root: %+v", kernel)
	}
	got, listErr := db.ListQoSOperationLeases()
	if listErr != nil || len(got) != 1 || got[0].ID != lease.ID {
		t.Fatalf("lease after ownership refusal = %#v, %v; want %q", got, listErr, lease.ID)
	}
}

func TestBenchmarkRestoresConfiguredQoSAfterRestartAtPhaseTransitions(t *testing.T) {
	boundaries := []recoveryBoundary{{name: "after_lease_save", panicAfterSave: true}}
	for write := 1; write <= 9; write++ {
		boundaries = append(boundaries, recoveryBoundary{name: fmt.Sprintf("after_kernel_write_%d", write), panicWrite: write})
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			kernel := newRestartKernel()
			cfg := qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200}
			if _, err := qos.NewService(kernel).Apply(context.Background(), cfg); err != nil {
				t.Fatalf("seed managed QoS: %v", err)
			}
			kernel.resetWrites()
			db, service := restartService(t, kernel, boundary)
			mustCrash(t, func() {
				_, _ = service.BenchmarkCurrent(context.Background(), cfg.Interface,
					qos.BenchmarkRequest{Server: "iperf.operator.lan"}, func() (qos.Config, error) { return cfg, nil })
			})
			recoverAfterReopen(t, db, kernel)
			state, err := qos.NewService(kernel).Observe(context.Background(), cfg.Interface)
			if err != nil || !state.Enabled {
				t.Fatalf("recovered benchmark state = %+v, err=%v, kernel=%+v; want configured QoS", state, err, kernel)
			}
		})
	}
}

type recoveryBoundary struct {
	name           string
	panicAfterSave bool
	panicWrite     int
	panicStage     int
}

func recoveryBoundaries(stages int) []recoveryBoundary {
	out := []recoveryBoundary{{name: "after_lease_save", panicAfterSave: true}}
	for stage := 1; stage <= stages; stage++ {
		out = append(out,
			recoveryBoundary{name: fmt.Sprintf("after_kernel_write_%d", stage), panicWrite: stage},
			recoveryBoundary{name: fmt.Sprintf("after_journal_stage_%d", stage), panicStage: stage},
		)
	}
	return out
}

type panicOperationStore struct {
	*qosStoreDB
	panicAfterSave bool
	panicStage     int
}

type qosStoreDB struct{ *storage.DB }

func (s *panicOperationStore) SaveQoSOperationLease(lease *qos.OperationLease) error {
	if err := s.DB.SaveQoSOperationLease(lease); err != nil {
		return err
	}
	if s.panicAfterSave {
		panic("simulated process death after lease save")
	}
	return nil
}

func (s *panicOperationStore) AdvanceQoSOperationLease(id string, from, to int) error {
	if err := s.DB.AdvanceQoSOperationLease(id, from, to); err != nil {
		return err
	}
	if to == s.panicStage {
		panic("simulated process death after journal advance")
	}
	return nil
}

func restartService(t *testing.T, kernel *restartKernel, boundary recoveryBoundary) (*storage.DB, *qos.Service) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restart.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	kernel.panicWrite = boundary.panicWrite
	store := &panicOperationStore{
		qosStoreDB: &qosStoreDB{DB: db}, panicAfterSave: boundary.panicAfterSave, panicStage: boundary.panicStage,
	}
	service := qos.NewService(kernel)
	service.SetOperationStore(store)
	return db, service
}

func recoverAfterReopen(t *testing.T, db *storage.DB, kernel *restartKernel) {
	t.Helper()
	var dbPath string
	if err := db.Conn().QueryRow(`PRAGMA database_list`).Scan(new(int), new(string), &dbPath); err != nil {
		t.Fatalf("database path: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	kernel.panicWrite = 0
	kernel.resetWrites()
	recovery := qos.NewService(kernel)
	recovery.SetOperationStore(reopened)
	if err := recovery.RecoverInterrupted(context.Background()); err != nil {
		t.Fatalf("RecoverInterrupted: %v", err)
	}
	leases, err := reopened.ListQoSOperationLeases()
	if err != nil || len(leases) != 0 {
		t.Fatalf("leases after recovery = %#v, %v; want empty", leases, err)
	}
}

func mustCrash(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("operation did not reach simulated process death")
		}
	}()
	run()
}

type restartKernel struct {
	egress      string
	ingress     string
	ifb         bool
	ifbUp       bool
	clsact      bool
	redirect    bool
	writes      int
	panicWrite  int
	metricRead  int
	counterRead int
}

func newRestartKernel() *restartKernel { return &restartKernel{} }

func (k *restartKernel) IsDryRun() bool { return false }

func (k *restartKernel) WriteFile(string, []byte, os.FileMode) error { return nil }

func (k *restartKernel) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "iperf3" {
		return "iperf 3.16", nil
	}
	if cmd == "ping" {
		return "10 packets transmitted, 10 received, 0% packet loss\nrtt min/avg/max/mdev = 10/20/30/1 ms", nil
	}
	if cmd == "cat" && len(args) == 1 && args[0] == "/proc/stat" {
		k.metricRead++
		return fmt.Sprintf("cpu %d 0 0 %d 0 0 0 0 0 0\n", k.metricRead*50, k.metricRead*50), nil
	}
	if cmd == "cat" && len(args) == 1 && strings.HasPrefix(args[0], "/sys/class/net/") {
		k.counterRead++
		return fmt.Sprintf("%d\n", k.counterRead*100_000_000), nil
	}
	if cmd == "ip" && hasArgs(args, "link", "show", "dev") {
		if !k.ifb {
			return "", errors.New("Cannot find device")
		}
		flags := "BROADCAST"
		state := "DOWN"
		if k.ifbUp {
			flags += ",UP"
			state = "UP"
		}
		return "7: " + args[3] + ": <" + flags + "> state " + state, nil
	}
	if cmd != "tc" {
		return "", nil
	}
	if hasArgs(args, "qdisc", "show", "dev") {
		dev := args[3]
		if strings.HasPrefix(dev, "ifb-") {
			if !k.ifb {
				return "", errors.New("Cannot find device")
			}
			if k.ingress != "" {
				return k.ingress, nil
			}
			return "qdisc noqueue 0: root\n", nil
		}
		out := k.egress
		if k.clsact {
			out += "qdisc clsact ffff: parent ffff:fff1\n"
		}
		return out, nil
	}
	if hasArgs(args, "filter", "show", "dev") {
		if len(args) >= 7 && args[4] == "ingress" && args[5] == "pref" && k.redirect {
			return "filter protocol all pref 49152 matchall action mirred egress redirect dev " + qos.IFBName("wan0"), nil
		}
		return "", nil
	}
	return "", nil
}

func (k *restartKernel) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "iperf3" {
		return `{"end":{"sum_sent":{"bits_per_second":50000000},"sum_received":{"bits_per_second":200000000}}}`, nil
	}
	k.mutate(cmd, args)
	k.writes++
	if k.panicWrite > 0 && k.writes == k.panicWrite {
		panic("simulated process death after kernel write")
	}
	return "", nil
}

func (k *restartKernel) mutate(cmd string, args []string) {
	if cmd == "ip" && hasArgs(args, "link", "add") {
		k.ifb = true
		return
	}
	if cmd == "ip" && hasArgs(args, "link", "set", "dev") {
		k.ifbUp = args[len(args)-1] == "up"
		return
	}
	if cmd == "ip" && hasArgs(args, "link", "del", "dev") {
		k.ifb, k.ifbUp, k.ingress = false, false, ""
		return
	}
	if cmd != "tc" {
		return
	}
	if hasArgs(args, "qdisc", "replace", "dev") && contains(args, "cake") {
		dev := args[3]
		line := "qdisc cake " + tokenAfter(args, "handle") + " root bandwidth " + tokenAfter(args, "bandwidth") + " "
		if contains(args, "diffserv4") {
			line += "diffserv4 "
		} else {
			line += "besteffort "
		}
		line += "nat "
		if contains(args, "dual-dsthost") {
			line += "dual-dsthost ingress\n"
			k.ingress = line
		} else {
			line += "dual-srchost\n"
			k.egress = line
		}
		_ = dev
		return
	}
	if hasArgs(args, "qdisc", "add", "dev") && args[len(args)-1] == "clsact" {
		k.clsact = true
		return
	}
	if hasArgs(args, "filter", "replace", "dev") {
		k.redirect = true
		return
	}
	if hasArgs(args, "filter", "del", "dev") {
		k.redirect = false
		return
	}
	if hasArgs(args, "qdisc", "del", "dev") {
		dev := args[3]
		if args[len(args)-1] == "clsact" {
			k.clsact = false
		} else if strings.HasPrefix(dev, "ifb-") {
			k.ingress = ""
		} else {
			k.egress = ""
		}
	}
}

func (k *restartKernel) hasManagedObjects() bool {
	return k.egress != "" || k.ingress != "" || k.redirect || k.ifb
}

func (k *restartKernel) resetWrites() { k.writes = 0 }

func hasArgs(got []string, prefix ...string) bool {
	if len(got) < len(prefix) {
		return false
	}
	for i := range prefix {
		if got[i] != prefix[i] {
			return false
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func tokenAfter(values []string, want string) string {
	for i, value := range values {
		if value == want && i+1 < len(values) {
			return values[i+1]
		}
	}
	return ""
}
