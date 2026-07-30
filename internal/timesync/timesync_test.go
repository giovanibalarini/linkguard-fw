package timesync

import (
	"context"
	"testing"
)

type fakeExec struct {
	unitFilesOut string
	enableCalled bool
	enableErr    error
	syncedOut    string
	syncedErr    error
}

func (f *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 3 && args[0] == "enable" && args[1] == "--now" && args[2] == "chrony" {
		f.enableCalled = true
		return "", f.enableErr
	}
	return "", nil
}
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 3 && args[0] == "list-unit-files" {
		return f.unitFilesOut, nil
	}
	if cmd == "timedatectl" {
		return f.syncedOut, f.syncedErr
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool { return false }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func TestEnsureEnabledCallsSystemctlWhenInstalled(t *testing.T) {
	fe := &fakeExec{unitFilesOut: "chrony.service                       enabled         enabled\n"}
	EnsureEnabled(context.Background(), fe)
	if !fe.enableCalled {
		t.Fatal("expected systemctl enable --now chrony to be called")
	}
}

func TestEnsureEnabledSkipsWhenNotInstalled(t *testing.T) {
	fe := &fakeExec{unitFilesOut: ""}
	EnsureEnabled(context.Background(), fe)
	if fe.enableCalled {
		t.Fatal("expected systemctl enable NOT to be called when chrony.service is absent")
	}
}

func TestIsSyncedTrue(t *testing.T) {
	fe := &fakeExec{syncedOut: "yes\n"}
	if !IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=true")
	}
}

func TestIsSyncedFalse(t *testing.T) {
	fe := &fakeExec{syncedOut: "no\n"}
	if IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=false")
	}
}

func TestIsSyncedErrorIsFalse(t *testing.T) {
	fe := &fakeExec{syncedErr: errBoom{}}
	if IsSynced(context.Background(), fe) {
		t.Fatal("expected IsSynced=false on exec error")
	}
}
