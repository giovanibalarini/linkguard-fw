package handlers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type fakeNetsvcProvider struct{}

func (fakeNetsvcProvider) Backend() netsvc.Backend { return netsvc.BackendKeaUnbound }
func (fakeNetsvcProvider) GenerateConfigs(netsvc.Config, []netsvc.Reservation, []string, string) []netsvc.ConfigFile {
	return nil
}
func (fakeNetsvcProvider) Apply(context.Context, netsvc.Config, []netsvc.Reservation, []string) (string, error) {
	return "", nil
}
func (fakeNetsvcProvider) ReloadConfigs(context.Context, netsvc.Config, []netsvc.Reservation, []string, string) (string, error) {
	return "", nil
}
func (fakeNetsvcProvider) Leases(context.Context) ([]netsvc.Lease, error) { return nil, nil }

// TestLastApplyStatusNilWhenNeverApplied is the regression test for a false
// "última aplicação falhou" banner shown on the DHCP/DNS pages of a brand-new
// install that has never actually attempted an apply. lastApplyStatus used to
// return the bare Go zero value (OK: false) when nothing was stored yet, which
// is indistinguishable on the wire from a real failure — the frontend renders
// the red banner for both. It must report "no attempt yet" as a nil/absent
// value instead.
func TestLastApplyStatusNilWhenNeverApplied(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewNetsvcHandler(db, fakeNetsvcProvider{}, nil)

	if got := h.lastApplyStatus(); got != nil {
		t.Fatalf("expected nil last_apply before any apply attempt, got %+v", got)
	}

	if err := h.doReload(context.Background()); err != nil {
		t.Fatalf("doReload: %v", err)
	}
	got := h.lastApplyStatus()
	if got == nil {
		t.Fatal("expected a non-nil last_apply after doReload ran")
	}
	if !got.OK {
		t.Errorf("expected OK=true after a successful fake reload, got %+v", got)
	}
}
