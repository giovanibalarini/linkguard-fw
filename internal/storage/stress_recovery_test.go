package storage_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestStressRecoveryLeaseSurvivesReopenAndCannotBeOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stress.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := &storage.StressRecoveryLease{
		TestID: "stress-1", LinkID: "link-1", Interface: "eth0", Mode: "degrade",
		DelayMs: 450, LossPct: 15, CreatedAt: time.Unix(1_777_000_000, 0).UTC(),
	}
	if err := db.SaveStressRecoveryLease(want); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	if err := db.SaveStressRecoveryLease(&storage.StressRecoveryLease{TestID: "stress-2", Interface: "eth1", Mode: "outage"}); err == nil {
		t.Fatal("SaveStressRecoveryLease overwrote an unresolved recovery lease")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err = storage.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	got, err := db.GetStressRecoveryLease()
	if err != nil {
		t.Fatalf("GetStressRecoveryLease: %v", err)
	}
	if got == nil || got.TestID != want.TestID || got.LinkID != want.LinkID || got.Interface != want.Interface ||
		got.Mode != want.Mode || got.DelayMs != want.DelayMs || got.LossPct != want.LossPct || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("GetStressRecoveryLease = %+v; want %+v", got, want)
	}
}

func TestStressRecoveryLeaseClearRequiresMatchingTestID(t *testing.T) {
	db := newTestDB(t)
	lease := &storage.StressRecoveryLease{TestID: "stress-1", LinkID: "link-1", Interface: "eth0", Mode: "outage", CreatedAt: time.Now().UTC()}
	if err := db.SaveStressRecoveryLease(lease); err != nil {
		t.Fatalf("SaveStressRecoveryLease: %v", err)
	}
	if err := db.ClearStressRecoveryLease("stress-other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ClearStressRecoveryLease(wrong id) error = %v; want sql.ErrNoRows", err)
	}
	if err := db.ClearStressRecoveryLease(lease.TestID); err != nil {
		t.Fatalf("ClearStressRecoveryLease: %v", err)
	}
	got, err := db.GetStressRecoveryLease()
	if err != nil || got != nil {
		t.Fatalf("GetStressRecoveryLease after clear = %+v, %v; want nil, nil", got, err)
	}
}
