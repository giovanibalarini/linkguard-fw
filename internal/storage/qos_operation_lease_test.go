package storage_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestQoSOperationLeaseSurvivesReopenWithRecoveryEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qos-operation.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := &qos.OperationLease{
		ID:        "qos-op-1",
		Interface: "wan0",
		Intent:    qos.OperationApply,
		Target: qos.Config{
			Interface: "wan0", Enabled: true, UploadMbps: 75, DownloadMbps: 300, Interactive: true,
		},
		Recovery: qos.Config{
			Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200,
		},
		BeforeEgress: &qos.CakeSignature{
			Handle: "cafe:", Bandwidth: "50mbit", Mode: "besteffort", HostMode: "dual-srchost", NAT: true,
		},
		BeforeIngress: &qos.CakeSignature{
			Handle: "caff:", Bandwidth: "200mbit", Mode: "besteffort", HostMode: "dual-dsthost", NAT: true, Ingress: true,
		},
		IFBExisted:    true,
		IFBWasUp:      false,
		ClsactExisted: true,
		CreatedAt:     time.Unix(1_788_000_000, 0).UTC(),
	}
	if err := db.SaveQoSOperationLease(want); err != nil {
		t.Fatalf("SaveQoSOperationLease: %v", err)
	}
	if err := db.SaveQoSOperationLease(&qos.OperationLease{ID: "qos-op-2", Interface: "wan0", Intent: qos.OperationDisable}); err == nil {
		t.Fatal("SaveQoSOperationLease overwrote an unresolved operation for the same interface")
	}
	if err := db.AdvanceQoSOperationLease(want.ID, 0, 1); err != nil {
		t.Fatalf("AdvanceQoSOperationLease: %v", err)
	}
	if err := db.AdvanceQoSOperationLease(want.ID, 0, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stale AdvanceQoSOperationLease error = %v; want sql.ErrNoRows", err)
	}
	want.Stage = 1
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err = storage.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	got, err := db.ListQoSOperationLeases()
	if err != nil {
		t.Fatalf("ListQoSOperationLeases: %v", err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
		t.Fatalf("ListQoSOperationLeases = %#v; want %#v", got, []qos.OperationLease{*want})
	}
}

func TestQoSOperationLeaseClearRequiresMatchingOperationAndInterface(t *testing.T) {
	db := newTestDB(t)
	lease := &qos.OperationLease{
		ID: "qos-op-1", Interface: "wan0", Intent: qos.OperationDisable,
		Target: qos.Config{Interface: "wan0"}, Recovery: qos.Config{Interface: "wan0"},
	}
	if err := db.SaveQoSOperationLease(lease); err != nil {
		t.Fatalf("SaveQoSOperationLease: %v", err)
	}
	if err := db.ClearQoSOperationLease("qos-op-other", "wan0"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ClearQoSOperationLease(wrong id) error = %v; want sql.ErrNoRows", err)
	}
	if err := db.ClearQoSOperationLease(lease.ID, "wan1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ClearQoSOperationLease(wrong interface) error = %v; want sql.ErrNoRows", err)
	}
	if err := db.ClearQoSOperationLease(lease.ID, lease.Interface); err != nil {
		t.Fatalf("ClearQoSOperationLease: %v", err)
	}
	got, err := db.ListQoSOperationLeases()
	if err != nil || len(got) != 0 {
		t.Fatalf("ListQoSOperationLeases after clear = %#v, %v; want empty", got, err)
	}
}

func TestUpdateLinkQoSAndClearOperationCommitsAtomically(t *testing.T) {
	db := newTestDB(t)
	link := &storage.Link{
		Name: "WAN", Interface: "wan0", Enabled: true,
		QoSEnabled: true, QoSUploadMbps: 50, QoSDownloadMbps: 200,
	}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	lease := &qos.OperationLease{
		ID: "qos-op-atomic", Interface: "wan0", Intent: qos.OperationApply,
		Target:   qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 75, DownloadMbps: 300, Interactive: true},
		Recovery: qos.Config{Interface: "wan0", Enabled: true, UploadMbps: 50, DownloadMbps: 200},
	}
	if err := db.SaveQoSOperationLease(lease); err != nil {
		t.Fatalf("SaveQoSOperationLease: %v", err)
	}

	err := db.UpdateLinkQoSIfCurrentAndClearOperation(
		link.ID, link.Interface, link.Enabled,
		link.QoSEnabled, link.QoSUploadMbps, link.QoSDownloadMbps, link.QoSInteractive,
		true, 75, 300, true, lease.ID,
	)
	if err != nil {
		t.Fatalf("UpdateLinkQoSIfCurrentAndClearOperation: %v", err)
	}
	got, err := db.GetLink(link.ID)
	if err != nil || got == nil || !got.QoSEnabled || got.QoSUploadMbps != 75 || got.QoSDownloadMbps != 300 || !got.QoSInteractive {
		t.Fatalf("updated link = %#v, %v", got, err)
	}
	leases, err := db.ListQoSOperationLeases()
	if err != nil || len(leases) != 0 {
		t.Fatalf("leases after atomic commit = %#v, %v; want empty", leases, err)
	}
}

func TestUpdateLinkQoSConflictKeepsOperationLease(t *testing.T) {
	db := newTestDB(t)
	link := &storage.Link{Name: "WAN", Interface: "wan0", Enabled: true}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	lease := &qos.OperationLease{
		ID: "qos-op-conflict", Interface: "wan0", Intent: qos.OperationDisable,
		Target: qos.Config{Interface: "wan0"}, Recovery: qos.Config{Interface: "wan0"},
	}
	if err := db.SaveQoSOperationLease(lease); err != nil {
		t.Fatalf("SaveQoSOperationLease: %v", err)
	}

	err := db.UpdateLinkQoSIfCurrentAndClearOperation(
		link.ID, link.Interface, false,
		false, 0, 0, false,
		false, 0, 0, false, lease.ID,
	)
	if !errors.Is(err, storage.ErrLinkStateChanged) {
		t.Fatalf("conflicting update error = %v; want ErrLinkStateChanged", err)
	}
	leases, listErr := db.ListQoSOperationLeases()
	if listErr != nil || len(leases) != 1 || leases[0].ID != lease.ID {
		t.Fatalf("lease after rollback = %#v, %v; want %q", leases, listErr, lease.ID)
	}
}
