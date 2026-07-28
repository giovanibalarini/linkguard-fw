package storage_test

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// newTestDB is already defined in storage_test.go (same package); reused here.

func TestManagedInterfaceUpsertAndGet(t *testing.T) {
	db := newTestDB(t)
	m := storage.ManagedInterface{Name: "eth0", Kind: "physical", AddrMode: "static", CIDR: "192.168.3.3/24", Gateway: "192.168.3.1", Description: "WAN principal"}
	if err := db.UpsertManagedInterface(m); err != nil {
		t.Fatalf("UpsertManagedInterface: %v", err)
	}
	got, err := db.GetManagedInterface("eth0")
	if err != nil {
		t.Fatalf("GetManagedInterface: %v", err)
	}
	if got == nil {
		t.Fatal("esperava encontrar eth0, veio nil")
	}
	if got.CIDR != "192.168.3.3/24" || got.Gateway != "192.168.3.1" {
		t.Errorf("dados errados: %+v", got)
	}

	// Upsert de novo com dado diferente deve substituir, não duplicar.
	m.Gateway = "192.168.3.254"
	if err := db.UpsertManagedInterface(m); err != nil {
		t.Fatalf("UpsertManagedInterface (update): %v", err)
	}
	all, err := db.ListManagedInterfaces()
	if err != nil {
		t.Fatalf("ListManagedInterfaces: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("esperava 1 interface gerenciada, veio %d", len(all))
	}
	if all[0].Gateway != "192.168.3.254" {
		t.Errorf("esperava gateway atualizado, veio %q", all[0].Gateway)
	}
}

func TestGetManagedInterfaceNotFound(t *testing.T) {
	db := newTestDB(t)
	got, err := db.GetManagedInterface("nao-existe")
	if err != nil {
		t.Fatalf("esperava nil error, veio: %v", err)
	}
	if got != nil {
		t.Errorf("esperava nil, veio %+v", got)
	}
}

func TestPendingInterfaceChangeLifecycle(t *testing.T) {
	db := newTestDB(t)
	deadline := time.Now().Add(90 * time.Second).Unix()
	p := storage.PendingInterfaceChange{
		ID:           "test-id-1",
		Interface:    "eth0",
		OldConfig:    `{"addr_mode":"dhcp"}`,
		OldFiles:     `[{"path":"/etc/systemd/network/10-eth0.network","content":"old"}]`,
		NewConfig:    `{"addr_mode":"static","cidr":"192.168.3.3/24"}`,
		DeadlineUnix: deadline,
	}
	if err := db.CreatePendingInterfaceChange(p); err != nil {
		t.Fatalf("CreatePendingInterfaceChange: %v", err)
	}

	got, err := db.GetPendingInterfaceChange("eth0")
	if err != nil {
		t.Fatalf("GetPendingInterfaceChange: %v", err)
	}
	if got == nil || got.ID != "test-id-1" {
		t.Fatalf("esperava encontrar a mudança pendente, veio %+v", got)
	}

	all, err := db.ListPendingInterfaceChanges()
	if err != nil {
		t.Fatalf("ListPendingInterfaceChanges: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("esperava 1 mudança pendente, veio %d", len(all))
	}

	if err := db.DeletePendingInterfaceChange("eth0"); err != nil {
		t.Fatalf("DeletePendingInterfaceChange: %v", err)
	}
	got, err = db.GetPendingInterfaceChange("eth0")
	if err != nil {
		t.Fatalf("GetPendingInterfaceChange after delete: %v", err)
	}
	if got != nil {
		t.Errorf("esperava nil depois de deletar, veio %+v", got)
	}
}
