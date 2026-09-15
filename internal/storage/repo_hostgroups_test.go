package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestHostGroupCRUD(t *testing.T) {
	db := newTestDB(t)

	// Create
	hg := &storage.HostGroup{
		Name:        "Cluster K3s OCI",
		Description: "Nós Kubernetes",
		Hosts:       []string{"10.0.1.20", "10.0.1.21/32"},
	}
	if err := db.CreateHostGroup(hg); err != nil {
		t.Fatalf("CreateHostGroup: %v", err)
	}
	if hg.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	// Read
	got, err := db.GetHostGroup(hg.ID)
	if err != nil {
		t.Fatalf("GetHostGroup: %v", err)
	}
	if got == nil || got.Name != "Cluster K3s OCI" {
		t.Fatalf("unexpected group: %+v", got)
	}
	if len(got.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(got.Hosts))
	}

	// Update
	got.Description = "Atualizado"
	got.Hosts = append(got.Hosts, "192.168.3.0/24")
	if err := db.UpdateHostGroup(got); err != nil {
		t.Fatalf("UpdateHostGroup: %v", err)
	}

	updated, err := db.GetHostGroup(hg.ID)
	if err != nil {
		t.Fatalf("GetHostGroup after update: %v", err)
	}
	if len(updated.Hosts) != 3 || updated.Description != "Atualizado" {
		t.Fatalf("unexpected updated group: %+v", updated)
	}

	// List
	list, err := db.ListHostGroups()
	if err != nil {
		t.Fatalf("ListHostGroups: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 group, got %d", len(list))
	}

	// Delete
	if err := db.DeleteHostGroup(hg.ID); err != nil {
		t.Fatalf("DeleteHostGroup: %v", err)
	}
	deleted, err := db.GetHostGroup(hg.ID)
	if err != nil {
		t.Fatalf("GetHostGroup deleted: %v", err)
	}
	if deleted != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestValidateHostGroup(t *testing.T) {
	valid := storage.HostGroup{
		Name:  "Test",
		Hosts: []string{"10.0.1.20", "10.0.1.0/24"},
	}
	if err := storage.ValidateHostGroup(valid); err != nil {
		t.Fatalf("expected valid: %v", err)
	}

	emptyName := storage.HostGroup{Name: "", Hosts: []string{"10.0.0.1"}}
	if err := storage.ValidateHostGroup(emptyName); err == nil {
		t.Fatal("expected error for empty name")
	}

	invalidHost := storage.HostGroup{Name: "Test", Hosts: []string{"not-an-ip"}}
	if err := storage.ValidateHostGroup(invalidHost); err == nil {
		t.Fatal("expected error for invalid host")
	}
}

func TestUpdateWireGuardPeerAccess(t *testing.T) {
	db := newTestDB(t)
	user := &storage.User{Username: "accessuser"}
	if err := db.CreateUser(user, "hash", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	peer := &storage.WireGuardPeer{
		UserID:          user.ID,
		PublicKey:       "pub123",
		Address:         "10.7.0.5/32",
		SecretName:      "secret_test",
		FirewallGroupID: "fg_test",
	}
	group := &storage.FirewallGroup{
		ID:        "fg_test",
		Name:      "VPN — accessuser",
		ChainName: "grp_fgtest",
	}
	if _, err := db.UpsertWireGuardPeer(peer, group); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}

	// Initial default should be "full"
	initial, err := db.GetWireGuardPeer(user.ID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if initial.AccessMode != "full" {
		t.Errorf("expected default access mode full, got %s", initial.AccessMode)
	}

	// Update to restricted
	if err := db.UpdateWireGuardPeerAccess(user.ID, "restricted", []string{"hg_k3s"}, "22, 6443"); err != nil {
		t.Fatalf("UpdateWireGuardPeerAccess: %v", err)
	}

	updated, err := db.GetWireGuardPeer(user.ID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if updated.AccessMode != "restricted" {
		t.Errorf("expected restricted, got %s", updated.AccessMode)
	}
	if len(updated.AllowedHostGroups) != 1 || updated.AllowedHostGroups[0] != "hg_k3s" {
		t.Errorf("unexpected allowed groups: %v", updated.AllowedHostGroups)
	}
	if updated.AllowedPorts != "22, 6443" {
		t.Errorf("unexpected allowed ports: %s", updated.AllowedPorts)
	}
}
