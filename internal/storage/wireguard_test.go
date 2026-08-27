package storage_test

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestWireGuardPeerPersistsWithStableFirewallGroup(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "ana"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	group := storage.FirewallGroup{
		ID: "550e8400-e29b-41d4-a716-446655440001", Name: "VPN — ana",
		ChainName: "grp_550e8400e29b", Enabled: true, CondSaddr: "10.7.0.2/32",
		Fallthrough: "continue", Kind: "wireguard_peer", Scope: "forward", ConnState: "any",
	}
	peer := storage.WireGuardPeer{
		UserID: u.ID, PublicKey: "public-one", Address: "10.7.0.2/32",
		SecretName: "wireguard_peer_secret_one", FirewallGroupID: group.ID,
	}
	old, err := db.UpsertWireGuardPeer(&peer, &group)
	if err != nil {
		t.Fatalf("UpsertWireGuardPeer(create): %v", err)
	}
	if old != nil {
		t.Fatalf("first upsert returned old peer: %+v", old)
	}

	peer.PublicKey = "public-two"
	peer.SecretName = "wireguard_peer_secret_two"
	old, err = db.UpsertWireGuardPeer(&peer, &group)
	if err != nil {
		t.Fatalf("UpsertWireGuardPeer(rotate): %v", err)
	}
	if old == nil || old.SecretName != "wireguard_peer_secret_one" {
		t.Fatalf("rotation old peer = %+v", old)
	}
	got, err := db.GetWireGuardPeer(u.ID)
	if err != nil || got == nil {
		t.Fatalf("GetWireGuardPeer = %+v, %v", got, err)
	}
	if got.FirewallGroupID != group.ID || got.Address != "10.7.0.2/32" || got.Username != "ana" {
		t.Fatalf("peer association changed: %+v", got)
	}
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, g := range groups {
		if g.Kind == "wireguard_peer" {
			count++
			if g.CondSaddr != peer.Address {
				t.Fatalf("group source = %q, want %q", g.CondSaddr, peer.Address)
			}
		}
	}
	if count != 1 {
		t.Fatalf("wireguard groups = %d, want 1", count)
	}
}

func TestDeleteUserCleansWireGuardOwnershipAndEncryptedSecret(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "carla"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	group := storage.FirewallGroup{ID: "g-user", Name: "VPN — carla", ChainName: "grp_carla", Enabled: true, CondSaddr: "10.7.0.2/32", Fallthrough: "continue", Kind: "wireguard_peer", Scope: "forward", ConnState: "any"}
	peer := storage.WireGuardPeer{UserID: u.ID, PublicKey: "pub-carla", Address: "10.7.0.2/32", SecretName: "secret-carla", FirewallGroupID: group.ID}
	if _, err := db.UpsertWireGuardPeer(&peer, &group); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at) VALUES (?, ?, ?, ?)`, peer.SecretName, []byte("nonce"), []byte("ciphertext"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got, _ := db.GetWireGuardPeer(u.ID); got != nil {
		t.Fatalf("peer survived user deletion: %+v", got)
	}
	var secrets int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, peer.SecretName).Scan(&secrets); err != nil {
		t.Fatal(err)
	}
	if secrets != 0 {
		t.Fatal("encrypted peer secret survived user deletion")
	}
	for _, g := range mustGroups(t, db) {
		if g.ID == group.ID {
			t.Fatal("peer firewall group survived user deletion")
		}
	}
}

func TestDeleteWireGuardPeerDeletesItsGroupAndRules(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "bia"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	group := storage.FirewallGroup{ID: "g-peer", Name: "VPN — bia", ChainName: "grp_aabbcc", Enabled: true, CondSaddr: "10.7.0.2/32", Fallthrough: "continue", Kind: "wireguard_peer", Scope: "forward", ConnState: "any"}
	peer := storage.WireGuardPeer{UserID: u.ID, PublicKey: "pub", Address: "10.7.0.2/32", SecretName: "sec", FirewallGroupID: group.ID}
	if _, err := db.UpsertWireGuardPeer(&peer, &group); err != nil {
		t.Fatal(err)
	}
	rule := &storage.FirewallRule{GroupID: group.ID, Action: "accept", Description: "VPN rule"}
	if err := db.CreateFirewallRule(rule); err != nil {
		t.Fatal(err)
	}
	removed, err := db.DeleteWireGuardPeer(u.ID)
	if err != nil || removed == nil || removed.SecretName != "sec" {
		t.Fatalf("DeleteWireGuardPeer = %+v, %v", removed, err)
	}
	if got, _ := db.GetWireGuardPeer(u.ID); got != nil {
		t.Fatalf("peer still exists: %+v", got)
	}
	for _, g := range mustGroups(t, db) {
		if g.ID == group.ID {
			t.Fatal("managed group still exists")
		}
	}
	for _, r := range mustRules(t, db) {
		if r.GroupID == group.ID {
			t.Fatal("group rule still exists")
		}
	}
}

func mustGroups(t *testing.T, db *storage.DB) []storage.FirewallGroup {
	t.Helper()
	v, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustRules(t *testing.T, db *storage.DB) []storage.FirewallRule {
	t.Helper()
	v, err := db.ListFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
