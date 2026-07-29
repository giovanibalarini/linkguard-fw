package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestUpdateUserPasswordIncrementsPasswordVersion(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "versiontest"}
	if err := db.CreateUser(u, "hash1", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	before, err := db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if before.PasswordVersion != 1 {
		t.Fatalf("expected PasswordVersion=1 on creation, got %d", before.PasswordVersion)
	}
	if err := db.UpdateUserPassword(u.ID, "hash2"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	after, err := db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordVersion != before.PasswordVersion+1 {
		t.Fatalf("expected PasswordVersion to increment from %d, got %d", before.PasswordVersion, after.PasswordVersion)
	}
}
