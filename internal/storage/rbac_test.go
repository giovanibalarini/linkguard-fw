package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// seedRoles installs a minimal set of roles for tests.
func seedRoles(t *testing.T, db *storage.DB) {
	t.Helper()
	seeds := []storage.RoleSeed{
		{ID: "role-admin", Name: "Administrador", Description: "tudo",
			Permissions: []string{"users.manage", "roles.manage", "links.write", "links.read"}},
		{ID: "role-operator", Name: "Operador", Description: "ops",
			Permissions: []string{"links.read", "links.write", "firewall.write"}},
		{ID: "role-viewer", Name: "Visualizador", Description: "leitura",
			Permissions: []string{"links.read", "firewall.read"}},
	}
	if err := db.EnsureDefaultRoles(seeds, "role-admin"); err != nil {
		t.Fatalf("EnsureDefaultRoles: %v", err)
	}
}

func TestEnsureDefaultRolesIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	seedRoles(t, db)
	seedRoles(t, db) // second call must not duplicate or error

	roles, err := db.ListRoles()
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}

	// default-admin must have been granted the admin role.
	ids, err := db.GetUserRoleIDs("default-admin")
	if err != nil {
		t.Fatalf("GetUserRoleIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "role-admin" {
		t.Fatalf("expected default-admin to hold role-admin, got %v", ids)
	}
}

func TestEnsureDefaultRolesPreservesCustomization(t *testing.T) {
	db := newTestDB(t)
	seedRoles(t, db)

	// Admin removes a permission from the built-in operator role.
	op, _ := db.GetRole("role-operator")
	op.Permissions = []string{"links.read"} // stripped down
	if err := db.UpdateRole(op); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}

	// Re-seeding (e.g. on restart) must NOT restore the removed permissions.
	seedRoles(t, db)
	op, _ = db.GetRole("role-operator")
	if len(op.Permissions) != 1 || op.Permissions[0] != "links.read" {
		t.Fatalf("re-seed clobbered customization: %v", op.Permissions)
	}
}

func TestGetUserPermissionsUnionsRoles(t *testing.T) {
	db := newTestDB(t)
	seedRoles(t, db)

	u := &storage.User{Username: "joao"}
	if err := db.CreateUser(u, "hash", []string{"role-viewer", "role-operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	perms, err := db.GetUserPermissions(u.ID)
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	// Union of viewer (links.read, firewall.read) and operator
	// (links.read, links.write, firewall.write).
	want := []string{"links.read", "links.write", "firewall.read", "firewall.write"}
	for _, p := range want {
		if !perms[p] {
			t.Errorf("expected effective permission %q", p)
		}
	}
	if perms["users.manage"] {
		t.Errorf("user must NOT have users.manage")
	}
}

func TestSetUserRolesReplaces(t *testing.T) {
	db := newTestDB(t)
	seedRoles(t, db)

	u := &storage.User{Username: "maria"}
	if err := db.CreateUser(u, "hash", []string{"role-admin"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.SetUserRoles(u.ID, []string{"role-viewer"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	ids, _ := db.GetUserRoleIDs(u.ID)
	if len(ids) != 1 || ids[0] != "role-viewer" {
		t.Fatalf("expected only role-viewer, got %v", ids)
	}
	perms, _ := db.GetUserPermissions(u.ID)
	if perms["users.manage"] {
		t.Errorf("after role replace, users.manage must be gone")
	}
}

func TestDeleteRoleCascadesAssignments(t *testing.T) {
	db := newTestDB(t)
	seedRoles(t, db)

	custom := &storage.Role{Name: "Suporte", Permissions: []string{"links.read"}}
	if err := db.CreateRole(custom); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	u := &storage.User{Username: "ana"}
	if err := db.CreateUser(u, "hash", []string{custom.ID}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if n, _ := db.CountUsersWithRole(custom.ID); n != 1 {
		t.Fatalf("expected 1 user with custom role, got %d", n)
	}
	if err := db.DeleteRole(custom.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	// The assignment must be gone (FK cascade), leaving the user with no roles.
	ids, _ := db.GetUserRoleIDs(u.ID)
	if len(ids) != 0 {
		t.Fatalf("expected user to have no roles after role delete, got %v", ids)
	}
}
