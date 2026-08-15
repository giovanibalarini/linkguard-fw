package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func newUsersTestHandler(t *testing.T) (*handlers.UsersHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return handlers.NewUsersHandler(db), db
}

// helpdeskOnlyUser creates a role with ONLY users.manage (no roles.manage) and
// a user assigned to it — the exact "limited helpdesk account" scenario the
// vulnerability targets.
func helpdeskOnlyUser(t *testing.T, db *storage.DB) *storage.User {
	t.Helper()
	role := &storage.Role{Name: "Helpdesk", Permissions: []string{string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	u := &storage.User{Username: "helpdesk"}
	if err := db.CreateUser(u, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{role.ID}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func adminRoleID(t *testing.T, db *storage.DB) string {
	t.Helper()
	role := &storage.Role{Name: "Admin de verdade", Permissions: []string{string(auth.PermRolesManage), string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	return role.ID
}

func TestUpdateBlocksSelfPromotionWithoutRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	adminRole := adminRoleID(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{adminRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (roles.manage required), got %d: %s", w.Code, w.Body.String())
	}
	roleIDs, err := db.GetUserRoleIDs(attacker.ID)
	if err != nil {
		t.Fatalf("GetUserRoleIDs: %v", err)
	}
	for _, rid := range roleIDs {
		if rid == adminRole {
			t.Fatal("attacker's role_ids were changed despite the 403 — self-promotion succeeded")
		}
	}
}

func TestCreateBlocksRoleGrantWithoutRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	adminRole := adminRoleID(t, db)

	body, _ := json.Marshal(map[string]interface{}{
		"username": "backdoor",
		"password": "senhaForte12345",
		"role_ids": []string{adminRole},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (roles.manage required to grant a role at creation), got %d: %s", w.Code, w.Body.String())
	}
	// The attack must not have created the user in the DB.
	created, err := db.GetUserByUsername("backdoor")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created != nil {
		t.Fatal("user was created despite the 403 — privilege escalation via Create succeeded")
	}
}

func TestCreateWithoutRolesDoesNotRequireRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actor := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{
		"username": "conta-sem-papel",
		"password": "senhaForte12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for role-less creation (no grant), got %d: %s", w.Code, w.Body.String())
	}
	created, err := db.GetUserByUsername("conta-sem-papel")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created == nil {
		t.Fatal("legitimate role-less user was not created")
	}
}

func TestCreateWithRolesManageCanGrantRoles(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"username": "novo-admin",
		"password": "senhaForte12345",
		"role_ids": []string{actorRole},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 — actor holds roles.manage, legitimate role grant, got %d: %s", w.Code, w.Body.String())
	}
	created, err := db.GetUserByUsername("novo-admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created == nil {
		t.Fatal("user with granted role was not created")
	}
}

func TestUpdatePasswordOnlyDoesNotRequireRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "novaSenhaForte123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for password-only update (no role change), got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWithRolesManageCanChangeRoles(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	target := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{actorRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — actor holds roles.manage, legitimate role change, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── Reset de senha como caminho de escalação ────────────────────────────────
//
// Trocar a senha de uma conta É adquirir as permissões daquela conta. O gate de
// roles.manage cobria só a troca de papel; o bloco de senha não tinha checagem
// nenhuma, então users.manage sozinho bastava para tomar a conta de admin.

func adminTargetUser(t *testing.T, db *storage.DB) *storage.User {
	t.Helper()
	u := &storage.User{Username: "admin-alvo"}
	if err := db.CreateUser(u, "$2a$10$originaloriginaloriginaloriginaloriginaloriginalor", []string{adminRoleID(t, db)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestUpdateRefusesPasswordResetOnMorePrivilegedTarget(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	target := adminTargetUser(t, db)

	before, err := db.GetUserByID(target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{"password": "novaSenhaForte123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 — helpdesk (users.manage only) must not reset an admin's password, got %d: %s", w.Code, w.Body.String())
	}
	after, err := db.GetUserByID(target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.Password != before.Password {
		t.Fatal("a senha do alvo foi trocada apesar do 403 — a escalação funcionou")
	}
	if after.PasswordVersion != before.PasswordVersion {
		t.Fatal("password_version subiu apesar do 403 — a sessão do admin legítimo foi derrubada")
	}
}

func TestUpdateAllowsSelfPasswordResetRegardlessOfPrivilege(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actor := adminTargetUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "minhaNovaSenha123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+actor.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", actor.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — trocar a própria senha nunca é escalação, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateAllowsPasswordResetOnEquallyOrLessPrivilegedTarget(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	target := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "senhaResetada123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — reset legítimo de conta menos privilegiada, got %d: %s", w.Code, w.Body.String())
	}
}
