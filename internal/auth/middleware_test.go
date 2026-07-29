package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newMiddlewareTestService(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Login always checks TwoFAEnabled, which reads through the secrets
	// vault -- a nil Secrets here would panic on first login, so use a real
	// (test-scoped) secrets.Service rather than the brief's literal nil.
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	return NewService(db, "test-secret-at-least-32-bytes-long-xxxx", sec), db
}

func TestMiddlewareRejectsTokenAfterPasswordChange(t *testing.T) {
	svc, db := newMiddlewareTestService(t)
	u := &storage.User{Username: "revoketest"}
	hash, _ := HashPassword("senhaOriginal123")
	if err := db.CreateUser(u, hash, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, _, err := svc.Login(u.Username, "senhaOriginal123", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The token must work before the password changes.
	ok := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ok = true })).
		ServeHTTP(httptest.NewRecorder(), authedRequest(token))
	if !ok {
		t.Fatal("expected middleware to accept a fresh token")
	}

	if err := db.UpdateUserPassword(u.ID, "novo-hash-irrelevante-pro-teste"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}

	rec := httptest.NewRecorder()
	called := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).
		ServeHTTP(rec, authedRequest(token))
	if called {
		t.Fatal("expected middleware to reject the OLD token after a password change")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a revoked token, got %d", rec.Code)
	}
}

func TestMiddlewareRejectsTokenForDeletedUser(t *testing.T) {
	svc, db := newMiddlewareTestService(t)
	u := &storage.User{Username: "deletetest"}
	hash, _ := HashPassword("senha123456")
	if err := db.CreateUser(u, hash, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, _, err := svc.Login(u.Username, "senha123456", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := db.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	rec := httptest.NewRecorder()
	called := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).
		ServeHTTP(rec, authedRequest(token))
	if called {
		t.Fatal("expected middleware to reject a token for a deleted user")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func authedRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
