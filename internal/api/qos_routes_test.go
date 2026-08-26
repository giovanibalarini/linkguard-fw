package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/go-chi/chi/v5"
)

type routeQosExec struct{}

func (routeQosExec) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (routeQosExec) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", nil
}
func (routeQosExec) IsDryRun() bool                              { return true }
func (routeQosExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestQosRoutesUseReadForGetAndWriteForMutations(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := handlers.NewQosHandler(qos.NewService(routeQosExec{}), db)
	r := chi.NewRouter()
	require := func(perm auth.Permission) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Test-Permission", string(perm))
				next.ServeHTTP(w, r)
			})
		}
	}
	registerQosRoutes(r, require, h)

	for _, tc := range []struct {
		method     string
		path       string
		permission auth.Permission
	}{
		{method: http.MethodGet, path: "/api/links/missing/qos", permission: auth.PermLinksRead},
		{method: http.MethodPut, path: "/api/links/missing/qos", permission: auth.PermLinksWrite},
		{method: http.MethodPost, path: "/api/links/missing/qos/test", permission: auth.PermLinksWrite},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, body = %s; want handler 404", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Test-Permission"); got != string(tc.permission) {
			t.Errorf("%s %s permission = %q, want %q", tc.method, tc.path, got, tc.permission)
		}
	}
}

func TestNewKeepsQosServiceFromConfig(t *testing.T) {
	service := qos.NewService(routeQosExec{})
	authSvc := auth.NewService(nil, "test-secret", nil)
	s := New(Config{QoS: service, WebFS: fstest.MapFS{}},
		nil, nil, nil, nil, nil, nil, nil, nil, authSvc, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if s.qosSvc != service {
		t.Fatalf("Server.qosSvc = %p, want configured service %p", s.qosSvc, service)
	}
}
