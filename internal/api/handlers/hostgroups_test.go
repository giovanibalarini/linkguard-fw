package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type vpnReconcilerStub struct {
	reconcileCount int
}

func (s *vpnReconcilerStub) Reconcile(context.Context) error {
	s.reconcileCount++
	return nil
}

func newHostGroupsTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestHostGroupHandlerCRUD(t *testing.T) {
	db := newHostGroupsTestDB(t)
	vpn := &vpnReconcilerStub{}
	h := NewHostGroupHandler(db, vpn)

	r := chi.NewRouter()
	r.Get("/api/hostgroups", h.List)
	r.Post("/api/hostgroups", h.Create)
	r.Get("/api/hostgroups/{id}", h.Get)
	r.Put("/api/hostgroups/{id}", h.Update)
	r.Delete("/api/hostgroups/{id}", h.Delete)

	// 1. Create
	createPayload := []byte(`{"name":"Servidores OCI","description":"Nós do cluster","hosts":["10.0.1.20","10.0.1.21"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hostgroups", bytes.NewReader(createPayload))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var created storage.HostGroup
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("Decode created: %v", err)
	}
	if created.ID == "" || created.Name != "Servidores OCI" {
		t.Fatalf("Unexpected created: %+v", created)
	}
	if vpn.reconcileCount != 1 {
		t.Fatalf("reconcileCount = %d, want 1", vpn.reconcileCount)
	}

	// 2. List
	req = httptest.NewRequest(http.MethodGet, "/api/hostgroups", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("List status = %d, want 200", w.Code)
	}
	var list []storage.HostGroup
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("Decode list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("List len = %d, want 1", len(list))
	}

	// 3. Get
	req = httptest.NewRequest(http.MethodGet, "/api/hostgroups/"+created.ID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Get status = %d, want 200", w.Code)
	}

	// 4. Update
	updatePayload := []byte(`{"name":"Servidores OCI Prod","description":"Cluster prod","hosts":["10.0.1.20/32","10.0.1.21/32","10.0.1.22/32"]}`)
	req = httptest.NewRequest(http.MethodPut, "/api/hostgroups/"+created.ID, bytes.NewReader(updatePayload))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Update status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if vpn.reconcileCount != 2 {
		t.Fatalf("reconcileCount = %d, want 2", vpn.reconcileCount)
	}

	// 5. Delete
	req = httptest.NewRequest(http.MethodDelete, "/api/hostgroups/"+created.ID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete status = %d, want 200", w.Code)
	}
	if vpn.reconcileCount != 3 {
		t.Fatalf("reconcileCount = %d, want 3", vpn.reconcileCount)
	}

	// 6. Get after delete -> 404
	req = httptest.NewRequest(http.MethodGet, "/api/hostgroups/"+created.ID, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("Get after delete status = %d, want 404", w.Code)
	}
}

