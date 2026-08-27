package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/wireguard"
)

type wireGuardServiceStub struct {
	overview       wireguard.Overview
	enrollment     wireguard.Enrollment
	updateCalled   bool
	enrolledUserID string
	revokedUserID  string
	recorded       error
}

func (s *wireGuardServiceStub) Overview(context.Context) (wireguard.Overview, error) {
	return s.overview, nil
}
func (s *wireGuardServiceStub) UpdateConfig(_ context.Context, _ wireguard.Config) error {
	s.updateCalled = true
	return nil
}
func (s *wireGuardServiceStub) Enroll(_ context.Context, userID string) (wireguard.Enrollment, error) {
	s.enrolledUserID = userID
	return s.enrollment, nil
}
func (s *wireGuardServiceStub) Revoke(_ context.Context, userID string) error {
	s.revokedUserID = userID
	return nil
}
func (s *wireGuardServiceStub) RecordIntegrationError(err error) { s.recorded = err }

type wireGuardReconcilerStub struct{ err error }

func (s wireGuardReconcilerStub) Reconcile(context.Context) error { return s.err }

type wireGuardInputStub struct{ err error }

func (s wireGuardInputStub) ReconcileInputProtection(context.Context) error { return s.err }

func newWireGuardHandlerTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestWireGuardEnrollUsesAuthenticatedUserAndNeverAuditsPrivateConfig(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	const private = "PRIVATE-SECRET-MUST-NOT-LEAK"
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{
		Peer:         wireguard.Peer{UserID: "local-user", Username: "luan", Address: "10.7.0.2/32"},
		ClientConfig: "[Interface]\nPrivateKey = " + private,
		QRDataURL:    "data:image/svg+xml;base64,PHN2Zz4=",
	}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		UserID: "local-user", Username: "luan",
	}))
	w := httptest.NewRecorder()

	h.EnrollSelf(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.enrolledUserID != "local-user" {
		t.Fatalf("enrolled user = %q, want authenticated user", svc.enrolledUserID)
	}
	if !strings.Contains(w.Body.String(), private) {
		t.Fatal("one-time response must contain the client private config")
	}
	logs, err := db.GetAuditLogs(10)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("audit log count = %d, want 1", len(logs))
	}
	if strings.Contains(logs[0].Details, private) || strings.Contains(logs[0].Resource, private) {
		t.Fatal("private client config leaked into audit log")
	}
}

func TestWireGuardUpdateRejectsInjectionBeforeCallingService(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	body := `{"enabled":true,"listen_port":51820,"address":"10.7.0.1/24\nPostUp = touch /tmp/pwn","endpoint_host":"vpn.example.test"}`
	w := httptest.NewRecorder()

	h.UpdateConfig(w, httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.updateCalled {
		t.Fatal("invalid input reached the service")
	}
}

func TestWireGuardEnrollmentSurvivesIntegrationFailure(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{err: errors.New("nft unavailable")}, wireGuardInputStub{})
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "local-user"}))
	w := httptest.NewRecorder()

	h.EnrollSelf(w, req)

	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "one-time-private") {
		t.Fatalf("one-time material was lost: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "apply_error") || svc.recorded == nil {
		t.Fatalf("integration failure not reported/recorded: body=%s recorded=%v", w.Body.String(), svc.recorded)
	}
}
