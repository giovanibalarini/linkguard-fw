package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/qos"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type qosHandlerExec struct {
	dryRun      bool
	executeErr  error
	pingOutputs []string
	events      []string
}

func (e *qosHandlerExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	event := "write:" + cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if e.executeErr != nil {
		return "", e.executeErr
	}
	return "", nil
}

func (e *qosHandlerExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	event := "read:" + cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if cmd == "ping" {
		if len(e.pingOutputs) == 0 {
			return "", errors.New("missing ping fixture")
		}
		out := e.pingOutputs[0]
		e.pingOutputs = e.pingOutputs[1:]
		return out, nil
	}
	return "", nil
}

func (e *qosHandlerExec) IsDryRun() bool { return e.dryRun }

func (e *qosHandlerExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func newQosHandlerFixture(t *testing.T, link storage.Link, exec *qosHandlerExec) (*handlers.QosHandler, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateLink(&link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	return handlers.NewQosHandler(qos.NewService(exec), db), db
}

func decodeQosJSON(t *testing.T, rec *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(target); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

func qosLink() storage.Link {
	return storage.Link{
		ID:              "wan-1",
		Name:            "Fibra principal",
		Interface:       "wan0",
		IPAddress:       "198.51.100.10",
		Gateway:         "198.51.100.1",
		Weight:          70,
		DNSTest:         "1.1.1.1",
		MonitorHosts:    "1.1.1.1,8.8.8.8",
		Status:          links.StatusOnline,
		Enabled:         true,
		TableID:         101,
		QoSEnabled:      false,
		QoSUploadMbps:   12,
		QoSDownloadMbps: 80,
		QoSInteractive:  true,
	}
}

func TestQosGetReturnsStoredConfigurationWithoutApplying(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	h, _ := newQosHandlerFixture(t, qosLink(), exec)

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/links/wan-1/qos", nil), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got qos.Config
	decodeQosJSON(t, rec, &got)
	want := qos.Config{Interface: "wan0", Enabled: false, UploadMbps: 12, DownloadMbps: 80, Interactive: true}
	if got != want {
		t.Errorf("GET config = %#v, want %#v", got, want)
	}
	if len(exec.events) != 0 {
		t.Errorf("GET applied kernel commands: %v", exec.events)
	}
}

func TestQosHandlersRejectMissingAndInvalidLinks(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	h, db := newQosHandlerFixture(t, qosLink(), exec)

	missing := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/links/missing/qos", nil), "id", "missing")
	rec := httptest.NewRecorder()
	h.Get(rec, missing)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing link GET status = %d, want 404", rec.Code)
	}

	invalid := qosLink()
	invalid.ID = "invalid"
	invalid.Interface = "wan bad"
	if err := db.CreateLink(&invalid); err != nil {
		t.Fatalf("CreateLink invalid fixture: %v", err)
	}
	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/links/invalid/qos", nil), "id", "invalid")
	rec = httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid link GET status = %d, body = %s; want 400", rec.Code, rec.Body.String())
	}
}

func TestQosPutAppliesBeforePersistingAndPreservesLinkFields(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	h, db := newQosHandlerFixture(t, original, exec)

	body := strings.NewReader(`{"enabled":true,"upload_mbps":50,"download_mbps":200,"interactive":true}`)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", body), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var state qos.State
	decodeQosJSON(t, rec, &state)
	wantState := qos.State{Enabled: true, Interface: "wan0", IFB: qos.IFBName("wan0"), Mode: "diffserv4", DryRun: true}
	if state != wantState {
		t.Errorf("PUT state = %#v, want %#v", state, wantState)
	}

	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after PUT: %v", err)
	}
	if !stored.QoSEnabled || stored.QoSUploadMbps != 50 || stored.QoSDownloadMbps != 200 || !stored.QoSInteractive {
		t.Errorf("persisted QoS = %#v, want enabled/50/200/interactive", stored)
	}
	if stored.Name != original.Name || stored.Interface != original.Interface || stored.IPAddress != original.IPAddress ||
		stored.Gateway != original.Gateway || stored.Weight != original.Weight || stored.DNSTest != original.DNSTest ||
		stored.MonitorHosts != original.MonitorHosts || stored.Status != original.Status || stored.TableID != original.TableID ||
		stored.Enabled != original.Enabled {
		t.Errorf("PUT changed non-QoS link fields: got %#v, original %#v", stored, original)
	}
	if len(exec.events) == 0 || exec.events[0] != "write:tc qdisc replace dev wan0 root cake bandwidth 50mbit diffserv4 dual-srchost" {
		t.Errorf("PUT did not apply the requested configuration first; events = %v", exec.events)
	}
}

func TestQosPutDoesNotPersistWhenApplyFails(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true, executeErr: errors.New("tc failed")}
	original := qosLink()
	h, db := newQosHandlerFixture(t, original, exec)

	body := strings.NewReader(`{"enabled":true,"upload_mbps":50,"download_mbps":200}`)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", body), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed PUT status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after failed PUT: %v", err)
	}
	if stored.QoSEnabled != original.QoSEnabled || stored.QoSUploadMbps != original.QoSUploadMbps ||
		stored.QoSDownloadMbps != original.QoSDownloadMbps || stored.QoSInteractive != original.QoSInteractive {
		t.Errorf("failed apply persisted QoS: got %#v, original %#v", stored, original)
	}
}

func TestQosPutRejectsMalformedAndInvalidPayloadsBeforeApplying(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"enabled":`},
		{name: "negative upload", body: `{"enabled":true,"upload_mbps":-1,"download_mbps":20}`},
		{name: "missing enabled bandwidth", body: `{"enabled":true,"upload_mbps":0,"download_mbps":20}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := &qosHandlerExec{dryRun: true}
			h, _ := newQosHandlerFixture(t, qosLink(), exec)
			req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", strings.NewReader(tc.body)), "id", "wan-1")
			rec := httptest.NewRecorder()
			h.Update(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s; want 400", rec.Code, rec.Body.String())
			}
			if len(exec.events) != 0 {
				t.Errorf("invalid payload applied commands: %v", exec.events)
			}
		})
	}
}

func TestQosPostReturnsBeforeAndAfterMeasurements(t *testing.T) {
	exec := &qosHandlerExec{
		dryRun: true,
		pingOutputs: []string{
			"5 packets transmitted, 5 received, 0% packet loss\nround-trip min/avg/max = 10/20/30 ms\n",
			"5 packets transmitted, 5 received, 0% packet loss\nround-trip min/avg/max = 8/12/18 ms\n",
		},
	}
	link := qosLink()
	link.QoSEnabled = true
	link.QoSUploadMbps = 50
	link.QoSDownloadMbps = 200
	h, _ := newQosHandlerFixture(t, link, exec)

	req := withChiURLParam(httptest.NewRequest(http.MethodPost, "/api/links/wan-1/qos/test", nil), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Test(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST test status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got qos.Comparison
	decodeQosJSON(t, rec, &got)
	want := qos.Comparison{
		Before: qos.Measurement{MinMs: 10, AvgMs: 20, MaxMs: 30, LossPct: 0},
		After:  qos.Measurement{MinMs: 8, AvgMs: 12, MaxMs: 18, LossPct: 0},
	}
	if got != want {
		t.Errorf("comparison = %#v, want %#v", got, want)
	}
	firstPing, secondPing, firstApply := -1, -1, -1
	for i, event := range exec.events {
		if strings.HasPrefix(event, "read:ping") && firstPing == -1 {
			firstPing = i
		} else if strings.HasPrefix(event, "read:ping") && secondPing == -1 {
			secondPing = i
		} else if strings.HasPrefix(event, "write:tc qdisc replace dev wan0 root cake") && firstApply == -1 {
			firstApply = i
		}
	}
	if firstPing == -1 || firstApply <= firstPing || secondPing <= firstApply {
		t.Errorf("expected ping → apply → ping ordering, events = %v", exec.events)
	}
}

func TestLinksUpdatePreservesQoSFields(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateLink(&original); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	body := strings.NewReader(`{"name":"WAN renomeada","interface":"wan0","weight":55,"enabled":true}`)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1", body), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("link PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if stored.QoSEnabled != original.QoSEnabled || stored.QoSUploadMbps != original.QoSUploadMbps ||
		stored.QoSDownloadMbps != original.QoSDownloadMbps || stored.QoSInteractive != original.QoSInteractive {
		t.Errorf("regular link PUT lost QoS fields: got %#v, want %v/%d/%d/%v", stored, original.QoSEnabled, original.QoSUploadMbps, original.QoSDownloadMbps, original.QoSInteractive)
	}
	_ = exec
}

func TestLinksUpdateReconcilesQoSWhenLinkIsDisabled(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	original.QoSEnabled = true
	original.QoSUploadMbps = 50
	original.QoSDownloadMbps = 200
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateLink(&original); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(qos.NewService(exec))
	body := strings.NewReader(`{"name":"Fibra principal","interface":"wan0","weight":70,"enabled":false}`)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1", body), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("link PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	foundDelete := false
	for _, event := range exec.events {
		if strings.HasPrefix(event, "write:tc filter del dev wan0 ingress pref 49152") {
			foundDelete = true
			break
		}
	}
	if !foundDelete {
		t.Errorf("disabling link did not remove stale QoS objects: %v", exec.events)
	}
}
