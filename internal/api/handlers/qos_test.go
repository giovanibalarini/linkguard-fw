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
	readOutputs map[string]string
	events      []string
	onExecute   func()
}

func (e *qosHandlerExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	event := "write:" + cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if e.onExecute != nil {
		onExecute := e.onExecute
		e.onExecute = nil
		onExecute()
	}
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
	if out, ok := e.readOutputs[strings.Join(append([]string{cmd}, args...), "\x00")]; ok {
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
	ifb := qos.IFBName("wan0")
	exec := &qosHandlerExec{
		dryRun: true,
		readOutputs: map[string]string{
			"ip\x00link\x00show\x00dev\x00" + ifb:                             "7: " + ifb + ": <BROADCAST,UP> mtu 1500",
			"tc\x00qdisc\x00show\x00dev\x00wan0":                              "qdisc cake 8001: root bandwidth 50Mbit diffserv4 dual-srchost\n",
			"tc\x00qdisc\x00show\x00dev\x00" + ifb:                            "qdisc cake 8002: root bandwidth 200Mbit diffserv4 dual-dsthost\n",
			"tc\x00filter\x00show\x00dev\x00wan0\x00ingress\x00pref\x0049152": "filter protocol all pref 49152 matchall action mirred egress redirect to device " + ifb,
		},
	}
	h, _ := newQosHandlerFixture(t, qosLink(), exec)

	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/links/wan-1/qos", nil), "id", "wan-1")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Desired  qos.Config `json:"desired"`
		Observed qos.State  `json:"observed"`
	}
	decodeQosJSON(t, rec, &got)
	wantDesired := qos.Config{Interface: "wan0", Enabled: false, UploadMbps: 12, DownloadMbps: 80, Interactive: true}
	wantObserved := qos.State{Enabled: true, Interface: "wan0", IFB: ifb, Mode: "diffserv4", DryRun: true}
	if got.Desired != wantDesired || got.Observed != wantObserved {
		t.Errorf("GET response = %#v, want desired=%#v observed=%#v", got, wantDesired, wantObserved)
	}
	for _, event := range exec.events {
		if strings.HasPrefix(event, "write:") {
			t.Errorf("GET issued a kernel write: %v", exec.events)
		}
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

func TestQosPutRestoresOldKernelConfigWhenPersistenceFails(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	original.QoSEnabled = true
	original.QoSUploadMbps = 50
	original.QoSDownloadMbps = 200
	h, db := newQosHandlerFixture(t, original, exec)
	exec.onExecute = func() { _ = db.Close() }

	body := strings.NewReader(`{"enabled":true,"upload_mbps":75,"download_mbps":200,"interactive":true}`)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", body), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	newApply, oldRestore := -1, -1
	for i, event := range exec.events {
		if strings.Contains(event, "bandwidth 75mbit") && newApply == -1 {
			newApply = i
		}
		if strings.Contains(event, "bandwidth 50mbit") && oldRestore == -1 {
			oldRestore = i
		}
	}
	if newApply == -1 || oldRestore <= newApply {
		t.Fatalf("persistence failure did not restore the old kernel configuration: %v", exec.events)
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

func TestLinksCreateIgnoresQoSFieldsFromGenericPayload(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	body := strings.NewReader(`{"name":"WAN nova","interface":"wan0","weight":10,"enabled":true,"qos_enabled":true,"qos_upload_mbps":50,"qos_download_mbps":200,"qos_interactive":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/links", body)
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("link POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got storage.Link
	decodeQosJSON(t, rec, &got)
	stored, err := db.GetLink(got.ID)
	if err != nil {
		t.Fatalf("GetLink created link: %v", err)
	}
	if stored.QoSEnabled || stored.QoSUploadMbps != 0 || stored.QoSDownloadMbps != 0 || stored.QoSInteractive {
		t.Fatalf("generic link create persisted QoS fields: %#v", stored)
	}
}

func TestQosPutDoesNotOverwriteConcurrentLinkFields(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	original := qosLink()
	if err := db.CreateLink(&original); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	service := &qosUpdateServiceStub{apply: func(_ context.Context, _ qos.Config) (qos.State, error) {
		current, err := db.GetLink(original.ID)
		if err != nil {
			return qos.State{}, err
		}
		current.Name = "alterado concorrentemente"
		if err := db.UpdateLink(current); err != nil {
			return qos.State{}, err
		}
		return qos.State{Enabled: true, Interface: original.Interface, IFB: qos.IFBName(original.Interface), Mode: "besteffort"}, nil
	}}
	h := handlers.NewQosHandler(service, db)
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", strings.NewReader(`{"enabled":true,"upload_mbps":50,"download_mbps":200}`)), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("QoS PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after concurrent update: %v", err)
	}
	if stored.Name != "alterado concorrentemente" {
		t.Fatalf("QoS PUT overwrote a concurrent link field: got name %q", stored.Name)
	}
}

type qosUpdateServiceStub struct {
	apply func(context.Context, qos.Config) (qos.State, error)
}

func (s *qosUpdateServiceStub) Apply(ctx context.Context, cfg qos.Config) (qos.State, error) {
	return s.apply(ctx, cfg)
}

func (s *qosUpdateServiceStub) ApplyAndPersist(ctx context.Context, cfg, _ qos.Config, persist func() error) (qos.State, error) {
	state, err := s.apply(ctx, cfg)
	if err != nil {
		return qos.State{}, err
	}
	if err := persist(); err != nil {
		return qos.State{}, err
	}
	return state, nil
}

func (*qosUpdateServiceStub) Observe(context.Context, string) (qos.State, error) {
	return qos.State{}, nil
}

func (*qosUpdateServiceStub) MeasureBeforeAfter(context.Context, qos.Config) (qos.Comparison, error) {
	return qos.Comparison{}, nil
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
