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
	failWhen    func(string, []string) error
}

func (e *qosHandlerExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	event := "write:" + cmd + " " + strings.Join(args, " ")
	e.events = append(e.events, event)
	if e.onExecute != nil {
		onExecute := e.onExecute
		e.onExecute = nil
		onExecute()
	}
	if e.failWhen != nil {
		if err := e.failWhen(cmd, args); err != nil {
			return "", err
		}
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
	h, db, _ := newQosHandlerServiceFixture(t, link, exec)
	return h, db
}

func newQosHandlerServiceFixture(t *testing.T, link storage.Link, exec *qosHandlerExec) (*handlers.QosHandler, *storage.DB, *qos.Service) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateLink(&link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	service := qos.NewService(exec)
	return handlers.NewQosHandler(service, db), db, service
}

func decodeQosJSON(t *testing.T, rec *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(target); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

func configureManagedQosReads(exec *qosHandlerExec, iface string, _, _ int) {
	ifb := qos.IFBName(iface)
	exec.readOutputs = map[string]string{
		"tc\x00qdisc\x00show\x00dev\x00" + iface:                                   "qdisc cake 1: root bandwidth 50Mbit besteffort dual-srchost\nqdisc clsact ffff: parent ffff:fff1\n",
		"tc\x00qdisc\x00show\x00dev\x00" + ifb:                                     "qdisc cake 1: root bandwidth 200Mbit besteffort dual-dsthost\n",
		"tc\x00filter\x00show\x00dev\x00" + iface + "\x00ingress\x00pref\x0049152": "filter protocol all pref 49152 matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
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
			"tc\x00qdisc\x00show\x00dev\x00wan0":                              "qdisc cake 1: root bandwidth 50Mbit diffserv4 dual-srchost\n",
			"tc\x00qdisc\x00show\x00dev\x00" + ifb:                            "qdisc cake 1: root bandwidth 200Mbit diffserv4 dual-dsthost\n",
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
	if !containsEvent(exec.events, "write:tc qdisc replace dev wan0 root handle 1: cake bandwidth 50mbit diffserv4 dual-srchost") {
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

func TestQosPutRejectsNewerLinkLifecycleAndRestoresWithoutOverwritingIt(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	h, db := newQosHandlerFixture(t, original, exec)
	configureManagedQosReads(exec, original.Interface, original.QoSUploadMbps, original.QoSDownloadMbps)
	exec.onExecute = func() {
		current, err := db.GetLink(original.ID)
		if err != nil {
			t.Fatalf("GetLink during concurrent lifecycle change: %v", err)
		}
		current.Name = "link newer"
		current.Enabled = false
		if err := db.UpdateLink(current); err != nil {
			t.Fatalf("persist concurrent lifecycle change: %v", err)
		}
	}

	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", strings.NewReader(`{"enabled":true,"upload_mbps":75,"download_mbps":200}`)), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("stale QoS PUT status = %d, body = %s; want 409", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after stale QoS PUT: %v", err)
	}
	if stored.Name != "link newer" || stored.Enabled {
		t.Fatalf("newer link lifecycle was overwritten: %+v", stored)
	}
	if stored.QoSEnabled != original.QoSEnabled || stored.QoSUploadMbps != original.QoSUploadMbps ||
		stored.QoSDownloadMbps != original.QoSDownloadMbps || stored.QoSInteractive != original.QoSInteractive {
		t.Fatalf("stale QoS PUT changed newer QoS fields: got %+v, want %+v", stored, original)
	}
	if !containsEventAfter(exec.events, "write:tc qdisc replace dev wan0 root handle 1: cake bandwidth 75mbit", "write:tc filter del dev wan0 ingress pref 49152") {
		t.Fatalf("stale QoS PUT did not restore the prior kernel config: %v", exec.events)
	}
}

func containsEvent(events []string, want string) bool {
	for _, event := range events {
		if event == want {
			return true
		}
	}
	return false
}

func TestQosPutReturns500AndReconcilesWhenCASAndRollbackFail(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	original.QoSEnabled = true
	original.QoSUploadMbps = 50
	original.QoSDownloadMbps = 200
	h, db := newQosHandlerFixture(t, original, exec)
	exec.onExecute = func() {
		if err := db.UpdateLinkQoS(original.ID, original.Interface, true, 60, 200, false); err != nil {
			t.Fatalf("persist concurrent QoS change: %v", err)
		}
	}
	rollbackFailure := true
	exec.failWhen = func(cmd string, args []string) error {
		if rollbackFailure && cmd == "tc" && strings.Contains(strings.Join(args, " "), "bandwidth 50mbit") {
			rollbackFailure = false
			return errors.New("rollback unavailable")
		}
		return nil
	}

	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", strings.NewReader(`{"enabled":true,"upload_mbps":75,"download_mbps":200}`)), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("CAS plus rollback failure status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	if countEventsContaining(exec.events, "bandwidth 50mbit") < 1 || countEventsContaining(exec.events, "bandwidth 60mbit") < 1 {
		t.Fatalf("fresh reconciliation did not load the concurrent persisted QoS after rollback failure: %v", exec.events)
	}
}

func TestQosCompensationReconciliationDetachesFromCanceledRequest(t *testing.T) {
	original := qosLink()
	service := &qosUpdateServiceStub{
		apply: func(_ context.Context, cfg qos.Config) (qos.State, error) {
			return qos.State{Enabled: cfg.Enabled, Interface: cfg.Interface}, nil
		},
		applyCurrentAndPersistErr: qos.ErrCompensationFailed,
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateLink(&original); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	h := handlers.NewQosHandler(service, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1/qos", strings.NewReader(`{"enabled":true,"upload_mbps":75,"download_mbps":200}`)).WithContext(ctx), "id", original.ID)
	rec := httptest.NewRecorder()

	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("compensation failure status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	if service.applyCurrentCtxErr != nil {
		t.Fatalf("emergency reconciliation inherited request cancellation: %v", service.applyCurrentCtxErr)
	}
	if !service.applyCurrentHasDeadline {
		t.Fatal("emergency reconciliation context has no bounded deadline")
	}
}

func containsEventAfter(events []string, first, second string) bool {
	firstIndex := -1
	for i, event := range events {
		if firstIndex == -1 && event == first {
			firstIndex = i
			continue
		}
		if firstIndex != -1 && event == second {
			return true
		}
	}
	return false
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
		} else if strings.HasPrefix(event, "write:tc qdisc replace dev wan0 root handle 1: cake") && firstApply == -1 {
			firstApply = i
		}
	}
	if firstPing == -1 || firstApply <= firstPing || secondPing <= firstApply {
		t.Errorf("expected ping → apply → ping ordering, events = %v", exec.events)
	}
}

func TestQosPostRejectsMovedLinkBeforeFirstPing(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	link := qosLink()
	link.QoSEnabled = true
	link.QoSUploadMbps = 50
	link.QoSDownloadMbps = 200
	h, db, service := newQosHandlerServiceFixture(t, link, exec)

	entered := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- service.WithInterfaceLock(context.Background(), link.Interface, func(qos.InterfaceOperations) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := withChiURLParam(httptest.NewRequest(http.MethodPost, "/api/links/wan-1/qos/test", nil), "id", link.ID)
		rec := httptest.NewRecorder()
		h.Test(rec, req)
		response <- rec
	}()
	current, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink before move: %v", err)
	}
	current.Interface = "wan1"
	if err := db.UpdateLink(current); err != nil {
		t.Fatalf("move link: %v", err)
	}
	close(release)
	if err := <-lockDone; err != nil {
		t.Fatalf("release interface lock: %v", err)
	}
	rec := <-response
	if rec.Code != http.StatusConflict {
		t.Fatalf("moved link POST status = %d, body = %s; want 409", rec.Code, rec.Body.String())
	}
	for _, event := range exec.events {
		if strings.HasPrefix(event, "read:ping") {
			t.Fatalf("moved link was pinged before lifecycle validation: %v", exec.events)
		}
	}
}

func TestQosPostRejectsDeletedLinkBeforeFirstPing(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	link := qosLink()
	link.QoSEnabled = true
	link.QoSUploadMbps = 50
	link.QoSDownloadMbps = 200
	h, db, service := newQosHandlerServiceFixture(t, link, exec)

	entered := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- service.WithInterfaceLock(context.Background(), link.Interface, func(qos.InterfaceOperations) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := withChiURLParam(httptest.NewRequest(http.MethodPost, "/api/links/wan-1/qos/test", nil), "id", link.ID)
		rec := httptest.NewRecorder()
		h.Test(rec, req)
		response <- rec
	}()
	if err := db.DeleteLink(link.ID); err != nil {
		t.Fatalf("delete link: %v", err)
	}
	close(release)
	if err := <-lockDone; err != nil {
		t.Fatalf("release interface lock: %v", err)
	}
	rec := <-response
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleted link POST status = %d, body = %s; want 404", rec.Code, rec.Body.String())
	}
	for _, event := range exec.events {
		if strings.HasPrefix(event, "read:ping") {
			t.Fatalf("deleted link was pinged before lifecycle validation: %v", exec.events)
		}
	}
}

func TestLinksUpdateReturnsConflictWhenLinkMovesBeforeSharedLockCallback(t *testing.T) {
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
	service := &linkLifecycleQosStub{entered: make(chan struct{}), release: make(chan struct{})}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(service)

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1", strings.NewReader(`{"name":"stale","interface":"wan0","weight":70,"enabled":true}`)), "id", original.ID)
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		response <- rec
	}()
	<-service.entered
	current, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink before move: %v", err)
	}
	current.Interface = "wan1"
	if err := db.UpdateLink(current); err != nil {
		t.Fatalf("move link: %v", err)
	}
	close(service.release)
	rec := <-response
	if rec.Code != http.StatusConflict {
		t.Fatalf("moved link PUT status = %d, body = %s; want 409", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after moved PUT: %v", err)
	}
	if stored.Interface != "wan1" || stored.Name == "stale" {
		t.Fatalf("moved link was overwritten by stale PUT: %+v", stored)
	}
}

func TestLinksDeleteReturnsConflictWhenLinkIsDeletedBeforeSharedLockCallback(t *testing.T) {
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
	service := &linkLifecycleQosStub{entered: make(chan struct{}), release: make(chan struct{})}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(service)

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := withChiURLParam(httptest.NewRequest(http.MethodDelete, "/api/links/wan-1", nil), "id", original.ID)
		rec := httptest.NewRecorder()
		h.Delete(rec, req)
		response <- rec
	}()
	<-service.entered
	if err := db.DeleteLink(original.ID); err != nil {
		t.Fatalf("delete link: %v", err)
	}
	close(service.release)
	rec := <-response
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleted link DELETE status = %d, body = %s; want 409", rec.Code, rec.Body.String())
	}
}

type linkLifecycleQosStub struct {
	entered chan struct{}
	release chan struct{}
}

func (s *linkLifecycleQosStub) Apply(context.Context, qos.Config) (qos.State, error) {
	return qos.State{}, nil
}

func (s *linkLifecycleQosStub) ApplyAndPersist(context.Context, qos.Config, qos.Config, func() error) (qos.State, error) {
	return qos.State{}, nil
}

func (s *linkLifecycleQosStub) ApplyCurrent(context.Context, string, func() (qos.Config, error)) (qos.State, error) {
	return qos.State{}, nil
}

func (s *linkLifecycleQosStub) ApplyCurrentAndPersist(context.Context, string, func() (qos.ApplyPlan, error)) (qos.State, error) {
	return qos.State{}, nil
}

func (s *linkLifecycleQosStub) Observe(context.Context, string) (qos.State, error) {
	return qos.State{}, nil
}

func (s *linkLifecycleQosStub) MeasureBeforeAfter(context.Context, qos.Config) (qos.Comparison, error) {
	return qos.Comparison{}, nil
}

func (s *linkLifecycleQosStub) MeasureCurrentBeforeAfter(context.Context, string, func() (qos.Config, error)) (qos.Comparison, error) {
	return qos.Comparison{}, nil
}

func (s *linkLifecycleQosStub) WithInterfaceLock(_ context.Context, _ string, fn func(qos.InterfaceOperations) error) error {
	close(s.entered)
	<-s.release
	return fn(lifecycleQosOperations{})
}

type lifecycleQosOperations struct{}

func (lifecycleQosOperations) Apply(context.Context, qos.Config) (qos.State, error) {
	return qos.State{}, nil
}

func (lifecycleQosOperations) ApplyNetem(context.Context, int, int) error {
	return nil
}

func (lifecycleQosOperations) RestoreAfterNetem(context.Context, qos.Config) (qos.State, error) {
	return qos.State{}, nil
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

func TestLinksSetQosServiceRejectsTypedNil(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	var nilService *qos.Service
	h.SetQosService(nilService)

	req := httptest.NewRequest(http.MethodPost, "/api/links", strings.NewReader(`{"name":"WAN nova","interface":"wan0","weight":10,"enabled":true}`))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("link POST with typed-nil QoS service status = %d, body = %s; want 201", rec.Code, rec.Body.String())
	}
}

func TestLinksUpdateReportsQosCleanupFailureBeforeMutatingRow(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true, executeErr: errors.New("cleanup failed")}
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
	configureManagedQosReads(exec, original.Interface, original.QoSUploadMbps, original.QoSDownloadMbps)
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(qos.NewService(exec))
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1", strings.NewReader(`{"name":"Fibra principal","interface":"wan0","weight":70,"enabled":false}`)), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("link PUT status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after failed cleanup: %v", err)
	}
	if !stored.Enabled || !stored.QoSEnabled {
		t.Fatalf("link row changed despite failed QoS cleanup: %+v", stored)
	}
}

func TestLinksUpdateReturns500AndReconcilesWhenCleanupRestoreFails(t *testing.T) {
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
	configureManagedQosReads(exec, original.Interface, original.QoSUploadMbps, original.QoSDownloadMbps)
	rollbackFailure := true
	exec.failWhen = func(cmd string, args []string) error {
		if rollbackFailure && cmd == "tc" && strings.Contains(strings.Join(args, " "), "bandwidth 50mbit") {
			rollbackFailure = false
			return errors.New("rollback unavailable")
		}
		return nil
	}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(qos.NewService(exec))
	req := withChiURLParam(httptest.NewRequest(http.MethodPut, "/api/links/wan-1", strings.NewReader(`{"name":"WAN","interface":"wan bad","weight":70,"enabled":false}`)), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("link PUT cleanup plus restore failure status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	if countEventsContaining(exec.events, "bandwidth 50mbit") < 2 {
		t.Fatalf("fresh reconciliation did not retry old QoS after cleanup restore failure: %v", exec.events)
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after cleanup restore failure: %v", err)
	}
	if stored.Interface != original.Interface || stored.Enabled != original.Enabled {
		t.Fatalf("link row changed after failed update compensation: %+v", stored)
	}
}

func TestLinksDeleteKeepsRetryableRowWhenQosCleanupFails(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true, executeErr: errors.New("cleanup failed")}
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
	configureManagedQosReads(exec, original.Interface, original.QoSUploadMbps, original.QoSDownloadMbps)
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(qos.NewService(exec))
	req := withChiURLParam(httptest.NewRequest(http.MethodDelete, "/api/links/wan-1", nil), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("link DELETE status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	stored, err := db.GetLink(original.ID)
	if err != nil {
		t.Fatalf("GetLink after failed delete cleanup: %v", err)
	}
	if stored == nil {
		t.Fatal("link row was deleted despite failed QoS cleanup; retry would be impossible")
	}
}

func TestLinksDeleteReturns500AndAttemptsFreshReconciliationWhenCleanupRestoreFails(t *testing.T) {
	exec := &qosHandlerExec{dryRun: true}
	original := qosLink()
	original.QoSEnabled = true
	original.QoSUploadMbps = 50
	original.QoSDownloadMbps = 200
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.CreateLink(&original); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	ifb := qos.IFBName(original.Interface)
	exec.readOutputs = map[string]string{
		"tc\x00qdisc\x00show\x00dev\x00" + original.Interface:                                   "qdisc cake 1: root bandwidth 50Mbit besteffort dual-srchost\n",
		"tc\x00qdisc\x00show\x00dev\x00" + ifb:                                                  "qdisc cake 1: root bandwidth 200Mbit besteffort dual-dsthost\n",
		"tc\x00filter\x00show\x00dev\x00" + original.Interface + "\x00ingress\x00pref\x0049152": "filter protocol all pref 49152 matchall\n\taction order 1: mirred (Egress Redirect to device " + ifb + ")\n",
	}
	closed := false
	exec.onExecute = func() {
		if !closed {
			closed = true
			_ = db.Close()
		}
	}
	rollbackFailure := true
	exec.failWhen = func(cmd string, args []string) error {
		if rollbackFailure && cmd == "tc" && strings.Contains(strings.Join(args, " "), "bandwidth 50mbit") {
			rollbackFailure = false
			return errors.New("rollback unavailable")
		}
		return nil
	}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetQosService(qos.NewService(exec))
	req := withChiURLParam(httptest.NewRequest(http.MethodDelete, "/api/links/wan-1", nil), "id", original.ID)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("link DELETE cleanup plus restore failure status = %d, body = %s; want 500", rec.Code, rec.Body.String())
	}
	if countEventsContaining(exec.events, "bandwidth 50mbit") < 1 {
		t.Fatalf("link DELETE did not attempt QoS restore after persistence failure: %v", exec.events)
	}
}

func countEventsContaining(events []string, want string) int {
	count := 0
	for _, event := range events {
		if strings.Contains(event, want) {
			count++
		}
	}
	return count
}

func TestQosPutPreservesConcurrentUnrelatedLinkFieldsWithoutSpuriousConflict(t *testing.T) {
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
		t.Fatalf("QoS PUT status = %d, body = %s; want 200 for unrelated concurrent link change", rec.Code, rec.Body.String())
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
	apply                     func(context.Context, qos.Config) (qos.State, error)
	applyCurrentAndPersistErr error
	applyCurrentCtxErr        error
	applyCurrentHasDeadline   bool
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

func (s *qosUpdateServiceStub) ApplyCurrent(ctx context.Context, _ string, load func() (qos.Config, error)) (qos.State, error) {
	s.applyCurrentCtxErr = ctx.Err()
	_, s.applyCurrentHasDeadline = ctx.Deadline()
	cfg, err := load()
	if err != nil {
		return qos.State{}, err
	}
	return s.apply(ctx, cfg)
}

func (s *qosUpdateServiceStub) ApplyCurrentAndPersist(ctx context.Context, _ string, load func() (qos.ApplyPlan, error)) (qos.State, error) {
	if s.applyCurrentAndPersistErr != nil {
		return qos.State{}, s.applyCurrentAndPersistErr
	}
	plan, err := load()
	if err != nil {
		return qos.State{}, err
	}
	state, err := s.apply(ctx, plan.Config)
	if err != nil {
		return qos.State{}, err
	}
	if err := plan.Persist(); err != nil {
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

func (s *qosUpdateServiceStub) MeasureCurrentBeforeAfter(ctx context.Context, _ string, load func() (qos.Config, error)) (qos.Comparison, error) {
	cfg, err := load()
	if err != nil {
		return qos.Comparison{}, err
	}
	return s.MeasureBeforeAfter(ctx, cfg)
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
	configureManagedQosReads(exec, original.Interface, original.QoSUploadMbps, original.QoSDownloadMbps)
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
