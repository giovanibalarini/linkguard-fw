package storage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ─── Links ─────────────────────────────────────────────────────────────────

func TestCreateAndGetLink(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{
		Name:         "WAN1",
		Interface:    "eth0",
		IPAddress:    "192.168.1.1",
		Gateway:      "192.168.1.254",
		Weight:       100,
		DNSTest:      "8.8.8.8",
		MonitorHosts: "1.1.1.1",
		TableID:      100,
		Enabled:      true,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if l.ID == "" {
		t.Error("expected ID to be set after create")
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got == nil {
		t.Fatal("expected link, got nil")
	}
	if got.Name != "WAN1" {
		t.Errorf("expected Name=WAN1, got %s", got.Name)
	}
	if got.Interface != "eth0" {
		t.Errorf("expected Interface=eth0, got %s", got.Interface)
	}
	if got.TableID != 100 {
		t.Errorf("expected TableID=100, got %d", got.TableID)
	}
}

func TestListLinks(t *testing.T) {
	db := newTestDB(t)

	for i, name := range []string{"WAN1", "WAN2", "WAN3"} {
		l := &storage.Link{
			Name:      name,
			Interface: "eth" + string(rune('0'+i)),
			Gateway:   "10.0.0.254",
			Enabled:   true,
		}
		if err := db.CreateLink(l); err != nil {
			t.Fatalf("CreateLink %s: %v", name, err)
		}
	}

	links, err := db.GetLinks()
	if err != nil {
		t.Fatalf("GetLinks: %v", err)
	}
	if len(links) != 3 {
		t.Errorf("expected 3 links, got %d", len(links))
	}
}

func TestUpdateLink(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	l.Name = "WAN1-updated"
	l.Weight = 200
	if err := db.UpdateLink(l); err != nil {
		t.Fatalf("UpdateLink: %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.Name != "WAN1-updated" {
		t.Errorf("expected Name=WAN1-updated, got %s", got.Name)
	}
	if got.Weight != 200 {
		t.Errorf("expected Weight=200, got %d", got.Weight)
	}
}

func TestUpdateLinkStatus(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	now := time.Now()
	l.Status = "online"
	l.LatencyMs = 12.5
	l.PacketLoss = 0.0
	l.LastCheck = &now
	if err := db.UpdateLink(l); err != nil {
		t.Fatalf("UpdateLink (status): %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.Status != "online" {
		t.Errorf("expected status=online, got %s", got.Status)
	}
	if got.LatencyMs != 12.5 {
		t.Errorf("expected LatencyMs=12.5, got %f", got.LatencyMs)
	}
}

func TestDeleteLink(t *testing.T) {
	db := newTestDB(t)

	l := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", Enabled: true}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if err := db.DeleteLink(l.ID); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got != nil {
		t.Error("expected nil link after delete")
	}
}

func TestLinkTableIDUnique(t *testing.T) {
	db := newTestDB(t)

	l1 := &storage.Link{Name: "WAN1", Interface: "eth0", Gateway: "10.0.0.1", TableID: 100, Enabled: true}
	l2 := &storage.Link{Name: "WAN2", Interface: "eth1", Gateway: "10.0.1.1", TableID: 101, Enabled: true}

	if err := db.CreateLink(l1); err != nil {
		t.Fatalf("CreateLink l1: %v", err)
	}
	if err := db.CreateLink(l2); err != nil {
		t.Fatalf("CreateLink l2: %v", err)
	}
	if l1.TableID == l2.TableID {
		t.Errorf("expected unique TableIDs, both got %d", l1.TableID)
	}
}

// ─── Alerts ──────────────────────────────────────────────────────────────────

func TestCreateAndGetAlerts(t *testing.T) {
	db := newTestDB(t)

	a := &storage.Alert{
		Type:     "link_offline",
		Severity: "critical",
		Title:    "WAN1 offline",
		Message:  "WAN1 link is down",
	}
	if err := db.CreateAlert(a); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	if a.ID == "" {
		t.Error("expected ID to be set")
	}

	alerts, err := db.GetAlerts(false, 10)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Type != "link_offline" {
		t.Errorf("expected type=link_offline, got %s", alerts[0].Type)
	}
}

func TestResolveAlert(t *testing.T) {
	db := newTestDB(t)

	a := &storage.Alert{Type: "link_offline", Severity: "critical", Title: "test"}
	if err := db.CreateAlert(a); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	if err := db.ResolveAlert(a.ID); err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}

	// Unresolved-only query should return 0
	alerts, err := db.GetAlerts(true, 10)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 unresolved alerts, got %d", len(alerts))
	}

	// All alerts query should still return 1
	all, err := db.GetAlerts(false, 10)
	if err != nil {
		t.Fatalf("GetAlerts all: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 total alert, got %d", len(all))
	}
	if !all[0].Resolved {
		t.Error("expected alert to be resolved")
	}
}

func TestGetAlertsEmpty(t *testing.T) {
	db := newTestDB(t)

	alerts, err := db.GetAlerts(false, 10)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	// Should return empty slice, not nil
	if alerts == nil {
		t.Error("expected empty slice, got nil")
	}
}

// ─── Default Admin ───────────────────────────────────────────────────────────

func TestDefaultAdminExists(t *testing.T) {
	db := newTestDB(t)

	user, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user == nil {
		t.Fatal("expected default admin user to exist")
	}
	if user.Username != "admin" {
		t.Errorf("expected username=admin, got %s", user.Username)
	}
	if user.Role != "admin" {
		t.Errorf("expected role=admin, got %s", user.Role)
	}
}

// ─── Audit Log ───────────────────────────────────────────────────────────────

func TestCreateAuditLog(t *testing.T) {
	db := newTestDB(t)

	log := &storage.AuditLog{
		User:     "admin",
		Action:   "create_link",
		Resource: "link",
		Details:  `{"name":"WAN1"}`,
		IP:       "127.0.0.1",
	}
	if err := db.CreateAuditLog(log); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}
	if log.ID == "" {
		t.Error("expected ID to be set")
	}

	logs, err := db.GetAuditLogs(10)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Action != "create_link" {
		t.Errorf("expected action=create_link, got %s", logs[0].Action)
	}
}

// ─── Settings ────────────────────────────────────────────────────────────────

func TestGetSetSetting(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetSetting("test_key", "test_value"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	val, err := db.GetSetting("test_key")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "test_value" {
		t.Errorf("expected test_value, got %s", val)
	}
}

func TestGetMissingSetting(t *testing.T) {
	db := newTestDB(t)

	val, err := db.GetSetting("nonexistent_key")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "" {
		t.Errorf("expected empty string for missing key, got %s", val)
	}
}

// ─── Traffic samples ────────────────────────────────────────────────────────

func TestTrafficSamplesUpsertAndQuery(t *testing.T) {
	db := newTestDB(t)

	s := storage.TrafficSample{
		Interface:   "eth0",
		StepSeconds: 60,
		Timestamp:   time.Now().Unix(),
		RxBps:       123.4,
		TxBps:       432.1,
	}
	if err := db.UpsertTrafficSample(s); err != nil {
		t.Fatalf("UpsertTrafficSample insert: %v", err)
	}

	// Upsert same key updates values.
	s.RxBps = 555.0
	if err := db.UpsertTrafficSample(s); err != nil {
		t.Fatalf("UpsertTrafficSample update: %v", err)
	}

	got, err := db.GetTrafficSamples("eth0", 60, s.Timestamp-1, s.Timestamp+1)
	if err != nil {
		t.Fatalf("GetTrafficSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(got))
	}
	if got[0].RxBps != 555.0 {
		t.Fatalf("expected updated rx=555.0, got %f", got[0].RxBps)
	}
}

func TestTrafficSamplesPrune(t *testing.T) {
	db := newTestDB(t)

	now := time.Now().Unix()
	_ = db.UpsertTrafficSample(storage.TrafficSample{Interface: "eth1", StepSeconds: 60, Timestamp: now - 3600, RxBps: 10, TxBps: 20})
	_ = db.UpsertTrafficSample(storage.TrafficSample{Interface: "eth1", StepSeconds: 60, Timestamp: now - 60, RxBps: 30, TxBps: 40})

	if err := db.PruneTrafficSamples(60, now-600); err != nil {
		t.Fatalf("PruneTrafficSamples: %v", err)
	}

	got, err := db.GetTrafficSamples("eth1", 60, now-7200, now)
	if err != nil {
		t.Fatalf("GetTrafficSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 remaining sample, got %d", len(got))
	}
}

// ─── Settings export ──────────────────────────────────────────────────────

func TestExportSettingsExcludesSecrets(t *testing.T) {
	db := newTestDB(t)

	plain := map[string]string{
		"monitoring":                `{"enabled":true}`,
		"routing_balance":           `{"mode":"failover"}`,
		"traffic_retention_profile": `{"profile":"30d"}`,
	}
	secret := map[string]string{
		"github_update_token": "ghp_supersecret",
		"notifications":       `{"webhook":{"url":"https://x"},"email":{"password":"hunter2"}}`,
		"totp_user-123":       `{"secret":"JBSWY3DPEHPK3PXP","enabled":true}`,
		"totp_user-456":       `{"secret":"ANOTHERSECRET","enabled":true}`,
	}
	for k, v := range plain {
		if err := db.SetSetting(k, v); err != nil {
			t.Fatalf("SetSetting(%s): %v", k, err)
		}
	}
	for k, v := range secret {
		if err := db.SetSetting(k, v); err != nil {
			t.Fatalf("SetSetting(%s): %v", k, err)
		}
	}

	out, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}

	for k := range secret {
		if _, present := out[k]; present {
			t.Fatalf("ExportSettings leaked secret key %q", k)
		}
	}
	for k, v := range plain {
		if out[k] != v {
			t.Fatalf("ExportSettings dropped or altered plain key %q: got %q, want %q", k, out[k], v)
		}
	}
	if len(out) != len(plain) {
		t.Fatalf("expected %d exported keys, got %d: %v", len(plain), len(out), out)
	}
}

// ─── Metric samples and state intervals ──────────────────────────────────────

func TestMetricSamplesAndStateIntervalsTablesExist(t *testing.T) {
	db := newTestDB(t)

	_, err := db.Conn().Exec(`INSERT INTO metric_samples
		(series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"link.latency_ms", "WAN VIVO", 10, 1000, 10.0, 15.0, 20.0)
	if err != nil {
		t.Fatalf("insert metric_samples: %v", err)
	}

	_, err = db.Conn().Exec(`INSERT INTO state_intervals
		(kind, label, state, started_at, ended_at) VALUES (?, ?, ?, ?, ?)`,
		"link", "WAN SUMICITY", "degraded", 1000, nil)
	if err != nil {
		t.Fatalf("insert state_intervals: %v", err)
	}
}

func TestUpsertAndGetMetricSamples(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 10,
		TsUnix: 1000, VMin: 10, VAvg: 15, VMax: 20,
	}); err != nil {
		t.Fatalf("UpsertMetricSample: %v", err)
	}
	// Overwrite same bucket — should update, not duplicate.
	if err := db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 10,
		TsUnix: 1000, VMin: 5, VAvg: 12, VMax: 25,
	}); err != nil {
		t.Fatalf("UpsertMetricSample overwrite: %v", err)
	}

	got, err := db.GetMetricSamples("link.latency_ms", "WAN VIVO", 10, 0, 2000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 sample after overwrite, got %d", len(got))
	}
	if got[0].VMin != 5 || got[0].VMax != 25 {
		t.Fatalf("expected overwritten min=5 max=25, got min=%v max=%v", got[0].VMin, got[0].VMax)
	}
}

func TestPruneMetricSamples(t *testing.T) {
	db := newTestDB(t)

	_ = db.UpsertMetricSample(storage.MetricSample{Series: "s", Label: "l", StepSeconds: 60, TsUnix: 100, VMin: 1, VAvg: 1, VMax: 1})
	_ = db.UpsertMetricSample(storage.MetricSample{Series: "s", Label: "l", StepSeconds: 60, TsUnix: 9000, VMin: 1, VAvg: 1, VMax: 1})

	if err := db.PruneMetricSamples(60, 5000); err != nil {
		t.Fatalf("PruneMetricSamples: %v", err)
	}

	got, err := db.GetMetricSamples("s", "l", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples: %v", err)
	}
	if len(got) != 1 || got[0].TsUnix != 9000 {
		t.Fatalf("expected only the newer sample to remain, got %v", got)
	}
}

func TestStateIntervalOpenAndClose(t *testing.T) {
	db := newTestDB(t)

	if err := db.OpenStateInterval("link", "WAN SUMICITY", "degraded", 1000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}

	got, err := db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 || got[0].EndedAt != nil {
		t.Fatalf("expected 1 open interval, got %v", got)
	}

	if err := db.CloseOpenStateInterval("link", "WAN SUMICITY", 1008); err != nil {
		t.Fatalf("CloseOpenStateInterval: %v", err)
	}

	got, err = db.GetStateIntervals("link", "WAN SUMICITY", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 1 || got[0].EndedAt == nil || *got[0].EndedAt != 1008 {
		t.Fatalf("expected interval closed at 1008, got %v", got)
	}
}

func TestStateIntervalsDoNotOverlap(t *testing.T) {
	db := newTestDB(t)

	_ = db.OpenStateInterval("link", "WAN VIVO", "online", 1000)
	_ = db.CloseOpenStateInterval("link", "WAN VIVO", 1010)
	_ = db.OpenStateInterval("link", "WAN VIVO", "degraded", 1010)
	_ = db.CloseOpenStateInterval("link", "WAN VIVO", 1020)
	_ = db.OpenStateInterval("link", "WAN VIVO", "online", 1020)

	got, err := db.GetStateIntervals("link", "WAN VIVO", 0, 5000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 intervals, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		prevEnd := got[i-1].EndedAt
		if prevEnd == nil {
			t.Fatalf("interval %d has no end but is followed by another interval", i-1)
		}
		if *prevEnd != got[i].StartedAt {
			t.Fatalf("gap or overlap between interval %d (ends %d) and %d (starts %d)", i-1, *prevEnd, i, got[i].StartedAt)
		}
	}
	if got[2].EndedAt != nil {
		t.Fatalf("expected the last interval to still be open, got ended_at=%v", *got[2].EndedAt)
	}
}

func TestGetStateIntervalsIncludesOpenIntervalStartedBeforeWindow(t *testing.T) {
	db := newTestDB(t)

	// Open an interval at timestamp 1000
	if err := db.OpenStateInterval("link", "WAN SUMMER", "degraded", 1000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}

	// Query with fromUnix=1500 and toUnix=2000, which is AFTER the interval started
	// The interval started at 1000 but is still open, so it should be included
	got, err := db.GetStateIntervals("link", "WAN SUMMER", 1500, 2000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}

	// Assert the open interval that started before the query window is included
	if len(got) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(got))
	}
	if got[0].StartedAt != 1000 {
		t.Errorf("expected interval to have started_at=1000, got %d", got[0].StartedAt)
	}
	if got[0].EndedAt != nil {
		t.Errorf("expected interval to still be open, got ended_at=%v", got[0].EndedAt)
	}
	if got[0].State != "degraded" {
		t.Errorf("expected interval state=degraded, got %s", got[0].State)
	}
}

func TestGetAllOpenStateIntervals(t *testing.T) {
	db := newTestDB(t)

	// Two open intervals for different (kind,label) keys, plus one closed
	// interval that must NOT be returned.
	if err := db.OpenStateInterval("link", "WAN VIVO", "degraded", 1000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	if err := db.OpenStateInterval("service", "unbound", "up", 2000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	if err := db.OpenStateInterval("link", "WAN SUMICITY", "online", 3000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	if err := db.CloseOpenStateInterval("link", "WAN SUMICITY", 3100); err != nil {
		t.Fatalf("CloseOpenStateInterval: %v", err)
	}

	got, err := db.GetAllOpenStateIntervals()
	if err != nil {
		t.Fatalf("GetAllOpenStateIntervals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 open intervals (closed one excluded), got %d: %+v", len(got), got)
	}
	byLabel := map[string]storage.StateInterval{}
	for _, si := range got {
		if si.EndedAt != nil {
			t.Fatalf("expected EndedAt nil for an open interval, got %+v", si)
		}
		byLabel[si.Label] = si
	}
	if si, ok := byLabel["WAN VIVO"]; !ok || si.Kind != "link" || si.State != "degraded" || si.StartedAt != 1000 {
		t.Fatalf("expected open link/WAN VIVO/degraded@1000, got %+v (present=%v)", si, ok)
	}
	if si, ok := byLabel["unbound"]; !ok || si.Kind != "service" || si.State != "up" || si.StartedAt != 2000 {
		t.Fatalf("expected open service/unbound/up@2000, got %+v (present=%v)", si, ok)
	}
}

func TestPruneStateIntervals(t *testing.T) {
	db := newTestDB(t)

	// Old, closed interval — must be pruned.
	if err := db.OpenStateInterval("link", "WAN VIVO", "degraded", 100); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	if err := db.CloseOpenStateInterval("link", "WAN VIVO", 200); err != nil {
		t.Fatalf("CloseOpenStateInterval: %v", err)
	}
	// Old, still-open interval — must survive pruning no matter how old.
	if err := db.OpenStateInterval("service", "unbound", "up", 50); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	// Recent, closed interval — must survive (not old enough to prune).
	if err := db.OpenStateInterval("link", "WAN SUMICITY", "online", 9000); err != nil {
		t.Fatalf("OpenStateInterval: %v", err)
	}
	if err := db.CloseOpenStateInterval("link", "WAN SUMICITY", 9100); err != nil {
		t.Fatalf("CloseOpenStateInterval: %v", err)
	}

	if err := db.PruneStateIntervals(5000); err != nil {
		t.Fatalf("PruneStateIntervals: %v", err)
	}

	got, err := db.GetAllOpenStateIntervals()
	if err != nil {
		t.Fatalf("GetAllOpenStateIntervals: %v", err)
	}
	if len(got) != 1 || got[0].Label != "unbound" {
		t.Fatalf("expected the old open interval to survive pruning, got %+v", got)
	}

	closedRecent, err := db.GetStateIntervals("link", "WAN SUMICITY", 0, 100000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(closedRecent) != 1 {
		t.Fatalf("expected the recent closed interval to survive, got %+v", closedRecent)
	}

	closedOld, err := db.GetStateIntervals("link", "WAN VIVO", 0, 100000)
	if err != nil {
		t.Fatalf("GetStateIntervals: %v", err)
	}
	if len(closedOld) != 0 {
		t.Fatalf("expected the old closed interval to be pruned, got %+v", closedOld)
	}
}

// ─── Migration: traffic_samples → metric_samples ────────────────────────────

func TestMigrateTrafficSamplesToMetricSamples(t *testing.T) {
	db := newTestDB(t)

	// Simulate a pre-migration row the way the old trafficrrd wrote it.
	_, err := db.Conn().Exec(`INSERT INTO traffic_samples
		(interface, step_seconds, ts_unix, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?)`,
		"eth0", 60, 5000, 1234.5, 6789.0)
	if err != nil {
		t.Fatalf("seed traffic_samples: %v", err)
	}

	if err := db.MigrateTrafficSamplesToMetricSamplesForTest(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rx, err := db.GetMetricSamples("if.rx_bps", "eth0", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples rx: %v", err)
	}
	if len(rx) != 1 || rx[0].VAvg != 1234.5 || rx[0].VMin != 1234.5 || rx[0].VMax != 1234.5 {
		t.Fatalf("expected 1 rx sample with min=avg=max=1234.5, got %v", rx)
	}

	tx, err := db.GetMetricSamples("if.tx_bps", "eth0", 60, 0, 100000)
	if err != nil {
		t.Fatalf("GetMetricSamples tx: %v", err)
	}
	if len(tx) != 1 || tx[0].VAvg != 6789.0 {
		t.Fatalf("expected 1 tx sample avg=6789.0, got %v", tx)
	}

	// Idempotent: running twice must not duplicate or error.
	if err := db.MigrateTrafficSamplesToMetricSamplesForTest(); err != nil {
		t.Fatalf("second migrate call: %v", err)
	}
	rx2, _ := db.GetMetricSamples("if.rx_bps", "eth0", 60, 0, 100000)
	if len(rx2) != 1 {
		t.Fatalf("expected migration to stay idempotent, got %d rx samples", len(rx2))
	}
}
