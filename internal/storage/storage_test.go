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
