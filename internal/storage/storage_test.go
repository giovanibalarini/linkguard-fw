package storage_test

import (
	"database/sql"
	"github.com/giovanibalarini/linkguard-fw/internal/dashboard"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

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

// O schema NÃO cria mais o administrador. Até a v1.0.82 a migração trazia um
// INSERT com o hash bcrypt fixo de "admin", e toda instalação nascia com
// admin/admin. Agora a conta é criada por SeedInitialAdmin, com uma senha que
// quem chama gera — e o teste guarda essa fronteira: um banco recém-migrado tem
// ZERO usuários.
func TestMigrationDoesNotSeedAnyUser(t *testing.T) {
	db := newTestDB(t)

	user, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user != nil {
		t.Fatal("a migração criou um usuário — se o hash voltar a ser constante, toda instalação nasce com a mesma senha")
	}
}

func TestSeedInitialAdminCreatesTheAccountOnceWithTheGivenHash(t *testing.T) {
	db := newTestDB(t)

	const hash = "$2a$10$hashgeradopelochamadorhashgeradopelochamadorxxxxxx"
	created, err := db.SeedInitialAdmin(hash)
	if err != nil {
		t.Fatalf("SeedInitialAdmin: %v", err)
	}
	if !created {
		t.Fatal("a primeira chamada deveria criar a conta")
	}

	user, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user == nil {
		t.Fatal("a conta administrativa não foi criada")
	}
	if user.Password != hash {
		t.Errorf("a senha gravada não é a que o chamador passou: %q", user.Password)
	}
	if user.Role != "admin" {
		t.Errorf("expected role=admin, got %s", user.Role)
	}

	// Segunda chamada: não recria, e sobretudo NÃO sobrescreve a senha que o
	// operador já trocou. Um seed que reescrevesse a cada boot devolveria a
	// máquina para a senha de fábrica sem ninguém pedir.
	created, err = db.SeedInitialAdmin("$2a$10$outrohashqualquerqueprecisaserignoradoxxxxxxxxxxxxx")
	if err != nil {
		t.Fatalf("segunda SeedInitialAdmin: %v", err)
	}
	if created {
		t.Fatal("a segunda chamada disse que criou a conta de novo")
	}
	user, err = db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user.Password != hash {
		t.Fatal("o seed sobrescreveu a senha existente — um reboot devolveria a máquina para a senha de fábrica")
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

// TestMigrateTrafficSamplesToMetricSamplesAtProductionScale is a regression
// test for a real incident (2026-07-24): a production box with months of
// retained history had 105,755 legacy rows. The migration upserted each one
// via its own db.conn.Exec call -- an implicit auto-commit transaction per
// row -- which under WAL mode meant one fsync per row. That turned a
// first-boot migration expected to take seconds into one still not finished
// after 50+ minutes, blocking storage.Open() (and therefore the secrets
// vault, the HTTP server, and the link monitor -- WAN failover detection was
// never running) for the whole time, forcing an emergency rollback. The fix
// wraps every upsert plus the rename in a single transaction. This test
// seeds a comparable row count and asserts the migration completes well
// within a healthy boot budget, not just that it eventually finishes.
func TestMigrateTrafficSamplesToMetricSamplesAtProductionScale(t *testing.T) {
	db := newTestDB(t)

	const rowCount = 110_000
	tx, err := db.Conn().Begin()
	if err != nil {
		t.Fatalf("begin seed tx: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO traffic_samples
		(interface, step_seconds, ts_unix, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatalf("prepare seed stmt: %v", err)
	}
	for i := 0; i < rowCount; i++ {
		if _, err := stmt.Exec("eth0", 60, int64(i), float64(i), float64(i)*2); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed tx: %v", err)
	}

	start := time.Now()
	if err := db.MigrateTrafficSamplesToMetricSamplesForTest(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	elapsed := time.Since(start)

	// Generous ceiling (a healthy single-transaction migration of this size
	// should take well under a second on any real hardware) -- this is here
	// to catch a regression back to per-row commits, not to be a tight
	// performance benchmark. The race detector's instrumentation overhead
	// alone can approach a minute for 220k statement executions, unrelated
	// to whether the migration is actually batched, so it gets a wider
	// budget -- still far below what an unbatched, one-fsync-per-row version
	// would take even under that same instrumentation.
	budget := 10 * time.Second
	if raceDetectorEnabled {
		budget = 90 * time.Second
	}
	if elapsed > budget {
		t.Fatalf("migration of %d legacy rows took %v, want under %v -- likely regressed back to one commit per row",
			rowCount, elapsed, budget)
	}
	t.Logf("migrated %d legacy rows in %v", rowCount, elapsed)

	rx, err := db.GetMetricSamples("if.rx_bps", "eth0", 60, 0, int64(rowCount))
	if err != nil {
		t.Fatalf("GetMetricSamples rx: %v", err)
	}
	if len(rx) != rowCount {
		t.Fatalf("expected %d rx samples migrated, got %d", rowCount, len(rx))
	}
}

// ─── Secrets ──────────────────────────────────────────────────────────────

func TestSecretsTableExists(t *testing.T) {
	db := newTestDB(t)

	_, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at)
		VALUES (?, ?, ?, ?)`, "test_key", []byte("012345678901"), []byte("ciphertext"), time.Now())
	if err != nil {
		t.Fatalf("insert secrets: %v", err)
	}
}

// ─── Settings ────────────────────────────────────────────────────────────────

// SettingKeys and DeleteSetting exist for the boot-time migration in
// internal/secrets, which is the only caller. They are tested here because
// this is where the SQL lives.
func TestSettingKeysListsEveryKeyAndDeleteSettingRemovesOne(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetSetting("monitoring", `{"enabled":true}`); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := db.SetSetting("totp_user-1", `{"secret":"AAA"}`); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	keys, err := db.SettingKeys()
	if err != nil {
		t.Fatalf("SettingKeys: %v", err)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if !seen["monitoring"] || !seen["totp_user-1"] {
		t.Fatalf("expected both keys listed, got %v", keys)
	}

	if err := db.DeleteSetting("totp_user-1"); err != nil {
		t.Fatalf("DeleteSetting: %v", err)
	}
	got, err := db.GetSetting("totp_user-1")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got != "" {
		t.Fatalf("expected key gone after DeleteSetting, got %q", got)
	}
	if v, _ := db.GetSetting("monitoring"); v != `{"enabled":true}` {
		t.Fatalf("DeleteSetting touched the wrong row, monitoring=%q", v)
	}

	// Deleting a key that was never there is not an error: the migration
	// retries whole keys after a partial failure and must not abort boot
	// because a row it already removed is no longer there.
	if err := db.DeleteSetting("never_existed"); err != nil {
		t.Fatalf("DeleteSetting on missing key should be a no-op, got %v", err)
	}
}

func TestCreateAndListAIReports(t *testing.T) {
	db := newTestDB(t)

	r := &storage.AIReport{
		Kind: "digest", Summary: "19 episódios na SUMICITY, nenhum com perda de carrier",
		Findings:       `["SUMICITY: 19 episódios, 8-18s cada"]`,
		Recommendation: "Considere abrir chamado com a operadora anexando este relatório.",
		Confidence:     "alta",
	}
	if err := db.CreateAIReport(r); err != nil {
		t.Fatalf("CreateAIReport: %v", err)
	}
	if r.ID == "" {
		t.Error("expected ID to be set")
	}

	got, err := db.ListAIReports(10)
	if err != nil {
		t.Fatalf("ListAIReports: %v", err)
	}
	if len(got) != 1 || got[0].Summary != r.Summary {
		t.Fatalf("expected 1 report matching what was created, got %v", got)
	}

	one, err := db.GetAIReport(r.ID)
	if err != nil {
		t.Fatalf("GetAIReport: %v", err)
	}
	if one == nil || one.ID != r.ID {
		t.Fatalf("expected GetAIReport to find the created report, got %v", one)
	}
}

func TestGetAIReportMissingReturnsNil(t *testing.T) {
	db := newTestDB(t)
	got, err := db.GetAIReport("does-not-exist")
	if err != nil {
		t.Fatalf("GetAIReport: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for a missing report")
	}
}

// ─── FirewallGroup (Fase C1: grupos de regras) ──────────────────────────────

func TestFirewallGroupCRUDAndOrder(t *testing.T) {
	db := newTestDB(t)

	a := storage.FirewallGroup{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaaa0001",
		Position: 0, Enabled: true, CondSaddr: "192.168.50.0/24", Fallthrough: "drop"}
	b := storage.FirewallGroup{ID: "b", Name: "Servidores", ChainName: "grp_bbbb0002",
		Position: 1, Enabled: true, CondSaddr: "192.168.3.10", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&a); err != nil {
		t.Fatalf("criar grupo a: %v", err)
	}
	if err := db.CreateFirewallGroup(&b); err != nil {
		t.Fatalf("criar grupo b: %v", err)
	}

	got, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("listar: %v", err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("esperava a,b em ordem de posição, obtive %+v", got)
	}
	if got[0].Fallthrough != "drop" || got[0].CondSaddr != "192.168.50.0/24" {
		t.Errorf("campos não persistiram: %+v", got[0])
	}

	if err := db.ReorderFirewallGroups([]string{"b", "a"}); err != nil {
		t.Fatalf("reordenar: %v", err)
	}
	got, _ = db.ListFirewallGroups()
	if got[0].ID != "b" || got[1].ID != "a" {
		t.Errorf("reordenar não teve efeito: %+v", got)
	}

	if err := db.SetFirewallGroupEnabled("a", false); err != nil {
		t.Fatalf("desligar: %v", err)
	}
	got, _ = db.ListFirewallGroups()
	for _, g := range got {
		if g.ID == "a" && g.Enabled {
			t.Error("grupo a deveria estar desligado")
		}
	}
}

// Apagar um grupo tem que levar as regras dele junto, na mesma transação:
// foreign keys estão DESLIGADAS no modernc, então nada no banco faz isso
// sozinho, e uma regra órfã seria renderizada em chain nenhuma — presente
// no painel, ausente do firewall.
func TestDeleteFirewallGroupRemovesItsRules(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "g1", Name: "Testes", ChainName: "grp_cccc0003", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar grupo: %v", err)
	}
	r := storage.FirewallRule{ID: "r1", GroupID: "g1", Action: "drop", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatalf("criar regra: %v", err)
	}

	if err := db.DeleteFirewallGroup("g1"); err != nil {
		t.Fatalf("apagar grupo: %v", err)
	}
	rules, _ := db.ListFirewallRules()
	for _, x := range rules {
		if x.GroupID == "g1" {
			t.Fatalf("regra %s ficou órfã depois de apagar o grupo", x.ID)
		}
	}
}

func TestDeleteFirewallGroupUnknownIDIsAnError(t *testing.T) {
	db := newTestDB(t)
	if err := db.DeleteFirewallGroup("nao-existe"); err == nil {
		t.Fatal("apagar grupo inexistente tem que ser erro, não silêncio")
	}
}

func TestFirewallGroupKindRoundTrips(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "s1", Name: "Hosts bloqueados", ChainName: "sys_blocked_hosts",
		Kind: "blocked_hosts", Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar: %v", err)
	}
	got, _ := db.ListFirewallGroups()
	if len(got) != 1 || got[0].Kind != "blocked_hosts" {
		t.Fatalf("kind não persistiu: %+v", got)
	}
}

// Bancos que já existem ganham a coluna com valor vazio, e continuam
// funcionando: toda linha antiga é grupo do admin.
func TestMigrateAddsKindToExistingGroups(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "a", Name: "Antigo", ChainName: "grp_aaa", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListFirewallGroups()
	if got[0].Kind != "" && got[0].Kind != "admin" {
		t.Errorf("linha sem kind explícito tem que sair vazia ou admin, obtive %q", got[0].Kind)
	}
}

// migrateAddFirewallGroupKind only ever does anything on a database created
// before the column existed — and every other test opens a fresh one, where
// CREATE TABLE already includes it. So the ALTER TABLE path had no coverage
// at all: an independent review deleted the call from migrate() entirely and
// the whole suite stayed green.
//
// This builds the pre-column schema by hand, then opens it through the real
// storage.Open() twice: once to migrate, once to prove the guard makes the
// second run a no-op. The existing row must survive with an empty kind — it
// is the admin's group, and turning one into a system group by accident
// would hand it protections (cannot delete, cannot rename) never asked for.
func TestMigrateAddsKindToADatabaseCreatedBeforeTheColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("abrir banco cru: %v", err)
	}
	if _, err := raw.Exec(`
        CREATE TABLE firewall_groups (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, chain_name TEXT NOT NULL UNIQUE,
            position INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            cond_saddr TEXT NOT NULL DEFAULT '', cond_daddr TEXT NOT NULL DEFAULT '',
            cond_iif TEXT NOT NULL DEFAULT '', fallthrough TEXT NOT NULL DEFAULT 'continue',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled)
        VALUES ('velho', 'Grupo antigo do admin', 'grp_velho01', 0, 1);`); err != nil {
		t.Fatalf("montar schema antigo: %v", err)
	}
	raw.Close()

	for pass := 1; pass <= 2; pass++ {
		db, err := storage.Open(path)
		if err != nil {
			t.Fatalf("passada %d: storage.Open: %v", pass, err)
		}
		groups, err := db.ListFirewallGroups()
		if err != nil {
			t.Fatalf("passada %d: listar: %v", pass, err)
		}
		if len(groups) != 1 {
			t.Fatalf("passada %d: esperava 1 grupo preservado, obtive %d", pass, len(groups))
		}
		if groups[0].ID != "velho" || groups[0].Name != "Grupo antigo do admin" {
			t.Errorf("passada %d: a linha antiga não sobreviveu: %+v", pass, groups[0])
		}
		if groups[0].Kind != "" {
			t.Errorf("passada %d: linha antiga tem que ficar com kind vazio (= do admin), obtive %q",
				pass, groups[0].Kind)
		}
		db.Close()
	}
}

// ─── Fase C2: escopo do grupo (forward × input) ──────────────────────────

func TestFirewallGroupScopeRoundTrips(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "i1", Name: "Acesso ao painel", ChainName: "grp_iii",
		Kind: "admin", Scope: "input", Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar: %v", err)
	}
	got, _ := db.ListFirewallGroups()
	if len(got) != 1 || got[0].Scope != "input" {
		t.Fatalf("scope não persistiu: %+v", got)
	}
}

// Linha criada sem escopo explícito sai vazia — e vazio conta como forward
// (nftables.ScopeForward), que é o que todo grupo existente é.
func TestFirewallGroupWithoutScopeStaysEmpty(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "a", Name: "Antigo", ChainName: "grp_aaa", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListFirewallGroups()
	if got[0].Scope != "" {
		t.Errorf("linha sem escopo explícito tem que sair vazia, obtive %q", got[0].Scope)
	}
}

// Mesmo raciocínio (e mesmo molde) de
// TestMigrateAddsKindToADatabaseCreatedBeforeTheColumn: o caminho do ALTER
// TABLE só roda em banco criado antes da coluna existir, e todo outro teste
// abre um banco novo onde o CREATE TABLE já a inclui — sem este teste, apagar
// a chamada de migrate() deixaria a suíte inteira verde.
//
// O grupo antigo tem que sobreviver com o escopo VAZIO: ele é tráfego
// atravessando o firewall, e promovê-lo a escopo input por acidente moveria
// as regras dele da chain forward para a input — aplicá-las a um tráfego que
// o admin nunca pretendeu filtrar.
func TestMigrateAddsScopeToADatabaseCreatedBeforeTheColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-scope.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("abrir banco cru: %v", err)
	}
	if _, err := raw.Exec(`
        CREATE TABLE firewall_groups (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, chain_name TEXT NOT NULL UNIQUE,
            position INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            cond_saddr TEXT NOT NULL DEFAULT '', cond_daddr TEXT NOT NULL DEFAULT '',
            cond_iif TEXT NOT NULL DEFAULT '', fallthrough TEXT NOT NULL DEFAULT 'continue',
            kind TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled)
        VALUES ('velho', 'Grupo antigo do admin', 'grp_velho01', 0, 1);`); err != nil {
		t.Fatalf("montar schema antigo: %v", err)
	}
	raw.Close()

	for pass := 1; pass <= 2; pass++ {
		db, err := storage.Open(path)
		if err != nil {
			t.Fatalf("passada %d: storage.Open: %v", pass, err)
		}
		groups, err := db.ListFirewallGroups()
		if err != nil {
			t.Fatalf("passada %d: listar: %v", pass, err)
		}
		if len(groups) != 1 {
			t.Fatalf("passada %d: esperava 1 grupo preservado, obtive %d", pass, len(groups))
		}
		if groups[0].ID != "velho" || groups[0].Name != "Grupo antigo do admin" {
			t.Errorf("passada %d: a linha antiga não sobreviveu: %+v", pass, groups[0])
		}
		if groups[0].Scope != "" {
			t.Errorf("passada %d: linha antiga tem que ficar com escopo vazio (= forward), obtive %q",
				pass, groups[0].Scope)
		}
		db.Close()
	}
}

// ─── Estado da conexão do grupo (any × new) ──────────────────────────────

func TestFirewallGroupConnStateRoundTrips(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "n1", Name: "Só conexões novas", ChainName: "grp_nnn",
		Kind: "admin", ConnState: "new", Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar: %v", err)
	}
	got, _ := db.ListFirewallGroups()
	if len(got) != 1 || got[0].ConnState != "new" {
		t.Fatalf("conn_state não persistiu: %+v", got)
	}
}

// A edição tem que gravar a escolha: um handler que leia o campo do corpo e
// não o veja chegar ao banco produz o pior bug de painel — o admin muda na
// tela, a resposta é 200, e o firewall continua exatamente como estava.
func TestUpdateFirewallGroupSavesConnState(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "n1", Name: "Visitantes", ChainName: "grp_nnn",
		Kind: "admin", Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar: %v", err)
	}
	g.ConnState = "new"
	if err := db.UpdateFirewallGroup(&g); err != nil {
		t.Fatalf("atualizar: %v", err)
	}
	got, _ := db.ListFirewallGroups()
	if len(got) != 1 || got[0].ConnState != "new" {
		t.Fatalf("a edição não gravou conn_state: %+v", got)
	}
}

// Linha criada sem escolha explícita sai vazia — e vazio conta como
// nftables.ConnStateAny, que é o que todo grupo existente é.
func TestFirewallGroupWithoutConnStateStaysEmpty(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "a", Name: "Antigo", ChainName: "grp_aaa", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListFirewallGroups()
	if got[0].ConnState != "" {
		t.Errorf("linha sem escolha explícita tem que sair vazia, obtive %q", got[0].ConnState)
	}
}

// Mesmo molde de TestMigrateAddsScopeToADatabaseCreatedBeforeTheColumn: o
// caminho do ALTER TABLE só roda em banco criado antes da coluna existir, e
// todo outro teste abre um banco novo onde o CREATE TABLE já a inclui — sem
// este teste, apagar a chamada de migrate() deixaria a suíte inteira verde.
//
// O grupo antigo tem que sobreviver com conn_state VAZIO: ele vale para TODA
// conexão, e promovê-lo a "só conexões novas" por acidente deixaria de
// bloquear (ou de liberar) o tráfego já estabelecido de alguém que nunca
// pediu essa mudança.
func TestMigrateAddsConnStateToADatabaseCreatedBeforeTheColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-connstate.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("abrir banco cru: %v", err)
	}
	if _, err := raw.Exec(`
        CREATE TABLE firewall_groups (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, chain_name TEXT NOT NULL UNIQUE,
            position INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            cond_saddr TEXT NOT NULL DEFAULT '', cond_daddr TEXT NOT NULL DEFAULT '',
            cond_iif TEXT NOT NULL DEFAULT '', fallthrough TEXT NOT NULL DEFAULT 'continue',
            kind TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled)
        VALUES ('velho', 'Grupo antigo do admin', 'grp_velho01', 0, 1);`); err != nil {
		t.Fatalf("montar schema antigo: %v", err)
	}
	raw.Close()

	for pass := 1; pass <= 2; pass++ {
		db, err := storage.Open(path)
		if err != nil {
			t.Fatalf("passada %d: storage.Open: %v", pass, err)
		}
		groups, err := db.ListFirewallGroups()
		if err != nil {
			t.Fatalf("passada %d: listar: %v", pass, err)
		}
		if len(groups) != 1 {
			t.Fatalf("passada %d: esperava 1 grupo preservado, obtive %d", pass, len(groups))
		}
		if groups[0].ID != "velho" || groups[0].Name != "Grupo antigo do admin" {
			t.Errorf("passada %d: a linha antiga não sobreviveu: %+v", pass, groups[0])
		}
		if groups[0].ConnState != "" {
			t.Errorf("passada %d: linha antiga tem que ficar com conn_state vazio (= toda conexão), obtive %q",
				pass, groups[0].ConnState)
		}
		db.Close()
	}
}

// ─── Layout do painel (Fase B, spec §4.1 e §6) ─────────────────────────────

// Layout inválido nunca trava a tela. Um item que aponta para um widget que não
// existe mais (versão anterior, widget removido do produto) é descartado item a
// item — o resto do painel do operador continua abrindo.
func TestUnknownWidgetIsDroppedItemByItemNotWholeLayout(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDashboardLayout("u1", []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "widget_que_nao_existe_mais", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 12, H: 3},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}
	got, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("ler: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 itens válidos, obtive %d: %+v", len(got), got)
	}
	for _, it := range got {
		if it.Widget == "widget_que_nao_existe_mais" {
			t.Error("o item desconhecido tinha que ter sido descartado")
		}
	}
}

// O layout é de quem o salvou. Um admin não vê nem sobrescreve o painel de
// outro: quem nunca salvou nada cai no layout de fábrica, e salvar o painel de
// um não mexe no do outro. Sem isto, "cada admin monta o seu" (spec §4.1) vira
// um layout único que o último a arrastar impõe a todos.
func TestLayoutIsPerUser(t *testing.T) {
	db := newTestDB(t)

	doU1 := []dashboard.LayoutItem{
		{Widget: "wan_links", X: 0, Y: 0, W: 12, H: 3},
	}
	if err := db.SaveDashboardLayout("u1", doU1); err != nil {
		t.Fatalf("salvar u1: %v", err)
	}

	// u2 nunca salvou nada: tem que receber o padrão de fábrica, não o painel
	// do u1 e não uma tela em branco.
	got2, err := db.GetDashboardLayout("u2")
	if err != nil {
		t.Fatalf("ler u2: %v", err)
	}
	padrao := dashboard.Default()
	if len(got2) != len(padrao) {
		t.Fatalf("u2 sem layout salvo tinha que cair no padrão (%d itens), obtive %d: %+v",
			len(padrao), len(got2), got2)
	}
	for i := range padrao {
		if got2[i] != padrao[i] {
			t.Errorf("u2 item %d: esperava %+v, obtive %+v", i, padrao[i], got2[i])
		}
	}

	// u2 monta o dele. O painel do u1 não pode mudar por causa disso.
	doU2 := []dashboard.LayoutItem{
		{Widget: "lan_hosts", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "open_alerts", X: 6, Y: 0, W: 6, H: 2},
	}
	if err := db.SaveDashboardLayout("u2", doU2); err != nil {
		t.Fatalf("salvar u2: %v", err)
	}

	got1, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("reler u1: %v", err)
	}
	if len(got1) != 1 || got1[0] != doU1[0] {
		t.Fatalf("o painel do u1 tinha que continuar intacto, obtive %+v", got1)
	}

	got2, err = db.GetDashboardLayout("u2")
	if err != nil {
		t.Fatalf("reler u2: %v", err)
	}
	if len(got2) != 2 || got2[0] != doU2[0] || got2[1] != doU2[1] {
		t.Fatalf("o painel do u2 tinha que ser o que ele salvou, obtive %+v", got2)
	}
}

// A migração do painel roda em banco que já existe e é idempotente: o segundo
// boot não recria nada e o painel que o admin já tinha montado continua lá. É a
// garantia que faltou no incidente de 2026-07-24 — migração de boot é caminho
// crítico, e o jeito de ela não travar a máquina é não ter trabalho para fazer
// da segunda vez em diante.
func TestDashboardLayoutMigrationIsIdempotentAndKeepsSavedLayouts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "painel.db")

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("primeiro Open: %v", err)
	}
	meu := []dashboard.LayoutItem{{Widget: "wan_links", X: 0, Y: 0, W: 12, H: 3}}
	if err := db.SaveDashboardLayout("u1", meu); err != nil {
		t.Fatalf("salvar: %v", err)
	}
	db.Close()

	for passada := 2; passada <= 3; passada++ {
		db, err := storage.Open(path)
		if err != nil {
			t.Fatalf("passada %d: storage.Open: %v", passada, err)
		}
		got, err := db.GetDashboardLayout("u1")
		if err != nil {
			t.Fatalf("passada %d: ler: %v", passada, err)
		}
		if len(got) != 1 || got[0] != meu[0] {
			t.Errorf("passada %d: o painel salvo não sobreviveu: %+v", passada, got)
		}
		db.Close()
	}
}

// "Restaurar padrão": apagar o layout devolve o de fábrica, para quem se perdeu
// arrastando (spec §6).
func TestDeleteDashboardLayoutRestoresTheFactoryDefault(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDashboardLayout("u1", []dashboard.LayoutItem{
		{Widget: "wan_links", X: 0, Y: 0, W: 12, H: 3},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}
	if err := db.DeleteDashboardLayout("u1"); err != nil {
		t.Fatalf("apagar: %v", err)
	}
	got, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("ler: %v", err)
	}
	if len(got) != len(dashboard.Default()) {
		t.Fatalf("esperava o layout de fábrica de volta, obtive %+v", got)
	}
}

// Layout vazio é uma escolha do admin — ele tirou todos os widgets — e é
// diferente de "nunca salvou nada". Se as duas situações se confundissem, quem
// esvaziasse o painel de propósito veria os widgets de fábrica voltarem
// sozinhos no próximo F5.
func TestEmptyLayoutIsAChoiceNotAMissingLayout(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDashboardLayout("u1", []dashboard.LayoutItem{}); err != nil {
		t.Fatalf("salvar vazio: %v", err)
	}
	got, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("ler: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("esperava painel vazio, obtive %+v", got)
	}
}

// Geometria impossível (fora da grade de 12 colunas, tamanho zero ou negativo)
// é descartada item a item, como o widget desconhecido — uma linha ruim no
// banco não pode levar o painel inteiro junto.
func TestOutOfGridItemIsDroppedItemByItem(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDashboardLayout("u1", []dashboard.LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 8, Y: 0, W: 6, H: 2},      // passa da coluna 12
		{Widget: "open_alerts", X: 0, Y: 2, W: 6, H: 0},    // sem altura
		{Widget: "lan_hosts", X: -1, Y: 0, W: 6, H: 2},     // fora à esquerda
		{Widget: "top_talkers", X: 0, Y: 4, W: 12, H: 999}, // altura absurda
		{Widget: "system_resources", X: 0, Y: 6, W: 12, H: 2},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}
	got, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("ler: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava só os 2 itens desenháveis, obtive %d: %+v", len(got), got)
	}
	for _, it := range got {
		if it.Widget != "system_health" && it.Widget != "system_resources" {
			t.Errorf("item fora da grade voltou: %+v", it)
		}
	}
}
