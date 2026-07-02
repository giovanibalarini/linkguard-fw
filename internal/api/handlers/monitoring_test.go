package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMonitoringConfigRoundTrip(t *testing.T) {
	db := openTestDB(t)
	h := &MonitoringHandler{col: nil, db: db}

	body := []byte(`{"enabled":false,"services":["unbound"],"disk_threshold_pct":80}`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/monitoring/config", bytes.NewReader(body))
	putRR := httptest.NewRecorder()
	h.SetConfig(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("SetConfig status = %d, want 200; body=%s", putRR.Code, putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/monitoring/config", nil)
	getRR := httptest.NewRecorder()
	h.GetConfig(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GetConfig status = %d, want 200; body=%s", getRR.Code, getRR.Body.String())
	}

	var got monitoring.Config
	if err := json.Unmarshal(getRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Enabled != false {
		t.Errorf("Enabled = %v, want false", got.Enabled)
	}
	if got.DiskThresholdPct != 80 {
		t.Errorf("DiskThresholdPct = %d, want 80", got.DiskThresholdPct)
	}
	if len(got.Services) != 1 || got.Services[0] != "unbound" {
		t.Errorf("Services = %v, want [unbound]", got.Services)
	}
}
