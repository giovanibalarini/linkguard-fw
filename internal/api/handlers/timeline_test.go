package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/tsdb"
)

func TestTimelineHandlerReturnsSeriesAndStates(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()
	_ = db.UpsertMetricSample(storage.MetricSample{
		Series: "link.latency_ms", Label: "WAN VIVO", StepSeconds: 60,
		TsUnix: now - now%60, VMin: 10, VAvg: 15, VMax: 20,
	})
	_ = db.OpenStateInterval("link", "WAN VIVO", "online", now-3600)

	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)
	h := handlers.NewTimelineHandler(tsdbSvc, alertSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/timeline?from="+itoa(now-7200)+"&to="+itoa(now)+"&series=link.latency_ms:WAN+VIVO&states=link:WAN+VIVO", nil)
	w := httptest.NewRecorder()
	h.Timeline(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !contains(body, "link.latency_ms") {
		t.Fatalf("expected response to contain the requested series, got: %s", body)
	}
	if !contains(body, "\"state\":\"online\"") {
		t.Fatalf("expected response to contain the open state interval, got: %s", body)
	}
}

func TestTimelineHandlerRequiresFromAndTo(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	tsdbSvc := tsdb.NewService(db)
	alertSvc := alerts.NewService(db)
	h := handlers.NewTimelineHandler(tsdbSvc, alertSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/timeline", nil)
	w := httptest.NewRecorder()
	h.Timeline(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing from/to, got %d", w.Code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
