package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/monitoring"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestUpdatesReturnsEmptyPackagesNotNull guards the same JSON contract the
// rest of this codebase follows: a nil slice marshals to `null` and breaks
// the frontend's .map(). A fresh box that has never run the check must
// return an empty list, not null.
//
// This lives in package handlers_test (not handlers, as the plan's snippet
// showed) because fakeEmptyIfaceExec is declared in netif_test.go under
// package handlers_test — an internal-test-package file can't see it.
func TestUpdatesReturnsEmptyPackagesNotNull(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	col := monitoring.NewCollector(db, nil, alerts.NewService(db), &fakeEmptyIfaceExec{}, nil)
	h := handlers.NewMonitoringHandler(col, db)

	r := httptest.NewRequest("GET", "/api/system/updates", nil)
	w := httptest.NewRecorder()
	h.Updates(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var got struct {
		Total    int   `json:"total"`
		Security int   `json:"security"`
		Packages []any `json:"packages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v — body: %s", err, w.Body.String())
	}
	if got.Packages == nil {
		t.Errorf("packages is null; expected [] — body: %s", w.Body.String())
	}
}
