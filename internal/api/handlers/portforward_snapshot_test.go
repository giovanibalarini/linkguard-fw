package handlers_test

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestPortForwardUpsertPersistsLiveSnapshot: port forwards already have their
// own structured `port_forwards` setting for the UI list, but the raw
// nftables snapshot must also pick up the DNAT chain they render into — it's
// what a from-scratch bootstrap restores (see nftables.EnsureTable).
func TestPortForwardUpsertPersistsLiveSnapshot(t *testing.T) {
	redirectConfPath(t)
	const wantRuleset = "table inet linkguard {\n\tchain prerouting_dnat {\n\t\trule tcp dport 8080 dnat to 192.168.3.50:80\n\t}\n}\n"

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	svc := nftables.NewService(&fakeNftExec{ruleset: wantRuleset})
	h := handlers.NewPortForwardHandler(db, svc)

	body := strings.NewReader(`{"name":"web","enabled":true,"proto":"tcp","ext_port":8080,"dest_ip":"192.168.3.50","dest_port":80}`)
	r := httptest.NewRequest("POST", "/api/portforward", body)
	w := httptest.NewRecorder()
	h.Upsert(w, r)

	if w.Code != 200 {
		t.Fatalf("Upsert: status %d, body %s", w.Code, w.Body.String())
	}
	got, _ := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if got != wantRuleset {
		t.Errorf("snapshot not persisted correctly:\ngot:  %q\nwant: %q", got, wantRuleset)
	}
}
