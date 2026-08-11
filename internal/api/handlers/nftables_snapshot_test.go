package handlers_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// redirectConfPath points nftables.ConfPath (normally /etc/nftables.conf, only
// writable as root) at a temp file for the duration of a test.
func redirectConfPath(t *testing.T) {
	t.Helper()
	orig := nftables.ConfPath
	nftables.ConfPath = filepath.Join(t.TempDir(), "nftables.conf")
	t.Cleanup(func() { nftables.ConfPath = orig })
}

// fakeNftExec is a minimal firewall.Executor that never touches the real
// system: every write succeeds, and `nft list ruleset` returns a fixed,
// recognizable string so tests can assert exactly what got persisted.
type fakeNftExec struct{ ruleset string }

func (f *fakeNftExec) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (f *fakeNftExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "nft" && len(args) >= 2 && args[0] == "list" && args[1] == "ruleset" {
		return f.ruleset, nil
	}
	return "", nil
}
func (f *fakeNftExec) IsDryRun() bool { return false }

func newNftTestHandler(t *testing.T, ruleset string) (*handlers.NftablesHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := nftables.NewService(&fakeNftExec{ruleset: ruleset})
	fr := firewallrules.NewService(db, svc)
	return handlers.NewNftablesHandler(svc, db, fr), db
}

// TestWanHostPersistsLiveSnapshot is the regression test for "regras de
// firewall persistidas no banco": every mutation that changes the live
// nftables ruleset (here, adding a host_wan entry) must also save a fresh
// snapshot to LiveSnapshotSettingKey, so a from-scratch install can restore
// it later (see nftables.EnsureTable + main.go's bootstrap-then-restore).
func TestWanHostPersistsLiveSnapshot(t *testing.T) {
	redirectConfPath(t)
	const wantRuleset = "table inet linkguard {\n\tmap host_wan {\n\t\telements = { 10.0.0.5 : 0x12c }\n\t}\n}\n"
	h, db := newNftTestHandler(t, wantRuleset)

	if got, _ := db.GetSetting(nftables.LiveSnapshotSettingKey); got != "" {
		t.Fatalf("expected no snapshot before any mutation, got %q", got)
	}

	body := strings.NewReader(`{"ip":"10.0.0.5","mark":"0x12c"}`)
	r := httptest.NewRequest("POST", "/api/nftables/wan-host", body)
	w := httptest.NewRecorder()
	h.WanHost(w, r)

	if w.Code != 200 {
		t.Fatalf("WanHost: status %d, body %s", w.Code, w.Body.String())
	}
	got, err := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if got != wantRuleset {
		t.Errorf("snapshot not persisted correctly:\ngot:  %q\nwant: %q", got, wantRuleset)
	}
}

// TestBlocklistPersistsLiveSnapshot covers the other mutating nftables
// endpoint family (sets, not just the map) through the same mechanism.
func TestBlocklistPersistsLiveSnapshot(t *testing.T) {
	redirectConfPath(t)
	const wantRuleset = "table inet linkguard {\n\tset blocklist {\n\t\telements = { 203.0.113.0/24 }\n\t}\n}\n"
	h, db := newNftTestHandler(t, wantRuleset)

	body := strings.NewReader(`{"cidr":"203.0.113.0/24"}`)
	r := httptest.NewRequest("POST", "/api/nftables/blocklist", body)
	w := httptest.NewRecorder()
	h.Blocklist(w, r)

	if w.Code != 200 {
		t.Fatalf("Blocklist: status %d, body %s", w.Code, w.Body.String())
	}
	got, _ := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if got != wantRuleset {
		t.Errorf("snapshot not persisted correctly:\ngot:  %q\nwant: %q", got, wantRuleset)
	}
}
