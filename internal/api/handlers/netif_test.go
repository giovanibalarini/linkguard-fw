package handlers_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/netif"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// fakeEmptyIfaceExec is a firewall.Executor test double for netif.Service
// that reports a kernel with no interfaces at all. fakeNftExec (defined in
// nftables_snapshot_test.go) can't be reused here: it returns "" for every
// command other than "nft list ruleset", but netif's parseLinks/parseAddrs
// call json.Unmarshal on that output and error on an empty string (only a
// valid empty JSON array parses to an empty list) — so reusing it turns
// this test's expected [] response into a 500.
type fakeEmptyIfaceExec struct{}

func (f *fakeEmptyIfaceExec) Execute(context.Context, string, ...string) (string, error) {
	return "", nil
}
func (f *fakeEmptyIfaceExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	switch cmd {
	case "ip":
		return "[]", nil
	case "cat":
		return "", nil
	}
	return "", nil
}
func (f *fakeEmptyIfaceExec) IsDryRun() bool { return false }

func TestStableNamesReturnsEmptyListNotNull(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	linkSvc := links.NewService(db)
	svc := netif.NewService(&fakeEmptyIfaceExec{}, db, linkSvc)
	h := handlers.NewNetifHandler(svc, db)

	r := httptest.NewRequest("GET", "/api/interfaces/stable-names", nil)
	w := httptest.NewRecorder()
	h.StableNames(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "null\n" {
		t.Error("expected [], got null — frontend .map() would crash on this")
	}
}

func TestApplyStableNamesReturnsEmptyListNotNull(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	linkSvc := links.NewService(db)
	svc := netif.NewService(&fakeEmptyIfaceExec{}, db, linkSvc)
	h := handlers.NewNetifHandler(svc, db)

	r := httptest.NewRequest("POST", "/api/interfaces/stable-names/apply", nil)
	w := httptest.NewRecorder()
	h.ApplyStableNames(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"entries":[]`) {
		t.Errorf("expected entries:[], got body = %s", body)
	}
	if strings.Contains(body, `"entries":null`) {
		t.Error("expected [], got null — frontend .map() would crash on this")
	}
}
