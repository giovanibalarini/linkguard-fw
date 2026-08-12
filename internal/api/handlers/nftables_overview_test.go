package handlers_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// fakeOverviewExec answers `nft -a list table inet linkguard` with a fixed
// captured table and nothing else — enough to exercise the handler without
// touching a real nft binary.
type fakeOverviewExec struct{ table string }

func (f *fakeOverviewExec) Execute(context.Context, string, ...string) (string, error) {
	return "", nil
}
func (f *fakeOverviewExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "nft" && len(args) >= 3 && args[0] == "-a" && args[1] == "list" && args[2] == "table" {
		return f.table, nil
	}
	return "", nil
}
func (f *fakeOverviewExec) IsDryRun() bool { return false }

const overviewFixture = `table inet linkguard {
	chain user_rules {
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		jump user_rules
		ip daddr @blocklist counter packets 11628 bytes 764849 drop
	}

	chain input {
		type filter hook input priority filter; policy accept;
		udp dport 123 ip saddr 192.168.3.0/24 accept
		udp dport 123 drop
	}
}
`

func newOverviewTestHandler(t *testing.T, table string) *handlers.NftablesHandler {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc := nftables.NewService(&fakeOverviewExec{table: table})
	fr := firewallrules.NewService(db, svc)
	// Como no boot: sem os dois grupos do sistema na lista, o Reconcile se
	// recusa a reconstruir a chain forward.
	if err := fr.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("EnsureSystemGroups: %v", err)
	}
	return handlers.NewNftablesHandler(svc, db, fr)
}

// TestOverviewReturnsAllChainsWithoutNullSlices is the standing-rule
// regression test for this codebase: a nil slice serializes as JSON `null`
// and breaks the frontend's `.map()`. The empty user_rules chain's `rules`
// must come back as `[]`, never `null`.
func TestOverviewReturnsAllChainsWithoutNullSlices(t *testing.T) {
	h := newOverviewTestHandler(t, overviewFixture)

	r := httptest.NewRequest("GET", "/api/nftables/overview", nil)
	w := httptest.NewRecorder()
	h.Overview(w, r)

	if w.Code != 200 {
		t.Fatalf("Overview: status %d, body %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "null") {
		t.Fatalf("response must never contain a null slice: %s", body)
	}

	var chains []nftables.ChainInfo
	if err := json.Unmarshal(w.Body.Bytes(), &chains); err != nil {
		t.Fatalf("response is not a JSON array of chains: %v (body: %s)", err, body)
	}
	if len(chains) != 3 {
		t.Fatalf("expected 3 chains, got %d: %+v", len(chains), chains)
	}
}

// TestOverviewCarriesCountersOwnershipAndDescription checks the response is
// the fully-classified view (Parts 1+2), not a bare re-dump of the ruleset.
func TestOverviewCarriesCountersOwnershipAndDescription(t *testing.T) {
	h := newOverviewTestHandler(t, overviewFixture)

	r := httptest.NewRequest("GET", "/api/nftables/overview", nil)
	w := httptest.NewRecorder()
	h.Overview(w, r)

	var chains []nftables.ChainInfo
	if err := json.Unmarshal(w.Body.Bytes(), &chains); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var fwd *nftables.ChainInfo
	for i := range chains {
		if chains[i].Name == "forward" {
			fwd = &chains[i]
		}
	}
	if fwd == nil {
		t.Fatal("forward chain missing from response")
	}
	var blockRule *nftables.ChainRule
	for i := range fwd.Rules {
		if strings.Contains(fwd.Rules[i].Expression, "@blocklist") {
			blockRule = &fwd.Rules[i]
		}
	}
	if blockRule == nil {
		t.Fatal("blocklist drop rule missing from forward chain")
	}
	if !blockRule.HasCounter || blockRule.Packets != 11628 || blockRule.Bytes != 764849 {
		t.Errorf("counters not carried through: %+v", blockRule)
	}
	if !blockRule.Managed || blockRule.Owner.Key != "blocklist" {
		t.Errorf("ownership not carried through: %+v", blockRule)
	}
	if blockRule.Description == "" {
		t.Error("description not carried through")
	}
}

// TestOverviewNamesTheGroupOnAJump proves the handler resolves a group jump
// line's chain to the admin-given name from the DB (nftables.ApplyGroupNames
// wired into Overview), rather than leaving describeRule's generic fallback
// on screen — the whole point of Task 6.
func TestOverviewNamesTheGroupOnAJump(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	g := newRuleGroup(t, db)

	fixture := `table inet linkguard {
	chain user_rules {
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		jump user_rules
		ip saddr 192.168.50.0/24 counter packets 0 bytes 0 jump ` + g.ChainName + `
	}
}
`
	svc := nftables.NewService(&fakeOverviewExec{table: fixture})
	fr := firewallrules.NewService(db, svc)
	h := handlers.NewNftablesHandler(svc, db, fr)

	r := httptest.NewRequest("GET", "/api/nftables/overview", nil)
	w := httptest.NewRecorder()
	h.Overview(w, r)
	if w.Code != 200 {
		t.Fatalf("Overview: status %d, body %s", w.Code, w.Body.String())
	}

	var chains []nftables.ChainInfo
	if err := json.Unmarshal(w.Body.Bytes(), &chains); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var fwd *nftables.ChainInfo
	for i := range chains {
		if chains[i].Name == "forward" {
			fwd = &chains[i]
		}
	}
	if fwd == nil {
		t.Fatal("forward chain missing from response")
	}
	var jumpRule *nftables.ChainRule
	for i := range fwd.Rules {
		if strings.Contains(fwd.Rules[i].Expression, g.ChainName) {
			jumpRule = &fwd.Rules[i]
		}
	}
	if jumpRule == nil {
		t.Fatalf("group jump rule missing from forward chain: %+v", fwd.Rules)
	}
	if !strings.Contains(jumpRule.Description, g.Name) {
		t.Errorf("description must name the group %q, got %q", g.Name, jumpRule.Description)
	}
	if !strings.Contains(jumpRule.Description, "192.168.50.0/24") {
		t.Errorf("description must say when the group is evaluated, got %q", jumpRule.Description)
	}
}

func TestOverviewPropagatesNftErrors(t *testing.T) {
	svc := nftables.NewService(&failingExec{})
	// db/fr stay nil: ListRuleset fails before Overview ever touches either.
	h := handlers.NewNftablesHandler(svc, nil, nil)
	r := httptest.NewRequest("GET", "/api/nftables/overview", nil)
	w := httptest.NewRecorder()
	h.Overview(w, r)
	if w.Code != 500 {
		t.Fatalf("expected 500 on nft failure, got %d: %s", w.Code, w.Body.String())
	}
}

type failingExec struct{}

func (failingExec) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (failingExec) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", context.DeadlineExceeded
}
func (failingExec) IsDryRun() bool { return false }
