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

// recordingRuleExec is a firewall.Executor that records every mutating
// command (so a test can assert nft actually got reconciled) and answers
// `nft -a list table ...` with the ruleset a box looks like after the Phase
// C1 migration: the forward chain and the fixture group's own chain, and NO
// user_rules — the migration deleted it.
type recordingRuleExec struct {
	executed []string
}

func (e *recordingRuleExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, cmd+" "+strings.Join(args, " "))
	return "", nil
}
func (e *recordingRuleExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	return "table inet linkguard {\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n" +
		"\tchain " + testGroupChain + " {\n\t}\n}\n", nil
}
func (e *recordingRuleExec) IsDryRun() bool { return false }

func newFirewallRulesTestHandler(t *testing.T) (*handlers.NftablesHandler, *storage.DB, *recordingRuleExec) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	exec := &recordingRuleExec{}
	nftSvc := nftables.NewService(exec)
	// m3 da revisão da Fase C2: sem uma fonte de NTP ligada, a reconciliação
	// da chain input agora devolve erro (fechou o fail-open de fonte não
	// ligada) em vez do antigo "NTP desligado" silencioso — o que faria toda
	// mutação de regra/grupo destes testes responder 500 só por causa da
	// chain input, que nenhum deles exercita. Declara a intenção
	// explicitamente: nenhum grupo de escopo input, NTP desligado.
	nftSvc.SetInputChainSources(
		func() ([]nftables.StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	frSvc := firewallrules.NewService(db, nftSvc)
	// Mesma ordem do boot (cmd/linkguard-fw/main.go): os dois grupos do
	// sistema primeiro, porque é a lista de grupos que passa a decidir se os
	// bloqueios existem na chain forward — sem eles, TODA reconciliação se
	// recusa a reconstruí-la e toda mutação desta API responderia 500.
	if err := frSvc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("EnsureSystemGroups: %v", err)
	}
	// Consume the initial import so its own reconcile commands don't
	// contaminate a test's assertions about a specific mutation.
	_ = frSvc.ImportOnce(context.Background())
	exec.executed = nil
	return handlers.NewNftablesHandler(nftSvc, db, frSvc), db, exec
}

// testGroupID/testGroupChain são o grupo fixo destas fixtures. O nome da
// chain é derivado do id pela mesma função do servidor, então o executor
// falso pode devolvê-lo no ruleset sem que os dois possam divergir.
const testGroupID = "a3f21c08-0000-4000-8000-000000000000"

var testGroupChain = nftables.GroupChainName(testGroupID)

// newRuleGroup cria um grupo com o formato de chain que a produção usa. A
// partir da Fase C1 as regras do admin só existem no firewall dentro de um
// grupo: uma linha de firewall_rules sem grupo válido é ignorada pela
// reconciliação (ver firewallrules.Service.StoredGroups), então um teste que
// queira ver a regra renderizada no nft precisa colocá-la num grupo.
func newRuleGroup(t *testing.T, db *storage.DB) storage.FirewallGroup {
	t.Helper()
	const id = testGroupID
	g := storage.FirewallGroup{
		ID: id, Name: "Minhas regras", ChainName: nftables.GroupChainName(id),
		Enabled: true, Fallthrough: nftables.FallthroughContinue,
	}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	return g
}

func ruleBodyJSON(t *testing.T, m map[string]any) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.NewReader(string(b))
}

// firewallRulesResponseBody mirrors the handler's unexported response
// shape, just enough for a test to decode it.
type firewallRulesResponseBody struct {
	Rules       []storage.FirewallRule     `json:"rules"`
	ApplyStatus *firewallrules.ApplyStatus `json:"apply_status,omitempty"`
}

func TestListRulesReturnsEmptySliceNotNull(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)
	r := httptest.NewRequest("GET", "/api/nftables/rules", nil)
	w := httptest.NewRecorder()
	h.ListRules(w, r)

	if w.Code != 200 {
		t.Fatalf("ListRules: status %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"rules":null`) {
		t.Fatalf("response must never contain a null slice: %s", w.Body.String())
	}
	var body firewallRulesResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(body.Rules))
	}
}

// TestListRulesReportsApplyStatusAfterAReconcile (C-3): the endpoint that
// feeds the panel's own "is this actually in effect" banner must expose the
// outcome of the reconcile a mutation just triggered, not leave the admin
// to guess from a 200 status code alone (a mutation can write to the DB
// successfully and still fail to reconcile into nft).
func TestListRulesReportsApplyStatusAfterAReconcile(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)

	// Before anything has ever reconciled through this handler in the test
	// (ImportOnce's own internal reconcile already ran during setup, so
	// apply_status is expected to be present, not nil, from the start).
	req := httptest.NewRequest("GET", "/api/nftables/rules", nil)
	w := httptest.NewRecorder()
	h.ListRules(w, req)
	var body firewallRulesResponseBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ApplyStatus == nil {
		t.Fatal("expected apply_status populated (ImportOnce's own reconcile already ran during setup)")
	}
	if !body.ApplyStatus.OK {
		t.Errorf("expected a clean setup to have reconciled ok, got %+v", body.ApplyStatus)
	}
}

func TestCreateRuleValidatesFieldsAndReconciles(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)
	g := newRuleGroup(t, db)

	// Malicious interface name must be rejected before it ever reaches nft.
	bad := httptest.NewRequest("POST", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"group_id": g.ID, "action": "accept", "iif": `eth0" ; flush ruleset #`,
	}))
	w := httptest.NewRecorder()
	h.CreateRule(w, bad)
	if w.Code != 400 {
		t.Fatalf("expected 400 for a malicious interface, got %d: %s", w.Code, w.Body.String())
	}
	if all, _ := db.ListFirewallRules(); len(all) != 0 {
		t.Fatalf("expected no rule created for the rejected request, got %d", len(all))
	}

	// A well-formed rule is created, persisted, and reconciled into nft.
	good := httptest.NewRequest("POST", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"group_id": g.ID, "action": "drop", "daddr": "203.0.113.0/24",
		"description": "bloqueia range suspeito",
	}))
	w = httptest.NewRecorder()
	h.CreateRule(w, good)
	if w.Code != 200 {
		t.Fatalf("CreateRule: status %d, body %s", w.Code, w.Body.String())
	}
	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 1 || all[0].Daddr != "203.0.113.0/24" || all[0].Description != "bloqueia range suspeito" {
		t.Fatalf("expected the rule stored with its fields, got %+v", all)
	}
	if all[0].GroupID != g.ID {
		t.Fatalf("expected the rule created inside its group, got %+v", all[0])
	}
	// A asserção forte, que é a única que prova a entrega: o CONTEÚDO da
	// regra chegou ao nft, dentro da chain do grupo dela. Provar só que
	// "algum reconcile rodou" deixaria passar exatamente o defeito que
	// mais custa aqui — a regra gravada no banco, exibida no painel, e
	// ausente do firewall.
	want := "nft add rule inet linkguard " + g.ChainName + " ip daddr 203.0.113.0/24 counter drop"
	found := false
	for _, c := range exec.executed {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q among the reconcile's commands, ran: %v", want, exec.executed)
	}
}

// TestCreateRuleRejectsIPv6AndBadPortBeforeTheyReachTheDB is the C-1
// regression test: an IPv6 saddr and an out-of-range port are ordinary
// typing mistakes (net.ParseIP happily accepts IPv6; a 5-digit port matches
// the old charset-only regex) that nft would reject only once the rule
// reached it — by which point (before the fix) the chain had already been
// flushed, truncating every rule after the bad one, permanently. Both must
// be rejected here, before any DB write.
func TestCreateRuleRejectsIPv6AndBadPortBeforeTheyReachTheDB(t *testing.T) {
	h, db, _ := newFirewallRulesTestHandler(t)

	ipv6 := httptest.NewRequest("POST", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"action": "accept", "saddr": "2001:db8::1",
	}))
	w := httptest.NewRecorder()
	h.CreateRule(w, ipv6)
	if w.Code != 400 {
		t.Fatalf("expected 400 for an IPv6 saddr, got %d: %s", w.Code, w.Body.String())
	}

	badPort := httptest.NewRequest("POST", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"action": "accept", "proto": "tcp", "dport": "99999",
	}))
	w = httptest.NewRecorder()
	h.CreateRule(w, badPort)
	if w.Code != 400 {
		t.Fatalf("expected 400 for port 99999, got %d: %s", w.Code, w.Body.String())
	}

	if all, _ := db.ListFirewallRules(); len(all) != 0 {
		t.Fatalf("expected neither rejected request to reach the DB, got %d rows: %+v", len(all), all)
	}
}

func TestCreateRuleRejectsOverlongDescription(t *testing.T) {
	h, db, _ := newFirewallRulesTestHandler(t)
	huge := strings.Repeat("a", 5000)
	req := httptest.NewRequest("POST", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"action": "accept", "description": huge,
	}))
	w := httptest.NewRecorder()
	h.CreateRule(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for an overlong description, got %d: %s", w.Code, w.Body.String())
	}
	if all, _ := db.ListFirewallRules(); len(all) != 0 {
		t.Fatalf("expected no rule created, got %d", len(all))
	}
}

func TestUpdateRuleRequiresID(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)
	req := httptest.NewRequest("PUT", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{"action": "accept"}))
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 without an id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRuleEditsContentAndReconciles(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)
	g := newRuleGroup(t, db)
	row := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.1"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("PUT", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{
		"id": row.ID, "action": "drop", "saddr": "10.0.0.9", "description": "editada",
	}))
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)
	if w.Code != 200 {
		t.Fatalf("UpdateRule: status %d, body %s", w.Code, w.Body.String())
	}
	all, _ := db.ListFirewallRules()
	if len(all) != 1 || all[0].Action != "drop" || all[0].Saddr != "10.0.0.9" || all[0].Description != "editada" {
		t.Fatalf("expected the edit applied, got %+v", all)
	}
	// C-2: editar não pode expulsar a regra do grupo dela — sem o group_id
	// preservado, a linha vira órfã, é descartada pela reconciliação e some
	// do firewall continuando visível no painel.
	if all[0].GroupID != g.ID {
		t.Fatalf("expected the rule to stay in its group, got %+v", all[0])
	}
	// Asserção forte restaurada: o conteúdo EDITADO chegou ao nft, dentro da
	// chain do grupo da regra.
	want := "nft add rule inet linkguard " + g.ChainName + " ip saddr 10.0.0.9 counter drop"
	found := false
	for _, c := range exec.executed {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q among the reconcile's commands, ran: %v", want, exec.executed)
	}
}

func TestDeleteRuleRemovesAndReconciles(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)
	g := newRuleGroup(t, db)
	row := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.5"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("DELETE", "/api/nftables/rules", ruleBodyJSON(t, map[string]any{"id": row.ID}))
	w := httptest.NewRecorder()
	h.DeleteRule(w, req)
	if w.Code != 200 {
		t.Fatalf("DeleteRule: status %d, body %s", w.Code, w.Body.String())
	}
	all, _ := db.ListFirewallRules()
	if len(all) != 0 {
		t.Fatalf("expected the rule deleted, got %d remaining", len(all))
	}
	flushed := false
	for _, c := range exec.executed {
		if c == "nft flush chain inet linkguard "+g.ChainName {
			flushed = true
		}
		if strings.Contains(c, "10.0.0.5") {
			t.Errorf("deleted rule must not be rendered into nft anymore, ran: %q", c)
		}
	}
	if !flushed {
		t.Errorf("expected the delete to trigger a reconcile (flush), ran: %v", exec.executed)
	}
}

func TestToggleRuleDisablesWithoutDeleting(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)
	row := &storage.FirewallRule{Action: "drop", Saddr: "10.0.0.7"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("POST", "/api/nftables/rules/toggle", ruleBodyJSON(t, map[string]any{
		"id": row.ID, "enabled": false,
	}))
	w := httptest.NewRecorder()
	h.ToggleRule(w, req)
	if w.Code != 200 {
		t.Fatalf("ToggleRule: status %d, body %s", w.Code, w.Body.String())
	}

	all, _ := db.ListFirewallRules()
	if len(all) != 1 {
		t.Fatalf("expected the rule to still exist (disabled, not deleted), got %d", len(all))
	}
	if all[0].Enabled {
		t.Error("expected the rule disabled")
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.7") {
			t.Errorf("a disabled rule must never be rendered into nft, ran: %q", c)
		}
	}
}

func TestReorderRulesRejectsPartialList(t *testing.T) {
	h, db, _ := newFirewallRulesTestHandler(t)
	r1 := &storage.FirewallRule{Action: "accept"}
	r2 := &storage.FirewallRule{Action: "drop"}
	for _, r := range []*storage.FirewallRule{r1, r2} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}

	// Missing r2 entirely — a partial reorder would silently drop it.
	req := httptest.NewRequest("POST", "/api/nftables/rules/reorder", ruleBodyJSON(t, map[string]any{
		"ids": []string{r1.ID},
	}))
	w := httptest.NewRecorder()
	h.ReorderRules(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for a partial reorder list, got %d: %s", w.Code, w.Body.String())
	}

	all, _ := db.ListFirewallRules()
	if all[0].ID != r1.ID || all[1].ID != r2.ID {
		t.Fatalf("expected the original order preserved after a rejected reorder, got %s,%s", all[0].ID, all[1].ID)
	}
}

func TestReorderRulesRejectsUnknownID(t *testing.T) {
	h, db, _ := newFirewallRulesTestHandler(t)
	r1 := &storage.FirewallRule{Action: "accept"}
	if err := db.CreateFirewallRule(r1); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/nftables/rules/reorder", ruleBodyJSON(t, map[string]any{
		"ids": []string{r1.ID, "does-not-exist"},
	}))
	w := httptest.NewRecorder()
	h.ReorderRules(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for an unknown id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReorderRulesAppliesValidFullList(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)
	r1 := &storage.FirewallRule{Action: "accept", Description: "first"}
	r2 := &storage.FirewallRule{Action: "drop", Description: "second"}
	for _, r := range []*storage.FirewallRule{r1, r2} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}
	exec.executed = nil

	req := httptest.NewRequest("POST", "/api/nftables/rules/reorder", ruleBodyJSON(t, map[string]any{
		"ids": []string{r2.ID, r1.ID},
	}))
	w := httptest.NewRecorder()
	h.ReorderRules(w, req)
	if w.Code != 200 {
		t.Fatalf("ReorderRules: status %d, body %s", w.Code, w.Body.String())
	}
	all, _ := db.ListFirewallRules()
	if all[0].ID != r2.ID || all[1].ID != r1.ID {
		t.Fatalf("expected reordered r2,r1, got %s,%s", all[0].ID, all[1].ID)
	}
	if len(exec.executed) == 0 {
		t.Error("expected the reorder to trigger a reconcile")
	}
}

// TestOverviewShowsDisabledRuleWithoutHandleOrCounter proves the unified
// overview represents a disabled rule honestly instead of hiding it: it
// exists in the DB but was never rendered into nft, so it shows up inside
// its group's chain with no handle and no counter — not zero, "not
// measured". Since Phase C1 the chain is the group's (I-3): the merge used
// to run only on user_rules, and the migration deleted that chain, so the
// disabled rule disappeared from the only screen that shows the whole
// firewall.
func TestOverviewShowsDisabledRuleWithoutHandleOrCounter(t *testing.T) {
	h, db, _ := newFirewallRulesTestHandler(t)
	g := newRuleGroup(t, db)
	row := &storage.FirewallRule{GroupID: g.ID, Action: "drop", Saddr: "10.0.0.42", Description: "em teste"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.SetFirewallRuleEnabled(row.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/nftables/overview", nil)
	w := httptest.NewRecorder()
	h.Overview(w, req)
	if w.Code != 200 {
		t.Fatalf("Overview: status %d, body %s", w.Code, w.Body.String())
	}

	var chains []nftables.ChainInfo
	if err := json.Unmarshal(w.Body.Bytes(), &chains); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var ur *nftables.ChainInfo
	for i := range chains {
		if chains[i].Name == g.ChainName {
			ur = &chains[i]
		}
	}
	if ur == nil {
		t.Fatalf("group chain %s missing from overview: %+v", g.ChainName, chains)
	}
	if len(ur.Rules) != 1 {
		t.Fatalf("expected the disabled rule to still show up, got %+v", ur.Rules)
	}
	got := ur.Rules[0]
	if got.ID != row.ID {
		t.Errorf("expected the disabled rule's stable id, got %+v", got)
	}
	if got.Enabled == nil || *got.Enabled {
		t.Errorf("expected enabled=false, got %+v", got)
	}
	if got.HasCounter {
		t.Errorf("a rule never sent to nft must never claim a counter, got %+v", got)
	}
	if got.Handle != 0 {
		t.Errorf("a disabled rule has no real nft handle, got %d", got.Handle)
	}
}
