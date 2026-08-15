package firewallrules_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// fakeExec is a minimal firewall.Executor: it answers ListUserRules'
// `nft -a list chain ... user_rules` with a configurable fixture and records
// every mutating command so ReconcileUserRules' output can be asserted.
// checkErr, when set, is what the `nft -c` pre-flight (ExecuteRead with a
// "-c" argument) fails with, independent of the ListUserRules/Persist reads.
type fakeExec struct {
	userRulesOut string
	dryRun       bool
	executed     []string
	checkErr     error
}

func (f *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	f.executed = append(f.executed, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-c") && strings.Contains(joined, "-f") {
		return "", f.checkErr
	}
	if strings.Contains(joined, "-a list chain") && strings.Contains(joined, "user_rules") {
		return f.userRulesOut, nil
	}
	return "table inet linkguard {\n}\n", nil // Persist's `nft list table` read
}

func (f *fakeExec) IsDryRun() bool { return f.dryRun }

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

// newTestService constrói o serviço já com os dois grupos do sistema na
// lista — que é como toda máquina fica logo no começo do boot, antes de
// qualquer coisa que reconcilie (ver a ordem em cmd/linkguard-fw/main.go).
//
// Sem eles, Reconcile se recusa a reconstruir a chain forward, e com razão:
// uma forward montada a partir de uma lista sem os grupos do sistema sairia
// sem os bloqueios administrativos. Um teste que reconcilia sem esse passo
// não estaria testando um estado que a produção alcança.
//
// Também liga nft a uma fonte de NTP explícita e vazia (m3 da revisão da
// Fase C2): antes, um *nftables.Service sem SetInputChainSources tratava a
// ausência da fonte como "NTP desligado" em silêncio; agora é erro, e faria
// todo teste que passa por aqui (praticamente todos os deste arquivo) falhar
// só por causa da chain input, que nenhum deles está exercitando. A fonte
// devolve "desligado, sem grupos" — a mesma coisa que o silêncio antigo
// fingia, só que declarada explicitamente por quem constrói o Service em vez
// de herdada de um default perigoso.
func newTestService(t *testing.T, db *storage.DB, nft *nftables.Service) *firewallrules.Service {
	t.Helper()
	nft.SetInputChainSources(
		func() ([]nftables.StoredGroup, error) { return nil, nil },
		func() ([]string, bool, error) { return nil, false, nil },
	)
	// Reconciliar termina em Persist, que grava o ruleset de BOOT em disco —
	// a única escrita que o executor falso não intercepta. Sem esta linha, a
	// suíte tenta sobrescrever o /etc/nftables.conf da máquina com o dump do
	// executor falso; como root na própria appliance, isso é o firewall vazio
	// no próximo boot.
	nft.SetConfPath(filepath.Join(t.TempDir(), "nftables.conf"))
	svc := firewallrules.NewService(db, nft)
	if err := svc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar os grupos do sistema: %v", err)
	}
	return svc
}

// newTestGroup cria um grupo com o mesmo formato de chain que a produção usa
// (GroupChainName sobre o id) — um nome fora de grp_[a-z0-9_] faria a
// reconciliação pular o grupo inteiro, e o teste passaria a medir o filtro
// de segurança em vez do que ele quer medir.
func newTestGroup(t *testing.T, db *storage.DB, name string) storage.FirewallGroup {
	t.Helper()
	id := fmt.Sprintf("%012x-0000-4000-8000-000000000000", len(name)*7+1)
	// Depois do que já existe (os grupos do sistema), como o CRUD real faz:
	// duas linhas na mesma posição deixariam a ordem da lista à mercê do
	// desempate do SELECT.
	existing, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	g := storage.FirewallGroup{
		ID:          id,
		Name:        name,
		ChainName:   nftables.GroupChainName(id),
		Position:    len(existing),
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
	}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	return g
}

// twoRulesFixture mirrors real `nft -a list chain inet linkguard user_rules`
// output: two rules, each carrying the `# handle N` comment ListUserRules
// relies on, in the order nft prints them (evaluation order).
const twoRulesFixture = `table inet linkguard {
	chain user_rules {
		ip saddr 192.168.3.50 tcp dport 22 counter packets 10 bytes 600 accept # handle 5
		ip daddr 203.0.113.5 counter packets 0 bytes 0 drop # handle 7
	}
}
`

func TestImportOnceImportsExistingRulesPreservingOrder(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: twoRulesFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}

	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 imported rules, got %d: %+v", len(rules), rules)
	}
	if rules[0].Action != "accept" || rules[0].Saddr != "192.168.3.50" || rules[0].Proto != "tcp" || rules[0].Dport != "22" {
		t.Errorf("expected rule 0 to match the first nft rule, got %+v", rules[0])
	}
	if rules[1].Action != "drop" || rules[1].Daddr != "203.0.113.5" {
		t.Errorf("expected rule 1 to match the second nft rule, got %+v", rules[1])
	}
	if rules[0].Position >= rules[1].Position {
		t.Errorf("expected order preserved (position 0 before 1), got %d, %d", rules[0].Position, rules[1].Position)
	}
	if !rules[0].Enabled || !rules[1].Enabled {
		t.Errorf("expected imported rules to start enabled, got %+v", rules)
	}

	flag, err := db.GetSetting(firewallrules.ImportedSettingKey)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag == "" {
		t.Error("expected the import guard to be set after ImportOnce")
	}
}

func TestImportOnceRunsOnlyOnce(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: twoRulesFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("first ImportOnce: %v", err)
	}

	// Simulate the nft chain gaining a rule between boots (should never be
	// picked up by a second ImportOnce — the guard already tripped).
	exec.userRulesOut = twoRulesFixture + "" // unchanged is fine; add a third below
	exec.userRulesOut = `table inet linkguard {
	chain user_rules {
		ip saddr 192.168.3.50 tcp dport 22 counter packets 10 bytes 600 accept # handle 5
		ip daddr 203.0.113.5 counter packets 0 bytes 0 drop # handle 7
		ip saddr 10.0.0.9 counter packets 0 bytes 0 drop # handle 9
	}
}
`
	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("second ImportOnce: %v", err)
	}

	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected the second ImportOnce to be a no-op (still 2 rules), got %d: %+v", len(rules), rules)
	}
}

// TestImportOnceDoesNotResurrectDeliberatelyDeletedRules is the regression
// test for the exact failure mode the design spec calls out: guarding the
// import on "has it ever run" (a settings flag) rather than "is the table
// empty" — otherwise an admin who legitimately deletes every rule would see
// them come back from nft on the very next boot, since nft's user_rules
// chain (rebuilt by ReconcileUserRules from the now-empty DB) would also be
// empty by then... but a NAIVE "table empty -> import" guard would instead
// re-read whatever ListUserRules still reports from the live nft chain
// before any reconcile has run post-boot. This test proves the settings-flag
// guard makes that impossible: once the import has run, a fully emptied DB
// stays empty no matter what ImportOnce is called again with.
func TestImportOnceDoesNotResurrectDeliberatelyDeletedRules(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: twoRulesFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("first ImportOnce: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules after the import, got %d", len(rules))
	}

	// The admin deliberately deletes every rule via the API/DB.
	for _, r := range rules {
		if err := db.DeleteFirewallRule(r.ID); err != nil {
			t.Fatalf("DeleteFirewallRule: %v", err)
		}
	}
	empty, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected 0 rules after deleting all, got %d", len(empty))
	}

	// Simulate a reboot: ImportOnce runs again with the OLD nft fixture (as
	// if ReconcileUserRules had not yet had a chance to flush the live
	// chain down to empty). A naive "table empty -> import" guard would
	// resurrect both rules here. The settings-flag guard must not.
	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce after delete-all: %v", err)
	}
	after, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("deliberately deleted rules must never be resurrected by ImportOnce, got %d rules back: %+v", len(after), after)
	}
}

// I-4: uma regra que o modelo de 7 campos nem consegue validar (aqui `meta
// mark set 0x1`, sem verbo accept/drop/reject) era pulada — nunca chegava
// ao banco — e o Reconcile da linha seguinte a apagava do nft. Sumia da
// máquina sem deixar rastro em lugar nenhum, contrariando o "nada é
// perdido" da spec §4.1. Agora usa a mesma saída de emergência do caso
// não-representável: entra DESATIVADA, com o texto bruto preservado na
// descrição.
func TestImportOnceImportsUnvalidatableRuleDisabledWithRawTextPreserved(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: `table inet linkguard {
	chain user_rules {
		meta mark set 0x1 # handle 3
		ip saddr 10.0.0.5 counter packets 0 bytes 0 drop # handle 4
	}
}
`}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce must not abort on one unparsable rule: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("as duas regras têm que chegar ao banco (nada é perdido), obtive %d: %+v", len(rules), rules)
	}
	unvalidatable := rules[0]
	if unvalidatable.Enabled {
		t.Errorf("a regra não-validável tem que entrar DESATIVADA, obtive enabled=%v: %+v", unvalidatable.Enabled, unvalidatable)
	}
	if !strings.Contains(unvalidatable.Description, "meta mark set 0x1") {
		t.Errorf("o texto bruto tem que ficar na descrição para o admin poder reescrevê-la, obtive %q", unvalidatable.Description)
	}
	if rules[1].Action != "drop" || rules[1].Saddr != "10.0.0.5" || !rules[1].Enabled {
		t.Errorf("a regra válida tem que ser importada normalmente, ativada e na mesma ordem, obtive %+v", rules[1])
	}
}

func TestImportOnceWithNoExistingRulesStillSetsGuard(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
	flag, err := db.GetSetting(firewallrules.ImportedSettingKey)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag == "" {
		t.Error("expected the import guard set even with nothing to import")
	}
}

// ─── C-2: round-trip check before trusting a best-effort parse ────────────
//
// parseRuleFields ignores tokens it doesn't understand, so a rule richer
// than the 7-field model isn't rejected by ValidateRuleFields — it's
// silently reduced to whatever survived, which then means something
// different once re-rendered. These two rules are the exact examples from
// the design review: `ct state established,related counter accept` and
// `tcp flags syn / fin,syn,rst,ack counter drop`.

const ctStateRuleFixture = `table inet linkguard {
	chain user_rules {
		ct state established,related counter packets 12 bytes 900 accept # handle 3
	}
}
`

const tcpFlagsRuleFixture = `table inet linkguard {
	chain user_rules {
		tcp flags syn / fin,syn,rst,ack counter packets 4 bytes 240 drop # handle 8
	}
}
`

func TestImportOnceImportsUnmodellableCtStateRuleDisabledWithRawTextPreserved(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: ctStateRuleFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected the rule imported (disabled, not skipped outright), got %d: %+v", len(rules), rules)
	}
	r := rules[0]
	// Before the fix: this rule's best-effort parse collapses to just
	// {Action: accept} — which, imported enabled and reconciled, silently
	// becomes "accept everything", not what the live rule actually said.
	if r.Action != "accept" || r.Saddr != "" || r.Proto != "" {
		t.Fatalf("expected the best-effort parse to have collapsed to just {Action: accept} (proving the danger), got %+v", r)
	}
	if r.Enabled {
		t.Errorf("expected an unmodellable rule imported DISABLED so it can never silently change what the live rule meant, got enabled=%v", r.Enabled)
	}
	if !strings.Contains(r.Description, "ct state established,related") {
		t.Errorf("expected the original raw nft text preserved in the description so the admin can see what could not be modelled and re-author it, got %q", r.Description)
	}
}

func TestImportOnceImportsUnmodellableTCPFlagsRuleDisabledWithRawTextPreserved(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: tcpFlagsRuleFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected the rule imported (disabled), got %d: %+v", len(rules), rules)
	}
	r := rules[0]
	// Before the fix: collapses to {Proto: tcp, Action: drop} — imported
	// enabled and reconciled, that silently becomes "drop all TCP", not
	// "drop this one TCP flag combination".
	if r.Proto != "tcp" || r.Action != "drop" || r.Dport != "" {
		t.Fatalf("expected the best-effort parse to have collapsed to {Proto: tcp, Action: drop} (proving the danger), got %+v", r)
	}
	if r.Enabled {
		t.Errorf("expected the unmodellable rule imported DISABLED, got enabled=%v", r.Enabled)
	}
	if !strings.Contains(r.Description, "fin,syn,rst,ack") {
		t.Errorf("expected the original raw nft text preserved in the description, got %q", r.Description)
	}
}

// TestImportOnceRoundTrippingRuleImportsEnabledWithNoDescriptionOverwrite is
// the GREEN contrast case: a rule that fits the 7-field model exactly
// round-trips identically, so it must import enabled, same as before this
// fix, with its (absent) description left alone rather than stuffed with
// raw nft text it doesn't need.
func TestImportOnceRoundTrippingRuleImportsEnabledWithNoDescriptionOverwrite(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{userRulesOut: twoRulesFixture}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if err := svc.ImportOnce(context.Background()); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected both plain rules imported, got %d: %+v", len(rules), rules)
	}
	for _, r := range rules {
		if !r.Enabled {
			t.Errorf("expected a faithfully-round-tripping rule imported enabled, got %+v", r)
		}
		if r.Description != "" {
			t.Errorf("expected no description stuffed onto a rule that round-tripped fine, got %+v", r)
		}
	}
}

// ─── C-3: apply-status is persisted after every Reconcile ─────────────────

func TestReconcileRecordsSuccessfulApplyStatus(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	if svc.LastApplyStatus() != nil {
		t.Fatal("expected no apply status before Reconcile has ever run")
	}

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("expected an apply status recorded after Reconcile")
	}
	if !st.OK || st.Error != "" {
		t.Errorf("expected a successful reconcile recorded ok with no error, got %+v", st)
	}
	if st.At == 0 {
		t.Errorf("expected a non-zero timestamp, got %+v", st)
	}
}

// failingRebuildExec makes rebuildChain's "add rule" step fail so
// ReconcileUserRules returns an error — recordApplyStatus must still see
// and persist it. Flush and Persist's own reads still succeed so the
// failure is unambiguously the rule-add step.
type failingRebuildExec struct{ fakeExec }

func (f *failingRebuildExec) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "add") && strings.Contains(joined, "rule") {
		return "", errors.New("nft: rejected")
	}
	return f.fakeExec.Execute(ctx, cmd, args...)
}

func TestReconcileRecordsFailedApplyStatusWithNftsMessage(t *testing.T) {
	db := newTestDB(t)
	exec := &failingRebuildExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	row := &storage.FirewallRule{Action: "accept", Saddr: "10.0.0.1"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("expected Reconcile to surface the rule-add failure")
	}
	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("expected an apply status recorded even though Reconcile failed")
	}
	if st.OK {
		t.Errorf("expected the failed reconcile recorded as not-ok, got %+v", st)
	}
	if st.Error == "" {
		t.Errorf("expected nft's own rejection message preserved in the status, got %+v", st)
	}
}

// ─── CheckPending (C-1 layer 2: pre-flight nft -c before any DB write) ─────

func TestCheckPendingRejectsWhatNftWouldReject(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{checkErr: errors.New("nft: Error: could not process rule")}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	candidate := []storage.FirewallRule{{Enabled: true, Action: "accept", Saddr: "10.0.0.1"}}
	if err := svc.CheckPending(context.Background(), candidate); err == nil {
		t.Fatal("expected CheckPending to surface nft's rejection")
	}
}

func TestCheckPendingAcceptsAWellFormedCandidate(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	candidate := []storage.FirewallRule{{Enabled: true, Action: "drop", Daddr: "203.0.113.0/24"}}
	if err := svc.CheckPending(context.Background(), candidate); err != nil {
		t.Fatalf("expected a well-formed candidate to pass, got: %v", err)
	}
}

// Fase C1: as regras do admin não moram mais na chain user_rules — cada uma
// mora na chain do SEU grupo, e a forward alcança o grupo por um jump. Este
// teste é o mesmo de antes traduzido para esse mundo: só a regra ativada é
// renderizada, e ela é renderizada na chain do grupo dela.
func TestReconcileRendersEnabledDBRulesIntoTheirGroupChain(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	g := newTestGroup(t, db, "Minhas regras")

	enabled := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.1"}
	if err := db.CreateFirewallRule(enabled); err != nil {
		t.Fatalf("CreateFirewallRule enabled: %v", err)
	}
	disabled := &storage.FirewallRule{GroupID: g.ID, Action: "drop", Saddr: "10.0.0.2"}
	if err := db.CreateFirewallRule(disabled); err != nil {
		t.Fatalf("CreateFirewallRule disabled: %v", err)
	}
	if err := db.SetFirewallRuleEnabled(disabled.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled: %v", err)
	}

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var adds []string
	flushedGroup, jumped := false, false
	for _, c := range exec.executed {
		if c == "nft flush chain inet linkguard "+g.ChainName {
			flushedGroup = true
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard "+g.ChainName) {
			adds = append(adds, c)
		}
		if strings.HasPrefix(c, "nft add rule inet linkguard forward") && strings.Contains(c, "jump "+g.ChainName) {
			jumped = true
		}
	}
	if !flushedGroup {
		t.Errorf("esperava a chain do grupo reconstruída, rodou: %v", exec.executed)
	}
	if !jumped {
		t.Errorf("a forward tem que alcançar o grupo com um jump, rodou: %v", exec.executed)
	}
	if len(adds) != 1 {
		t.Fatalf("esperava exatamente 1 add-rule (a regra ativada), obtive %d: %v", len(adds), adds)
	}
	if !strings.Contains(adds[0], "10.0.0.1") {
		t.Errorf("esperava o saddr da regra ativada renderizado, obtive %q", adds[0])
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.2") {
			t.Errorf("a regra desativada nunca pode ser renderizada no nft, rodou: %q", c)
		}
	}
}

// Uma regra cujo group_id não aponta para grupo nenhum não tem chain para
// onde ir. Renderizá-la em lugar nenhum é o comportamento correto — mas ela
// não pode ser renderizada na chain de OUTRO grupo, nem reviver a user_rules.
func TestReconcileLeavesARuleWithoutAValidGroupOutOfTheFirewall(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	g := newTestGroup(t, db, "Minhas regras")
	if err := db.CreateFirewallRule(&storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.1"}); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{GroupID: "grupo-que-nao-existe", Action: "accept", Saddr: "10.0.0.9"}); err != nil {
		t.Fatalf("CreateFirewallRule órfã: %v", err)
	}

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.9") {
			t.Errorf("regra sem grupo válido foi renderizada mesmo assim: %q", c)
		}
	}
}

// O contrato de ReconcileGroups: lista vazia APAGA todas as chains de grupo
// e esvazia a forward, bloqueios inclusive (eles são itens da lista desde que
// a forward virou uma lista ordenada só). Um erro de leitura do banco que virasse
// lista vazia levaria junto o firewall inteiro do admin. Erro de leitura tem
// que abortar antes de qualquer comando do nft.
func TestReconcileAbortsOnDBErrorInsteadOfWipingTheFirewall(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	newTestGroup(t, db, "Minhas regras")
	db.Close() // qualquer leitura a partir daqui falha

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("esperava que o erro de leitura do banco abortasse o Reconcile")
	}
	if len(exec.executed) != 0 {
		t.Errorf("nenhum comando do nft pode ter rodado com o banco ilegível, rodou: %v", exec.executed)
	}
}

// TestReconcileRecordsApplyStatusOnDBReadError prova que o caminho de erro
// de leitura de storedGroups grava o apply-status antes de retornar — não só
// que ele aborta sem rodar comando do nft (já coberto acima). Sem essa
// asserção, remover o s.recordApplyStatus(err) desse `if err != nil` não é
// pego por teste nenhum: o Reconcile continua devolvendo erro do mesmo jeito
// (o caller vê a falha), só o painel é que fica sem explicação nenhuma do
// que aconteceu.
//
// Diferente do teste acima, aqui só a tabela lida (firewall_groups) é
// derrubada, não o banco inteiro: se fechássemos a conexão como o teste
// irmão faz, a própria escrita do apply-status em `settings` falharia junto
// (seria logada como aviso e engolida), e a asserção de LastApplyStatus não
// provaria nada.
func TestReconcileRecordsApplyStatusOnDBReadError(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	newTestGroup(t, db, "Minhas regras")
	if _, err := db.Conn().Exec(`DROP TABLE firewall_groups`); err != nil {
		t.Fatalf("derrubar firewall_groups: %v", err)
	}

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("esperava que o erro de leitura do banco abortasse o Reconcile")
	}

	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("o erro de leitura do banco tem que ficar registrado no apply-status -- sem isso o painel não mostra nada de errado")
	}
	if st.OK {
		t.Errorf("apply-status não pode dizer ok quando o Reconcile abortou por erro de leitura: %+v", st)
	}
	if st.Error == "" {
		t.Error("apply-status tem que trazer a mensagem do erro de leitura")
	}
}

// I-8: uma regra ativada que não pôde ser renderizada (campos inválidos
// numa linha de banco antiga ou editada à mão) some do firewall sem
// nenhum aviso: o rebuild da chain termina bem, Reconcile devolvia nil e
// o apply_status era gravado ok:true. O painel dizia "aplicado" com a
// regra ausente do nft. Agora o status registra não-ok, com a contagem e
// o id da regra, para a faixa de aviso do painel poder mostrar.
func TestReconcileRecordsNotOKWhenAnEnabledRuleCouldNotBeRendered(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	g := newTestGroup(t, db, "Minhas regras")
	bad := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Iif: "eth0\" ; flush ruleset #"}
	if err := db.CreateFirewallRule(bad); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{GroupID: g.ID, Action: "drop", Saddr: "10.0.0.5"}); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("uma regra impossível de renderizar não pode abortar o reconcile das outras: %v", err)
	}
	st := svc.LastApplyStatus()
	if st == nil {
		t.Fatal("esperava um status de apply registrado")
	}
	if st.OK {
		t.Errorf("apply_status não pode dizer ok com uma regra ativada fora do firewall: %+v", st)
	}
	if !strings.Contains(st.Error, bad.ID) {
		t.Errorf("o status tem que identificar a regra que não foi aplicada, obtive %q", st.Error)
	}
}

// forwardFailingExec recusa exatamente os `add rule` da chain forward — o
// resto (chains de grupo, flushes, leituras) funciona. É como se comporta um
// nft que rejeita a linha do jump (condição que o kernel recusa, set que
// sumiu): o firewall fica com as chains dos grupos prontas e a forward
// vazia, sem alcançar nenhuma delas.
type forwardFailingExec struct{ fakeExec }

func (f *forwardFailingExec) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if strings.HasPrefix(joined, "add rule inet linkguard forward") {
		f.executed = append(f.executed, cmd+" "+joined)
		return "", errors.New("nft: Error: Could not process rule: Device or resource busy")
	}
	return f.fakeExec.Execute(ctx, cmd, args...)
}

// ReconcileGroups pode devolver, numa passada só, um erro que embrulha um
// SkippedRulesError (regra ativada que não renderiza — não fatal, vira faixa
// no painel) E a recusa do próprio nft (fatal: o firewall NÃO está como o
// banco manda). Um errors.As ingênuo, herdado do tempo da user_rules, trata
// os dois como "só uma regra fora" e devolve nil: o chamador acha que
// aplicou, e a migração — que só remove a user_rules depois de a forward ter
// sido reconstruída — removeria a chain com a forward ainda quebrada.
func TestReconcileDoesNotSwallowAnNftRefusalThatArrivesWithASkippedRule(t *testing.T) {
	db := newTestDB(t)
	exec := &forwardFailingExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	g := newTestGroup(t, db, "Minhas regras")
	bad := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Iif: "eth0\" ; flush ruleset #"}
	if err := db.CreateFirewallRule(bad); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	err := svc.Reconcile(context.Background())
	if err == nil {
		t.Fatal("a recusa do nft não pode ser engolida só porque veio junto de uma regra pulada")
	}
	var skipped *nftables.SkippedRulesError
	if !errors.As(err, &skipped) {
		t.Errorf("o erro composto tem que continuar carregando os ids das regras puladas, obtive %q", err)
	}
	st := svc.LastApplyStatus()
	if st == nil || st.OK {
		t.Errorf("apply_status não pode dizer ok com a forward recusada pelo nft: %+v", st)
	}
}

// CheckPendingGroups é o pré-voo (`nft -c`) do mundo dos grupos, espelhando
// CheckPending: roda ANTES da escrita no banco, e o que o nft recusa nunca
// chega a ser gravado.
func TestCheckPendingGroupsRejectsWhatNftWouldReject(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{checkErr: errors.New("nft: Error: could not process rule")}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	candidate := []nftables.StoredGroup{{
		ID: "a3f21c08-0000-4000-8000-000000000000", Name: "Wi-Fi",
		ChainName: nftables.GroupChainName("a3f21c08-0000-4000-8000-000000000000"),
		Enabled:   true, Fallthrough: nftables.FallthroughContinue,
		Rules: []nftables.StoredRule{{ID: "r1", Enabled: true,
			Fields: nftables.RuleFields{Action: "accept", Saddr: "10.0.0.1"}}},
	}}
	if err := svc.CheckPendingGroups(context.Background(), candidate); err == nil {
		t.Fatal("esperava que CheckPendingGroups mostrasse a recusa do nft")
	}
}

func TestCheckPendingGroupsAcceptsAWellFormedCandidate(t *testing.T) {
	db := newTestDB(t)
	exec := &fakeExec{}
	nft := nftables.NewService(exec)
	svc := newTestService(t, db, nft)

	candidate := []nftables.StoredGroup{{
		ID: "b3f21c08-0000-4000-8000-000000000000", Name: "Wi-Fi",
		ChainName: nftables.GroupChainName("b3f21c08-0000-4000-8000-000000000000"),
		Enabled:   true, Fallthrough: nftables.FallthroughDrop,
		Rules: []nftables.StoredRule{{ID: "r1", Enabled: true,
			Fields: nftables.RuleFields{Action: "drop", Daddr: "203.0.113.0/24"}}},
	}}
	if err := svc.CheckPendingGroups(context.Background(), candidate); err != nil {
		t.Fatalf("um candidato bem formado tinha que passar, obtive: %v", err)
	}
}

// Fase C2: a conversão banco → nftables tem que carregar o escopo. Ela é o
// que decide em QUAL chain o grupo é alcançado — perder o campo aqui compila,
// passa em todo o resto da suíte, e o efeito é um grupo que o admin escreveu
// para o tráfego destinado ao firewall (SSH, painel) ser aplicado ao tráfego
// que atravessa. Pela mesma razão, Kind e todos os campos compartilhados são
// protegidos pelo mapper canônico firewallrules.ToStoredGroup.
func TestStoredGroupsCarriesTheScope(t *testing.T) {
	db := newTestDB(t)
	nft := nftables.NewService(&fakeExec{})
	svc := firewallrules.NewService(db, nft)

	for _, g := range []storage.FirewallGroup{
		{ID: "i", Name: "Acesso ao painel", ChainName: "grp_iii", Position: 0,
			Enabled: true, Fallthrough: nftables.FallthroughContinue,
			Kind: nftables.GroupKindAdmin, Scope: nftables.ScopeInput},
		{ID: "f", Name: "Visitantes", ChainName: "grp_fff", Position: 1,
			Enabled: true, Fallthrough: nftables.FallthroughContinue,
			Kind: nftables.GroupKindAdmin, Scope: nftables.ScopeForward},
	} {
		row := g
		if err := db.CreateFirewallGroup(&row); err != nil {
			t.Fatalf("criar grupo %s: %v", g.ID, err)
		}
	}

	got, err := svc.StoredGroups()
	if err != nil {
		t.Fatalf("StoredGroups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 grupos, obtive %d", len(got))
	}
	if got[0].Scope != nftables.ScopeInput {
		t.Errorf("o escopo input não sobreviveu à conversão: %q", got[0].Scope)
	}
	if got[1].Scope != nftables.ScopeForward {
		t.Errorf("o escopo forward não sobreviveu à conversão: %q", got[1].Scope)
	}
}
