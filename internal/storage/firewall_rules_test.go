package storage_test

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── firewall_rules (Phase B: the admin's rules live in the DB) ────────────

func TestCreateFirewallRuleAppendsAtTheEndAndStartsEnabled(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24"}
	if err := db.CreateFirewallRule(r1); err != nil {
		t.Fatalf("CreateFirewallRule r1: %v", err)
	}
	if r1.ID == "" {
		t.Error("expected ID to be set after create")
	}
	if !r1.Enabled {
		t.Error("expected a newly created rule to start enabled")
	}
	if r1.Position != 0 {
		t.Errorf("expected first rule at position 0, got %d", r1.Position)
	}

	r2 := &storage.FirewallRule{Action: "accept", Saddr: "192.168.3.0/24"}
	if err := db.CreateFirewallRule(r2); err != nil {
		t.Fatalf("CreateFirewallRule r2: %v", err)
	}
	if r2.Position != 1 {
		t.Errorf("expected second rule appended at position 1, got %d", r2.Position)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(all))
	}
	if all[0].ID != r1.ID || all[1].ID != r2.ID {
		t.Errorf("expected rules ordered by position (r1, r2), got %+v", all)
	}
}

func TestListFirewallRulesEmptyIsNotNil(t *testing.T) {
	db := newTestDB(t)

	got, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if got == nil {
		t.Error("expected an empty slice, got nil")
	}
}

func TestUpdateFirewallRuleChangesContentNotPositionOrEnabled(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24", Description: "bloqueio inicial"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.SetFirewallRuleEnabled(r.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled: %v", err)
	}

	edit := &storage.FirewallRule{
		ID: r.ID, Action: "reject", Saddr: "10.0.0.0/8", Proto: "tcp", Dport: "22",
		Description: "regra editada",
	}
	if err := db.UpdateFirewallRule(edit); err != nil {
		t.Fatalf("UpdateFirewallRule: %v", err)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(all))
	}
	got := all[0]
	if got.Action != "reject" || got.Saddr != "10.0.0.0/8" || got.Proto != "tcp" || got.Dport != "22" {
		t.Errorf("expected edited content, got %+v", got)
	}
	if got.Description != "regra editada" {
		t.Errorf("expected updated description, got %q", got.Description)
	}
	if got.Position != 0 {
		t.Errorf("expected position untouched by content edit, got %d", got.Position)
	}
	if got.Enabled {
		t.Error("expected enabled flag untouched by content edit (still disabled)")
	}
}

func TestDeleteFirewallRule(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "accept"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if err := db.DeleteFirewallRule(r.ID); err != nil {
		t.Fatalf("DeleteFirewallRule: %v", err)
	}
	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(all))
	}
}

// TestDeleteFirewallRuleUnknownIDErrors is the I-7 regression test:
// DeleteFirewallRule used to ignore RowsAffected, so deleting a
// non-existent id silently "succeeded" — unlike UpdateFirewallRule and
// SetFirewallRuleEnabled, both of which already report not-found.
func TestDeleteFirewallRuleUnknownIDErrors(t *testing.T) {
	db := newTestDB(t)
	if err := db.DeleteFirewallRule("does-not-exist"); err == nil {
		t.Error("expected an error for an unknown rule id")
	}
}

func TestSetFirewallRuleEnabledTogglesWithoutDeleting(t *testing.T) {
	db := newTestDB(t)

	r := &storage.FirewallRule{Action: "drop"}
	if err := db.CreateFirewallRule(r); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	if err := db.SetFirewallRuleEnabled(r.ID, false); err != nil {
		t.Fatalf("SetFirewallRuleEnabled(false): %v", err)
	}
	all, _ := db.ListFirewallRules()
	if len(all) != 1 {
		t.Fatalf("expected the rule to still exist after disabling, got %d rules", len(all))
	}
	if all[0].Enabled {
		t.Error("expected rule to be disabled")
	}

	if err := db.SetFirewallRuleEnabled(r.ID, true); err != nil {
		t.Fatalf("SetFirewallRuleEnabled(true): %v", err)
	}
	all, _ = db.ListFirewallRules()
	if !all[0].Enabled {
		t.Error("expected rule to be re-enabled")
	}
}

func TestSetFirewallRuleEnabledUnknownIDErrors(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetFirewallRuleEnabled("does-not-exist", true); err == nil {
		t.Error("expected an error for an unknown rule id")
	}
}

func TestReorderFirewallRulesSetsExplicitPositions(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "accept", Description: "first"}
	r2 := &storage.FirewallRule{Action: "drop", Description: "second"}
	r3 := &storage.FirewallRule{Action: "reject", Description: "third"}
	for _, r := range []*storage.FirewallRule{r1, r2, r3} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}

	// New order: r3, r1, r2
	if err := db.ReorderFirewallRules([]string{r3.ID, r1.ID, r2.ID}); err != nil {
		t.Fatalf("ReorderFirewallRules: %v", err)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(all))
	}
	if all[0].ID != r3.ID || all[1].ID != r1.ID || all[2].ID != r2.ID {
		t.Fatalf("expected order r3,r1,r2 after reorder, got %s,%s,%s", all[0].ID, all[1].ID, all[2].ID)
	}
}

func TestReorderFirewallRulesUnknownIDErrorsAndChangesNothing(t *testing.T) {
	db := newTestDB(t)

	r1 := &storage.FirewallRule{Action: "accept"}
	r2 := &storage.FirewallRule{Action: "drop"}
	for _, r := range []*storage.FirewallRule{r1, r2} {
		if err := db.CreateFirewallRule(r); err != nil {
			t.Fatalf("CreateFirewallRule: %v", err)
		}
	}

	err := db.ReorderFirewallRules([]string{r2.ID, "does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for an unknown id in the reorder list")
	}

	// Nothing should have changed (the whole reorder is one transaction).
	all, lerr := db.ListFirewallRules()
	if lerr != nil {
		t.Fatalf("ListFirewallRules: %v", lerr)
	}
	if all[0].ID != r1.ID || all[1].ID != r2.ID {
		t.Fatalf("expected original order preserved after a failed reorder, got %s,%s", all[0].ID, all[1].ID)
	}
}

// ─── ImportFirewallRules (I-5: one-time import must be atomic) ─────────────
//
// Before this fix, ImportOnce inserted rows one CreateFirewallRule call at a
// time, then set the import guard as a separate write; a crash or DB error
// anywhere in between left the guard unset, so the next boot's ImportOnce
// ran the whole loop again and duplicated every already-imported rule.
// ImportFirewallRules lands every row and the guard flag in a single
// transaction — either all of it commits, or none of it does.

func TestImportFirewallRulesInsertsRowsAndSetsFlagAtomically(t *testing.T) {
	db := newTestDB(t)

	rows := []storage.FirewallRule{
		{Enabled: true, Action: "accept", Saddr: "10.0.0.1"},
		{Enabled: false, Action: "drop", Daddr: "203.0.113.0/24", Description: "não pôde ser importada fielmente"},
	}
	if err := db.ImportFirewallRules(rows, "firewall_rules_imported", "true"); err != nil {
		t.Fatalf("ImportFirewallRules: %v", err)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(all), all)
	}
	if all[0].Position != 0 || all[1].Position != 1 {
		t.Errorf("expected positions assigned by slice order, got %d, %d", all[0].Position, all[1].Position)
	}
	if !all[0].Enabled {
		t.Errorf("expected row 0 enabled as given, got %+v", all[0])
	}
	if all[1].Enabled {
		t.Errorf("expected row 1 disabled as given, got %+v", all[1])
	}
	if all[1].Description != "não pôde ser importada fielmente" {
		t.Errorf("expected the description preserved, got %q", all[1].Description)
	}
	for _, r := range all {
		if r.ID == "" {
			t.Error("expected an ID assigned to every row")
		}
	}

	flag, err := db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag != "true" {
		t.Fatalf("expected the import guard set in the same transaction, got %q", flag)
	}
}

func TestImportFirewallRulesRollsBackEverythingOnFailure(t *testing.T) {
	db := newTestDB(t)

	dupID := "duplicate-id"
	rows := []storage.FirewallRule{
		{ID: dupID, Enabled: true, Action: "accept"},
		{ID: dupID, Enabled: true, Action: "drop"}, // same ID -> UNIQUE constraint failure
	}
	if err := db.ImportFirewallRules(rows, "firewall_rules_imported", "true"); err == nil {
		t.Fatal("expected an error from the duplicate-ID insert")
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected the whole import rolled back (0 rows), got %d: %+v", len(all), all)
	}
	flag, err := db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag != "" {
		t.Fatalf("expected the import guard NOT set when the insert failed partway, got %q", flag)
	}
}

func TestFirewallRulesImportedSettingRoundTrips(t *testing.T) {
	db := newTestDB(t)

	val, err := db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "" {
		t.Fatalf("expected the import guard unset on a fresh DB, got %q", val)
	}

	if err := db.SetSetting("firewall_rules_imported", "true"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	val, err = db.GetSetting("firewall_rules_imported")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if val != "true" {
		t.Fatalf("expected the import guard to stick, got %q", val)
	}
}

// ─── firewall_groups: a migração única (Fase C1) ──────────────────────────

func TestMigrateRulesIntoGroupAdoptsOrphansAndSetsTheGuardAtomically(t *testing.T) {
	db := newTestDB(t)

	solta := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24"}
	if err := db.CreateFirewallRule(solta); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	outro := &storage.FirewallGroup{ID: "grupo-existente", Name: "Wi-Fi",
		ChainName: "grp_ffffffffffff", Enabled: true, Fallthrough: "drop"}
	if err := db.CreateFirewallGroup(outro); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	jaAgrupada := &storage.FirewallRule{GroupID: outro.ID, Action: "accept", Proto: "tcp", Dport: "443"}
	if err := db.CreateFirewallRule(jaAgrupada); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	g := storage.FirewallGroup{ID: "grupo-novo", Name: "Minhas regras",
		ChainName: "grp_aaaaaaaaaaaa", Enabled: true, Fallthrough: "continue"}
	if err := db.MigrateRulesIntoGroup(g, "firewall_groups_migrated", "true"); err != nil {
		t.Fatalf("MigrateRulesIntoGroup: %v", err)
	}

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("esperava o grupo novo ao lado do que já existia, obtive %+v", groups)
	}
	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	for _, r := range all {
		switch r.ID {
		case solta.ID:
			if r.GroupID != g.ID {
				t.Errorf("a regra solta não foi adotada pelo grupo novo: %+v", r)
			}
		case jaAgrupada.ID:
			if r.GroupID != outro.ID {
				t.Errorf("a regra que já tinha grupo foi movida: %+v", r)
			}
		}
	}
	flag, err := db.GetSetting("firewall_groups_migrated")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag != "true" {
		t.Fatalf("esperava a trava gravada na mesma transação, obtive %q", flag)
	}
}

// A trava gravada com só metade das regras adotadas deixaria a outra metade
// órfã — exibida no painel e ausente do firewall — sem nunca mais ter uma
// segunda chance de ser adotada, porque a trava impede a migração de rodar
// de novo. Ou tudo, ou nada.
func TestMigrateRulesIntoGroupRollsBackEverythingOnFailure(t *testing.T) {
	db := newTestDB(t)

	solta := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24"}
	if err := db.CreateFirewallRule(solta); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	const dupID = "id-repetido"
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{ID: dupID, Name: "Já existe",
		ChainName: "grp_bbbbbbbbbbbb", Enabled: true, Fallthrough: "continue"}); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}

	g := storage.FirewallGroup{ID: dupID, Name: "Minhas regras",
		ChainName: "grp_aaaaaaaaaaaa", Enabled: true, Fallthrough: "continue"}
	if err := db.MigrateRulesIntoGroup(g, "firewall_groups_migrated", "true"); err == nil {
		t.Fatal("esperava erro do INSERT com id duplicado")
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if all[0].GroupID != "" {
		t.Errorf("a adoção tinha que ter voltado atrás junto com o INSERT: %+v", all[0])
	}
	flag, err := db.GetSetting("firewall_groups_migrated")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag != "" {
		t.Fatalf("a trava não pode ficar gravada numa migração que falhou, obtive %q", flag)
	}
}

// TestMigrateRulesIntoGroupRollsBackWhenTheUpdateFails prova que a transação
// cobre TODOS os três passos, não só o primeiro. O teste acima
// (TestMigrateRulesIntoGroupRollsBackEverythingOnFailure) injeta a falha no
// INSERT do grupo -- o primeiro comando -- então o UPDATE e o INSERT da
// trava nunca chegam a rodar, e o teste passa igualzinho mesmo se
// MigrateRulesIntoGroup não tivesse transação nenhuma (três db.conn.Exec
// soltos). Aqui a falha é injetada no SEGUNDO comando, via um trigger
// BEFORE UPDATE que aborta o UPDATE de group_id. Isso só prova algo se o
// INSERT do grupo (passo 1, já executado com sucesso antes do trigger
// disparar) for desfeito -- o que só acontece com uma transação de verdade.
func TestMigrateRulesIntoGroupRollsBackWhenTheUpdateFails(t *testing.T) {
	db := newTestDB(t)

	solta := &storage.FirewallRule{Action: "drop", Daddr: "203.0.113.0/24"}
	if err := db.CreateFirewallRule(solta); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	if _, err := db.Conn().Exec(`
		CREATE TRIGGER boom_on_group_id_update
		BEFORE UPDATE OF group_id ON firewall_rules
		BEGIN
			SELECT RAISE(ABORT, 'boom');
		END;`); err != nil {
		t.Fatalf("criar trigger de teste: %v", err)
	}

	g := storage.FirewallGroup{ID: "novo-grupo", Name: "Minhas regras",
		ChainName: "grp_aaaaaaaaaaaa", Enabled: true, Fallthrough: "continue"}
	if err := db.MigrateRulesIntoGroup(g, "firewall_groups_migrated", "true"); err == nil {
		t.Fatal("esperava erro do UPDATE abortado pelo trigger")
	}

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("o INSERT do grupo (passo 1) tinha que ter voltado atrás junto com o UPDATE abortado (passo 2): %+v", groups)
	}

	all, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if all[0].GroupID != "" {
		t.Errorf("a adoção não pode ter pegado: %+v", all[0])
	}

	flag, err := db.GetSetting("firewall_groups_migrated")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if flag != "" {
		t.Fatalf("a trava (passo 3, nunca chega a rodar) não pode ficar gravada, obtive %q", flag)
	}
}

// ─── pending_firewall_change (Fase C2: confirmar-ou-reverte) ───────────────

// O ciclo de vida do pendente: grava, lê de volta com o expires_at intacto,
// apaga. É o estado que faz um reboot dentro da janela reverter em vez de
// deixar valendo para sempre uma regra que pode ter trancado o operador.
func TestPendingFirewallChangeLifecycle(t *testing.T) {
	db := newTestDB(t)

	if p, err := db.GetPendingChange(); err != nil || p != nil {
		t.Fatalf("banco novo tem que estar sem pendente, obtive %v/%v", p, err)
	}

	criado := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	expires := time.Now().Add(90 * time.Second).Truncate(time.Second)
	if err := db.SavePendingChange(storage.PendingChange{
		ID:        "p1",
		Snapshot:  `{"groups":[{"id":"g1"}],"rules":[]}`,
		ExpiresAt: expires,
		AppliedBy: "gov",
		Summary:   "grupo Trava SSH aplicado",
		CreatedAt: criado,
	}); err != nil {
		t.Fatalf("SavePendingChange: %v", err)
	}

	got, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if got == nil {
		t.Fatal("o pendente gravado não voltou")
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("expires_at = %v, queria %v — é dele que sai a contagem regressiva do painel", got.ExpiresAt, expires)
	}
	if got.AppliedBy != "gov" || got.Summary != "grupo Trava SSH aplicado" || got.Snapshot == "" {
		t.Errorf("pendente lido diferente do gravado: %+v", got)
	}
	// m-4: created_at é o do CHAMADOR (que usa o relógio injetado do serviço,
	// o mesmo de que sai o expires_at), não um time.Now() cru aqui dentro.
	if !got.CreatedAt.Equal(criado) {
		t.Errorf("created_at = %v, queria o do chamador (%v): dois relógios diferentes na mesma linha fazem 'aberta às 03:00, expira às 02:31'",
			got.CreatedAt.UTC(), criado)
	}

	if err := db.ClearPendingChange(); err != nil {
		t.Fatalf("ClearPendingChange: %v", err)
	}
	if p, err := db.GetPendingChange(); err != nil || p != nil {
		t.Errorf("depois de apagado não pode sobrar pendente, obtive %v/%v", p, err)
	}
}

// Uma linha no máximo, garantida pelo PRÓPRIO BANCO (only_row UNIQUE com
// CHECK = 1) e não só pela checagem em Go que vem antes.
//
// Com dois pendentes, "reverter ao estado anterior" fica sem resposta —
// anterior a qual das duas mudanças? A trava no schema é o que faz essa
// garantia sobreviver a um chamador futuro que esqueça de perguntar antes.
func TestPendingFirewallChangeAllowsOnlyOneRow(t *testing.T) {
	db := newTestDB(t)

	first := storage.PendingChange{ID: "p1", Snapshot: "{}", ExpiresAt: time.Now(), Summary: "primeira"}
	if err := db.SavePendingChange(first); err != nil {
		t.Fatalf("gravar o primeiro pendente: %v", err)
	}
	if err := db.SavePendingChange(storage.PendingChange{
		ID: "p2", Snapshot: "{}", ExpiresAt: time.Now(), Summary: "segunda",
	}); err == nil {
		t.Fatal("o banco aceitou um segundo pendente; empilhar janelas torna a reversão ambígua")
	}

	got, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if got == nil || got.Summary != "primeira" {
		t.Errorf("a janela em aberto tem que continuar sendo a primeira, obtive %+v", got)
	}
}

// ReplaceFirewallGroupsAndRules é o lado banco da reversão: substitui tudo
// pelo conteúdo do snapshot, numa transação. Restaurar tem que preservar
// position e enabled exatamente como estavam — é um estado que já existiu,
// não uma criação nova.
func TestReplaceFirewallGroupsAndRulesRestoresExactly(t *testing.T) {
	db := newTestDB(t)

	// o estado "novo", que a reversão vai jogar fora
	novo := storage.FirewallGroup{ID: "novo", Name: "Trava SSH", ChainName: "grp_novo",
		Position: 0, Enabled: true, Fallthrough: "continue", Scope: "input"}
	if err := db.CreateFirewallGroup(&novo); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{
		GroupID: "novo", Action: "drop", Proto: "tcp", Dport: "22"}); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	// o snapshot do estado anterior. Os dois grupos do sistema vão junto
	// porque todo snapshot legítimo os tem (I-2): um sem eles é recusado, e há
	// um teste só para isso logo abaixo.
	nascido := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	alterado := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	antes := append(systemGroupsFixture(), storage.FirewallGroup{
		ID: "antigo", Name: "Minhas regras", ChainName: "grp_antigo",
		Position: 3, Enabled: false, Fallthrough: "accept", Kind: "admin", Scope: "forward",
		CreatedAt: nascido, UpdatedAt: alterado})
	antesRules := []storage.FirewallRule{{ID: "r1", Position: 7, GroupID: "antigo",
		Enabled: false, Action: "accept", Proto: "tcp", Dport: "9997",
		CreatedAt: nascido, UpdatedAt: alterado}}

	if err := db.ReplaceFirewallGroupsAndRules(antes, antesRules); err != nil {
		t.Fatalf("ReplaceFirewallGroupsAndRules: %v", err)
	}

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != len(antes) {
		t.Fatalf("os grupos não foram substituídos pelo snapshot: %+v", groups)
	}
	var g storage.FirewallGroup
	for _, cand := range groups {
		if cand.ID == "antigo" {
			g = cand
		}
	}
	if g.ID != "antigo" {
		t.Fatalf("o grupo do snapshot não foi restaurado: %+v", groups)
	}
	if g.Position != 3 || g.Enabled || g.Fallthrough != "accept" || g.Scope != "forward" {
		t.Errorf("o grupo restaurado não é idêntico ao do snapshot: %+v", g)
	}
	// m-3: updated_at vem do SNAPSHOT, não de time.Now(). Carimbar a hora da
	// reversão num campo de AUDITORIA descreve um estado que nunca existiu —
	// o operador leria "esta regra foi alterada às 03:14" sobre uma linha que
	// às 03:14 apenas voltou a ser o que já era.
	if !g.UpdatedAt.Equal(alterado) {
		t.Errorf("updated_at do grupo restaurado = %v, queria o do snapshot (%v): restaurar repõe um estado que já existiu, não cria um novo",
			g.UpdatedAt.UTC(), alterado)
	}
	if !g.CreatedAt.Equal(nascido) {
		t.Errorf("created_at do grupo restaurado = %v, queria %v", g.CreatedAt.UTC(), nascido)
	}

	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("as regras não foram substituídas pelo snapshot: %+v", rules)
	}
	if rules[0].Position != 7 || rules[0].Enabled {
		t.Errorf("a regra restaurada não é idêntica à do snapshot (position/enabled): %+v", rules[0])
	}
	if !rules[0].UpdatedAt.Equal(alterado) {
		t.Errorf("updated_at da regra restaurada = %v, queria o do snapshot (%v)", rules[0].UpdatedAt.UTC(), alterado)
	}
}

// systemGroupsFixture são os dois grupos que o LinkGuard mantém por conta
// própria — os bloqueios administrativos. Todo snapshot legítimo os contém, e
// é por isso que ReplaceFirewallGroupsAndRules os exige (I-2).
func systemGroupsFixture() []storage.FirewallGroup {
	return []storage.FirewallGroup{
		{ID: "sys-hosts", Name: "Hosts bloqueados", ChainName: "sys_blocked_hosts",
			Position: 0, Enabled: true, Fallthrough: "continue", Kind: "blocked_hosts", Scope: "forward"},
		{ID: "sys-blocklist", Name: "Lista de bloqueio", ChainName: "sys_blocklist",
			Position: 1, Enabled: true, Fallthrough: "continue", Kind: "blocklist", Scope: "forward"},
	}
}

// I-2. A guarda de "lista vazia" não cobre o caso que de fato acontece: um
// snapshot com grupos do admin e SEM os dois do sistema. Ele passava, o
// `DELETE FROM firewall_groups` apagava os bloqueios administrativos, e nada
// os recria (firewallrules.EnsureSystemGroups é travado por flag de settings).
// A partir dali ensureSystemGroupsPresent aborta TODA reconciliação da
// máquina, para sempre: o firewall congela no último estado aplicado e nenhuma
// mudança do admin volta a valer. É a mesma invariante, defendida dos dois
// lados.
func TestReplaceFirewallGroupsAndRulesRefusesASnapshotWithoutTheSystemGroups(t *testing.T) {
	db := newTestDB(t)
	for _, g := range systemGroupsFixture() {
		linha := g
		if err := db.CreateFirewallGroup(&linha); err != nil {
			t.Fatalf("CreateFirewallGroup: %v", err)
		}
	}

	// um snapshot não-vazio, com um grupo do admin só
	semSistema := []storage.FirewallGroup{{ID: "g1", Name: "Minhas regras",
		ChainName: "grp_g1", Position: 0, Enabled: true, Fallthrough: "continue", Kind: "admin"}}
	err := db.ReplaceFirewallGroupsAndRules(semSistema, nil)
	if err == nil {
		t.Fatal("restaurar um snapshot sem os grupos do sistema tinha que falhar: apagá-los trava toda reconciliação da máquina, para sempre")
	}
	if !strings.Contains(err.Error(), "Hosts bloqueados") || !strings.Contains(err.Error(), "Lista de bloqueio") {
		t.Errorf("a mensagem tem que nomear os bloqueios que faltam, obtive %q", err.Error())
	}

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("os bloqueios administrativos foram apagados por um snapshot sem eles: %+v", groups)
	}
}

// Um snapshot que traz os dois bloqueios continua sendo aceito — a guarda de
// I-2 não pode virar um "nada mais é restaurável".
func TestReplaceFirewallGroupsAndRulesAcceptsASnapshotWithTheSystemGroups(t *testing.T) {
	db := newTestDB(t)
	if err := db.ReplaceFirewallGroupsAndRules(systemGroupsFixture(), nil); err != nil {
		t.Fatalf("um snapshot com os dois grupos do sistema tem que ser aceito: %v", err)
	}
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("os dois bloqueios tinham que ter sido restaurados, obtive %+v", groups)
	}
}

// Snapshot sem nenhum grupo é recusado em vez de obedecido: obedecê-lo
// esvaziaria a chain forward por completo na reconciliação seguinte —
// bloqueios administrativos incluídos, que desde a Fase C1 também são itens
// da lista — e apagaria todas as chains grp_. Derrubar o firewall inteiro em
// nome de uma reversão de segurança é o oposto do que ela existe para fazer.
func TestReplaceFirewallGroupsAndRulesRefusesAnEmptyGroupList(t *testing.T) {
	db := newTestDB(t)
	g := storage.FirewallGroup{ID: "g1", Name: "Minhas regras", ChainName: "grp_g1",
		Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}

	if err := db.ReplaceFirewallGroupsAndRules(nil, nil); err == nil {
		t.Fatal("restaurar um snapshot sem grupos tinha que falhar, não apagar o firewall")
	}
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("os grupos foram apagados por um snapshot vazio: %+v", groups)
	}
}

// A migração da tabela do pendente roda em banco JÁ EXISTENTE e é idempotente
// — é o caminho de toda máquina que está subindo de versão, e o pendente
// gravado tem que sobreviver ao reboot que a atualização provoca (é
// exatamente o cenário que este mecanismo existe para cobrir).
func TestPendingFirewallChangeMigrationIsIdempotentOnAnExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("primeira abertura: %v", err)
	}
	if err := db.SavePendingChange(storage.PendingChange{
		ID: "p1", Snapshot: `{"groups":[{"id":"g1"}]}`,
		ExpiresAt: time.Now().Add(90 * time.Second), Summary: "grupo Trava SSH aplicado",
	}); err != nil {
		t.Fatalf("SavePendingChange: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// o processo volta (reboot, atualização): a migração roda de novo
	db2, err := storage.Open(path)
	if err != nil {
		t.Fatalf("segunda abertura (a migração tem que ser idempotente): %v", err)
	}
	defer db2.Close()

	got, err := db2.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange depois do restart: %v", err)
	}
	if got == nil || got.Summary != "grupo Trava SSH aplicado" {
		t.Errorf("o pendente não sobreviveu ao restart do processo: %+v", got)
	}
}

// N-1: a marca de "a reversão desta mudança já começou" tem que sobreviver ao
// RESTART, e é por isso que ela é uma coluna e não um campo do serviço.
//
// Sem ela no banco, um processo novo sobre o mesmo banco voltava a aceitar
// "confirmar" uma mudança cujo estado anterior já tinha sido restaurado aqui:
// respondia sucesso ao operador, apagava o pendente, e deixava a regra que
// cortou o acesso dele viva no firewall, sem ninguém para retomar a reversão.
func TestPendingChangeRevertingMarkSurvivesTheProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reverting.db")

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("primeira abertura: %v", err)
	}
	if err := db.SavePendingChange(storage.PendingChange{
		ID: "p1", Snapshot: `{"groups":[{"id":"g1"}]}`,
		ExpiresAt: time.Now().Add(90 * time.Second), Summary: "grupo Trava SSH aplicado",
	}); err != nil {
		t.Fatalf("SavePendingChange: %v", err)
	}
	got, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if got.Reverting() {
		t.Error("um pendente recém-gravado não pode nascer 'em reversão': é isso que trava a confirmação do operador")
	}

	comecou := time.Now().Truncate(time.Second)
	if err := db.MarkPendingReverting("p1", comecou); err != nil {
		t.Fatalf("MarkPendingReverting: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// o LinkGuard reinicia no meio da reversão travada
	db2, err := storage.Open(path)
	if err != nil {
		t.Fatalf("segunda abertura: %v", err)
	}
	defer db2.Close()
	got, err = db2.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange depois do restart: %v", err)
	}
	if got == nil {
		t.Fatal("o pendente não sobreviveu ao restart")
	}
	if !got.Reverting() {
		t.Fatal("a marca de reversão em andamento não sobreviveu ao restart: o processo novo voltaria a ACEITAR a confirmação de uma mudança que já saiu do banco, e a regra que trancou o operador ficaria viva no nft sem ninguém retomando a reversão")
	}
	if !got.RevertingAt.Equal(comecou) {
		t.Errorf("reverting_at = %v, queria %v", got.RevertingAt, comecou)
	}

	// pendente que não existe mais é erro, não silêncio: quem chama acabou de
	// restaurar o banco e precisa saber que a marca não ficou.
	if err := db2.MarkPendingReverting("nao-existe", comecou); err == nil {
		t.Error("marcar um pendente inexistente tinha que falhar")
	}
}

// A coluna reverting_at chega por ALTER TABLE nos bancos que já tinham a
// tabela — o caminho de TODA máquina que está subindo de versão, inclusive a
// de produção. Em transação, como toda migração deste projeto (incidente de
// 2026-07-24), e sem tocar na linha que já estava lá.
func TestRevertingAtMigrationRunsOnAPreExistingTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-c2.db")

	// Um banco no formato ANTERIOR: a tabela do pendente sem a coluna nova,
	// com uma janela já aberta (é o estado de uma máquina que atualiza no meio
	// de uma janela de confirmação).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("abrir o banco cru: %v", err)
	}
	if _, err := raw.Exec(`
CREATE TABLE pending_firewall_change (
    id         TEXT PRIMARY KEY,
    only_row   INTEGER NOT NULL DEFAULT 1 CHECK (only_row = 1) UNIQUE,
    snapshot   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    applied_by TEXT NOT NULL DEFAULT '',
    summary    TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		t.Fatalf("criar a tabela no formato antigo: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO pending_firewall_change (id, only_row, snapshot, expires_at, applied_by, summary)
		 VALUES ('velho', 1, '{"groups":[{"id":"g1"}]}', ?, 'gov', 'grupo Trava SSH aplicado')`,
		time.Now().Add(90*time.Second).Unix()); err != nil {
		t.Fatalf("gravar o pendente antigo: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("fechar o banco cru: %v", err)
	}

	db, err := storage.Open(path)
	if err != nil {
		t.Fatalf("abrir depois da atualização (a migração tem que rodar sozinha): %v", err)
	}
	defer db.Close()

	got, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if got == nil || got.Summary != "grupo Trava SSH aplicado" {
		t.Fatalf("a janela aberta antes da atualização tem que sobreviver a ela: %+v", got)
	}
	if got.Reverting() {
		t.Error("uma janela aberta por uma versão anterior é, por definição, uma janela cuja reversão ainda não começou")
	}
	if err := db.MarkPendingReverting("velho", time.Now()); err != nil {
		t.Errorf("a coluna nova tem que estar utilizável depois da migração: %v", err)
	}

	// segunda subida: idempotente
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db2, err := storage.Open(path)
	if err != nil {
		t.Fatalf("segunda abertura (a migração tem que ser idempotente): %v", err)
	}
	defer db2.Close()
	got, err = db2.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange na segunda abertura: %v", err)
	}
	if got == nil || !got.Reverting() {
		t.Errorf("a marca gravada tinha que continuar lá depois da segunda migração: %+v", got)
	}
}
