package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// ─── Rollback (I-1) ─────────────────────────────────────────────────────────
//
// Restore writes a stored ruleset snapshot straight into nft via `nft -f`,
// bypassing the DB-authoritative model entirely (design spec §4.1): right
// after a rollback, the live user_rules chain would hold whatever the
// snapshot happened to contain, disagreeing with the DB's own rule rows
// until the next unrelated mutation silently re-renders over it. Rollback
// must reconcile user_rules from the DB immediately afterwards, the same as
// every other mutation, so the panel and the firewall never disagree.

func TestRollbackReconcilesGroupsFromDBAfterRestoring(t *testing.T) {
	h, db, exec := newFirewallRulesTestHandler(t)

	g := newRuleGroup(t, db)
	row := &storage.FirewallRule{GroupID: g.ID, Action: "accept", Saddr: "10.0.0.55"}
	if err := db.CreateFirewallRule(row); err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n\tchain user_rules {\n\t}\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	exec.executed = nil

	req := httptest.NewRequest("POST", "/api/nftables/rollback", strings.NewReader(mustJSON(t, map[string]any{"backup_id": backup.ID})))
	w := httptest.NewRecorder()
	h.Rollback(w, req)
	if w.Code != 200 {
		t.Fatalf("Rollback: status %d, body %s", w.Code, w.Body.String())
	}

	found := false
	for _, c := range exec.executed {
		if strings.Contains(c, "10.0.0.55") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the rollback to reconcile the admin's groups from the DB afterwards (the DB rule's content must be re-rendered), ran: %v", exec.executed)
	}
}

func mustJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// M-3 da revisão final — o rollback é a operação que mais briga com uma reversão
// em andamento: ele reescreve o RULESET INTEIRO (`flush ruleset` dentro de
// Service.Restore) e, até aqui, era a única mutação que não consultava a trava
// da janela de confirmação. Disparado no meio dos 90 segundos, ele escreve por
// cima do que o watchdog acabou de impor, e a reconciliação que viria depois
// falha em silêncio — slog.Warn e HTTP 200 na tela.
func TestRollbackIsRefusedWhileAConfirmWindowIsOpen(t *testing.T) {
	h, db, exec, fr := newGroupTestHandlerFR(t)

	backup := &storage.IptablesBackup{Label: "antes-do-incidente", Rules: "table inet linkguard {\n}\n"}
	if err := db.CreateIptablesBackup(backup); err != nil {
		t.Fatalf("CreateIptablesBackup: %v", err)
	}
	if _, err := fr.OpenConfirmWindow(context.Background(), "admin", "grupo de escopo input aplicado"); err != nil {
		t.Fatalf("abrir a janela: %v", err)
	}

	w := doJSON(t, h.Rollback, "POST", "/api/nftables/rollback", `{"backup_id":"`+backup.ID+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("o rollback tinha que ser recusado com a janela aberta: status %d, body %s", w.Code, w.Body.String())
	}
	// E a recusa não pode ter tocado no firewall vivo: `nft -f` é o comando com
	// que Restore aplica o snapshot inteiro.
	if exec.ranWith("nft -f") {
		t.Error("o rollback recusado chegou a reescrever o ruleset")
	}
}
