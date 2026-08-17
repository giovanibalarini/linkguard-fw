package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Rede de segurança para o recorte da issue #26: SearchAuditLogs estava a ~900
// linhas do resto do domínio de auditoria (sob um cabeçalho "helpers") e não
// tinha teste, apesar de ser o que a tela de logs chama.

func seedAuditLog(t *testing.T, db *storage.DB, action, resource string) {
	t.Helper()
	l := &storage.AuditLog{
		User:     "admin",
		Action:   action,
		Resource: resource,
		Details:  "detalhe",
		IP:       "192.168.3.20",
	}
	if err := db.CreateAuditLog(l); err != nil {
		t.Fatalf("CreateAuditLog(%s): %v", action, err)
	}
}

func TestSearchAuditLogsWithoutFilterReturnsEverything(t *testing.T) {
	db := newTestDB(t)

	seedAuditLog(t, db, "firewall.apply", "firewall")
	seedAuditLog(t, db, "user.login", "auth")

	got, err := db.SearchAuditLogs("", 100)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 registros, veio %d", len(got))
	}
}

func TestSearchAuditLogsFiltersByActionSubstring(t *testing.T) {
	db := newTestDB(t)

	seedAuditLog(t, db, "firewall.apply", "firewall")
	seedAuditLog(t, db, "firewall.revert", "firewall")
	seedAuditLog(t, db, "user.login", "auth")

	got, err := db.SearchAuditLogs("firewall", 100)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 registros de firewall, veio %d", len(got))
	}
	for _, l := range got {
		if l.Action != "firewall.apply" && l.Action != "firewall.revert" {
			t.Errorf("registro fora do filtro: %+v", l)
		}
	}

	// O filtro é por action, não por resource: buscar pelo recurso não traz nada.
	got, err = db.SearchAuditLogs("auth", 100)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("esperava 0 registros filtrando por resource, veio %d", len(got))
	}
}

func TestSearchAuditLogsFilterIgnoresCase(t *testing.T) {
	db := newTestDB(t)

	seedAuditLog(t, db, "firewall.apply", "firewall")

	got, err := db.SearchAuditLogs("FIREWALL", 100)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 registro com filtro em maiúsculas, veio %d", len(got))
	}
}

func TestSearchAuditLogsRespectsTheLimit(t *testing.T) {
	db := newTestDB(t)

	for i := 0; i < 5; i++ {
		seedAuditLog(t, db, "firewall.apply", "firewall")
	}

	got, err := db.SearchAuditLogs("", 2)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 registros, veio %d", len(got))
	}

	// limit <= 0 cai no padrão de 100, não em "nenhum" — vale com e sem filtro.
	got, err = db.SearchAuditLogs("", 0)
	if err != nil {
		t.Fatalf("SearchAuditLogs(limit=0): %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("esperava os 5 registros com limit=0, veio %d", len(got))
	}

	got, err = db.SearchAuditLogs("firewall", -1)
	if err != nil {
		t.Fatalf("SearchAuditLogs(limit=-1): %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("esperava os 5 registros com limit=-1, veio %d", len(got))
	}
}

func TestSearchAuditLogsIsNilWhenNothingMatches(t *testing.T) {
	db := newTestDB(t)

	seedAuditLog(t, db, "user.login", "auth")

	got, err := db.SearchAuditLogs("nada-com-isso", 100)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	// Devolve nil, e é por isso que o handler de logs troca por [] antes de
	// serializar — a tela nunca recebe null.
	if got != nil {
		t.Fatalf("esperava nil, veio %#v", got)
	}
}
