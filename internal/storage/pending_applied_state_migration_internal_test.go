package storage

// O caminho de UPGRADE da coluna applied_state (issue #20a).
//
// Um banco novo recebe a coluna pelo CREATE TABLE e a migração 11 não faz nada.
// O caso que importa é o outro — a máquina em produção, cuja
// pending_firewall_change nasceu do DDL antigo —, e ele não é exercitado por
// nenhum teste que só abra um banco em branco. Aqui o DDL antigo é recriado à
// mão, para que o ALTER TABLE seja de verdade obrigado a rodar.
//
// A razão de existir deste teste é o incidente de 2026-07-24: uma migração que
// não passou travou o boot do firewall da empresa por mais de 50 minutos. Uma
// coluna nova sem o upgrade coberto é a mesma aposta.

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createPendingFirewallChangeTableBeforeAppliedState é o DDL como ele era até a
// issue #20a. Cópia literal e congelada de propósito: é o schema que está nas
// máquinas hoje, e ele não pode mudar quando o DDL de cima mudar.
const createPendingFirewallChangeTableBeforeAppliedState = `
CREATE TABLE pending_firewall_change (
    id           TEXT PRIMARY KEY,
    only_row     INTEGER NOT NULL DEFAULT 1 CHECK (only_row = 1) UNIQUE,
    snapshot     TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    applied_by   TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reverting_at INTEGER NOT NULL DEFAULT 0
);`

func TestTheAppliedStateColumnReachesADatabaseThatAlreadyHadTheTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")

	// Uma máquina de antes: a tabela no formato antigo, com uma janela ABERTA
	// dentro dela (o pior instante possível para um upgrade), e o runner
	// acreditando que as migrações 1..10 já rodaram.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("abrir o banco cru: %v", err)
	}
	if _, err := raw.Exec(createPendingFirewallChangeTableBeforeAppliedState); err != nil {
		t.Fatalf("criar a tabela no formato antigo: %v", err)
	}
	if _, err := raw.Exec(createSchemaMigrationsTable); err != nil {
		t.Fatalf("criar schema_migrations: %v", err)
	}
	for _, m := range schemaMigrations {
		if m.version >= 11 {
			continue
		}
		if _, err := raw.Exec(
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			m.version, m.name, time.Now().Unix()); err != nil {
			t.Fatalf("registrar a migração %d: %v", m.version, err)
		}
	}
	if _, err := raw.Exec(`
        INSERT INTO pending_firewall_change (id, only_row, snapshot, expires_at, applied_by, summary, created_at, reverting_at)
        VALUES ('janela-antiga', 1, '{"groups":[],"rules":[]}', ?, 'admin', 'de antes do upgrade', ?, 0)`,
		time.Now().Add(time.Minute).Unix(), time.Now()); err != nil {
		t.Fatalf("gravar a janela em aberto: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("fechar o banco cru: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open (é o boot depois do upgrade): %v", err)
	}
	defer db.Close()

	// A leitura tem que voltar a funcionar — sem a coluna, o SELECT de
	// GetPendingChange falha e a faixa do painel some justamente na máquina que
	// está com uma janela correndo.
	p, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange depois do upgrade: %v", err)
	}
	if p == nil || p.ID != "janela-antiga" {
		t.Fatalf("a janela que já estava aberta se perdeu no upgrade: %+v", p)
	}
	// Vazio é a resposta certa para uma linha de antes: ninguém registrou o
	// estado pós-mutação dela, e AppliedStateOrSnapshot cai no snapshot.
	if p.AppliedState != "" {
		t.Errorf("uma janela anterior ao upgrade não pode ter estado pós-mutação nenhum; veio %q", p.AppliedState)
	}
	if p.AppliedStateOrSnapshot() != p.Snapshot {
		t.Errorf("sem applied_state, o estado pós-mutação tem que ser o snapshot; veio %q", p.AppliedStateOrSnapshot())
	}
	// E a coluna passa a aceitar escrita.
	if err := db.SetPendingAppliedState("janela-antiga", `{"groups":[],"rules":[]}`); err != nil {
		t.Fatalf("SetPendingAppliedState depois do upgrade: %v", err)
	}
	p, err = db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if p.AppliedState == "" {
		t.Errorf("o estado pós-mutação não ficou gravado")
	}
}
