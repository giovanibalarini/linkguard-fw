package storage

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func openRunnerTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func appliedVersions(t *testing.T, db *DB) map[int]string {
	t.Helper()
	rows, err := db.conn.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var n string
		if err := rows.Scan(&v, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[v] = n
	}
	return out
}

// Um banco recém-aberto tem que ter registrado TODA a lista. Se o runner
// esquecer de registrar, o boot seguinte roda tudo de novo — e é a sonda de
// dentro de cada migração que estaria segurando o estrago, não o runner.
func TestOpenRecordsEveryMigrationInTheList(t *testing.T) {
	db := openRunnerTestDB(t)
	applied := appliedVersions(t, db)

	if len(applied) != len(schemaMigrations) {
		t.Fatalf("registradas %d de %d migrações", len(applied), len(schemaMigrations))
	}
	for _, m := range schemaMigrations {
		if applied[m.version] != m.name {
			t.Errorf("versão %d registrada como %q, esperado %q", m.version, applied[m.version], m.name)
		}
	}
}

// A lista é ordenada e as versões são únicas. Reordenar ou reaproveitar um
// número faz um banco em produção pular uma migração em silêncio.
func TestSchemaMigrationsAreOrderedAndUnique(t *testing.T) {
	seen := map[int]bool{}
	prev := 0
	for _, m := range schemaMigrations {
		if m.version <= prev {
			t.Errorf("versão %d vem depois de %d — a lista tem que ser crescente", m.version, prev)
		}
		if seen[m.version] {
			t.Errorf("versão %d duplicada", m.version)
		}
		if m.name == "" {
			t.Errorf("versão %d sem nome", m.version)
		}
		if m.up == nil {
			t.Errorf("versão %d sem função up", m.version)
		}
		seen[m.version] = true
		prev = m.version
	}
}

// O que o incidente de 2026-07-24 cobra: uma migração que falha no meio não
// pode deixar metade da mudança gravada. A `up` abaixo cria uma tabela e SÓ
// ENTÃO falha — sem transação, a tabela sobreviveria.
func TestFailedMigrationLeavesNothingBehind(t *testing.T) {
	db := openRunnerTestDB(t)
	boom := errors.New("falha proposital no meio da migração")

	err := db.runMigrations([]migration{{
		version: 9001,
		name:    "cria tabela e falha depois",
		up: func(tx *sql.Tx) error {
			if _, err := tx.Exec(`CREATE TABLE meia_migracao (id TEXT PRIMARY KEY)`); err != nil {
				return err
			}
			return boom
		},
	}})
	if !errors.Is(err, boom) {
		t.Fatalf("esperava o erro da migração, veio: %v", err)
	}

	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meia_migracao'`).Scan(&n); err != nil {
		t.Fatalf("checar a tabela: %v", err)
	}
	if n != 0 {
		t.Fatal("a tabela criada antes da falha sobreviveu — a migração NÃO rodou em transação")
	}
	if _, ok := appliedVersions(t, db)[9001]; ok {
		t.Fatal("a migração que falhou foi registrada como aplicada")
	}
}

// O espelho do anterior: registro e mudança commitam juntos. Se o INSERT no
// schema_migrations ficasse fora da transação, existiria a janela em que a
// migração conta como feita sem ter feito nada.
func TestSuccessfulMigrationCommitsChangeAndRecordTogether(t *testing.T) {
	db := openRunnerTestDB(t)

	if err := db.runMigrations([]migration{{
		version: 9002,
		name:    "cria tabela de verdade",
		up: func(tx *sql.Tx) error {
			_, err := tx.Exec(`CREATE TABLE migracao_ok (id TEXT PRIMARY KEY)`)
			return err
		},
	}}); err != nil {
		t.Fatalf("runMigrations: %v", err)
	}

	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migracao_ok'`).Scan(&n); err != nil {
		t.Fatalf("checar a tabela: %v", err)
	}
	if n != 1 {
		t.Fatal("a tabela não foi criada")
	}
	if _, ok := appliedVersions(t, db)[9002]; !ok {
		t.Fatal("a migração aplicada não foi registrada")
	}
}

// Rodar duas vezes não aplica duas vezes. É o que o registro compra: a `up`
// não precisa mais ser idempotente por conta própria.
func TestRunMigrationsSkipsWhatIsAlreadyApplied(t *testing.T) {
	db := openRunnerTestDB(t)
	runs := 0
	ms := []migration{{
		version: 9003,
		name:    "conta execuções",
		up: func(tx *sql.Tx) error {
			runs++
			_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS contador (id TEXT PRIMARY KEY)`)
			return err
		},
	}}

	for i := 0; i < 3; i++ {
		if err := db.runMigrations(ms); err != nil {
			t.Fatalf("passada %d: %v", i+1, err)
		}
	}
	if runs != 1 {
		t.Fatalf("a migração rodou %d vezes, esperado 1", runs)
	}
}

// Uma migração que falha bloqueia as seguintes. Aplicar a versão 3 com a 2
// falhada deixaria o schema num estado que ninguém escreveu.
func TestRunMigrationsStopsAtTheFirstFailure(t *testing.T) {
	db := openRunnerTestDB(t)
	depoisRodou := false

	err := db.runMigrations([]migration{
		{version: 9004, name: "falha", up: func(*sql.Tx) error { return errors.New("boom") }},
		{version: 9005, name: "não deveria rodar", up: func(*sql.Tx) error {
			depoisRodou = true
			return nil
		}},
	})
	if err == nil {
		t.Fatal("esperava erro")
	}
	if depoisRodou {
		t.Fatal("a migração seguinte rodou depois de uma falha")
	}
}

// O outro lado da garantia, e o que o comentário do runner afirma: se o
// REGISTRO falhar, a mudança também não vale. Sem isso existiria a janela
// inversa — a migração aplicada no schema e não registrada, reaplicada a cada
// boot seguinte.
//
// A falha do registro é forçada por chave primária duplicada: a versão já está
// em schema_migrations. Chamamos applyMigration direto porque runMigrations
// pularia uma versão já registrada, que é justamente o caminho normal.
func TestMigrationIsRolledBackWhenTheRecordCannotBeWritten(t *testing.T) {
	db := openRunnerTestDB(t)

	const v = 9006
	if _, err := db.conn.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'ocupando a versão', 0)`, v); err != nil {
		t.Fatalf("preparar o conflito: %v", err)
	}

	err := db.applyMigration(migration{
		version: v,
		name:    "muda o schema e não consegue registrar",
		up: func(tx *sql.Tx) error {
			_, err := tx.Exec(`CREATE TABLE registro_impossivel (id TEXT PRIMARY KEY)`)
			return err
		},
	})
	if err == nil {
		t.Fatal("esperava erro no registro da migração")
	}

	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='registro_impossivel'`).Scan(&n); err != nil {
		t.Fatalf("checar a tabela: %v", err)
	}
	if n != 0 {
		t.Fatal("a mudança de schema ficou aplicada sem registro — no boot seguinte ela roda de novo")
	}
}
