package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

// As pragmas do DSN precisam estar EM EFEITO, não só escritas na string.
//
// Isto já falhou uma vez, e em silêncio: o DSN usava a forma
// `_journal_mode=WAL&_foreign_keys=on` do mattn/go-sqlite3, que o driver
// modernc ignora sem reclamar. O banco rodou sem WAL e sem checagem de chave
// estrangeira, e nada no build, no vet ou na suíte apontou — a string estava
// lá, parecendo certa.
//
// Um teste que lesse o DSN teria continuado verde. Este pergunta ao banco.
//
// Ressalva medida, para ninguém confiar mais do que deve: com o modernc
// v1.56 as DUAS sintaxes funcionam. Sondando os três casos numa instalação
// limpa deste driver:
//
//	sem parâmetro nenhum   journal=delete  fk=0  busy=0
//	?_pragma=…             journal=wal     fk=1  busy=5000
//	?_journal_mode=…       journal=wal     fk=1  busy=5000
//
// Ou seja, o driver passou a aceitar também a forma que ele ignorava quando o
// defeito aconteceu — este teste não distingue as duas, e não é para isso que
// serve. O que ele pega é o estado que importa: as pragmas NÃO estarem em
// efeito, seja porque o DSN se perdeu, porque uma versão futura do driver
// mudou de ideia, ou porque alguém trocou a string por algo que este driver
// não entende. Provado por mutação: DSN sem parâmetro deixa os dois testes
// vermelhos, com journal=delete, fk=0 e busy=0.
func TestDSNPragmasAreActuallyInEffect(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	var journal string
	if err := db.conn.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if !strings.EqualFold(journal, "wal") {
		t.Errorf("journal_mode = %q, esperado wal — o banco está sem WAL, e o DSN só parece certo", journal)
	}

	var fk int
	if err := db.conn.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Error("foreign_keys desligado — as FKs do schema viram decoração")
	}

	var busy int
	if err := db.conn.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busy != 5000 {
		t.Errorf("busy_timeout = %d, esperado 5000", busy)
	}
}

// E a consequência de foreign_keys estar ligado, medida em vez de presumida:
// uma FK violada tem que ser recusada pelo banco.
func TestForeignKeysAreEnforcedNotJustEnabled(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// user_roles referencia users(id) e roles(id); nenhum dos dois existe aqui.
	_, err = db.conn.Exec(
		`INSERT INTO user_roles (user_id, role_id) VALUES ('fantasma', 'inexistente')`)
	if err == nil {
		t.Fatal("o banco aceitou uma linha com chave estrangeira órfã — foreign_keys não está sendo aplicado")
	}
}
