package storage

import (
	"path/filepath"
	"testing"
)

func openRestoreTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func countRows(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("contar %s: %v", table, err)
	}
	return n
}

func TestApplyRestoreWritesEverythingOnSuccess(t *testing.T) {
	db := openRestoreTestDB(t)

	c, err := db.ApplyRestore(RestorePayload{
		Settings:     map[string]string{"ntp_config": `{"serve_lan":true}`, "retention": "30d"},
		Reservations: []DHCPReservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.10", Hostname: "impressora"}},
		Blocklist:    []string{"anuncios.example", "rastreio.example"},
	})
	if err != nil {
		t.Fatalf("ApplyRestore: %v", err)
	}
	if c.Settings != 2 || c.Reservations != 1 || c.Blocklist != 2 {
		t.Fatalf("contagens erradas: %+v", c)
	}
	if got := countRows(t, db, "settings"); got < 2 {
		t.Errorf("settings gravadas: %d", got)
	}
	if got := countRows(t, db, "dhcp_reservations"); got != 1 {
		t.Errorf("reservas gravadas: %d", got)
	}
	if got := countRows(t, db, "dns_blocklist"); got != 2 {
		t.Errorf("domínios gravados: %d", got)
	}
}

// A garantia que dá nome à correção: se a escrita falhar no meio, o banco fica
// exatamente como estava. Antes eram três laços com o erro engolido e HTTP 200
// no fim — metade da configuração restaurada e sucesso reportado.
//
// A falha é forçada tirando a tabela dns_blocklist do caminho: settings e
// reservas gravam primeiro, e o INSERT do blocklist quebra com "no such table".
// É determinístico, e quebra DEPOIS de a transação já ter escrito — que é
// exatamente a situação que o defeito produzia. (Um MAC vazio não serve: no
// SQLite string vazia não viola NOT NULL.)
func TestApplyRestoreLeavesNothingBehindWhenItFailsHalfway(t *testing.T) {
	db := openRestoreTestDB(t)

	settingsAntes := countRows(t, db, "settings")
	if _, err := db.conn.Exec(`ALTER TABLE dns_blocklist RENAME TO dns_blocklist_escondida`); err != nil {
		t.Fatalf("preparar a falha: %v", err)
	}

	_, err := db.ApplyRestore(RestorePayload{
		Settings:     map[string]string{"chave_que_nao_pode_sobrar": "valor"},
		Reservations: []DHCPReservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.10"}},
		Blocklist:    []string{"quebra.example"},
	})
	if err == nil {
		t.Fatal("esperava erro na restauração")
	}

	var n int
	if err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM settings WHERE key = 'chave_que_nao_pode_sobrar'`).Scan(&n); err != nil {
		t.Fatalf("consultar: %v", err)
	}
	if n != 0 {
		t.Fatal("a setting gravada antes da falha sobreviveu — a restauração NÃO é transacional")
	}
	if got := countRows(t, db, "settings"); got != settingsAntes {
		t.Errorf("a tabela settings mudou de tamanho: %d → %d", settingsAntes, got)
	}
	if got := countRows(t, db, "dhcp_reservations"); got != 0 {
		t.Errorf("a reserva válida gravada antes da falha sobreviveu: %d", got)
	}
}
