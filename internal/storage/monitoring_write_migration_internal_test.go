package storage

import (
	"path/filepath"
	"testing"
)

// Resolver alerta era gateado por monitoring.read. A permissão nova separa
// leitura de escrita — mas papéis embutidos são semeados uma vez e não são
// re-semeados, então sem migração um Operador legítimo perderia no upgrade algo
// que fazia ontem. A migração devolve a capacidade a quem já a exercia, e só a
// esses.

// openForMigrationTest devolve um banco no estado de ANTES desta migração.
//
// Open() já roda migrate(), e num banco novo a migração se marca como feita sem
// conceder nada — o que está certo em produção: instalação nova recebe os
// papéis de DefaultRoles, que já trazem monitoring.write. O caso que interessa
// testar é o outro, o do upgrade: um banco que já tem papéis e ainda não passou
// por aqui. Apagar o marcador reproduz exatamente esse estado.
func openForMigrationTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.conn.Exec(
		`DELETE FROM settings WHERE key = 'migration_monitoring_write_granted'`); err != nil {
		t.Fatalf("limpar o marcador: %v", err)
	}
	return db
}

func rolePerms(t *testing.T, db *DB, roleID string) map[string]bool {
	t.Helper()
	rows, err := db.conn.Query(`SELECT permission FROM role_permissions WHERE role_id = ?`, roleID)
	if err != nil {
		t.Fatalf("query perms: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[p] = true
	}
	return out
}

func TestMigrationGrantsMonitoringWriteOnlyToOperationalRoles(t *testing.T) {
	db := openForMigrationTest(t)

	operator := &Role{Name: "Operador", Permissions: []string{"monitoring.read", "firewall.write"}}
	viewer := &Role{Name: "Visualizador", Permissions: []string{"monitoring.read", "links.read"}}
	admin := &Role{Name: "Administrador", Permissions: []string{"monitoring.read", "users.manage", "roles.manage"}}
	noMonitoring := &Role{Name: "Só DHCP", Permissions: []string{"dhcp.read", "dhcp.write"}}
	for _, r := range []*Role{operator, viewer, admin, noMonitoring} {
		if err := db.CreateRole(r); err != nil {
			t.Fatalf("CreateRole %s: %v", r.Name, err)
		}
	}

	if err := db.runOneMigrationForTest(upGrantMonitoringWrite); err != nil {
		t.Fatalf("migrateGrantMonitoringWrite: %v", err)
	}

	if !rolePerms(t, db, operator.ID)["monitoring.write"] {
		t.Error("o Operador perdeu a capacidade de resolver alerta que tinha antes do upgrade")
	}
	if !rolePerms(t, db, admin.ID)["monitoring.write"] {
		t.Error("o Administrador perdeu a capacidade de resolver alerta")
	}
	if rolePerms(t, db, viewer.ID)["monitoring.write"] {
		t.Error("o Visualizador (somente leitura) recebeu monitoring.write — é exatamente o que a correção existe para impedir")
	}
	if rolePerms(t, db, noMonitoring.ID)["monitoring.write"] {
		t.Error("papel sem monitoring.read recebeu monitoring.write")
	}
}

func TestMigrationIsIdempotentAndDoesNotReGrantAfterRevocation(t *testing.T) {
	db := openForMigrationTest(t)
	operator := &Role{Name: "Operador", Permissions: []string{"monitoring.read", "firewall.write"}}
	if err := db.CreateRole(operator); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := db.runOneMigrationForTest(upGrantMonitoringWrite); err != nil {
		t.Fatalf("primeira passada: %v", err)
	}

	// O admin decide tirar a permissão. Um boot seguinte não pode devolvê-la —
	// migração que desfaz decisão do operador é pior que migração que falta.
	if _, err := db.conn.Exec(
		`DELETE FROM role_permissions WHERE role_id = ? AND permission = 'monitoring.write'`,
		operator.ID); err != nil {
		t.Fatalf("revogar: %v", err)
	}
	if err := db.runOneMigrationForTest(upGrantMonitoringWrite); err != nil {
		t.Fatalf("segunda passada: %v", err)
	}
	if rolePerms(t, db, operator.ID)["monitoring.write"] {
		t.Error("a migração devolveu uma permissão que o admin tinha revogado")
	}
}
