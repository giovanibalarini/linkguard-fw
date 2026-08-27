package storage

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

const createDomainTargetsBeforeLinkID = `
CREATE TABLE domain_targets (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    capability TEXT NOT NULL DEFAULT 'barrar',
    stage TEXT NOT NULL DEFAULT 'ensaio',
    link_name TEXT NOT NULL DEFAULT '',
    mark INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

func TestDomainTargetLinkIDMigrationBackfillsAnExistingLinkByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(createLinksTable); err != nil {
		t.Fatalf("create links: %v", err)
	}
	if _, err := raw.Exec(createDomainTargetsBeforeLinkID); err != nil {
		t.Fatalf("create old domain_targets: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO links (id,name,interface,status,enabled,table_id) VALUES ('wan-2','WAN 2','wan2','online',1,200)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO domain_targets (id,domain,capability,stage,link_name,mark) VALUES ('legacy','video.example.com','direcionar','ativo','WAN 2',200)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open depois do upgrade: %v", err)
	}
	defer db.Close()
	target, err := db.GetDomainTarget("legacy")
	if err != nil || target == nil {
		t.Fatalf("GetDomainTarget: %+v, %v", target, err)
	}
	if target.LinkID != "wan-2" {
		t.Fatalf("link_id não foi retropreenchido: %+v", target)
	}
}
