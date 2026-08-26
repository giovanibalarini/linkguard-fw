package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createLinksTableBeforeQoS is the links schema shipped before issue #121.
// Keep this frozen so the test continues to exercise a real upgrade.
const createLinksTableBeforeQoS = `
CREATE TABLE links (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    interface        TEXT NOT NULL,
    ip_address       TEXT NOT NULL DEFAULT '',
    gateway          TEXT NOT NULL DEFAULT '',
    weight           INTEGER NOT NULL DEFAULT 100,
    dns_test         TEXT NOT NULL DEFAULT '8.8.8.8',
    monitor_hosts    TEXT NOT NULL DEFAULT '1.1.1.1,8.8.8.8',
    status           TEXT NOT NULL DEFAULT 'unknown',
    latency_ms       REAL NOT NULL DEFAULT 0,
    packet_loss      REAL NOT NULL DEFAULT 0,
    last_check       DATETIME,
    enabled          INTEGER NOT NULL DEFAULT 1,
    table_id         INTEGER NOT NULL DEFAULT 0,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

func TestLinkQoSMigrationUpgradesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-qos.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open pre-migration database: %v", err)
	}
	if _, err := raw.Exec(createLinksTableBeforeQoS); err != nil {
		t.Fatalf("create pre-QoS links table: %v", err)
	}
	if _, err := raw.Exec(createSchemaMigrationsTable); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, migration := range schemaMigrations {
		if migration.version >= 17 {
			continue
		}
		if _, err := raw.Exec(
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			migration.version, migration.name, time.Now().Unix(),
		); err != nil {
			t.Fatalf("record migration %d: %v", migration.version, err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO links (id, name, interface) VALUES ('wan-before-qos', 'WAN antiga', 'eth0')`); err != nil {
		t.Fatalf("insert pre-QoS link: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close pre-migration database: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open after upgrade: %v", err)
	}
	defer db.Close()

	if _, ok := appliedVersions(t, db)[17]; !ok {
		t.Fatal("QoS migration version 17 was not recorded")
	}

	link, err := db.GetLink("wan-before-qos")
	if err != nil {
		t.Fatalf("GetLink after upgrade: %v", err)
	}
	if link == nil {
		t.Fatal("pre-migration link was lost")
	}
	if link.QoSEnabled || link.QoSUploadMbps != 0 || link.QoSDownloadMbps != 0 || link.QoSInteractive {
		t.Fatalf("pre-migration QoS defaults = enabled:%v upload:%d download:%d interactive:%v; want false/0/0/false",
			link.QoSEnabled, link.QoSUploadMbps, link.QoSDownloadMbps, link.QoSInteractive)
	}

	link.QoSEnabled = true
	link.QoSUploadMbps = 25
	link.QoSDownloadMbps = 200
	link.QoSInteractive = true
	if err := db.UpdateLink(link); err != nil {
		t.Fatalf("UpdateLink after upgrade: %v", err)
	}
	reloaded, err := db.GetLink(link.ID)
	if err != nil {
		t.Fatalf("GetLink after update: %v", err)
	}
	if reloaded == nil || !reloaded.QoSEnabled || reloaded.QoSUploadMbps != 25 || reloaded.QoSDownloadMbps != 200 || !reloaded.QoSInteractive {
		t.Fatalf("QoS values after update = %+v; want enabled with 25/200 Mbps and interactive", reloaded)
	}
}
