package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database connection.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and runs migrations.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	conn.SetMaxOpenConns(1)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

// Close shuts down the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn returns the underlying *sql.DB for use in repositories.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

// migrate applies all schema migrations in order.
func (db *DB) migrate() error {
	migrations := []string{
		createUsersTable,
		createLinksTable,
		createAlertsTable,
		createAuditLogsTable,
		createFailoverEventsTable,
		createRoutingPoliciesTable,
		createIptablesBackupsTable,
		createSettingsTable,
		insertDefaultAdmin,
	}

	for _, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	return nil
}

// ─── Schema ──────────────────────────────────────────────────────────────────

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'admin',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// Default admin password is "admin" (bcrypt hash). User must change it.
const insertDefaultAdmin = `
INSERT OR IGNORE INTO users (id, username, password, role)
VALUES (
    'default-admin',
    'admin',
    '$2a$12$qtlsjeM5KxHZEI4kAqnCje6Jyb24mW7SZ/uaPaFPzMJXFQJyGGIJq',
    'admin'
);`

const createLinksTable = `
CREATE TABLE IF NOT EXISTS links (
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

const createAlertsTable = `
CREATE TABLE IF NOT EXISTS alerts (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'info',
    title      TEXT NOT NULL,
    message    TEXT NOT NULL,
    link_id    TEXT,
    resolved   INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME
);`

const createAuditLogsTable = `
CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT PRIMARY KEY,
    user       TEXT NOT NULL DEFAULT 'system',
    action     TEXT NOT NULL,
    resource   TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createFailoverEventsTable = `
CREATE TABLE IF NOT EXISTS failover_events (
    id          TEXT PRIMARY KEY,
    link_id     TEXT NOT NULL,
    link_name   TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    commands    TEXT NOT NULL DEFAULT '',
    dry_run     INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createRoutingPoliciesTable = `
CREATE TABLE IF NOT EXISTS routing_policies (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    source_cidr  TEXT NOT NULL DEFAULT '',
    dest_cidr    TEXT NOT NULL DEFAULT '',
    link_id      TEXT NOT NULL,
    priority     INTEGER NOT NULL DEFAULT 100,
    enabled      INTEGER NOT NULL DEFAULT 1,
    failover     INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createIptablesBackupsTable = `
CREATE TABLE IF NOT EXISTS iptables_backups (
    id         TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    rules      TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createSettingsTable = `
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
