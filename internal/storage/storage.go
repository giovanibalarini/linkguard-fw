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

	// NOTE: modernc.org/sqlite uses the `_pragma=` connection-string syntax.
	// The older `_journal_mode=WAL&_foreign_keys=on` form (mattn/go-sqlite3) is
	// silently ignored by this driver, which left WAL and FK enforcement OFF.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	conn, err := sql.Open("sqlite", dsn)
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
		createRolesTable,
		createRolePermissionsTable,
		createUserRolesTable,
		createLinksTable,
		createAlertsTable,
		createAuditLogsTable,
		createFailoverEventsTable,
		createRoutingPoliciesTable,
		createIptablesBackupsTable,
		createSettingsTable,
		createSecretsTable,
		createTrafficSamplesTable,
		createMetricSamplesTable,
		createStateIntervalsTable,
		createStateIntervalsOpenIndex,
		createHostMetadataTable,
		createDHCPReservationsTable,
		createDNSBlocklistTable,
		insertDefaultAdmin,
	}

	for _, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	if err := db.migrateTrafficSamplesToMetricSamples(); err != nil {
		return fmt.Errorf("migrate traffic_samples to metric_samples: %w", err)
	}

	return nil
}

// migrateTrafficSamplesToMetricSamples copies every row from the legacy
// traffic_samples table into metric_samples as if.rx_bps/if.tx_bps, then
// renames (never drops) the populated old table so a second boot is a no-op.
// min=avg=max=value for migrated rows — the old table never recorded a spike,
// so there is nothing more honest to backfill. The rename only fires when
// there is at least one legacy row to move: traffic_samples is still created
// unconditionally (CREATE TABLE IF NOT EXISTS) by the plain migrations list
// above on every boot, so an empty table here just means "nothing to do"
// (fresh install, or a boot after the real migration already renamed the
// populated table away) rather than "rename an empty shell" — which would
// otherwise collide with traffic_samples_pre_tsdb_migration on every boot
// after the real one.
func (db *DB) migrateTrafficSamplesToMetricSamples() error {
	var exists int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='traffic_samples'`).Scan(&exists)
	if err != nil {
		return err
	}
	if exists == 0 {
		return nil // already migrated on a prior boot, or fresh install
	}

	rows, err := db.conn.Query(`SELECT interface, step_seconds, ts_unix, rx_bps, tx_bps FROM traffic_samples`)
	if err != nil {
		return err
	}
	type legacyRow struct {
		iface  string
		step   int
		ts     int64
		rx, tx float64
	}
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.iface, &r.step, &r.ts, &r.rx, &r.tx); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if len(legacy) == 0 {
		// Nothing to migrate: either a fresh install (createTrafficSamplesTable,
		// still unconditionally in the migrations list above, just created an
		// empty traffic_samples table on this very boot) or a boot after the
		// real migration already ran and renamed the populated table away —
		// CREATE TABLE IF NOT EXISTS keeps recreating an empty traffic_samples
		// every time it's missing. Leave the empty table in place rather than
		// renaming it: renaming here would collide with (or pointlessly
		// shadow) traffic_samples_pre_tsdb_migration from the real migration.
		return nil
	}

	for _, r := range legacy {
		if err := db.UpsertMetricSample(MetricSample{
			Series: "if.rx_bps", Label: r.iface, StepSeconds: r.step, TsUnix: r.ts,
			VMin: r.rx, VAvg: r.rx, VMax: r.rx,
		}); err != nil {
			return err
		}
		if err := db.UpsertMetricSample(MetricSample{
			Series: "if.tx_bps", Label: r.iface, StepSeconds: r.step, TsUnix: r.ts,
			VMin: r.tx, VAvg: r.tx, VMax: r.tx,
		}); err != nil {
			return err
		}
	}

	_, err = db.conn.Exec(`ALTER TABLE traffic_samples RENAME TO traffic_samples_pre_tsdb_migration`)
	return err
}

// MigrateTrafficSamplesToMetricSamplesForTest exposes the migration for tests
// in the storage_test package (which cannot call the unexported method
// directly). Test-only.
func (db *DB) MigrateTrafficSamplesToMetricSamplesForTest() error {
	return db.migrateTrafficSamplesToMetricSamples()
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

// ─── RBAC schema ─────────────────────────────────────────────────────────────
// Roles are user-defined sets of permissions; users are assigned one or more
// roles. The permission catalog itself lives in code (internal/auth).

const createRolesTable = `
CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    builtin     INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createRolePermissionsTable = `
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);`

const createUserRolesTable = `
CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);`

const createHostMetadataTable = `
CREATE TABLE IF NOT EXISTS host_metadata (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    alias      TEXT NOT NULL DEFAULT '',
    blocked    INTEGER NOT NULL DEFAULT 0,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// ─── DHCP/DNS schema ─────────────────────────────────────────────────────────

const createDHCPReservationsTable = `
CREATE TABLE IF NOT EXISTS dhcp_reservations (
    mac        TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    hostname   TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createDNSBlocklistTable = `
CREATE TABLE IF NOT EXISTS dns_blocklist (
    domain     TEXT PRIMARY KEY,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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

const createSecretsTable = `
CREATE TABLE IF NOT EXISTS secrets (
    name       TEXT PRIMARY KEY,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at DATETIME NOT NULL
);`

const createTrafficSamplesTable = `
CREATE TABLE IF NOT EXISTS traffic_samples (
    interface     TEXT NOT NULL,
    step_seconds  INTEGER NOT NULL,
    ts_unix       INTEGER NOT NULL,
    rx_bps        REAL NOT NULL,
    tx_bps        REAL NOT NULL,
    PRIMARY KEY (interface, step_seconds, ts_unix)
);`

const createMetricSamplesTable = `
CREATE TABLE IF NOT EXISTS metric_samples (
    series        TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    step_seconds  INTEGER NOT NULL,
    ts_unix       INTEGER NOT NULL,
    v_min         REAL NOT NULL,
    v_avg         REAL NOT NULL,
    v_max         REAL NOT NULL,
    PRIMARY KEY (series, label, step_seconds, ts_unix)
);`

const createStateIntervalsTable = `
CREATE TABLE IF NOT EXISTS state_intervals (
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    state      TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    PRIMARY KEY (kind, label, started_at)
);`

const createStateIntervalsOpenIndex = `
CREATE INDEX IF NOT EXISTS idx_state_intervals_open
ON state_intervals(kind, label) WHERE ended_at IS NULL;`
