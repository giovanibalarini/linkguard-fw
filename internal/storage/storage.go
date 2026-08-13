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
		createManagedInterfacesTable,
		createPendingInterfaceChangesTable,
		createAIReportsTable,
		createFirewallGroupsTable,
		createFirewallRulesTable,
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
	if err := db.migrateAddPasswordVersion(); err != nil {
		return fmt.Errorf("migrate add password_version: %w", err)
	}
	if err := db.migrateAddFirewallRuleGroupID(); err != nil {
		return fmt.Errorf("migrate add firewall_rules.group_id: %w", err)
	}
	if err := db.migrateAddFirewallGroupKind(); err != nil {
		return fmt.Errorf("migrate add firewall_groups.kind: %w", err)
	}
	if err := db.migrateAddFirewallGroupScope(); err != nil {
		return fmt.Errorf("migrate add firewall_groups.scope: %w", err)
	}
	if err := db.migratePendingFirewallChange(); err != nil {
		return fmt.Errorf("migrate create pending_firewall_change: %w", err)
	}

	return nil
}

// migrateAddPasswordVersion adds users.password_version if the column doesn't
// exist yet (first ALTER TABLE ADD COLUMN in this project — every prior
// migration was a fresh CREATE TABLE IF NOT EXISTS). Existing rows get
// DEFAULT 1, matching a freshly created user's starting version.
func (db *DB) migrateAddPasswordVersion() error {
	rows, err := db.conn.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "password_version" {
			return nil // already migrated
		}
	}
	_, err = db.conn.Exec(`ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 1`)
	return err
}

// migrateAddFirewallRuleGroupID adiciona firewall_rules.group_id em bancos
// que já existem. Fica vazio nas linhas antigas de propósito: é assim que
// firewallrules.MigrateRulesIntoDefaultGroup reconhece o que ainda precisa
// ser adotado por um grupo. Em transação como toda migração deste projeto
// (incidente de 2026-07-24).
func (db *DB) migrateAddFirewallRuleGroupID() error {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_rules') WHERE name = 'group_id'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna group_id: %w", err)
	}
	if count > 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE firewall_rules ADD COLUMN group_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna group_id: %w", err)
	}
	return tx.Commit()
}

// migrateAddFirewallGroupKind adiciona firewall_groups.kind em bancos que já
// existem. Fica vazio nas linhas antigas de propósito: nftables.IsSystemGroup
// trata kind vazio como grupo do admin, então toda linha criada antes desta
// coluna existir continua se comportando exatamente como antes. Em
// transação como toda migração deste projeto (incidente de 2026-07-24).
func (db *DB) migrateAddFirewallGroupKind() error {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_groups') WHERE name = 'kind'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna kind: %w", err)
	}
	if count > 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE firewall_groups ADD COLUMN kind TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna kind: %w", err)
	}
	return tx.Commit()
}

// migrateAddFirewallGroupScope adiciona firewall_groups.scope (Fase C2) em
// bancos que já existem. Fica vazio nas linhas antigas de propósito: vazio
// conta como nftables.ScopeForward, e todo grupo criado antes desta coluna é
// de tráfego ATRAVESSANDO o firewall. Promover uma linha antiga a escopo
// input moveria as regras dela da chain forward para a input — ou seja,
// aplicá-las a um tráfego que o admin nunca pediu para filtrar. Em transação
// como toda migração deste projeto (incidente de 2026-07-24).
func (db *DB) migrateAddFirewallGroupScope() error {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_groups') WHERE name = 'scope'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna scope: %w", err)
	}
	if count > 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE firewall_groups ADD COLUMN scope TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna scope: %w", err)
	}
	return tx.Commit()
}

// migratePendingFirewallChange cria a tabela pending_firewall_change (Fase
// C2) — a mudança de firewall aplicada e ainda não confirmada, com o snapshot
// do estado anterior dos grupos e o instante em que ela vira reversão
// automática.
//
// Ela mora no BANCO, não num timer em memória, e é essa escolha que a torna
// uma rede de proteção de verdade: um reboot dentro da janela encontra a
// linha aqui no próximo boot e reverte, em vez de deixar valendo para sempre
// uma regra não confirmada que pode ter trancado o operador fora da máquina
// (spec §5.1).
//
// Migração imperativa em transação, no molde de migrateAddFirewallGroupKind e
// migrateAddFirewallGroupScope, e não uma linha a mais na lista de
// `CREATE TABLE IF NOT EXISTS` acima: toda migração deste projeto roda em
// transação desde o incidente de 2026-07-24, em que uma que não rodava travou
// o boot de uma máquina de produção por mais de 50 minutos. Sai barata — um
// SELECT em sqlite_master nos boots seguintes, e nada mais.
//
// A coluna only_row é o que garante o "uma linha no máximo": CHECK (only_row
// = 1) UNIQUE faz o segundo INSERT falhar no próprio SQLite. Sem isso, abrir
// uma janela com outra já aberta empilharia pendentes e "reverter ao estado
// anterior" viraria uma pergunta sem resposta — anterior a qual das duas
// mudanças? (spec §5.3).
func (db *DB) migratePendingFirewallChange() error {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pending_firewall_change'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar a tabela pending_firewall_change: %w", err)
	}
	if count > 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido
	if _, err := tx.Exec(createPendingFirewallChangeTable); err != nil {
		return fmt.Errorf("criar a tabela pending_firewall_change: %w", err)
	}
	return tx.Commit()
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

	// A production box can carry months of retained history here (one real
	// deploy hit 105k+ legacy rows -> up to ~211k upserts). Each db.conn.Exec
	// call is its own implicit auto-commit transaction, and under WAL mode
	// that means one fsync per row -- on real disks that turned a first-boot
	// migration that should take seconds into something still not finished
	// after 50+ minutes, blocking storage.Open() (and therefore the entire
	// rest of run(): the secrets vault, the HTTP server, the link monitor)
	// for the whole time. Wrapping every upsert plus the rename in ONE
	// transaction reduces this to a single commit/fsync at the end.
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`
		INSERT INTO metric_samples (series, label, step_seconds, ts_unix, v_min, v_avg, v_max)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(series, label, step_seconds, ts_unix)
		DO UPDATE SET v_min=excluded.v_min, v_avg=excluded.v_avg, v_max=excluded.v_max`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range legacy {
		if _, err := stmt.Exec("if.rx_bps", r.iface, r.step, r.ts, r.rx, r.rx, r.rx); err != nil {
			return err
		}
		if _, err := stmt.Exec("if.tx_bps", r.iface, r.step, r.ts, r.tx, r.tx, r.tx); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`ALTER TABLE traffic_samples RENAME TO traffic_samples_pre_tsdb_migration`); err != nil {
		return err
	}

	return tx.Commit()
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

// ─── Managed interfaces schema (netif Fase 2) ───────────────────────────────

const createManagedInterfacesTable = `
CREATE TABLE IF NOT EXISTS managed_interfaces (
    name        TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    addr_mode   TEXT NOT NULL,
    cidr        TEXT NOT NULL DEFAULT '',
    gateway     TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createPendingInterfaceChangesTable = `
CREATE TABLE IF NOT EXISTS pending_interface_changes (
    id            TEXT PRIMARY KEY,
    interface     TEXT NOT NULL UNIQUE,
    old_config    TEXT NOT NULL,
    old_files     TEXT NOT NULL,
    new_config    TEXT NOT NULL,
    deadline_unix INTEGER NOT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createAIReportsTable = `
CREATE TABLE IF NOT EXISTS ai_reports (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    summary        TEXT NOT NULL,
    findings       TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    created_at     DATETIME NOT NULL
);`

// ─── Firewall rules schema (Phase B: appliance-style user_rules) ───────────
//
// A plain CREATE TABLE IF NOT EXISTS, deliberately nothing heavier: a prior
// migration here once hung a production boot for 50+ minutes (see
// migrateTrafficSamplesToMetricSamples' history) by doing per-row work on
// the startup path. This table starts empty on every box — the one-time
// import of pre-existing nft rules (internal/firewallrules) is a separate,
// explicitly guarded step that runs after storage.Open returns, not part of
// this migration.
const createFirewallGroupsTable = `
CREATE TABLE IF NOT EXISTS firewall_groups (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    chain_name   TEXT NOT NULL UNIQUE,
    position     INTEGER NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    cond_saddr   TEXT NOT NULL DEFAULT '',
    cond_daddr   TEXT NOT NULL DEFAULT '',
    cond_iif     TEXT NOT NULL DEFAULT '',
    fallthrough  TEXT NOT NULL DEFAULT 'continue',
    kind         TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// ─── Confirmar-ou-reverte (Fase C2) ───────────────────────────────────────
//
// Criada por migratePendingFirewallChange (em transação), NÃO pela lista de
// migrações simples acima — ver o doc-comment daquela função.
//
// expires_at é unix segundos, e é do SERVIDOR: é a única fonte da verdade da
// contagem regressiva do painel. A tela lê este instante e desenha o relógio
// a partir dele; um contador local reiniciaria a cada F5 e mentiria sobre
// quanto tempo o operador ainda tem para confirmar.
const createPendingFirewallChangeTable = `
CREATE TABLE IF NOT EXISTS pending_firewall_change (
    id         TEXT PRIMARY KEY,
    only_row   INTEGER NOT NULL DEFAULT 1 CHECK (only_row = 1) UNIQUE,
    snapshot   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    applied_by TEXT NOT NULL DEFAULT '',
    summary    TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

const createFirewallRulesTable = `
CREATE TABLE IF NOT EXISTS firewall_rules (
    id          TEXT PRIMARY KEY,
    position    INTEGER NOT NULL,
    group_id    TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    action      TEXT NOT NULL,
    iif         TEXT NOT NULL DEFAULT '',
    oif         TEXT NOT NULL DEFAULT '',
    saddr       TEXT NOT NULL DEFAULT '',
    daddr       TEXT NOT NULL DEFAULT '',
    proto       TEXT NOT NULL DEFAULT '',
    dport       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
