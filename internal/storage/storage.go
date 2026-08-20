package storage

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

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
		createLinkQuotaTable,
		createLinkUsageTable,
	}

	for _, m := range migrations {
		if _, err := db.conn.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	if err := db.runMigrations(schemaMigrations); err != nil {
		return err
	}

	return db.ensureUniqueDHCPReservationIP()
}

// ensureUniqueDHCPReservationIP cria o índice único de dhcp_reservations.ip
// (issue #59) quando — e só quando — a base já está limpa.
//
// A tabela tinha PK só em `mac`, então dois MACs podiam reivindicar o mesmo
// endereço. O kea aceitava a configuração gerada e entregava o IP aos dois; o
// que chegava ao admin não era "reserva duplicada", era conflito de endereço
// intermitente, visível só com os dois aparelhos ligados juntos.
//
// A defesa que vale para toda escrita do produto é a transação em
// UpsertDHCPReservation. Este índice é a rede de baixo, para o que escrever no
// banco por fora dela.
//
// POR QUE NÃO É UMA MIGRAÇÃO VERSIONADA. `CREATE UNIQUE INDEX` sobre uma tabela
// que JÁ tem duplicata falha, e migração que falha no boot não é um erro de
// índice: é o firewall não subir por causa de dado que já estava lá — a classe
// do incidente de 2026-07-24. E o runner registra a migração como aplicada
// assim que ela retorna sem erro, então uma migração que "pulasse" o índice
// nunca mais seria tentada: o índice não existiria para sempre, em silêncio.
//
// Aqui roda a cada boot, o que torna a espera real. Com duplicata, ANOTA no log
// qual é (o IP e os MACs) e segue sem criar. Quando o admin resolver o conflito
// pela tela, o boot seguinte cria o índice sozinho, sem ninguém pedir.
//
// As duas saídas que não foram escolhidas, de propósito: falhar o boot tira do
// admin justamente o painel com que ele resolveria o conflito; e apagar a
// duplicata sozinho decide por ele qual das duas reservas morre — o que pode
// ser o aparelho que dependia daquele endereço fixo.
func (db *DB) ensureUniqueDHCPReservationIP() error {
	rows, err := db.conn.Query(`
		SELECT ip, COUNT(*) AS n, GROUP_CONCAT(mac, ', ')
		  FROM dhcp_reservations
		 GROUP BY ip
		HAVING n > 1`)
	if err != nil {
		return fmt.Errorf("procurar reservas DHCP com IP repetido: %w", err)
	}
	duplicados := 0
	for rows.Next() {
		var ip, macs string
		var n int
		if err := rows.Scan(&ip, &n, &macs); err != nil {
			rows.Close() //nolint:errcheck // já estamos devolvendo erro
			return fmt.Errorf("ler as reservas DHCP repetidas: %w", err)
		}
		duplicados++
		slog.Warn("reservas DHCP com o mesmo IP — dois aparelhos vão disputar o endereço",
			"ip", ip, "macs", macs, "reservas", n)
	}
	rows.Close() //nolint:errcheck // leitura terminada
	if err := rows.Err(); err != nil {
		return fmt.Errorf("ler as reservas DHCP repetidas: %w", err)
	}

	if duplicados > 0 {
		slog.Warn("remova a reserva sobrando em DHCP → Reservas; o serviço sobe normalmente e o índice é criado no próximo boot",
			"ips_em_conflito", duplicados)
		return nil
	}

	if _, err := db.conn.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_reservations_ip ON dhcp_reservations(ip)`,
	); err != nil {
		return fmt.Errorf("criar o índice único de dhcp_reservations.ip: %w", err)
	}
	return nil
}

// ─── Runner de migração ──────────────────────────────────────────────────────

// migration é uma mudança de schema versionada. `up` recebe a transação já
// aberta pelo runner: nenhuma migração abre a sua própria, e é essa inversão
// que importa.
//
// Antes daqui, cada migração era responsável por duas coisas independentes —
// decidir se já tinha rodado, e lembrar do Begin/Commit. As sondas divergiam
// entre si (pragma_table_info numa, PRAGMA table_info com rows.Scan noutra,
// sqlite_master numa terceira) e uma delas rodava o ALTER TABLE fora de
// transação. A regra "toda migração em transação" nasceu do incidente de
// 2026-07-24, em que uma migração travou no meio e o firewall da empresa ficou
// mais de 50 minutos sem subir; deixá-la na disciplina de quem escreve a
// próxima é confiar no que já falhou uma vez.
type migration struct {
	version int
	name    string
	up      func(*sql.Tx) error
}

// schemaMigrations é a lista ordenada e imutável. Versão nunca é reordenada nem
// reaproveitada: bancos em produção já registraram esses números.
//
// As sondas de "já rodei?" continuam dentro de cada `up` de propósito. Elas são
// redundantes com o schema_migrations num banco que passou por aqui, mas são o
// que torna a primeira execução do runner segura em TODA instalação que já
// existe — nelas a tabela nasce vazia, e sem sonda o runner tentaria aplicar de
// novo dez migrações que já valem. Podem sair um release depois.
var schemaMigrations = []migration{
	{1, "traffic_samples para metric_samples", upTrafficSamplesToMetricSamples},
	{2, "users.password_version", upAddPasswordVersion},
	{3, "firewall_rules.group_id", upAddFirewallRuleGroupID},
	{4, "firewall_groups.kind", upAddFirewallGroupKind},
	{5, "firewall_groups.scope", upAddFirewallGroupScope},
	{6, "firewall_groups.conn_state", upAddFirewallGroupConnState},
	{7, "pending_firewall_change", upPendingFirewallChange},
	{8, "pending_firewall_change.reverting_at", upAddPendingChangeRevertingAt},
	{9, "dashboard_layout", upDashboardLayout},
	{10, "monitoring.write nos papéis operacionais", upGrantMonitoringWrite},
	{11, "pending_firewall_change.applied_state", upAddPendingChangeAppliedState},
	{12, "traffic.capture nos papéis que administram papéis", upGrantTrafficCapture},
}

const createSchemaMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);`

// runMigrations aplica o que ainda não foi aplicado, uma transação por
// migração. A gravação do registro entra na MESMA transação da mudança: ou as
// duas valem, ou nenhuma. Registrar depois abriria a janela em que a migração
// conta como feita sem ter feito nada.
func (db *DB) runMigrations(ms []migration) error {
	if _, err := db.conn.Exec(createSchemaMigrationsTable); err != nil {
		return fmt.Errorf("criar schema_migrations: %w", err)
	}
	applied, err := db.appliedMigrations()
	if err != nil {
		return err
	}

	highestKnown := 0
	for _, m := range ms {
		if m.version > highestKnown {
			highestKnown = m.version
		}
		if applied[m.version] {
			continue
		}
		if err := db.applyMigration(m); err != nil {
			return fmt.Errorf("migração %d (%s): %w", m.version, m.name, err)
		}
		slog.Info("migração de schema aplicada", "versao", m.version, "nome", m.name)
	}

	// Banco à frente do binário: aconteceu um downgrade, ou uma máquina leu um
	// backup mais novo. Não é motivo para recusar o boot — um firewall que não
	// sobe é pior do que um firewall com um schema mais novo do que ele conhece,
	// e o SQLite tolera coluna a mais. Mas o operador precisa saber, porque é a
	// explicação de qualquer estranheza que venha depois.
	for v := range applied {
		if v > highestKnown {
			slog.Warn("o banco tem migração mais nova do que este binário conhece — provável downgrade de versão",
				"versao_no_banco", v, "maior_versao_conhecida", highestKnown)
		}
	}
	return nil
}

func (db *DB) appliedMigrations() (map[int]bool, error) {
	rows, err := db.conn.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("ler schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("ler schema_migrations: %w", err)
		}
		out[v] = true
	}
	return out, rows.Err()
}

func (db *DB) applyMigration(m migration) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido
	if err := m.up(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, time.Now().Unix()); err != nil {
		return fmt.Errorf("registrar a migração: %w", err)
	}
	return tx.Commit()
}

// migrateGrantMonitoringWrite dá monitoring.write aos papéis operacionais que já
// existem, e só a eles.
//
// Resolver um alerta era gateado por monitoring.read — uma permissão de LEITURA
// protegendo uma escrita. Na prática o papel Visualizador conseguia limpar do
// painel os alertas de WAN caída, disco com setor realocado e divergência do
// firewall. A permissão nova separa as duas coisas, mas papéis embutidos são
// semeados uma vez só e não são re-semeados, então sem esta migração um
// Operador legítimo perderia, no upgrade, algo que fazia ontem.
//
// O critério é preservar exatamente quem já podia e devia: papel que tem
// monitoring.read E pelo menos uma permissão de escrita/ação. Quem só tem
// leitura fica de fora — que é o ponto da correção, não um efeito colateral.
// Roda uma vez só, e a sonda é um marcador próprio em settings — não a presença
// da permissão nos papéis. A diferença tem consequência: com a sonda pela
// presença, um admin que revogasse monitoring.write do único papel que a tinha
// veria a migração devolvê-la no boot seguinte. Migração que desfaz decisão do
// operador é pior do que migração que falta. (O runner com tabela de versão da
// issue #19 generaliza isto; até lá, o marcador é explícito aqui.)
func upGrantMonitoringWrite(tx *sql.Tx) error {
	const marker = "migration_monitoring_write_granted"
	var already int
	err := tx.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = ?`, marker).Scan(&already)
	if err != nil {
		return fmt.Errorf("checar o marcador da migração monitoring.write: %w", err)
	}
	if already > 0 {
		return nil
	}

	// A lista de permissões "de escrita" é literal e fechada de propósito: um
	// LIKE '%write%' pegaria qualquer chave futura por acidente, e este é o
	// tipo de decisão que não deve depender do nome que alguém escolher depois.
	if _, err := tx.Exec(`
		INSERT INTO role_permissions (role_id, permission)
		SELECT DISTINCT r.role_id, 'monitoring.write'
		FROM role_permissions r
		WHERE r.permission = 'monitoring.read'
		  AND EXISTS (
			SELECT 1 FROM role_permissions w
			WHERE w.role_id = r.role_id
			  AND w.permission IN (
				'links.write','routes.write','firewall.write','hosts.block',
				'hosts.assign','system.write','dhcp.write','dns.write',
				'interfaces.write','ntp.write','users.manage','roles.manage'
			  )
		  )`); err != nil {
		return fmt.Errorf("conceder monitoring.write aos papéis operacionais: %w", err)
	}
	// O marcador entra na MESMA transação da concessão: ou os dois valem, ou
	// nenhum. Gravá-lo depois abriria a janela em que a migração conta como
	// feita sem ter concedido nada.
	if _, err := tx.Exec(
		`INSERT INTO settings (key, value) VALUES (?, '1')`, marker); err != nil {
		return fmt.Errorf("gravar o marcador da migração monitoring.write: %w", err)
	}
	return nil
}

// upGrantTrafficCapture concede traffic.capture (issue #114) aos papéis que já
// administram papéis.
//
// POR QUE SÓ ESSES, E POR QUE CONCEDER. A permissão é NOVA — ninguém a tinha,
// então não há direito adquirido a preservar, e o padrão certo para capacidade
// nova é não distribuí-la sozinha. A exceção é o papel que tem roles.manage:
// quem pode editar papéis já pode se conceder qualquer permissão, então
// conceder aqui não move fronteira de segurança nenhuma — só evita que o
// administrador de uma instalação existente encontre a aba nova desligada, sem
// nada na tela explicando que a permissão existe e é dele.
//
// O critério NÃO é "papel embutido chamado Administrador": papéis embutidos são
// semeados uma vez e podem ter sido editados desde então. A pergunta certa é o
// que o papel PODE, não como ele se chama.
//
// Marcador próprio em settings, e não a presença da permissão, pelo mesmo
// motivo da migração 10: com a sonda pela presença, um admin que revogasse a
// permissão a veria voltar no boot seguinte, e migração que desfaz decisão do
// operador é pior que migração que falta.
func upGrantTrafficCapture(tx *sql.Tx) error {
	const marker = "migration_traffic_capture_granted"
	var already int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = ?`, marker).Scan(&already); err != nil {
		return fmt.Errorf("checar o marcador da migração traffic.capture: %w", err)
	}
	if already > 0 {
		return nil
	}
	if _, err := tx.Exec(`
		INSERT OR IGNORE INTO role_permissions (role_id, permission)
		SELECT DISTINCT role_id, 'traffic.capture'
		FROM role_permissions
		WHERE permission = 'roles.manage'`); err != nil {
		return fmt.Errorf("conceder traffic.capture aos papéis administrativos: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO settings (key, value) VALUES (?, '1')`, marker); err != nil {
		return fmt.Errorf("gravar o marcador da migração traffic.capture: %w", err)
	}
	return nil
}

// migrateDashboardLayout cria a tabela dashboard_layout — o painel que cada
// admin montou para si (spec §4.1). Uma linha por usuário, e a ausência de
// linha é o estado normal de quem nunca arrastou nada: GetDashboardLayout
// devolve o layout de fábrica nesse caso, nunca uma tela em branco.
//
// Não há chave estrangeira para users(id) de propósito. Ela custaria mais do
// que protege: uma preferência órfã de um usuário removido não faz mal nenhum
// (o id é único e nunca é reaproveitado), enquanto a FK ligaria o boot do
// painel à integridade de outra tabela — e este banco roda com
// foreign_keys(1), então um id fora do ar aqui viraria erro de gravação numa
// tela que é só preferência pessoal.
//
// Migração imperativa em transação, no molde de migrateAddFirewallGroupScope, e
// não uma linha a mais na lista de CREATE TABLE IF NOT EXISTS acima: toda
// migração deste projeto roda em transação desde o incidente de 2026-07-24, em
// que uma que não rodava travou o boot de uma máquina de produção por mais de
// 50 minutos. Sai barata — um SELECT em sqlite_master nos boots seguintes, e
// nada mais.
func upDashboardLayout(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dashboard_layout'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar a tabela dashboard_layout: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(createDashboardLayoutTable); err != nil {
		return fmt.Errorf("criar a tabela dashboard_layout: %w", err)
	}
	return nil
}

// migrateAddPasswordVersion adds users.password_version if the column doesn't
// exist yet (first ALTER TABLE ADD COLUMN in this project — every prior
// migration was a fresh CREATE TABLE IF NOT EXISTS). Existing rows get
// DEFAULT 1, matching a freshly created user's starting version.
func upAddPasswordVersion(tx *sql.Tx) error {
	rows, err := tx.Query(`PRAGMA table_info(users)`)
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
	_, err = tx.Exec(`ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 1`)
	return err
}

// migrateAddFirewallRuleGroupID adiciona firewall_rules.group_id em bancos
// que já existem. Fica vazio nas linhas antigas de propósito: é assim que
// firewallrules.MigrateRulesIntoDefaultGroup reconhece o que ainda precisa
// ser adotado por um grupo. Em transação como toda migração deste projeto
// (incidente de 2026-07-24).
func upAddFirewallRuleGroupID(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_rules') WHERE name = 'group_id'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna group_id: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE firewall_rules ADD COLUMN group_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna group_id: %w", err)
	}
	return nil
}

// migrateAddFirewallGroupKind adiciona firewall_groups.kind em bancos que já
// existem. Fica vazio nas linhas antigas de propósito: nftables.IsSystemGroup
// trata kind vazio como grupo do admin, então toda linha criada antes desta
// coluna existir continua se comportando exatamente como antes. Em
// transação como toda migração deste projeto (incidente de 2026-07-24).
func upAddFirewallGroupKind(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_groups') WHERE name = 'kind'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna kind: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE firewall_groups ADD COLUMN kind TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna kind: %w", err)
	}
	return nil
}

// migrateAddFirewallGroupScope adiciona firewall_groups.scope (Fase C2) em
// bancos que já existem. Fica vazio nas linhas antigas de propósito: vazio
// conta como nftables.ScopeForward, e todo grupo criado antes desta coluna é
// de tráfego ATRAVESSANDO o firewall. Promover uma linha antiga a escopo
// input moveria as regras dela da chain forward para a input — ou seja,
// aplicá-las a um tráfego que o admin nunca pediu para filtrar. Em transação
// como toda migração deste projeto (incidente de 2026-07-24).
func upAddFirewallGroupScope(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_groups') WHERE name = 'scope'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna scope: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE firewall_groups ADD COLUMN scope TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna scope: %w", err)
	}
	return nil
}

// migrateAddFirewallGroupConnState adiciona firewall_groups.conn_state em
// bancos que já existem: "vale para toda conexão" × "vale só para conexões
// novas".
//
// Fica VAZIA nas linhas antigas de propósito, e esta é a decisão que protege
// toda máquina já instalada: vazio conta como nftables.ConnStateAny, e a linha
// de jump do grupo sai byte a byte como sempre saiu. Preencher as antigas com
// "new" faria um upgrade afrouxar, sozinho, todo bloqueio que hoje já derruba
// conexão estabelecida — o admin nunca pediu isso, e ele só descobriria pelo
// tráfego que voltou a passar.
//
// Em transação como toda migração deste projeto (incidente de 2026-07-24, em
// que uma migração sem transação travou o boot de uma máquina de produção por
// mais de 50 minutos). Sai barata: um SELECT em pragma_table_info nos boots
// seguintes, e nada mais.
func upAddFirewallGroupConnState(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('firewall_groups') WHERE name = 'conn_state'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna conn_state: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE firewall_groups ADD COLUMN conn_state TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna conn_state: %w", err)
	}
	return nil
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
func upPendingFirewallChange(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pending_firewall_change'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar a tabela pending_firewall_change: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(createPendingFirewallChangeTable); err != nil {
		return fmt.Errorf("criar a tabela pending_firewall_change: %w", err)
	}
	return nil
}

// migrateAddPendingChangeRevertingAt adiciona pending_firewall_change.reverting_at
// nos bancos que já tinham a tabela (N-1 da segunda revisão da Fase C2).
//
// A coluna marca "a reversão desta mudança JÁ COMEÇOU: o estado anterior já
// voltou ao banco e o que faltou foi o firewall vivo". Ela precisa estar no
// BANCO, e não só num campo do Service, pelo mesmo motivo de o pendente inteiro
// morar aqui: um restart no meio de uma reversão travada perdia a marca em
// memória, e o processo novo voltava a ACEITAR a confirmação daquela mudança —
// o pendente era apagado, a alteração do operador já não existia mais no banco,
// ninguém retomava a reversão no nft, e ele era informado de que a mudança
// "passa a valer definitivamente" enquanto a regra que trancou o acesso dele
// seguia viva. É exatamente o modo de falha crítico que a Fase C2 existe para
// fechar, alcançável de novo por um simples restart.
//
// Zero (o default) quer dizer "nenhuma reversão começou". Linhas antigas ficam
// zeradas de propósito: uma janela aberta por uma versão anterior é, por
// definição, uma janela cuja reversão ainda não começou.
//
// Em transação como toda migração deste projeto (incidente de 2026-07-24).
func upAddPendingChangeRevertingAt(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('pending_firewall_change') WHERE name = 'reverting_at'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna reverting_at: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE pending_firewall_change ADD COLUMN reverting_at INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("adicionar coluna reverting_at: %w", err)
	}
	return nil
}

// upAddPendingChangeAppliedState adiciona pending_firewall_change.applied_state
// (issue #20a) nos bancos que já tinham a tabela.
//
// A coluna guarda o estado dos grupos e regras COMO A MUTAÇÃO DESTA JANELA O
// DEIXOU — o par do `snapshot`, que guarda o estado de antes. Com os dois, a
// reversão consegue responder a pergunta que ela não sabia fazer: "o banco de
// agora ainda é o que esta janela produziu, ou tem coisa de OUTRA pessoa aqui
// dentro?". Sem ela, restaurar o snapshot era um "volte tudo" que apagava, sem
// erro e sem auditoria, qualquer alteração que outro admin tivesse gravado
// dentro dos 90 segundos (ver firewallrules.revert).
//
// Vazio quer dizer "esta janela ainda não gravou nada, ou o processo morreu
// antes de registrar o que gravou". É o default das linhas antigas de
// propósito, e o lado seguro: ver PendingChange.AppliedStateOrSnapshot.
//
// Em transação como toda migração deste projeto (incidente de 2026-07-24).
func upAddPendingChangeAppliedState(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('pending_firewall_change') WHERE name = 'applied_state'`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("checar coluna applied_state: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := tx.Exec(`ALTER TABLE pending_firewall_change ADD COLUMN applied_state TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("adicionar coluna applied_state: %w", err)
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
func upTrafficSamplesToMetricSamples(tx *sql.Tx) error {
	var exists int
	err := tx.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='traffic_samples'`).Scan(&exists)
	if err != nil {
		return err
	}
	if exists == 0 {
		return nil // already migrated on a prior boot, or fresh install
	}

	rows, err := tx.Query(`SELECT interface, step_seconds, ts_unix, rx_bps, tx_bps FROM traffic_samples`)
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
	// deploy hit 105k+ legacy rows -> up to ~211k upserts). Each tx.Exec
	// call is its own implicit auto-commit transaction, and under WAL mode
	// that means one fsync per row -- on real disks that turned a first-boot
	// migration that should take seconds into something still not finished
	// after 50+ minutes, blocking storage.Open() (and therefore the entire
	// rest of run(): the secrets vault, the HTTP server, the link monitor)
	// for the whole time. Wrapping every upsert plus the rename in ONE
	// transaction reduces this to a single commit/fsync at the end.

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

	return nil
}

// MigrateTrafficSamplesToMetricSamplesForTest exposes the migration for tests
// in the storage_test package (which cannot call the unexported function
// directly). Test-only. Abre a transação por conta própria porque o runner não
// está no caminho: o teste chama a migração isolada, de propósito.
func (db *DB) MigrateTrafficSamplesToMetricSamplesForTest() error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido
	if err := upTrafficSamplesToMetricSamples(tx); err != nil {
		return err
	}
	return tx.Commit()
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

// SeedInitialAdmin cria a conta administrativa inicial se — e somente se — o
// banco ainda não tem usuário nenhum. Devolve created=false quando já existe
// alguém, e nesse caso não toca em nada.
//
// A senha vem de fora, gerada por quem chama, e não é mais constante. Até a
// v1.0.82 esta era uma linha de INSERT com o hash bcrypt fixo de "admin": toda
// instalação nascia com admin/admin, sem troca obrigatória, num painel que
// escuta a LAN inteira. Quem chama é responsável por mostrar a senha gerada ao
// operador — ela não é recuperável depois, só redefinível.
func (db *DB) SeedInitialAdmin(hashedPassword string) (created bool, err error) {
	var n int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("contar usuários: %w", err)
	}
	if n > 0 {
		return false, nil
	}
	if _, err := db.conn.Exec(
		`INSERT INTO users (id, username, password, role) VALUES ('default-admin', 'admin', ?, 'admin')`,
		hashedPassword); err != nil {
		return false, fmt.Errorf("criar o administrador inicial: %w", err)
	}
	return true, nil
}

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

// createRoutingPoliciesTable cria uma tabela que NENHUMA parte do produto lê ou
// escreve (issue #62): não há handler, service nem tela do outro lado. Ela
// continua sendo criada porque dropá-la é irreversível — e uma base instalada
// pode ter linhas que alguém colocou por SQL. Ver o comentário do bloco
// "Routing Policies" em repo_netsvc.go.
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

// link_quota é a franquia declarada de um link — o que o plano contratado
// permite —, e link_usage é o consumo medido dentro do ciclo vigente.
//
// SÃO DUAS TABELAS, E NÃO COLUNAS EM `links`, por dois motivos: a franquia é
// opcional (a maioria dos links não tem), e o consumo é escrita frequente
// (um UPDATE por minuto por link). Misturar isso na linha do link faria toda
// leitura de link disputar com o acumulador.
const createLinkQuotaTable = `
CREATE TABLE IF NOT EXISTS link_quota (
    link_id    TEXT PRIMARY KEY,
    limit_gb   REAL NOT NULL,
    cycle_day  INTEGER NOT NULL DEFAULT 1,
    alert_pct  INTEGER NOT NULL DEFAULT 80,
    enabled    INTEGER NOT NULL DEFAULT 1
);`

// A chave inclui cycle_start: o histórico dos ciclos anteriores fica, e o
// ciclo novo nasce zerado sem precisar apagar nada. É o que permite responder
// "quanto gastei no mês passado" sem uma segunda tabela de histórico.
const createLinkUsageTable = `
CREATE TABLE IF NOT EXISTS link_usage (
    link_id     TEXT NOT NULL,
    cycle_start INTEGER NOT NULL,
    rx_bytes    INTEGER NOT NULL DEFAULT 0,
    tx_bytes    INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (link_id, cycle_start)
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
    conn_state   TEXT NOT NULL DEFAULT '',
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
    id           TEXT PRIMARY KEY,
    only_row     INTEGER NOT NULL DEFAULT 1 CHECK (only_row = 1) UNIQUE,
    snapshot     TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    applied_by   TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reverting_at INTEGER NOT NULL DEFAULT 0,
    applied_state TEXT NOT NULL DEFAULT ''
);`

// ─── Painel com widgets (Fase B) ──────────────────────────────────────────
//
// Criada por migrateDashboardLayout (em transação), NÃO pela lista de
// migrações simples acima — ver o doc-comment daquela função.
//
// items guarda a lista de {widget,x,y,w,h} em JSON, e não uma linha por
// widget: o layout é lido e gravado sempre inteiro, nunca item a item, e uma
// segunda tabela só acrescentaria junção e ordem explícita para representar
// exatamente o mesmo documento.
const createDashboardLayoutTable = `
CREATE TABLE IF NOT EXISTS dashboard_layout (
    user_id    TEXT PRIMARY KEY,
    items      TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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

// runOneMigrationForTest aplica uma única `up` numa transação, sem passar pelo
// runner nem tocar em schema_migrations. Test-only: existe para os testes que
// exercitam UMA migração isolada, e não a sequência do boot.
func (db *DB) runOneMigrationForTest(up func(*sql.Tx) error) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido
	if err := up(tx); err != nil {
		return err
	}
	return tx.Commit()
}
