package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ─── Firewall rules repository (Phase B) ────────────────────────────────────

// ListFirewallRules returns every stored rule (enabled or not), ordered by
// position — the order ReconcileUserRules renders them into nft and the
// order the panel displays them in. The `created_at` tiebreaker makes that
// order deterministic even when two rows share the same position (should
// not normally happen — ReorderFirewallRules/CreateFirewallRule both assign
// distinct positions — but a hand-edited row or a bug elsewhere must not be
// able to make evaluation order flip between boots depending on SQLite's
// unspecified tie order for an ORDER BY with duplicate keys).
func (db *DB) ListFirewallRules() ([]FirewallRule, error) {
	rows, err := db.conn.Query(`
		SELECT id, position, group_id, enabled, action, iif, oif, saddr, daddr, proto, dport,
		       description, created_at, updated_at
		FROM firewall_rules ORDER BY position, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FirewallRule{}
	for rows.Next() {
		r, err := scanFirewallRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateFirewallRule inserts a new rule, always appended after every
// existing rule (position = current max + 1, or 0 for the first rule) and
// always starting enabled — a freshly created rule is never born disabled.
func (db *DB) CreateFirewallRule(r *FirewallRule) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now
	r.Enabled = true

	var maxPos sql.NullInt64
	if err := db.conn.QueryRow(`SELECT MAX(position) FROM firewall_rules`).Scan(&maxPos); err != nil {
		return err
	}
	r.Position = 0
	if maxPos.Valid {
		r.Position = int(maxPos.Int64) + 1
	}

	_, err := db.conn.Exec(`
		INSERT INTO firewall_rules (id, position, group_id, enabled, action, iif, oif, saddr, daddr, proto, dport,
		                            description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Position, r.GroupID, boolToInt(r.Enabled), r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport,
		r.Description, r.CreatedAt, r.UpdatedAt)
	return err
}

// ImportFirewallRules bulk-inserts rows (the Phase B one-time import,
// internal/firewallrules.Service.ImportOnce) and marks settingKey=settingValue
// (the import guard), all inside a single transaction — either every row
// lands and the guard flips, or neither does (I-5). Before this, the import
// loop inserted rows one CreateFirewallRule call at a time and then set the
// guard as an entirely separate write; a crash or DB error anywhere in
// between left the guard unset, so the next boot's ImportOnce ran the whole
// loop again and duplicated every already-imported rule.
//
// Position is assigned here as each row's index in rows (not by the
// caller) — the same sequential-from-zero scheme CreateFirewallRule uses
// for an ordinary create, kept consistent here so a bulk import can never
// collide with it. Enabled is taken exactly as given (unlike
// CreateFirewallRule, which always forces it true): C-2's round-trip check
// needs to import a rule it could not faithfully reproduce as disabled,
// not enabled-then-immediately-wrong.
func (db *DB) ImportFirewallRules(rows []FirewallRule, settingKey, settingValue string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`
		INSERT INTO firewall_rules (id, position, group_id, enabled, action, iif, oif, saddr, daddr, proto, dport,
		                            description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for i, r := range rows {
		if r.ID == "" {
			r.ID = uuid.NewString()
		}
		if _, err := stmt.Exec(r.ID, i, r.GroupID, boolToInt(r.Enabled), r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport,
			r.Description, now, now); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		settingKey, settingValue, now); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateFirewallRule edits a rule's content in place, by ID. It deliberately
// never touches Position or Enabled — reordering and enabling/disabling are
// their own dedicated operations (ReorderFirewallRules,
// SetFirewallRuleEnabled) so an ordinary content edit can never accidentally
// move a rule or flip it back on.
func (db *DB) UpdateFirewallRule(r *FirewallRule) error {
	res, err := db.conn.Exec(`
		UPDATE firewall_rules
		SET group_id=?, action=?, iif=?, oif=?, saddr=?, daddr=?, proto=?, dport=?, description=?, updated_at=?
		WHERE id=?`,
		r.GroupID, r.Action, r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport, r.Description, time.Now(), r.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("regra %q não encontrada", r.ID)
	}
	return nil
}

// DeleteFirewallRule removes a rule permanently by ID.
// DeleteFirewallRule removes a rule, reporting "não encontrada" when the id
// matches nothing — same contract as UpdateFirewallRule/SetFirewallRuleEnabled.
// Returning success for a no-op delete (the previous behaviour) hid a stale
// client from the admin and still triggered a full chain reconcile for
// nothing.
func (db *DB) DeleteFirewallRule(id string) error {
	res, err := db.conn.Exec(`DELETE FROM firewall_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("regra %q não encontrada", id)
	}
	return nil
}

// SetFirewallRuleEnabled flips a rule's enabled flag without touching
// anything else about it — the "disable without deleting" capability the
// whole DB-backed model exists for (design spec §4.1).
func (db *DB) SetFirewallRuleEnabled(id string, enabled bool) error {
	res, err := db.conn.Exec(`UPDATE firewall_rules SET enabled=?, updated_at=? WHERE id=?`,
		boolToInt(enabled), time.Now(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("regra %q não encontrada", id)
	}
	return nil
}

// ReorderFirewallRules sets each rule's position to its index in ids (0-based),
// in a single transaction — either every id in the list is a real rule and the
// whole reorder lands, or none of it does. It does not itself check that ids
// covers exactly the current set of rules (a partial list would silently
// leave the missing rules stranded at their old positions, which could
// collide with the new ones); that full-set check belongs to the caller,
// which has both the request and the current list to compare — see the API
// handler for the "ids missing or extra" rejection required by the design
// spec.
func (db *DB) ReorderFirewallRules(ids []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`UPDATE firewall_rules SET position=?, updated_at=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for i, id := range ids {
		res, err := stmt.Exec(i, now, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("regra %q não encontrada", id)
		}
	}
	return tx.Commit()
}

// ─── Firewall groups repository (Fase C1: grupos de regras) ────────────────

// FirewallGroup é um grupo de regras do admin: uma chain própria no nft,
// alcançada por um jump condicional a partir da chain forward.
type FirewallGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ChainName   string `json:"chain_name"`
	Position    int    `json:"position"`
	Enabled     bool   `json:"enabled"`
	CondSaddr   string `json:"cond_saddr"`
	CondDaddr   string `json:"cond_daddr"`
	CondIif     string `json:"cond_iif"`
	Fallthrough string `json:"fallthrough"` // continue | accept | drop
	Kind        string `json:"kind"`        // "" ou "admin" | nftables.GroupKindBlockedHosts | nftables.GroupKindBlocklist
	// Scope (Fase C2) diz em qual chain o grupo é alcançado: "" ou
	// nftables.ScopeForward (tráfego ATRAVESSANDO o firewall) e
	// nftables.ScopeInput (tráfego DESTINADO ao próprio firewall — SSH,
	// painel, DNS, Samba). Vazio conta como forward: é o valor de toda linha
	// criada antes desta coluna existir.
	Scope string `json:"scope"`
	// ConnState diz para QUAIS CONEXÕES o grupo vale: "" ou
	// nftables.ConnStateAny (toda conexão, estabelecida ou não — o
	// comportamento de sempre) e nftables.ConnStateNew (só conexões novas: a
	// linha do jump ganha `ct state new` e o que já está em curso segue até
	// terminar). Vazio conta como "any": é o valor de toda linha criada antes
	// desta coluna existir, e toda máquina em produção hoje bloqueia de
	// imediato.
	ConnState string `json:"conn_state"`
	// Janela de horário (#125). Vazio nos três = grupo vale sempre, que é o
	// valor de toda linha criada antes destas colunas existirem.
	//
	// SchedDays é lista de chaves curtas separadas por vírgula ("mon,tue"), e
	// vazio significa TODOS os dias — não "nenhum". SchedStart/SchedEnd são
	// "HH:MM" em hora LOCAL da máquina: medido no nft 1.1.3 do Debian 13, o
	// `meta hour` é avaliado na hora local do kernel, e não em UTC.
	//
	// Faixa que atravessa a meia-noite é válida e é o caso comum ("22:00" às
	// "06:00"); o nft trata a volta sozinho — também medido, não presumido.
	SchedDays  string    `json:"sched_days"`
	SchedStart string    `json:"sched_start"`
	SchedEnd   string    `json:"sched_end"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (db *DB) ListFirewallGroups() ([]FirewallGroup, error) {
	rows, err := db.conn.Query(`
        SELECT id, name, chain_name, position, enabled, cond_saddr, cond_daddr,
               cond_iif, fallthrough, kind, scope, conn_state,
               sched_days, sched_start, sched_end, created_at, updated_at
          FROM firewall_groups ORDER BY position ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirewallGroup
	for rows.Next() {
		var g FirewallGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.ChainName, &g.Position, &g.Enabled,
			&g.CondSaddr, &g.CondDaddr, &g.CondIif, &g.Fallthrough, &g.Kind, &g.Scope,
			&g.ConnState, &g.SchedDays, &g.SchedStart, &g.SchedEnd,
			&g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (db *DB) CreateFirewallGroup(g *FirewallGroup) error {
	now := time.Now()
	g.CreatedAt, g.UpdatedAt = now, now
	_, err := db.conn.Exec(`
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled,
            cond_saddr, cond_daddr, cond_iif, fallthrough, kind, scope, conn_state,
            sched_days, sched_start, sched_end, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Name, g.ChainName, g.Position, g.Enabled,
		g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.Kind, g.Scope, g.ConnState,
		g.SchedDays, g.SchedStart, g.SchedEnd,
		g.CreatedAt, g.UpdatedAt)
	return err
}

// UpdateFirewallGroup grava também o scope (Fase C2). As duas pontas mudaram
// JUNTAS, e é isso que este comentário existe para registrar: o handler passou
// a aceitar `scope` no corpo (internal/api/handlers.UpdateGroup) na mesma
// entrega em que a coluna entrou nesta lista.
//
// Enquanto o campo não existia na API, ele ficava DE FORA daqui de propósito —
// o chamador faz `row := existing`, a struct nasce da linha lida do banco e só
// os campos editáveis são sobrescritos, então nada era rebaixado. O perigo era
// o oposto e continua valendo como aviso para o próximo campo: um handler que
// leia um campo do corpo e NÃO mexa aqui produz o pior tipo de bug de painel —
// o admin muda o valor na tela, a resposta é 200, a tela mostra o valor novo
// até o próximo F5, e o banco (e portanto o firewall) continua exatamente como
// estava. Mudei na tela e não aconteceu nada.
//
// conn_state ("vale para toda conexão" × "só conexões novas") entrou nesta
// lista pela mesma porta e com a mesma disciplina: o campo só passou a ser
// gravado aqui junto com a entrega que o expõe. Vale para ele o mesmo aviso —
// e a mesma responsabilidade de quem chama, logo abaixo, de resolver "campo
// ausente no corpo" mantendo o valor já gravado, para que um cliente que não
// conheça o campo não devolva a "toda conexão" um grupo que o admin restringiu.
//
// Quem chama é responsável por não rebaixar o escopo sem querer: g.Scope é
// gravado como veio. O handler resolve "campo ausente no corpo" mantendo o
// valor já gravado, porque um cliente que não conhece o campo transformaria um
// grupo de input em forward em silêncio — mudando de chain as regras dele.
func (db *DB) UpdateFirewallGroup(g *FirewallGroup) error {
	g.UpdatedAt = time.Now()
	res, err := db.conn.Exec(`
        UPDATE firewall_groups
           SET name=?, cond_saddr=?, cond_daddr=?, cond_iif=?, fallthrough=?, scope=?,
               conn_state=?, sched_days=?, sched_start=?, sched_end=?, updated_at=?
         WHERE id=?`,
		g.Name, g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.Scope, g.ConnState,
		g.SchedDays, g.SchedStart, g.SchedEnd,
		g.UpdatedAt, g.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("grupo %q não encontrado", g.ID)
	}
	return nil
}

// DeleteFirewallGroup apaga o grupo E as regras dentro dele, na mesma
// transação. Foreign keys estão desligadas no driver, então nada no banco
// faria isso sozinho — e uma regra órfã seria exibida no painel sem chain
// nenhuma para ser renderizada, que é exatamente o tipo de mentira que o
// modelo de reconciliação existe para eliminar.
func (db *DB) DeleteFirewallGroup(id string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM firewall_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("grupo %q não encontrado", id)
	}
	if _, err := tx.Exec(`DELETE FROM firewall_rules WHERE group_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// MigrateRulesIntoGroup cria o grupo g, adota nele TODAS as regras que ainda
// não têm grupo, e grava a trava — tudo numa transação só. Se qualquer parte
// falhar, nada acontece: a alternativa seria a trava gravada com metade das
// regras adotadas, e a outra metade ficaria órfã, exibida no painel e
// ausente do firewall — sem segunda chance, já que a trava impediria a
// migração de rodar de novo. É a mesma disciplina de ImportFirewallRules
// (I-5), pela mesma razão.
//
// O UPDATE é escopado em `group_id = ”` de propósito: adota só o que está
// solto. Um UPDATE sem essa cláusula jogaria para dentro de "Minhas regras"
// grupos que o admin já tinha organizado.
func (db *DB) MigrateRulesIntoGroup(g FirewallGroup, settingKey, settingValue string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido

	now := time.Now()
	if _, err := tx.Exec(`
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled,
            cond_saddr, cond_daddr, cond_iif, fallthrough, kind, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Name, g.ChainName, g.Position, g.Enabled,
		g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.Kind, now, now); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE firewall_rules SET group_id = ?, updated_at = ? WHERE group_id = ''`,
		g.ID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		settingKey, settingValue, now); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSystemGroups insere os grupos que o próprio LinkGuard mantém (os dois
// bloqueios) no TOPO da lista e grava a trava de "isto já rodou" — tudo numa
// transação só, mesma disciplina de MigrateRulesIntoGroup e ImportFirewallRules,
// pela mesma razão: a trava gravada com só um dos dois grupos inseridos deixaria
// o outro bloqueio fora da lista para sempre (a trava impede uma segunda
// tentativa), e é a lista que passa a decidir se o bloqueio existe no firewall.
//
// O deslocamento (`position = position + n`) vem ANTES dos INSERTs e abre
// exatamente n posições no topo: os grupos do admin continuam na mesma ordem
// relativa, só empurrados para depois dos bloqueios — que é o padrão que já
// está valendo em produção (bloqueio vence regra do admin). Reordenar depois é
// escolha do admin, não desta migração.
//
// Position é atribuída aqui como o índice de cada linha em rows, não pelo
// chamador — mesmo esquema sequencial-a-partir-do-zero de ImportFirewallRules,
// para uma inserção em lote nunca colidir com o que o CRUD normal produz.
// Enabled vai exatamente como veio na linha.
func (db *DB) CreateSystemGroups(rows []FirewallGroup, settingKey, settingValue string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido

	now := time.Now()
	if len(rows) > 0 {
		if _, err := tx.Exec(
			`UPDATE firewall_groups SET position = position + ?, updated_at = ?`, len(rows), now); err != nil {
			return err
		}
	}

	stmt, err := tx.Prepare(`
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled,
            cond_saddr, cond_daddr, cond_iif, fallthrough, kind, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i, g := range rows {
		if _, err := stmt.Exec(g.ID, g.Name, g.ChainName, i, g.Enabled,
			g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.Kind, now, now); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		settingKey, settingValue, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) SetFirewallGroupEnabled(id string, enabled bool) error {
	res, err := db.conn.Exec(
		`UPDATE firewall_groups SET enabled=?, updated_at=? WHERE id=?`,
		enabled, time.Now(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("grupo %q não encontrado", id)
	}
	return nil
}

func (db *DB) ReorderFirewallGroups(ids []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	for i, id := range ids {
		res, err := tx.Exec(
			`UPDATE firewall_groups SET position=?, updated_at=? WHERE id=?`, i, now, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("grupo %q não encontrado", id)
		}
	}
	return tx.Commit()
}

// ─── Confirmar-ou-reverte: o pendente (Fase C2) ────────────────────────────

// PendingChange é uma mudança de firewall APLICADA e ainda não confirmada
// pelo operador — o coração do confirmar-ou-reverte (spec §5).
//
// Snapshot é o estado ANTERIOR dos grupos e das regras, serializado (ver
// internal/firewallrules). Não é o ruleset inteiro do nft: reverter aqui é
// escopado — restaura estas linhas no banco e reconcilia as chains próprias
// (spec §5.2). O projeto nunca dá flush no que não é dele.
//
// ExpiresAt é o instante, do relógio do servidor, em que a reversão
// automática acontece se ninguém confirmar. É a única fonte da verdade da
// contagem regressiva: o painel a desenha a partir daqui, e recarregar a
// página não reinicia nada.
// RevertingAt é o instante em que a reversão desta mudança COMEÇOU —
// zero enquanto ela não começou. Ele mora no banco, e não num campo do
// serviço, porque é a única forma de a marca sobreviver a um restart: com ela
// só em memória, um processo novo sobre o mesmo banco voltava a aceitar
// "confirmar" uma mudança cujo estado anterior já tinha sido restaurado aqui,
// respondia sucesso ao operador e apagava o pendente — deixando a regra que
// trancou o acesso dele viva no firewall, sem ninguém para retomar a reversão.
//
// AppliedState é o OUTRO lado do Snapshot: o estado dos grupos e regras como a
// mutação desta janela o deixou (issue #20a). Ele é gravado depois da escrita da
// mutação, e é o que permite à reversão distinguir "o banco ainda é o que esta
// janela produziu" de "outro admin gravou aqui dentro no meio do caminho" — a
// diferença entre desfazer a própria mudança e apagar em silêncio a de outra
// pessoa. Ver AppliedStateOrSnapshot e firewallrules.revert.
type PendingChange struct {
	ID           string    `json:"id"`
	Snapshot     string    `json:"snapshot"`
	AppliedState string    `json:"applied_state,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	AppliedBy    string    `json:"applied_by"`
	Summary      string    `json:"summary"`
	CreatedAt    time.Time `json:"created_at"`
	RevertingAt  time.Time `json:"reverting_at,omitempty"`
}

// AppliedStateOrSnapshot é o estado pós-mutação desta janela, com o Snapshot
// como resposta quando ele ainda não foi registrado.
//
// Vazio acontece em dois casos, e a mesma resposta serve para os dois:
//
//   - a janela foi armada e a mutação dela ainda não gravou nada. O estado
//     pós-mutação é, literalmente, o de antes, e responder o Snapshot está
//     CERTO;
//   - o processo morreu entre a escrita e o registro, ou a linha veio de uma
//     versão anterior a esta coluna existir. Aqui o Snapshot subestima o que a
//     janela fez, e a resposta é o lado possível, não o lado certo.
//
// E o segundo caso tem um preço que não dá para suavizar. Com applied ==
// snapshot, tudo o que esta janela mudou "diverge do pós-mutação" — parece
// escrita de outro admin — e é PRESERVADO pela reversão. Ela deixa de ser um
// "volte tudo" e passa a ser quase o oposto: desfaz apenas o que alcança a
// chain input.
//
// O que continua segurando o ACESSO à máquina é esse limite da input
// (mergeRevertTarget nunca preserva o que a alcança), e não o fallback. Fora
// dele a janela fica de pé, e não é pouco: uma reordenação de grupos abre a
// janela pelo índice de um grupo de input mas reescreve a posição de todos os
// grupos, os de forward inclusive — essas posições não voltam, e a auditoria
// ainda registra como alteração de terceiros o que a própria janela fez.
func (p PendingChange) AppliedStateOrSnapshot() string {
	if p.AppliedState != "" {
		return p.AppliedState
	}
	return p.Snapshot
}

// Reverting diz se a reversão desta mudança já começou (o estado anterior já
// voltou ao banco; o que faltou foi o firewall vivo). Enquanto for verdade,
// confirmar é recusado e a próxima passada do watchdog RETOMA a reversão.
func (p PendingChange) Reverting() bool { return !p.RevertingAt.IsZero() }

// SavePendingChange grava o pendente. Falha se já houver um (a coluna
// only_row é UNIQUE com CHECK (only_row = 1)), e essa falha é o
// comportamento desejado: abrir janela com uma já aberta é ERRO, não
// empilhamento — com dois pendentes, "reverter ao estado anterior" não teria
// resposta (spec §5.3). Quem chama tem que exigir a confirmação ou a
// reversão da janela em aberto primeiro.
//
// CreatedAt vem do CHAMADOR (m-4): quem abre a janela usa o relógio injetado
// do serviço, o mesmo de que sai o expires_at, e um time.Now() cru aqui
// gravaria um created_at que não bate com ele. Zero cai para time.Now() só
// para não obrigar chamadores que não têm relógio próprio.
func (db *DB) SavePendingChange(p PendingChange) error {
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := db.conn.Exec(`
        INSERT INTO pending_firewall_change (id, only_row, snapshot, expires_at, applied_by, summary, created_at, reverting_at, applied_state)
        VALUES (?, 1, ?, ?, ?, ?, ?, 0, ?)`,
		p.ID, p.Snapshot, p.ExpiresAt.Unix(), p.AppliedBy, p.Summary, created, p.AppliedState)
	return err
}

// SetPendingAppliedState grava o estado pós-mutação desta janela — o que a
// mutação que a armou acabou de deixar no banco (issue #20a).
//
// Chamada logo depois da escrita da mutação, e não no arme: no arme o banco
// ainda é o estado ANTERIOR, que já está no snapshot. É a distância entre os
// dois que diz o que esta janela mudou, e é isso que a reversão desfaz —
// deixando de pé o que outra pessoa gravou no meio dos 90 segundos.
//
// Pendente que já não existe (confirmado, revertido, trocado) NÃO é erro: a
// janela cujo estado se ia registrar acabou, e não há nada a registrar. O id
// na cláusula WHERE é o que impede escrever o estado desta mutação por cima da
// janela de outra pessoa.
func (db *DB) SetPendingAppliedState(id, state string) error {
	_, err := db.conn.Exec(
		`UPDATE pending_firewall_change SET applied_state = ? WHERE id = ?`, state, id)
	return err
}

// SetPendingSnapshot troca o estado anterior guardado por esta janela.
//
// Tem UM chamador e uma razão: a reversão que precisou preservar a alteração de
// outro admin restaura um estado que não é mais o snapshot original, e o
// snapshot é o que responde "a reversão já terminou no banco?"
// (firewallrules.RevertSettled). Sem atualizá-lo, uma reconciliação que falhasse
// depois deixaria a trava das mutações fechada para sempre — o beco C-6, que já
// custou uma máquina só alcançável por sqlite3.
func (db *DB) SetPendingSnapshot(id, snapshot string) error {
	_, err := db.conn.Exec(
		`UPDATE pending_firewall_change SET snapshot = ? WHERE id = ?`, snapshot, id)
	return err
}

// MarkPendingReverting grava que a reversão desta mudança já começou — isto é,
// que o estado anterior JÁ voltou aos grupos e regras do banco e que o que
// falta é só o firewall vivo.
//
// Chamada DEPOIS de a transação de restauração ter commitado, nunca antes: a
// marca é uma afirmação sobre o banco ("o estado anterior já está aqui"), e
// gravá-la antes a tornaria mentira exatamente no caso em que a restauração
// falha — com dois efeitos, os dois ruins: confirmar passaria a responder "o
// estado anterior já foi restaurado" sobre um banco intocado, e a verificação
// de expiração passaria a reverter antes do prazo, tirando do operador o tempo
// que ele ainda tinha.
//
// Pendente que sumiu no meio do caminho é erro, e não silêncio: quem chama
// acabou de restaurar o banco e precisa saber que a marca não ficou.
func (db *DB) MarkPendingReverting(id string, at time.Time) error {
	res, err := db.conn.Exec(
		`UPDATE pending_firewall_change SET reverting_at = ? WHERE id = ?`, at.Unix(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("marcar a reversão em andamento: a mudança pendente %s não está mais no banco", id)
	}
	return nil
}

// GetPendingChange devolve o pendente, ou nil quando não há nenhum. Erro de
// leitura viaja como erro: quem chama não pode confundir "não consegui ler"
// com "não há janela aberta" — o segundo libera mutação e some com a faixa
// do painel.
func (db *DB) GetPendingChange() (*PendingChange, error) {
	var p PendingChange
	var expires, reverting int64
	err := db.conn.QueryRow(`
        SELECT id, snapshot, expires_at, applied_by, summary, created_at, reverting_at, applied_state
          FROM pending_firewall_change LIMIT 1`).
		Scan(&p.ID, &p.Snapshot, &expires, &p.AppliedBy, &p.Summary, &p.CreatedAt, &reverting, &p.AppliedState)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ExpiresAt = time.Unix(expires, 0)
	if reverting != 0 {
		p.RevertingAt = time.Unix(reverting, 0)
	}
	return &p, nil
}

// ClearPendingChange apaga o pendente — chamado quando o operador confirma
// (a mudança fica) e depois de uma reversão (a mudança foi desfeita). Nos
// dois casos a janela está resolvida.
func (db *DB) ClearPendingChange() error {
	_, err := db.conn.Exec(`DELETE FROM pending_firewall_change`)
	return err
}

// systemGroupKinds são os dois `kind` de grupo que o próprio LinkGuard mantém
// (os bloqueios administrativos). Os literais estão repetidos aqui, e não
// importados, porque internal/storage não depende de internal/nftables — a
// fonte deles é nftables.GroupKindBlockedHosts/GroupKindBlocklist, e o
// comentário do campo Kind em FirewallGroup diz o mesmo.
var systemGroupKinds = map[string]string{
	"blocked_hosts": "Hosts bloqueados",
	"blocklist":     "Lista de bloqueio",
}

// missingSystemGroupKinds devolve, pelo nome que o operador conhece, os grupos
// do sistema que NÃO aparecem na lista. Ver ReplaceFirewallGroupsAndRules.
func missingSystemGroupKinds(groups []FirewallGroup) []string {
	present := make(map[string]bool, len(systemGroupKinds))
	for _, g := range groups {
		if _, isSystem := systemGroupKinds[g.Kind]; isSystem {
			present[g.Kind] = true
		}
	}
	var missing []string
	// Ordem fixa (e não a do map) para a mensagem de erro ser estável.
	for _, kind := range []string{"blocked_hosts", "blocklist"} {
		if !present[kind] {
			missing = append(missing, systemGroupKinds[kind])
		}
	}
	return missing
}

// ReplaceFirewallGroupsAndRules substitui, numa transação só, TODOS os grupos
// e TODAS as regras pelo conteúdo do snapshot — é o lado banco da reversão
// (spec §5.2).
//
// Uma transação, e não uma sequência de DELETE/INSERT soltos, pela mesma
// razão de ImportFirewallRules e CreateSystemGroups: um erro no meio deixaria
// o firewall do admin pela metade — parte dos grupos do estado novo, parte do
// antigo — e a reconciliação que vem logo depois renderizaria exatamente essa
// mistura no nft. É o estado que ninguém sabe consertar remotamente.
//
// Position e Enabled vão exatamente como estão nas linhas do snapshot: isto
// restaura um estado que já existiu, não cria um novo (nada de renumerar como
// CreateFirewallRule faz).
//
// Lista de grupos VAZIA é recusada: com ela, a reconciliação seguinte
// esvaziaria a chain forward por completo — inclusive os bloqueios
// administrativos, que desde a Fase C1 também são itens da lista — e apagaria
// todas as chains grp_. Nenhum snapshot legítimo é assim (toda máquina tem os
// dois grupos do sistema); um que seja é corrupção, e obedecer a ele
// derrubaria o firewall inteiro em nome de uma reversão de segurança.
//
// I-2: lista SEM OS DOIS GRUPOS DO SISTEMA é recusada pela mesma razão e é o
// caso realmente perigoso, porque passava pela guarda de cima. Um snapshot com
// um único grupo do admin e sem blocked_hosts/blocklist tinha `len(groups) > 0`
// e o `DELETE FROM firewall_groups` apagava os dois — e nada os recria
// (firewallrules.EnsureSystemGroups é travado por flag de settings). A partir
// dali ensureSystemGroupsPresent aborta TODA reconciliação da máquina, para
// sempre: o firewall congela no último estado aplicado e nenhuma mudança do
// admin volta a valer. É a MESMA invariante que ensureSystemGroupsPresent
// defende do outro lado, aqui na única função que consegue violá-la.
func (db *DB) ReplaceFirewallGroupsAndRules(groups []FirewallGroup, rules []FirewallRule) error {
	if len(groups) == 0 {
		return fmt.Errorf("recusando restaurar um snapshot sem nenhum grupo: isso apagaria o firewall inteiro, inclusive os bloqueios administrativos")
	}
	if missing := missingSystemGroupKinds(groups); len(missing) > 0 {
		return fmt.Errorf("recusando restaurar um snapshot sem o grupo do sistema %s: isso apagaria o bloqueio do banco, e nada o recria — toda reconciliação da máquina passaria a abortar",
			strings.Join(missing, " e "))
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois de um Commit bem-sucedido

	if _, err := tx.Exec(`DELETE FROM firewall_rules`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM firewall_groups`); err != nil {
		return err
	}

	// created_at E updated_at vêm do SNAPSHOT (m-3). Carimbar time.Now() no
	// updated_at, como esta função fazia, escrevia num campo de AUDITORIA um
	// estado que nunca existiu: o operador abriria o histórico e leria "esta
	// regra foi alterada às 03:14", quando às 03:14 ela foi restaurada
	// exatamente como estava antes. Restaurar é repor um estado que já
	// existiu, não criar um novo — a mesma disciplina que faz position e
	// enabled irem literais.
	gstmt, err := tx.Prepare(`
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled,
            cond_saddr, cond_daddr, cond_iif, fallthrough, kind, scope, conn_state,
            sched_days, sched_start, sched_end, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer gstmt.Close()
	for _, g := range groups {
		if _, err := gstmt.Exec(g.ID, g.Name, g.ChainName, g.Position, g.Enabled,
			g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.Kind, g.Scope, g.ConnState,
			g.SchedDays, g.SchedStart, g.SchedEnd,
			g.CreatedAt, g.UpdatedAt); err != nil {
			return err
		}
	}

	rstmt, err := tx.Prepare(`
        INSERT INTO firewall_rules (id, position, group_id, enabled, action, iif, oif,
            saddr, daddr, proto, dport, description, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer rstmt.Close()
	for _, r := range rules {
		if _, err := rstmt.Exec(r.ID, r.Position, r.GroupID, r.Enabled, r.Action,
			r.Iif, r.Oif, r.Saddr, r.Daddr, r.Proto, r.Dport, r.Description,
			r.CreatedAt, r.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func scanFirewallRule(s interface {
	Scan(...interface{}) error
}) (FirewallRule, error) {
	var r FirewallRule
	var enabled int
	err := s.Scan(
		&r.ID, &r.Position, &r.GroupID, &enabled, &r.Action, &r.Iif, &r.Oif, &r.Saddr, &r.Daddr, &r.Proto, &r.Dport,
		&r.Description, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = enabled != 0
	return r, err
}
