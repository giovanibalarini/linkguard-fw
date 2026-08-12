# Grupos de regras — Fase C1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Substituir a lista chapada de regras personalizadas por grupos nomeados com condição de entrada, ordem própria e ligar/desligar em bloco — mantendo tudo que existe hoje funcionando através de uma migração automática.

**Architecture:** Cada grupo vira uma chain regular do nftables (`grp_<hex>`), e a condição de entrada vira a linha de `jump` na chain `forward`. O banco continua sendo a fonte de verdade e o nft o resultado renderizado, exatamente como a Fase B já faz para `user_rules`. A chain `forward` passa a ser renderizada dinamicamente: bloqueios primeiro, depois um `jump` por grupo ativado, na ordem configurada.

**Tech Stack:** Go 1.25 (`~/sdk/go1.25.0/bin`), SQLite via `modernc.org/sqlite`, nftables, React + TypeScript + Tailwind (Node via `~/.nvm/versions/node/v22.21.1/bin`).

## Global Constraints

Toda tarefa herda estas restrições. Violá-las é motivo de reprovação na revisão.

1. **Fixture de nft tem que ser saída real do nft.** O nft aspeia `iifname`/`oifname` (`iifname "enp5s0"`) e canonicaliza endereço (`10.0.0.1/32` → `10.0.0.1`). Nunca use a saída de `buildRuleTokens` como fixture do que o nft devolveria — foi assim que um bug crítico passou por 5 testes verdes em 2026-08-11.
2. **Nunca dar flush em ruleset inteiro nem em tabela.** Só `nft flush chain inet linkguard <chain>`, um chain por vez. Todo teste de reconciliação assere isso.
3. **Toda migração de schema em transação.** Em 2026-07-24 uma migração sem transação travou o boot por 50+ minutos.
4. **Nada de dado falso na UI.** Estado que não pôde ser avaliado exibe `—` ou "não sei". Nunca zero sintético, nunca `ok` sintético.
5. **Validar com a ferramenta real antes de escrever no banco.** `nft -c -f` via `Service.CheckChain`, sempre antes do `INSERT`/`UPDATE`, nunca depois.
6. **Ordem na remoção de chain:** reconstruir `forward` sem o `jump` **antes** de apagar a chain referenciada; o nft recusa apagar chain ainda referenciada.
7. **Nomes de chain derivam do id, nunca do nome digitado.** Nome com caractere especial viraria injeção no argv do `nft`; renomear quebraria a chain.
8. **Foreign keys estão desligadas** no driver `modernc.org/sqlite`. Integridade referencial é responsabilidade do código, não do banco.
9. **Escopo:** apenas tráfego atravessando (chain `forward`). O escopo "destinado ao firewall" e o confirmar-ou-reverte são a Fase C2 e **não** entram aqui.
10. Comentários e mensagens ao usuário em português; nomes de identificador em inglês, como no resto do repositório.

## File Structure

**Criar:**
- `internal/nftables/groups.go` — modelo `StoredGroup`, nome de chain, validação da condição, tokens do `jump`, renderização do chain do grupo.
- `internal/nftables/groups_test.go`
- `internal/nftables/reconcile_groups.go` — `ReconcileGroups`, `CheckGroups`, limpeza de chains órfãs.
- `internal/nftables/reconcile_groups_test.go`
- `internal/nftables/merge_groups.go` — `MergeGroups` (visão honesta com `Applied`).
- `internal/nftables/merge_groups_test.go`
- `internal/firewallrules/migrate_groups.go` — migração única das regras atuais.
- `internal/firewallrules/migrate_groups_test.go`
- `internal/api/handlers/groups.go` — CRUD de grupos.
- `internal/api/handlers/groups_test.go`
- `web/src/components/RuleGroups.tsx` — índice + detalhe.
- `web/src/components/BlocksAndRouting.tsx` — aba "Bloqueios e direcionamento".

**Modificar:**
- `internal/storage/storage.go` — tabela `firewall_groups`, coluna `firewall_rules.group_id`.
- `internal/storage/repository.go` — CRUD de grupo, migração transacional.
- `internal/nftables/reconcile.go` — `forwardChainRules` passa a receber os grupos.
- `internal/nftables/classify.go` — descrever `jump` para grupo.
- `internal/firewallrules/service.go` — `Reconcile` passa a reconciliar grupos.
- `internal/api/handlers/nftables.go` — regras passam a viver dentro de grupo.
- `internal/api/server.go` — rotas novas.
- `cmd/linkguard-fw/main.go` — migração e reconciliação no boot.
- `web/src/pages/Firewall.tsx`, `web/src/types.ts`.

---

### Task 1: Schema e persistência dos grupos

**Files:**
- Modify: `internal/storage/storage.go` (lista `migrations` em `migrate()`, ~linha 55; constantes de schema ~linha 485)
- Modify: `internal/storage/repository.go` (após `ReorderFirewallRules`, ~linha 1614)
- Test: `internal/storage/storage_test.go`

**Interfaces:**
- Consumes: `storage.FirewallRule` (já existe), `db.conn` (`*sql.DB`).
- Produces:
  - `type FirewallGroup struct { ID, Name, ChainName string; Position int; Enabled bool; CondSaddr, CondDaddr, CondIif string; Fallthrough string; CreatedAt, UpdatedAt time.Time }`
  - `func (db *DB) ListFirewallGroups() ([]FirewallGroup, error)`
  - `func (db *DB) CreateFirewallGroup(g *FirewallGroup) error`
  - `func (db *DB) UpdateFirewallGroup(g *FirewallGroup) error`
  - `func (db *DB) DeleteFirewallGroup(id string) error`
  - `func (db *DB) SetFirewallGroupEnabled(id string, enabled bool) error`
  - `func (db *DB) ReorderFirewallGroups(ids []string) error`
  - `func (db *DB) MigrateRulesIntoGroup(g FirewallGroup, settingKey, settingValue string) error`
  - `FirewallRule` ganha o campo `GroupID string`

- [ ] **Step 1: Escrever o teste que falha**

Em `internal/storage/storage_test.go`:

```go
func TestFirewallGroupCRUDAndOrder(t *testing.T) {
	db := newTestDB(t)

	a := FirewallGroup{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaaa0001",
		Position: 0, Enabled: true, CondSaddr: "192.168.50.0/24", Fallthrough: "drop"}
	b := FirewallGroup{ID: "b", Name: "Servidores", ChainName: "grp_bbbb0002",
		Position: 1, Enabled: true, CondSaddr: "192.168.3.10", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&a); err != nil {
		t.Fatalf("criar grupo a: %v", err)
	}
	if err := db.CreateFirewallGroup(&b); err != nil {
		t.Fatalf("criar grupo b: %v", err)
	}

	got, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatalf("listar: %v", err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("esperava a,b em ordem de posição, obtive %+v", got)
	}
	if got[0].Fallthrough != "drop" || got[0].CondSaddr != "192.168.50.0/24" {
		t.Errorf("campos não persistiram: %+v", got[0])
	}

	if err := db.ReorderFirewallGroups([]string{"b", "a"}); err != nil {
		t.Fatalf("reordenar: %v", err)
	}
	got, _ = db.ListFirewallGroups()
	if got[0].ID != "b" || got[1].ID != "a" {
		t.Errorf("reordenar não teve efeito: %+v", got)
	}

	if err := db.SetFirewallGroupEnabled("a", false); err != nil {
		t.Fatalf("desligar: %v", err)
	}
	got, _ = db.ListFirewallGroups()
	for _, g := range got {
		if g.ID == "a" && g.Enabled {
			t.Error("grupo a deveria estar desligado")
		}
	}
}

// Apagar um grupo tem que levar as regras dele junto, na mesma transação:
// foreign keys estão DESLIGADAS no modernc, então nada no banco faz isso
// sozinho, e uma regra órfã seria renderizada em chain nenhuma — presente
// no painel, ausente do firewall.
func TestDeleteFirewallGroupRemovesItsRules(t *testing.T) {
	db := newTestDB(t)
	g := FirewallGroup{ID: "g1", Name: "Testes", ChainName: "grp_cccc0003", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar grupo: %v", err)
	}
	r := FirewallRule{ID: "r1", GroupID: "g1", Action: "drop", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatalf("criar regra: %v", err)
	}

	if err := db.DeleteFirewallGroup("g1"); err != nil {
		t.Fatalf("apagar grupo: %v", err)
	}
	rules, _ := db.ListFirewallRules()
	for _, x := range rules {
		if x.GroupID == "g1" {
			t.Fatalf("regra %s ficou órfã depois de apagar o grupo", x.ID)
		}
	}
}

func TestDeleteFirewallGroupUnknownIDIsAnError(t *testing.T) {
	db := newTestDB(t)
	if err := db.DeleteFirewallGroup("nao-existe"); err == nil {
		t.Fatal("apagar grupo inexistente tem que ser erro, não silêncio")
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/storage/ -run TestFirewallGroup
```
Esperado: FAIL — `undefined: FirewallGroup`.

- [ ] **Step 3: Adicionar o schema**

Em `internal/storage/storage.go`, junto das outras constantes de schema:

```go
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
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
```

Registrar `createFirewallGroupsTable` na lista `migrations` de `migrate()`, **antes** de `createFirewallRulesTable`.

`chain_name` é `UNIQUE` porque duas chains com o mesmo nome fariam o `jump` de um grupo cair no chain de outro — silenciosamente, sem erro do nft.

- [ ] **Step 4: Adicionar `group_id` a `firewall_rules`**

Ainda em `internal/storage/storage.go`, seguindo o padrão de `migrateAddPasswordVersion` (~linha 102), que é o único `ALTER TABLE ADD COLUMN` do projeto:

```go
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
```

Chamar em `migrate()`, depois do laço de `migrations` e junto das outras migrações imperativas:

```go
	if err := db.migrateAddFirewallRuleGroupID(); err != nil {
		return fmt.Errorf("migrate add firewall_rules.group_id: %w", err)
	}
```

E acrescentar `group_id` ao `CREATE TABLE IF NOT EXISTS firewall_rules` (para bancos novos), logo depois de `position`:

```sql
    group_id    TEXT NOT NULL DEFAULT '',
```

- [ ] **Step 5: Implementar o CRUD**

Em `internal/storage/repository.go`, depois de `ReorderFirewallRules`. Espelhar exatamente o estilo das funções de `FirewallRule` logo acima (mesma checagem de `RowsAffected`, mesmo uso de `time.Now()`):

```go
// FirewallGroup é um grupo de regras do admin: uma chain própria no nft,
// alcançada por um jump condicional a partir da chain forward.
type FirewallGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ChainName   string    `json:"chain_name"`
	Position    int       `json:"position"`
	Enabled     bool      `json:"enabled"`
	CondSaddr   string    `json:"cond_saddr"`
	CondDaddr   string    `json:"cond_daddr"`
	CondIif     string    `json:"cond_iif"`
	Fallthrough string    `json:"fallthrough"` // continue | accept | drop
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (db *DB) ListFirewallGroups() ([]FirewallGroup, error) {
	rows, err := db.conn.Query(`
        SELECT id, name, chain_name, position, enabled, cond_saddr, cond_daddr,
               cond_iif, fallthrough, created_at, updated_at
          FROM firewall_groups ORDER BY position ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirewallGroup
	for rows.Next() {
		var g FirewallGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.ChainName, &g.Position, &g.Enabled,
			&g.CondSaddr, &g.CondDaddr, &g.CondIif, &g.Fallthrough,
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
            cond_saddr, cond_daddr, cond_iif, fallthrough, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Name, g.ChainName, g.Position, g.Enabled,
		g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.CreatedAt, g.UpdatedAt)
	return err
}

func (db *DB) UpdateFirewallGroup(g *FirewallGroup) error {
	g.UpdatedAt = time.Now()
	res, err := db.conn.Exec(`
        UPDATE firewall_groups
           SET name=?, cond_saddr=?, cond_daddr=?, cond_iif=?, fallthrough=?, updated_at=?
         WHERE id=?`,
		g.Name, g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, g.UpdatedAt, g.ID)
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
```

Acrescentar `GroupID string \`json:"group_id"\`` ao struct `FirewallRule` (logo depois de `Position`) e incluir a coluna em `ListFirewallRules`, `CreateFirewallRule`, `ImportFirewallRules` e `UpdateFirewallRule` — todos os `SELECT`/`INSERT` que hoje listam as colunas explicitamente.

- [ ] **Step 6: Rodar e confirmar que passa**

```bash
go test ./internal/storage/ -run 'TestFirewallGroup|TestDeleteFirewallGroup' -v
```
Esperado: PASS nos três testes.

- [ ] **Step 7: Suíte inteira do pacote**

```bash
go test ./internal/storage/
```
Esperado: `ok` — nenhum teste existente quebrado pela coluna nova.

- [ ] **Step 8: Commit**

```bash
git add internal/storage/
git commit -m "feat(storage): tabela de grupos de firewall e group_id nas regras"
```

---

### Task 2: Modelo do grupo no pacote nftables

**Files:**
- Create: `internal/nftables/groups.go`
- Test: `internal/nftables/groups_test.go`

**Interfaces:**
- Consumes: `RuleFields`, `buildRuleTokens`, `validIPv4OrCIDR`, `reIface`, `StoredRule` (todos já em `internal/nftables`).
- Produces:
  - `type GroupFallthrough = string` com as constantes `FallthroughContinue = "continue"`, `FallthroughAccept = "accept"`, `FallthroughDrop = "drop"`
  - `type StoredGroup struct { ID, Name, ChainName string; Position int; Enabled bool; CondSaddr, CondDaddr, CondIif string; Fallthrough string; Rules []StoredRule }`
  - `func GroupChainName(id string) string`
  - `func ValidateGroup(g StoredGroup) error`
  - `func groupJumpTokens(g StoredGroup) ([]string, error)`
  - `func renderGroupChain(g StoredGroup) (tokenSets [][]string, skipped []string)`

- [ ] **Step 1: Escrever o teste que falha**

Crie `internal/nftables/groups_test.go`:

```go
package nftables

import (
	"strings"
	"testing"
)

func TestGroupChainNameDerivesFromIDNotName(t *testing.T) {
	// O nome digitado nunca entra no nome da chain: renomear quebraria o
	// jump, e um nome com caractere especial viraria injeção no argv do nft.
	got := GroupChainName("a3f21c08-9d4e-4b1a-8c77-0e5b2d6f1a99")
	if got != "grp_a3f21c089d4e" {
		t.Fatalf("nome de chain inesperado: %q", got)
	}
	if strings.ContainsAny(got, " ;\"'`$&|") {
		t.Fatalf("nome de chain com caractere perigoso: %q", got)
	}
	// Determinístico entre chamadas.
	if GroupChainName("a3f21c08-9d4e-4b1a-8c77-0e5b2d6f1a99") != got {
		t.Fatal("GroupChainName não é determinístico")
	}
}

func TestGroupJumpTokensCarriesConditionAndCounter(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_abc123def456",
		CondIif: "enp0s3", CondSaddr: "192.168.50.0/24"}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	want := "iifname enp0s3 ip saddr 192.168.50.0/24 counter jump grp_abc123def456"
	if strings.Join(toks, " ") != want {
		t.Fatalf("jump inesperado:\n  obtive %q\n  queria %q", strings.Join(toks, " "), want)
	}
}

func TestGroupWithoutConditionJumpsUnconditionally(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_abc123def456"}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if strings.Join(toks, " ") != "counter jump grp_abc123def456" {
		t.Fatalf("grupo sem condição deveria pular incondicionalmente, obtive %q",
			strings.Join(toks, " "))
	}
}

func TestValidateGroupRejectsBadCondition(t *testing.T) {
	cases := []struct{ name string; g StoredGroup }{
		{"origem IPv6", StoredGroup{Name: "g", CondSaddr: "2001:db8::1"}},
		{"origem lixo", StoredGroup{Name: "g", CondSaddr: "nao-e-ip"}},
		{"destino inválido", StoredGroup{Name: "g", CondDaddr: "999.1.1.1"}},
		{"interface com espaço", StoredGroup{Name: "g", CondIif: "eth0; rm -rf /"}},
		{"fallthrough desconhecido", StoredGroup{Name: "g", Fallthrough: "talvez"}},
		{"sem nome", StoredGroup{Name: "   "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateGroup(c.g); err == nil {
				t.Fatalf("esperava recusa para %+v", c.g)
			}
		})
	}
}

func TestRenderGroupChainAppendsFallthroughLine(t *testing.T) {
	rules := []StoredRule{
		{ID: "r1", Position: 0, Enabled: true, Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "443"}},
		{ID: "r2", Position: 1, Enabled: false, Fields: RuleFields{Action: "drop", Proto: "udp", Dport: "53"}},
	}
	g := StoredGroup{ID: "x", ChainName: "grp_a", Fallthrough: FallthroughDrop, Rules: rules}

	sets, skipped := renderGroupChain(g)
	if len(skipped) != 0 {
		t.Fatalf("nada deveria ser pulado, obtive %v", skipped)
	}
	if len(sets) != 2 {
		t.Fatalf("esperava 1 regra ativada + 1 linha de fallthrough, obtive %d: %v", len(sets), sets)
	}
	if strings.Join(sets[0], " ") != "tcp dport 443 counter accept" {
		t.Errorf("regra renderizada errada: %q", strings.Join(sets[0], " "))
	}
	if strings.Join(sets[1], " ") != "counter drop" {
		t.Errorf("linha de fallthrough errada: %q", strings.Join(sets[1], " "))
	}
}

func TestRenderGroupChainContinueEmitsNoFinalLine(t *testing.T) {
	g := StoredGroup{ID: "x", ChainName: "grp_a", Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}
	sets, _ := renderGroupChain(g)
	if len(sets) != 1 {
		t.Fatalf("\"continuar\" não emite linha final; esperava 1 conjunto, obtive %d: %v", len(sets), sets)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run 'TestGroup|TestValidateGroup|TestRenderGroup'
```
Esperado: FAIL — `undefined: GroupChainName`.

- [ ] **Step 3: Implementar**

Crie `internal/nftables/groups.go`:

```go
package nftables

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// GroupChainPrefix identifica, no ruleset vivo, as chains que pertencem a
// grupos do admin — é assim que a reconciliação sabe quais chains são suas
// para poder apagar as órfãs sem tocar em nada de terceiros.
const GroupChainPrefix = "grp_"

// Valores possíveis para StoredGroup.Fallthrough: o que o grupo faz com o
// tráfego que entrou nele (a condição casou) mas não casou com nenhuma
// regra de dentro.
const (
	FallthroughContinue = "continue" // não emite linha final: o jump retorna e a avaliação segue
	FallthroughAccept   = "accept"   // counter accept como última linha
	FallthroughDrop     = "drop"     // counter drop como última linha
)

// StoredGroup é a visão deste pacote de um grupo de regras, deliberadamente
// independente de internal/storage.FirewallGroup — internal/nftables não
// pode importar internal/storage (ciclo), exatamente como já acontece com
// StoredRule. O chamador converte antes de chamar.
type StoredGroup struct {
	ID          string
	Name        string
	ChainName   string
	Position    int
	Enabled     bool
	CondSaddr   string
	CondDaddr   string
	CondIif     string
	Fallthrough string
	Rules       []StoredRule
}

// GroupChainName deriva o nome da chain do id do grupo, nunca do nome que o
// admin digitou: o nome é editável (renomear quebraria a chain e deixaria a
// antiga órfã) e é texto livre (um nome com espaço, aspa ou `;` entraria
// num argv do nft). 12 dígitos hexadecimais de um UUID dão folga de sobra
// contra colisão, e o resultado casa com [a-z0-9_], que o nft aceita sem
// aspas.
func GroupChainName(id string) string {
	hex := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, id)
	if len(hex) > 12 {
		hex = hex[:12]
	}
	if hex == "" {
		hex = "0"
	}
	return GroupChainPrefix + hex
}

// ValidateGroup checa tudo que vai parar num argv do nft ou numa tela, com
// o mesmo rigor que ValidateRuleFields aplica aos campos de uma regra: a
// condição de entrada do grupo é interpolada num comando do nft igual a
// qualquer outra.
func ValidateGroup(g StoredGroup) error {
	if strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("o grupo precisa de um nome")
	}
	if len(g.Name) > 80 {
		return fmt.Errorf("nome muito longo (máx. 80 caracteres)")
	}
	if g.CondIif != "" && !reIface.MatchString(g.CondIif) {
		return fmt.Errorf("interface de entrada inválida")
	}
	if g.CondSaddr != "" && !validIPv4OrCIDR(g.CondSaddr) {
		return fmt.Errorf("origem inválida: use um IP/CIDR IPv4 (IPv6 ainda não é suportado)")
	}
	if g.CondDaddr != "" && !validIPv4OrCIDR(g.CondDaddr) {
		return fmt.Errorf("destino inválido: use um IP/CIDR IPv4 (IPv6 ainda não é suportado)")
	}
	switch g.Fallthrough {
	case FallthroughContinue, FallthroughAccept, FallthroughDrop:
	default:
		return fmt.Errorf("valor inválido para \"e o que sobrar\" (use continue, accept ou drop)")
	}
	return nil
}

// groupJumpTokens monta a linha que vai na chain forward: a condição de
// entrada seguida de `counter jump <chain do grupo>`. A ordem dos campos é
// a mesma de buildRuleTokens de propósito — as duas produzem texto que é
// comparado com a saída do nft, e divergir na ordem faria a comparação
// falhar sem que nada estivesse errado.
//
// O `counter` aqui é o que mede quanto tráfego de fato ENTROU no grupo, e é
// esse número que o painel mostra ao lado do grupo — não a soma das regras,
// que contaria a mais o que casou duas condições e a menos o que entrou e
// não casou com nada.
func groupJumpTokens(g StoredGroup) ([]string, error) {
	if g.ChainName == "" {
		return nil, fmt.Errorf("grupo %q sem nome de chain", g.ID)
	}
	var t []string
	if g.CondIif != "" {
		if !reIface.MatchString(g.CondIif) {
			return nil, fmt.Errorf("interface de entrada inválida")
		}
		t = append(t, "iifname", g.CondIif)
	}
	if g.CondSaddr != "" {
		if !validIPv4OrCIDR(g.CondSaddr) {
			return nil, fmt.Errorf("origem inválida")
		}
		t = append(t, "ip", "saddr", g.CondSaddr)
	}
	if g.CondDaddr != "" {
		if !validIPv4OrCIDR(g.CondDaddr) {
			return nil, fmt.Errorf("destino inválido")
		}
		t = append(t, "ip", "daddr", g.CondDaddr)
	}
	return append(t, "counter", "jump", g.ChainName), nil
}

// renderGroupChain rende o conteúdo da chain do grupo: as regras ativadas
// em ordem de posição, e depois a linha de "e o que sobrar" quando ela
// existe. Espelha renderEnabledUserRules (mesma ordenação, mesmo filtro de
// ativadas, mesmo buildRuleTokens, mesma devolução dos ids pulados) para
// que a validação e a reconciliação nunca rendam coisas diferentes.
//
// "continuar avaliando" não emite linha nenhuma: no nftables, um jump que
// chega ao fim da chain simplesmente retorna e a avaliação segue de onde
// parou. É o comportamento nativo, não um caso especial.
func renderGroupChain(g StoredGroup) (tokenSets [][]string, skipped []string) {
	sorted := make([]StoredRule, len(g.Rules))
	copy(sorted, g.Rules)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		tokens, err := buildRuleTokens(r.Fields)
		if err != nil {
			skipped = append(skipped, r.ID)
			slog.Warn("regra ignorada ao renderizar a chain do grupo: campos inválidos",
				"grupo", g.ID, "regra", r.ID, "err", err)
			continue
		}
		tokenSets = append(tokenSets, tokens)
	}

	switch g.Fallthrough {
	case FallthroughAccept:
		tokenSets = append(tokenSets, []string{"counter", "accept"})
	case FallthroughDrop:
		tokenSets = append(tokenSets, []string{"counter", "drop"})
	}
	return tokenSets, skipped
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run 'TestGroup|TestValidateGroup|TestRenderGroup' -v
```
Esperado: PASS nos seis testes.

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/groups.go internal/nftables/groups_test.go
git commit -m "feat(nftables): modelo de grupo, nome de chain por id e renderização"
```

---

### Task 3: Reconciliação dos grupos e inversão da ordem na chain forward

**Files:**
- Create: `internal/nftables/reconcile_groups.go`
- Test: `internal/nftables/reconcile_groups_test.go`
- Modify: `internal/nftables/reconcile.go` (`forwardChainRules`, ~linha 199; `ReconcileStructuralChains`, ~linha 242)

**Interfaces:**
- Consumes: `StoredGroup`, `groupJumpTokens`, `renderGroupChain`, `GroupChainPrefix` (Task 2); `rebuildChain`, `CheckChain`, `renderChainScript`, `Persist`, `ForwardChain`, `BlockedSet`, `UserChain` (já existem).
- Produces:
  - `func forwardChainRules(groups []StoredGroup) [][]string`
  - `func (s *Service) ReconcileGroups(ctx context.Context, groups []StoredGroup) error`
  - `func (s *Service) CheckGroups(ctx context.Context, groups []StoredGroup) error`
  - `func (s *Service) listGroupChains(ctx context.Context) ([]string, error)`

- [ ] **Step 1: Escrever o teste que falha**

Crie `internal/nftables/reconcile_groups_test.go`:

```go
package nftables

import (
	"context"
	"strings"
	"testing"
)

// A inversão da spec §3: bloqueio administrativo é avaliado ANTES dos
// grupos do admin e sempre vence. Até a Fase B era o contrário — um
// "permitir" do usuário anulava a lista de bloqueio — e ninguém percebia.
func TestForwardChainPutsBlocksBeforeGroupJumps(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa", Enabled: true, Position: 0, CondSaddr: "192.168.50.0/24"},
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 1},
	}
	var lines []string
	for _, toks := range forwardChainRules(groups) {
		lines = append(lines, strings.Join(toks, " "))
	}

	firstJump, lastBlock := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "jump grp_") && firstJump < 0 {
			firstJump = i
		}
		if strings.Contains(l, "drop") {
			lastBlock = i
		}
	}
	if firstJump < 0 {
		t.Fatalf("nenhum jump para grupo foi emitido: %v", lines)
	}
	if lastBlock > firstJump {
		t.Fatalf("bloqueio depois do primeiro jump — a ordem da §3 não vale:\n%v", lines)
	}
	if !strings.Contains(lines[firstJump], "ip saddr 192.168.50.0/24") {
		t.Errorf("o jump perdeu a condição do grupo: %q", lines[firstJump])
	}
}

func TestForwardChainSkipsDisabledGroups(t *testing.T) {
	groups := []StoredGroup{
		{ID: "a", ChainName: "grp_aaa", Enabled: false, Position: 0},
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 1},
	}
	joined := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Contains(joined, "grp_aaa") {
		t.Error("grupo desligado não pode ter jump na forward")
	}
	if !strings.Contains(joined, "grp_bbb") {
		t.Error("grupo ligado precisa ter jump na forward")
	}
}

func TestForwardChainRespectsGroupOrder(t *testing.T) {
	groups := []StoredGroup{
		{ID: "b", ChainName: "grp_bbb", Enabled: true, Position: 5},
		{ID: "a", ChainName: "grp_aaa", Enabled: true, Position: 1},
	}
	s := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Index(s, "grp_aaa") > strings.Index(s, "grp_bbb") {
		t.Errorf("ordem dos jumps não seguiu Position:\n%s", s)
	}
}

// A regra de segurança do projeto, replicada de ReconcileMasquerade: nunca
// dar flush em ruleset nem em tabela, só nos chains próprios.
func TestReconcileGroupsNeverFlushesRulesetOrTable(t *testing.T) {
	exec := &fakeNftExec{}
	s := NewService(exec)
	groups := []StoredGroup{{ID: "a", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue,
		Rules: []StoredRule{{ID: "r", Enabled: true,
			Fields: RuleFields{Action: "accept", Proto: "tcp", Dport: "22"}}}}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, cmd := range exec.executed {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "flush ruleset") {
			t.Fatalf("deu flush no ruleset inteiro: %q", joined)
		}
		if strings.Contains(joined, "flush table") {
			t.Fatalf("deu flush na tabela: %q", joined)
		}
	}
}

// A chain do grupo tem que existir antes de a forward pular para ela, e a
// chain órfã só pode ser apagada depois de a forward parar de referenciá-la
// — o nft recusa apagar chain ainda referenciada.
func TestReconcileGroupsOrdersCreateBeforeJumpAndDeleteAfter(t *testing.T) {
	exec := &fakeNftExec{
		readOut: map[string]string{
			"list chains inet linkguard": "chain grp_orfa\nchain grp_aaa\nchain forward\n",
		},
	}
	s := NewService(exec)
	groups := []StoredGroup{{ID: "a", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	idxAdd, idxJump, idxDel := -1, -1, -1
	for i, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		switch {
		case strings.HasPrefix(j, "add chain") && strings.Contains(j, "grp_aaa"):
			idxAdd = i
		case strings.Contains(j, "jump grp_aaa"):
			idxJump = i
		case strings.HasPrefix(j, "delete chain") && strings.Contains(j, "grp_orfa"):
			idxDel = i
		}
	}
	if idxAdd < 0 || idxJump < 0 {
		t.Fatalf("faltou criar a chain ou emitir o jump: %v", exec.executed)
	}
	if idxAdd > idxJump {
		t.Error("a chain do grupo precisa existir ANTES de a forward pular para ela")
	}
	if idxDel < 0 {
		t.Fatal("chain órfã não foi removida")
	}
	if idxDel < idxJump {
		t.Error("chain órfã removida antes de a forward ser reconstruída — o nft recusaria")
	}
}
```

Se `fakeNftExec` ainda não tiver um campo `readOut map[string]string`, acrescente-o e faça `ExecuteRead` devolver a entrada cujo prefixo casar com os argumentos, mantendo o comportamento atual como padrão.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run 'TestForwardChain|TestReconcileGroups'
```
Esperado: FAIL — `forwardChainRules` não aceita argumento, `ReconcileGroups` indefinido.

- [ ] **Step 3: Reescrever `forwardChainRules` em `reconcile.go`**

Trocar a função atual por:

```go
// forwardChainRules é o conteúdo canônico e ordenado da chain forward.
// Ordem importa — o nft avalia de cima para baixo:
//
//  1. Os bloqueios administrativos (host bloqueado, destino bloqueado)
//     vêm PRIMEIRO e vencem qualquer regra do admin. Até a Fase B era o
//     contrário: um "permitir" do usuário anulava a lista de bloqueio, o
//     que fazia o botão "bloquear host em 1 clique" mentir. Se o bloqueio
//     não vence, ele não é bloqueio (design spec §3).
//  2. Depois, um jump por grupo ativado, na ordem que o admin configurou.
//     A condição de entrada do grupo vai na própria linha do jump: se ela
//     não casa, o grupo inteiro é pulado sem o kernel olhar as regras de
//     dentro.
//
// Toda linha carrega `counter`: ver ReconcileStructuralChains sobre por que
// isso não é negociável.
func forwardChainRules(groups []StoredGroup) [][]string {
	rules := [][]string{
		{"ip", "saddr", "@" + BlockedSet, "counter", "drop"},
		{"ip", "daddr", "@" + BlockedSet, "counter", "drop"},
		{"ip", "daddr", "@blocklist", "counter", "drop"},
		{"ip", "saddr", "@blocklist", "counter", "drop"},
	}

	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	for _, g := range sorted {
		if !g.Enabled {
			continue // desligar = tirar o jump; a chain e as regras continuam guardadas
		}
		tokens, err := groupJumpTokens(g)
		if err != nil {
			slog.Error("grupo ignorado ao montar a chain forward: condição inválida",
				"grupo", g.ID, "nome", g.Name, "err", err)
			continue
		}
		rules = append(rules, tokens)
	}
	return rules
}
```

Acrescentar `"sort"` aos imports de `reconcile.go`.

Em `ReconcileStructuralChains`, trocar a chamada `s.rebuildChain(ctx, ForwardChain, forwardChainRules())` por uma que não mexe mais na forward — a forward passa a ser responsabilidade de `ReconcileGroups`, que é quem conhece os grupos:

```go
func (s *Service) ReconcileStructuralChains(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	// A chain forward saiu daqui: ela agora depende dos grupos do admin e é
	// reconstruída por ReconcileGroups, que é quem os conhece. Reconciliar
	// as duas em lugares diferentes faria a última a rodar apagar os jumps
	// da outra.
	if err := s.rebuildChain(ctx, MarkHostsChain, markHostsChainRules()); err != nil {
		return err
	}
	slog.Info("chains estruturais reconciliadas a partir da definição canônica", "chains", []string{MarkHostsChain})
	if err := s.Persist(ctx); err != nil {
		slog.Warn("chains estruturais reconciliadas, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}
```

- [ ] **Step 4: Implementar a reconciliação dos grupos**

Crie `internal/nftables/reconcile_groups.go`:

```go
package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

var reChainName = regexp.MustCompile(`^\s*chain\s+([A-Za-z0-9_]+)\s*{?`)

// listGroupChains devolve os nomes das chains do ruleset vivo que pertencem
// a grupos (prefixo grp_). É o que permite apagar a chain de um grupo que o
// admin removeu sem nunca tocar em chain de terceiros.
func (s *Service) listGroupChains(ctx context.Context) ([]string, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "chains", Family, Table)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		m := reChainName.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.HasPrefix(m[1], GroupChainPrefix) {
			names = append(names, m[1])
		}
	}
	return names, nil
}

// ReconcileGroups reconstrói, a partir do banco, todo o conjunto de chains
// dos grupos e a chain forward que os alcança. Mantém as mesmas garantias
// de segurança do resto do pacote: só dá flush nos chains próprios (nunca
// na tabela nem no ruleset), é idempotente para a mesma entrada, é no-op em
// dry-run, e persiste ao final.
//
// A ordem dos quatro passos não é arbitrária, e trocá-la quebra:
//
//  1. Criar as chains que faltam. O nft recusa um `jump` para chain
//     inexistente, então elas precisam existir antes do passo 3.
//  2. Preencher cada chain (flush + regras + linha de "e o que sobrar").
//     Vale também para grupo desligado: as regras dele continuam guardadas
//     no nft, só que ninguém pula para lá.
//  3. Reconstruir a forward: bloqueios primeiro, depois um jump por grupo
//     ativado, na ordem do admin.
//  4. Só agora apagar as chains órfãs (grupos que o admin removeu). O nft
//     recusa apagar chain ainda referenciada — se isto rodasse antes do
//     passo 3, a forward ainda teria o jump e a remoção falharia.
func (s *Service) ReconcileGroups(ctx context.Context, groups []StoredGroup) error {
	if s.exec.IsDryRun() {
		return nil
	}

	wanted := make(map[string]bool, len(groups))
	for _, g := range groups {
		wanted[g.ChainName] = true
	}

	// 1. criar o que falta (idempotente: `add chain` não reclama se já existe)
	for _, g := range groups {
		if _, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, g.ChainName); err != nil {
			return fmt.Errorf("criar chain do grupo %q: %w", g.Name, err)
		}
	}

	// 2. preencher cada chain
	var skippedAll []string
	for _, g := range groups {
		tokenSets, skipped := renderGroupChain(g)
		skippedAll = append(skippedAll, skipped...)
		if err := s.rebuildChain(ctx, g.ChainName, tokenSets); err != nil {
			return fmt.Errorf("reconstruir chain do grupo %q: %w", g.Name, err)
		}
	}

	// 3. reconstruir a forward
	if err := s.rebuildChain(ctx, ForwardChain, forwardChainRules(groups)); err != nil {
		return err
	}

	// 4. remover as órfãs, agora que ninguém mais pula para elas
	live, err := s.listGroupChains(ctx)
	if err != nil {
		slog.Warn("não foi possível listar as chains de grupo para limpar as órfãs", "err", err)
	} else {
		for _, name := range live {
			if wanted[name] {
				continue
			}
			if _, err := s.exec.Execute(ctx, "nft", "delete", "chain", Family, Table, name); err != nil {
				slog.Warn("não foi possível remover chain de grupo órfã", "chain", name, "err", err)
				continue
			}
			slog.Info("chain de grupo órfã removida", "chain", name)
		}
	}

	slog.Info("grupos de regras reconciliados a partir do banco",
		"grupos", len(groups), "regras_puladas", len(skippedAll))

	if err := s.Persist(ctx); err != nil {
		slog.Warn("grupos reconciliados, mas não foi possível persistir para o próximo boot", "err", err)
	}
	if len(skippedAll) > 0 {
		return &SkippedRulesError{IDs: skippedAll}
	}
	return nil
}

// CheckGroups valida, com um dry run só de parsing (`nft -c`), exatamente
// as chains que ReconcileGroups renderizaria — mesma renderização, mesma
// ordem — para que uma regra que passa aqui esteja garantida de virar os
// mesmos comandos que a reconciliação de verdade vai emitir depois.
//
// Roda ANTES de qualquer escrita no banco (ver
// internal/firewallrules.Service.CheckPendingGroups): validação de campo
// não pega tudo que o nft recusaria, e reconciliar direto numa regra que o
// nft recusa já custou uma chain truncada em produção.
func (s *Service) CheckGroups(ctx context.Context, groups []StoredGroup) error {
	for _, g := range groups {
		tokenSets, _ := renderGroupChain(g)
		if err := s.CheckChain(ctx, g.ChainName, tokenSets); err != nil {
			return fmt.Errorf("grupo %q: %w", g.Name, err)
		}
	}
	return s.CheckChain(ctx, ForwardChain, forwardChainRules(groups))
}
```

- [ ] **Step 5: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run 'TestForwardChain|TestReconcileGroups' -v
```
Esperado: PASS nos cinco testes.

- [ ] **Step 6: Ajustar os testes existentes que ainda chamam `forwardChainRules()`**

```bash
go build ./... && go test ./internal/nftables/
```
Esperado: compila e passa. Onde um teste antigo chamava `forwardChainRules()`, passe `nil`. Se algum teste assertava que a forward começa com `jump user_rules`, ele agora está descrevendo o comportamento errado: **atualize a expectativa para a ordem nova e registre no commit que a mudança é intencional** — a chain `user_rules` deixa de ser alcançada pela forward (a Task 5 a remove).

- [ ] **Step 7: Commit**

```bash
git add internal/nftables/
git commit -m "feat(nftables): reconciliar grupos e inverter a ordem dos bloqueios na forward"
```

---

### Task 4: Visão honesta dos grupos (`Applied`)

**Files:**
- Create: `internal/nftables/merge_groups.go`
- Test: `internal/nftables/merge_groups_test.go`

**Interfaces:**
- Consumes: `StoredGroup`, `ChainInfo`, `ChainRule`, `MergeUserRules`, `ExpressionMatches`, `syntheticUserRule`.
- Produces:
  - `type GroupView struct { StoredGroup; Applied bool; Handle int; Packets, Bytes uint64; HasCounter bool; Rules ChainInfo }`
  - `func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView`

- [ ] **Step 1: Escrever o teste que falha**

Crie `internal/nftables/merge_groups_test.go`:

```go
package nftables

import "testing"

// Fixture com a forma REAL do nft: interface aspeada e /32 comido. Fixture
// gerado por buildRuleTokens esconderia exatamente a classe de bug que
// custou a revisão de 2026-08-11.
func TestMergeGroupsMarksAppliedFromRealNftOutput(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Wi-Fi visitantes", ChainName: "grp_aaa",
		Enabled: true, CondSaddr: "192.168.50.0/24", Fallthrough: FallthroughDrop,
		Rules: []StoredRule{{ID: "r1", Enabled: true,
			Fields: RuleFields{Action: "accept", Iif: "enp0s3", Saddr: "10.0.0.1/32",
				Proto: "tcp", Dport: "443"}}}}

	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: `ip saddr 192.168.50.0/24 jump grp_aaa`, Handle: 7,
			HasCounter: true, Packets: 1247, Bytes: 4312576},
	}}
	chains := map[string]ChainInfo{"grp_aaa": {Name: "grp_aaa", Rules: []ChainRule{
		{Expression: `iifname "enp0s3" ip saddr 10.0.0.1 tcp dport 443 accept`,
			Handle: 9, HasCounter: true, Packets: 1219, Bytes: 4302438},
	}}}

	views := MergeGroups([]StoredGroup{g}, chains, forward)
	if len(views) != 1 {
		t.Fatalf("esperava 1 grupo, obtive %d", len(views))
	}
	v := views[0]
	if !v.Applied {
		t.Error("o grupo está na forward e deveria constar como aplicado")
	}
	if v.Packets != 1247 || !v.HasCounter {
		t.Errorf("o contador do grupo tem que vir da linha do jump, obtive %+v", v)
	}
	if len(v.Rules.Rules) != 1 || !v.Rules.Rules[0].Applied {
		t.Errorf("a regra de dentro deveria constar como aplicada: %+v", v.Rules.Rules)
	}
}

// Grupo desligado: não existe jump para ele, e isso é o esperado — não pode
// virar alarme falso de "configurada, não aplicada".
func TestMergeGroupsDisabledGroupIsNotFlaggedUnapplied(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Testes", ChainName: "grp_aaa", Enabled: false,
		Fallthrough: FallthroughContinue}
	views := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})
	if views[0].Applied {
		t.Error("grupo desligado não está aplicado, e isso é o correto")
	}
	if views[0].HasCounter {
		t.Error("sem contador medido, HasCounter tem que ser false — nunca um zero inventado")
	}
}

// Grupo ligado cujo jump sumiu do firewall: é o caso que o selo
// "Configurada, não aplicada" existe para expor.
func TestMergeGroupsEnabledWithoutJumpIsUnapplied(t *testing.T) {
	g := StoredGroup{ID: "a", Name: "Servidores", ChainName: "grp_aaa", Enabled: true,
		Fallthrough: FallthroughContinue}
	views := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})
	if views[0].Applied {
		t.Error("grupo ligado sem jump vivo NÃO está aplicado")
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run TestMergeGroups
```
Esperado: FAIL — `undefined: MergeGroups`.

- [ ] **Step 3: Implementar**

Crie `internal/nftables/merge_groups.go`:

```go
package nftables

import (
	"sort"
	"strings"
)

// GroupView é um grupo do banco somado ao que o firewall vivo diz sobre
// ele: se o jump está mesmo lá (Applied), quanto tráfego entrou (o contador
// da linha do jump) e as regras de dentro já pareadas com suas contrapartes
// vivas.
type GroupView struct {
	StoredGroup
	Applied    bool      `json:"applied"`
	Handle     int       `json:"handle"`
	Packets    uint64    `json:"packets"`
	Bytes      uint64    `json:"bytes"`
	HasCounter bool      `json:"has_counter"`
	RuleChain  ChainInfo `json:"rule_chain"`
}

// MergeGroups produz a visão honesta dos grupos: todos os grupos do banco,
// em ordem, cada um dizendo se está de fato valendo no firewall.
//
// Applied só é verdadeiro quando existe, na chain forward viva, uma linha de
// jump para a chain deste grupo — nunca inferido de Enabled. Enabled é o que
// o admin pediu; Applied é o que o kernel está fazendo. Confundir os dois é
// exatamente a confiança falsa que este painel existe para eliminar, e foi
// um achado crítico da revisão da Fase B.
//
// Sem contrapartida viva, o contador fica com HasCounter=false — "não
// medido" —, jamais com um zero, que significaria "medido, e deu zero".
func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	// Indexa os jumps vivos por nome de chain de destino.
	type live struct {
		handle           int
		packets, bytes   uint64
		hasCounter       bool
	}
	jumps := map[string]live{}
	for _, r := range forward.Rules {
		idx := strings.LastIndex(r.Expression, "jump ")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(r.Expression[idx+len("jump "):])
		if !strings.HasPrefix(target, GroupChainPrefix) {
			continue
		}
		jumps[target] = live{handle: r.Handle, packets: r.Packets,
			bytes: r.Bytes, hasCounter: r.HasCounter}
	}

	out := make([]GroupView, 0, len(sorted))
	for _, g := range sorted {
		v := GroupView{StoredGroup: g}
		if l, ok := jumps[g.ChainName]; ok {
			v.Applied = true
			v.Handle = l.handle
			v.Packets, v.Bytes, v.HasCounter = l.packets, l.bytes, l.hasCounter
		}
		// As regras de dentro reusam integralmente o pareamento por
		// identidade da Fase B — inclusive a normalização da forma que o nft
		// imprime (aspas em iifname, /32 comido).
		v.RuleChain = MergeUserRules(g.Rules, chains[g.ChainName])
		out = append(out, v)
	}
	return out
}
```

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run TestMergeGroups -v
```
Esperado: PASS nos três testes.

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/merge_groups.go internal/nftables/merge_groups_test.go
git commit -m "feat(nftables): visão honesta dos grupos com Applied vindo do jump vivo"
```

---

**As tarefas 5 a 10 continuam em `2026-08-11-firewall-rule-groups-c1-parte2.md`** — migração, classify/overview, API, boot, e as duas telas. O arquivo foi dividido porque um plano único ficaria grande demais para um implementador carregar de uma vez.
