# Grupos de regras — Fase C1 — Plano, parte 2 (tarefas 5 a 10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Continuação de `2026-08-11-firewall-rule-groups-c1.md` — as **Global Constraints** daquele arquivo valem integralmente aqui e não são repetidas.

**Interfaces já produzidas pelas tarefas 1 a 4** (um implementador destas tarefas não vê aquelas, então esta é a única fonte):

```go
// internal/storage
type FirewallGroup struct {
    ID, Name, ChainName string
    Position            int
    Enabled             bool
    CondSaddr, CondDaddr, CondIif string
    Fallthrough         string // "continue" | "accept" | "drop"
    CreatedAt, UpdatedAt time.Time
}
type FirewallRule struct { ID string; GroupID string; Position int; Enabled bool
    Action, Iif, Oif, Saddr, Daddr, Proto, Dport, Description string
    CreatedAt, UpdatedAt time.Time }

func (db *DB) ListFirewallGroups() ([]FirewallGroup, error)
func (db *DB) CreateFirewallGroup(g *FirewallGroup) error
func (db *DB) UpdateFirewallGroup(g *FirewallGroup) error
func (db *DB) DeleteFirewallGroup(id string) error          // apaga as regras junto, em transação
func (db *DB) SetFirewallGroupEnabled(id string, enabled bool) error
func (db *DB) ReorderFirewallGroups(ids []string) error
func (db *DB) ListFirewallRules() ([]FirewallRule, error)

// internal/nftables
const GroupChainPrefix = "grp_"
const FallthroughContinue, FallthroughAccept, FallthroughDrop = "continue", "accept", "drop"
type StoredGroup struct { ID, Name, ChainName string; Position int; Enabled bool
    CondSaddr, CondDaddr, CondIif, Fallthrough string; Rules []StoredRule }
type GroupView struct { StoredGroup; Applied bool; Handle int
    Packets, Bytes uint64; HasCounter bool; RuleChain ChainInfo }

func GroupChainName(id string) string
func ValidateGroup(g StoredGroup) error
func (s *Service) ReconcileGroups(ctx context.Context, groups []StoredGroup) error
func (s *Service) CheckGroups(ctx context.Context, groups []StoredGroup) error
func MergeGroups(groups []StoredGroup, chains map[string]ChainInfo, forward ChainInfo) []GroupView
```

---

### Task 5: Migração única das regras atuais para o grupo "Minhas regras"

**Files:**
- Create: `internal/firewallrules/migrate_groups.go`
- Test: `internal/firewallrules/migrate_groups_test.go`
- Modify: `internal/storage/repository.go` (acrescentar `MigrateRulesIntoGroup`)
- Modify: `internal/firewallrules/service.go` (`Reconcile` passa a reconciliar grupos)

**Interfaces:**
- Produces:
  - `func (db *DB) MigrateRulesIntoGroup(g FirewallGroup, settingKey, settingValue string) error`
  - `const GroupsMigratedSettingKey = "firewall_groups_migrated"`
  - `func (s *Service) MigrateRulesIntoDefaultGroup(ctx context.Context) error`
  - `func (s *Service) storedGroups() ([]nftables.StoredGroup, error)`
  - `Service.Reconcile` passa a chamar `ReconcileGroups`

- [ ] **Step 1: Escrever o teste que falha**

Crie `internal/firewallrules/migrate_groups_test.go`:

```go
package firewallrules

import (
	"context"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestMigrateCreatesDefaultGroupAndAdoptsRulesInOrder(t *testing.T) {
	db := newTestDB(t)
	for i, r := range []storage.FirewallRule{
		{ID: "r1", Position: 0, Enabled: true, Action: "drop", Proto: "udp", Dport: "161"},
		{ID: "r2", Position: 1, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"},
	} {
		r.Position = i
		if err := db.CreateFirewallRule(&r); err != nil {
			t.Fatalf("preparar regra: %v", err)
		}
	}
	svc := newTestService(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	groups, _ := db.ListFirewallGroups()
	if len(groups) != 1 {
		t.Fatalf("esperava exatamente 1 grupo, obtive %d: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Name != "Minhas regras" {
		t.Errorf("nome do grupo padrão: %q", g.Name)
	}
	// Comportamento idêntico ao de hoje: sem condição, "continuar avaliando".
	if g.CondSaddr != "" || g.CondDaddr != "" || g.CondIif != "" {
		t.Errorf("o grupo da migração não pode ter condição: %+v", g)
	}
	if g.Fallthrough != "continue" {
		t.Errorf("o grupo da migração tem que continuar avaliando, obtive %q", g.Fallthrough)
	}
	if !g.Enabled {
		t.Error("o grupo da migração tem que nascer ligado")
	}

	rules, _ := db.ListFirewallRules()
	for _, r := range rules {
		if r.GroupID != g.ID {
			t.Errorf("regra %s ficou fora do grupo (group_id=%q)", r.ID, r.GroupID)
		}
	}
	if rules[0].ID != "r1" || rules[1].ID != "r2" {
		t.Errorf("a ordem das regras não foi preservada: %+v", rules)
	}
}

func TestMigrateIsIdempotentAndDoesNotResurrectDeletedRules(t *testing.T) {
	db := newTestDB(t)
	r := storage.FirewallRule{ID: "r1", Position: 0, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("primeira migração: %v", err)
	}
	groups, _ := db.ListFirewallGroups()
	if err := db.DeleteFirewallGroup(groups[0].ID); err != nil {
		t.Fatalf("apagar: %v", err)
	}

	if err := svc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		t.Fatalf("segunda migração: %v", err)
	}
	groups, _ = db.ListFirewallGroups()
	if len(groups) != 0 {
		t.Fatalf("a migração rodou de novo e ressuscitou o que o admin apagou: %+v", groups)
	}
}

func TestMigrateWithNoRulesStillSetsTheGuard(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}
	groups, _ := db.ListFirewallGroups()
	if len(groups) != 0 {
		t.Errorf("sem regras não há o que agrupar, não deveria criar grupo vazio: %+v", groups)
	}
	v, _ := db.GetSetting(GroupsMigratedSettingKey)
	if v == "" {
		t.Error("a trava tem que ser gravada mesmo sem nada a migrar, senão roda de novo todo boot")
	}
}

// A chain user_rules só pode ser apagada depois de a forward parar de
// referenciá-la — o nft recusa apagar chain ainda referenciada.
func TestMigrateRemovesUserRulesChainOnlyAfterForwardRebuild(t *testing.T) {
	db := newTestDB(t)
	r := storage.FirewallRule{ID: "r1", Position: 0, Enabled: true, Action: "accept", Proto: "tcp", Dport: "22"}
	if err := db.CreateFirewallRule(&r); err != nil {
		t.Fatal(err)
	}
	svc, exec := newTestServiceWithExec(t, db)

	if err := svc.MigrateRulesIntoDefaultGroup(context.Background()); err != nil {
		t.Fatalf("migrar: %v", err)
	}

	idxForward, idxDelete := -1, -1
	for i, cmd := range exec.executed {
		j := strings.Join(cmd, " ")
		if strings.HasPrefix(j, "flush chain") && strings.HasSuffix(j, " forward") {
			idxForward = i
		}
		if strings.HasPrefix(j, "delete chain") && strings.Contains(j, "user_rules") {
			idxDelete = i
		}
	}
	if idxDelete < 0 {
		t.Fatal("a chain user_rules não foi removida depois da migração")
	}
	if idxForward < 0 || idxDelete < idxForward {
		t.Errorf("user_rules apagada antes de a forward ser reconstruída — o nft recusaria (ordem: forward=%d, delete=%d)", idxForward, idxDelete)
	}
}
```

Se `newTestDB`/`newTestService` ainda não existirem neste pacote, crie-os no mesmo arquivo seguindo o padrão do teste existente de `ImportOnce`; `newTestServiceWithExec` devolve também o fake executor para inspeção da ordem dos comandos.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/firewallrules/ -run TestMigrate
```
Esperado: FAIL — `MigrateRulesIntoDefaultGroup` indefinido.

- [ ] **Step 3: Adicionar a transação de migração no storage**

Em `internal/storage/repository.go`, junto das funções de grupo:

```go
// MigrateRulesIntoGroup cria o grupo g, adota nele TODAS as regras que
// ainda não têm grupo, e grava a trava — tudo numa transação só. Se
// qualquer parte falhar, nada acontece: a alternativa seria a trava gravada
// com metade das regras adotadas, e a outra metade ficaria órfã, exibida no
// painel e ausente do firewall. É a mesma disciplina de ImportFirewallRules.
func (db *DB) MigrateRulesIntoGroup(g FirewallGroup, settingKey, settingValue string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	if _, err := tx.Exec(`
        INSERT INTO firewall_groups (id, name, chain_name, position, enabled,
            cond_saddr, cond_daddr, cond_iif, fallthrough, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.Name, g.ChainName, g.Position, g.Enabled,
		g.CondSaddr, g.CondDaddr, g.CondIif, g.Fallthrough, now, now); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE firewall_rules SET group_id = ?, updated_at = ? WHERE group_id = ''`,
		g.ID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		settingKey, settingValue); err != nil {
		return err
	}
	return tx.Commit()
}
```

- [ ] **Step 4: Implementar a migração no serviço**

Crie `internal/firewallrules/migrate_groups.go`:

```go
package firewallrules

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// GroupsMigratedSettingKey trava a migração única das regras soltas para o
// grupo padrão. É uma flag de "isto já rodou alguma vez", deliberadamente,
// e não uma checagem de "a tabela de grupos está vazia": esta última faria
// o grupo voltar a existir no boot seguinte a um admin ter apagado todos os
// grupos de propósito — exatamente a confiança falsa que o modelo de
// reconciliação existe para eliminar. Mesmo raciocínio de
// ImportedSettingKey.
const GroupsMigratedSettingKey = "firewall_groups_migrated"

// DefaultGroupName é o nome do grupo que recebe as regras que já existiam.
// Escolhido pelo operador: neutro, e o comportamento resultante é idêntico
// ao de antes da migração — sem condição de entrada e "continuar
// avaliando" —, então ele renomeia e divide depois, com calma.
const DefaultGroupName = "Minhas regras"

// MigrateRulesIntoDefaultGroup adota, uma única vez, as regras que hoje
// vivem soltas (sem group_id) num grupo chamado "Minhas regras": sem
// condição, escopo atravessando, "continuar avaliando", em primeira
// posição. A ordem é preservada, e o comportamento do firewall depois da
// migração é o mesmo de antes.
//
// Ao final, a chain user_rules é removida do ruleset — mas só DEPOIS de
// ReconcileGroups ter reconstruído a chain forward, que deixa de emitir o
// `jump user_rules`: o nft recusa apagar uma chain ainda referenciada, e
// inverter esses dois passos deixaria uma chain morta no ruleset para
// sempre.
func (s *Service) MigrateRulesIntoDefaultGroup(ctx context.Context) error {
	flag, err := s.db.GetSetting(GroupsMigratedSettingKey)
	if err != nil {
		return fmt.Errorf("ler a trava de migração de grupos: %w", err)
	}
	if flag != "" {
		return nil // já rodou num boot anterior
	}

	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return err
	}
	var orphans int
	for _, r := range rules {
		if r.GroupID == "" {
			orphans++
		}
	}

	if orphans == 0 {
		// Nada a agrupar — mas a trava é gravada assim mesmo, senão isto
		// roda de novo a cada boot, para sempre.
		if err := s.db.SetSetting(GroupsMigratedSettingKey, "true"); err != nil {
			return err
		}
		slog.Info("nenhuma regra solta para migrar; grupos marcados como migrados")
		return s.removeLegacyUserRulesChain(ctx)
	}

	id := uuid.NewString()
	g := storage.FirewallGroup{
		ID:          id,
		Name:        DefaultGroupName,
		ChainName:   nftables.GroupChainName(id),
		Position:    0,
		Enabled:     true,
		Fallthrough: nftables.FallthroughContinue,
	}
	if err := s.db.MigrateRulesIntoGroup(g, GroupsMigratedSettingKey, "true"); err != nil {
		return fmt.Errorf("migrar regras para o grupo padrão: %w", err)
	}
	slog.Info("regras existentes adotadas pelo grupo padrão",
		"grupo", g.Name, "id", g.ID, "regras", orphans)

	// Reconcilia AGORA: é isto que reconstrói a forward sem o jump para
	// user_rules, condição para o passo seguinte.
	if err := s.Reconcile(ctx); err != nil {
		return err
	}
	return s.removeLegacyUserRulesChain(ctx)
}

// removeLegacyUserRulesChain apaga a chain user_rules, que a partir dos
// grupos não é mais referenciada por ninguém. Falhar aqui não é fatal: a
// chain fica órfã e vazia no ruleset, sem efeito nenhum sobre o tráfego, e
// a próxima tentativa a remove.
func (s *Service) removeLegacyUserRulesChain(ctx context.Context) error {
	if err := s.nft.DeleteChainIfEmpty(ctx, nftables.UserChain); err != nil {
		slog.Warn("não foi possível remover a chain legada user_rules; ela está vazia e sem referência, sem efeito sobre o tráfego",
			"err", err)
	}
	return nil
}
```

Acrescentar em `internal/nftables/reconcile_groups.go`:

```go
// DeleteChainIfEmpty remove uma chain que não é mais usada. Dá flush antes
// para que a remoção não dependa de a chain já estar vazia, e é tolerante a
// "não existe" — é chamada em todo boot depois da migração e não pode virar
// ruído no log de uma máquina onde a chain já sumiu há semanas.
func (s *Service) DeleteChainIfEmpty(ctx context.Context, chain string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "chain", Family, Table, chain)
	if err != nil {
		return nil // não existe mais: nada a fazer
	}
	_ = out
	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, chain); err != nil {
		return fmt.Errorf("limpar chain %s antes de removê-la: %w", chain, err)
	}
	if _, err := s.exec.Execute(ctx, "nft", "delete", "chain", Family, Table, chain); err != nil {
		return fmt.Errorf("remover chain %s: %w", chain, err)
	}
	slog.Info("chain legada removida do ruleset", "chain", chain)
	return nil
}
```

- [ ] **Step 5: Fazer `Reconcile` trabalhar com grupos**

Em `internal/firewallrules/service.go`, acrescentar o conversor e trocar o corpo de `Reconcile`:

```go
// storedGroups converte as linhas do banco na visão que internal/nftables
// entende, encaixando cada regra no seu grupo. Regra órfã (group_id que não
// aponta para grupo nenhum) é deixada de fora e registrada: renderizá-la em
// chain nenhuma seria mostrá-la no painel sem existir no firewall.
func (s *Service) storedGroups() ([]nftables.StoredGroup, error) {
	groups, err := s.db.ListFirewallGroups()
	if err != nil {
		return nil, err
	}
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return nil, err
	}

	byGroup := map[string][]nftables.StoredRule{}
	known := map[string]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	for _, r := range rules {
		if !known[r.GroupID] {
			slog.Warn("regra sem grupo válido foi ignorada na reconciliação",
				"regra", r.ID, "group_id", r.GroupID)
			continue
		}
		byGroup[r.GroupID] = append(byGroup[r.GroupID], nftables.StoredRule{
			ID: r.ID, Position: r.Position, Enabled: r.Enabled,
			Description: r.Description,
			Fields: nftables.RuleFields{Action: r.Action, Iif: r.Iif, Oif: r.Oif,
				Saddr: r.Saddr, Daddr: r.Daddr, Proto: r.Proto, Dport: r.Dport},
		})
	}

	out := make([]nftables.StoredGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, nftables.StoredGroup{
			ID: g.ID, Name: g.Name, ChainName: g.ChainName, Position: g.Position,
			Enabled: g.Enabled, CondSaddr: g.CondSaddr, CondDaddr: g.CondDaddr,
			CondIif: g.CondIif, Fallthrough: g.Fallthrough, Rules: byGroup[g.ID],
		})
	}
	return out, nil
}
```

E em `Reconcile`, trocar a chamada a `ReconcileUserRules` por `ReconcileGroups(ctx, groups)`, mantendo intacto todo o resto — inclusive a gravação do apply status via `recordApplyStatus`, que é o que faz a faixa de aviso aparecer na tela.

Adicionar também `CheckPendingGroups(ctx context.Context, groups []nftables.StoredGroup) error` espelhando `CheckPending`, chamando `s.nft.CheckGroups`.

- [ ] **Step 6: Rodar e confirmar que passa**

```bash
go test ./internal/firewallrules/ -v
```
Esperado: PASS nos quatro testes novos e nos existentes de `ImportOnce`.

- [ ] **Step 7: Commit**

```bash
git add internal/firewallrules/ internal/storage/ internal/nftables/reconcile_groups.go
git commit -m "feat(firewallrules): migrar regras existentes para o grupo \"Minhas regras\""
```

---

### Task 6: Nomear o grupo na Visão geral

**Files:**
- Modify: `internal/nftables/classify.go` (`describeRule`, bloco `case ForwardChain`)
- Test: `internal/nftables/classify_test.go`

**Interfaces:**
- Produces: `describeRule` passa a receber `groupNames map[string]string` (chain → nome do grupo); `Service.Overview` idem.

- [ ] **Step 1: Escrever o teste que falha**

Em `internal/nftables/classify_test.go`:

```go
func TestDescribeRuleNamesTheGroupOnAJump(t *testing.T) {
	names := map[string]string{"grp_a3f21c08": "Wi-Fi visitantes"}
	got := describeRule(ForwardChain, `ip saddr 192.168.50.0/24 counter jump grp_a3f21c08`, names)
	if !strings.Contains(got, "Wi-Fi visitantes") {
		t.Errorf("a descrição tem que nomear o grupo, obtive %q", got)
	}
	if !strings.Contains(got, "192.168.50.0/24") {
		t.Errorf("a descrição tem que dizer quando o grupo é avaliado, obtive %q", got)
	}
}

// Grupo apagado entre a leitura do banco e a do nft: não pode inventar nome
// nem exibir vazio — mostra a chain crua, que é verdade.
func TestDescribeRuleUnknownGroupFallsBackToChainName(t *testing.T) {
	got := describeRule(ForwardChain, `counter jump grp_desconhecido`, map[string]string{})
	if !strings.Contains(got, "grp_desconhecido") {
		t.Errorf("sem nome conhecido, mostrar a chain crua; obtive %q", got)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run TestDescribeRule
```
Esperado: FAIL — `describeRule` aceita 2 argumentos, não 3.

- [ ] **Step 3: Implementar**

Acrescentar o parâmetro `groupNames map[string]string` a `describeRule` e, no `case ForwardChain`, antes dos casos de bloqueio:

```go
	case ForwardChain:
		if idx := strings.LastIndex(expr, "jump "+GroupChainPrefix); idx >= 0 {
			chain := strings.TrimSpace(expr[idx+len("jump "):])
			name, ok := groupNames[chain]
			if !ok {
				// Grupo removido entre a leitura do banco e a do nft.
				// Mostrar a chain crua é a única coisa honesta a dizer.
				name = chain
			}
			cond := strings.TrimSpace(expr[:idx])
			cond = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(cond, "counter")), "counter")
			if strings.TrimSpace(cond) == "" {
				return fmt.Sprintf("Avalia o grupo %q (sem condição: vale para todo tráfego)", name)
			}
			return fmt.Sprintf("Avalia o grupo %q quando %s", name, strings.TrimSpace(cond))
		}
```

Atualizar todos os chamadores de `describeRule` (passar `nil` onde não há grupos) e a assinatura de `Service.Overview` para receber e repassar `groupNames`.

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run TestDescribeRule -v && go build ./...
```
Esperado: PASS e build limpo.

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/classify.go internal/nftables/classify_test.go internal/nftables/service.go
git commit -m "feat(nftables): nomear o grupo na descrição do jump da visão geral"
```

---

### Task 7: API dos grupos

**Files:**
- Create: `internal/api/handlers/groups.go`, `internal/api/handlers/groups_test.go`
- Modify: `internal/api/handlers/nftables.go` (regras passam a carregar `group_id`), `internal/api/server.go` (rotas)

> **Três defeitos ficaram esperando esta tarefa.** Eles não são melhorias:
> a Task 5 apaga a chain `user_rules`, e sem os dois primeiros o painel fica
> quebrado em produção. Nenhum deles pode sair desta entrega.
>
> **C-1 — o pré-voo `nft -c` de toda mutação de regra quebra.**
> `CreateRule`, `UpdateRule` e `ToggleRule` (ao reativar) chamam
> `checkPendingRules` → `firewallrules.CheckPending` → `nftables.CheckUserRules`,
> que gera um script começando por `flush chain inet linkguard user_rules`.
> Depois da migração essa chain não existe mais, e o bootstrap não a recria.
> Verificado ao vivo no nft de produção (Debian 13):
>
> ```
> $ printf 'flush chain inet lgprobe user_rules\n...' | nft -c -f -
> Error: No such file or directory
> $ printf 'add chain inet lgprobe user_rules\nflush chain ...' | nft -c -f -
> (passa limpo)
> ```
>
> Sem correção: **todo POST/PUT de regra e todo "reativar" devolve 400** com a
> mensagem crua do nft. Delete e reorder continuam funcionando, o que torna o
> sintoma ainda mais confuso. **Correção:** os handlers passam a validar por
> `firewallrules.CheckPendingGroups` (criada na Task 5 e hoje sem chamador),
> que valida as chains dos grupos e a `forward` com o `add chain` no topo.
>
> **C-2 — `UpdateRule` zera o `group_id`.** Ele monta o `storage.FirewallRule`
> sem `GroupID`, e `UpdateFirewallRule` faz `SET group_id=?`. Editar uma regra
> pelo painel a expulsa do grupo — `storedGroups` a descarta com um
> `slog.Warn` e ela some do firewall, continuando visível no painel. Perda
> silenciosa de dado, sem undo. **Correção:** preservar o `group_id` da linha
> existente (ou aceitá-lo no corpo e validar que o grupo existe).
>
> **I-3 — a Visão geral perde as regras desativadas.** `Overview` só chama
> `MergeUserRules` na chain de nome `UserChain`; apagada a chain, o merge
> nunca roda, as regras desativadas (que só existem no banco) somem da tela e
> as chains `grp_` aparecem cruas. **Correção:** `Overview` passa a usar
> `nftables.MergeGroups` (criada na Task 4, hoje sem chamador), montando o
> mapa `chain → ChainInfo` e passando a `forward`.
>
> **Dois testes foram enfraquecidos de propósito na Task 5** e é aqui que
> voltam: `TestCreateRuleValidatesFieldsAndReconciles` e
> `TestUpdateRuleEditsContentAndReconciles` deixaram de provar que o conteúdo
> da regra chega ao nft (hoje não chega, por causa de C-2) e provam só que o
> reconcile rodou. Restaure a asserção forte: a regra criada/editada pelo
> painel tem que aparecer no comando do nft, dentro da chain do grupo dela.

**Interfaces:**
- Produces, todas gated por `auth.PermFirewallRead`/`PermFirewallWrite`:
  - `GET /api/nftables/groups` → `{ groups: []GroupView, apply_status: *LastApply }`
  - `POST /api/nftables/groups` (body: `name, cond_saddr, cond_daddr, cond_iif, fallthrough`)
  - `PUT /api/nftables/groups` (body: idem + `id`)
  - `DELETE /api/nftables/groups` (body: `id`)
  - `POST /api/nftables/groups/toggle` (body: `id, enabled`)
  - `POST /api/nftables/groups/reorder` (body: `ids []string`)
  - `CreateRule` passa a exigir `group_id` válido no corpo

- [ ] **Step 1: Escrever o teste que falha**

Em `internal/api/handlers/groups_test.go`, testes que assertem:

```go
// A ordem que a Fase B estabeleceu e a revisão confirmou: nada chega ao
// banco antes de o nft aceitar.
func TestCreateGroupRejectsBadConditionBeforeItReachesTheDB(t *testing.T) {
	h, db := newGroupTestHandler(t)
	for _, body := range []string{
		`{"name":"g","cond_saddr":"2001:db8::1","fallthrough":"continue"}`,
		`{"name":"g","cond_iif":"eth0; rm -rf /","fallthrough":"continue"}`,
		`{"name":"g","fallthrough":"talvez"}`,
		`{"name":"   ","fallthrough":"continue"}`,
	} {
		req := httptest.NewRequest("POST", "/api/nftables/groups", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.CreateGroup(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("corpo %s: esperava 400, obtive %d", body, w.Code)
		}
	}
	groups, _ := db.ListFirewallGroups()
	if len(groups) != 0 {
		t.Fatalf("nada podia ter chegado ao banco, obtive %+v", groups)
	}
}

func TestCreateRuleRequiresAnExistingGroup(t *testing.T) {
	h, db := newGroupTestHandler(t)
	req := httptest.NewRequest("POST", "/api/nftables/rules",
		strings.NewReader(`{"group_id":"nao-existe","action":"accept","proto":"tcp","dport":"22"}`))
	w := httptest.NewRecorder()
	h.CreateRule(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("esperava 400 para grupo inexistente, obtive %d", w.Code)
	}
	rules, _ := db.ListFirewallRules()
	if len(rules) != 0 {
		t.Fatal("regra órfã foi gravada")
	}
}

func TestReorderGroupsRejectsUnknownID(t *testing.T) { /* 400, e a ordem original intacta */ }
func TestDeleteGroupRemovesItsRules(t *testing.T)    { /* regras somem junto */ }
```

Complete os dois últimos com o mesmo estilo dos dois primeiros.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/api/handlers/ -run 'TestCreateGroup|TestCreateRuleRequires|TestReorderGroups|TestDeleteGroup'
```
Esperado: FAIL — handlers indefinidos.

- [ ] **Step 3: Implementar os handlers**

Em `internal/api/handlers/groups.go`, seguindo exatamente o formato dos handlers de regra em `nftables.go:267-490`: decodificar, validar com `nftables.ValidateGroup`, **rodar `CheckPendingGroups` antes de escrever**, escrever, reconciliar com `h.fr.Reconcile`, e chamar `saveNftSnapshot`. O `ChainName` é gerado no `CreateGroup` com `nftables.GroupChainName(uuid.NewString())` e nunca é aceito do cliente.

`ListGroups` monta a resposta com `nftables.MergeGroups`, lendo do nft a chain `forward` e as chains dos grupos.

Em `CreateRule`, acrescentar a checagem de que `group_id` existe, devolvendo 400 antes de qualquer escrita.

- [ ] **Step 4: Registrar as rotas**

Em `internal/api/server.go`, junto das rotas de `/api/nftables/rules`:

```go
		r.With(require(auth.PermFirewallRead)).Get("/api/nftables/groups", nftH.ListGroups)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups", nftH.CreateGroup)
		r.With(require(auth.PermFirewallWrite)).Put("/api/nftables/groups", nftH.UpdateGroup)
		r.With(require(auth.PermFirewallWrite)).Delete("/api/nftables/groups", nftH.DeleteGroup)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups/toggle", nftH.ToggleGroup)
		r.With(require(auth.PermFirewallWrite)).Post("/api/nftables/groups/reorder", nftH.ReorderGroups)
```

- [ ] **Step 5: Rodar e confirmar que passa**

```bash
go test ./internal/api/... && go build ./...
```
Esperado: PASS e build limpo.

- [ ] **Step 6: Commit**

```bash
git add internal/api/
git commit -m "feat(api): CRUD de grupos de regras, validando antes de gravar"
```

---

### Task 8: Ligar no boot

**Files:**
- Modify: `cmd/linkguard-fw/main.go` (bloco de reconciliação no startup, ~linha 280-345)
- Test: manual, na VM (Task 10)

- [ ] **Step 1: Alterar a sequência de boot**

Depois de `ReconcileMasquerade` e `ReconcileNTPInput`, e no lugar da chamada atual a `frSvc.ImportOnce`:

```go
	// A importação da Fase B continua rodando primeiro em máquinas que
	// nunca a executaram: ela traz para o banco o que só existe no nft.
	// Só depois os grupos adotam o que estiver solto.
	if err := frSvc.ImportOnce(ctx); err != nil {
		slog.Error("não foi possível importar as regras existentes do user_rules", "err", err)
	}
	if err := frSvc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
		slog.Error("não foi possível migrar as regras para o grupo padrão", "err", err)
	}
	// Reconcilia os grupos em TODO boot — é isto que reconstrói a chain
	// forward (bloqueios primeiro, depois os jumps) e as chains dos grupos
	// a partir do banco.
	if err := frSvc.Reconcile(ctx); err != nil {
		slog.Error("não foi possível reconciliar os grupos de regras", "err", err)
	}
```

A ordem importa: `ImportOnce` antes de `MigrateRulesIntoDefaultGroup`, senão uma máquina vinda da Fase A perde as regras que ainda só existem no nft.

- [ ] **Step 2: Verificar**

```bash
go build ./... && go vet ./... && go test ./...
```
Esperado: tudo limpo.

- [ ] **Step 3: Commit**

```bash
git add cmd/linkguard-fw/main.go
git commit -m "feat(boot): migrar e reconciliar grupos de regras no startup"
```

---

### Task 9: Tela de grupos (índice + detalhe)

**Files:**
- Create: `web/src/components/RuleGroups.tsx`
- Modify: `web/src/types.ts`

**Interfaces:**
- Consumes: `GET/POST/PUT/DELETE /api/nftables/groups`, `/api/nftables/groups/toggle`, `/api/nftables/groups/reorder`, `/api/nftables/rules`.
- Produces: `export default function RuleGroups({ canWrite, onChanged }: { canWrite: boolean; onChanged: () => void })`

O desenho está fechado na spec §7 (decidido com o operador no companion visual). Requisitos, todos verificáveis:

- [ ] **Step 1: Tipos**

Em `web/src/types.ts`, acrescentar `FirewallGroup` e `GroupView` espelhando os JSON tags do Go, incluindo `applied`, `has_counter`, `packets`, `bytes`, `rule_chain`.

- [ ] **Step 2: Layout de duas colunas**

- Coluna esquerda fixa (~252px): cabeçalho com `N grupos` e botão **Novo**; lista com, por item: ordem, ponto de estado (verde ligado / cinza desligado), nome, e uma segunda linha `N regras · <tráfego>`.
- Coluna direita: nome do grupo, botões **Desligar/Ligar**, **Editar**, **Remover**; faixa da condição (`QUANDO … · ONDE atravessando`) com o contador do `jump` à direita; tabela de regras; linha de "e o que sobrar"; botão **Nova regra neste grupo**.
- Nada expande nem colapsa. Selecionar troca o painel da direita.

- [ ] **Step 3: Tabela de regras com colunas alinhadas**

Colunas: `#`, **Ação** (selo verde/vermelho), **Quando a regra casa** (sintaxe nft crua, em `font-mono` — decisão do operador: o que se lê na tela é o que se acha no `nft list`), **Descrição**, **Pacotes**, **Tráfego**, ações. Números com `tabular-nums`, alinhados à direita.

**O selo de ação traz o keyword do nftables, em `font-mono`, nunca traduzido** — `accept`, `drop`, `reject`, e para as chains gerenciadas também `dnat`, `snat`, `masquerade`, `jump`, `mark` (spec §7.2.1). Reaproveite o mapa `ACTIONS` de `web/src/pages/Firewall.tsx`, que já foi convertido: ele tem `label` (o keyword) e `hint` (a explicação curta em português, para o formulário). Não reintroduza "Permitir"/"Bloquear" em lugar nenhum.

Para "e o que sobrar", os três valores na tela são `accept`, `drop` e **"continuar avaliando"** — este último em português porque não é uma ação do nft, e sim a ausência de uma (nenhuma linha final é emitida; o `jump` retorna sozinho). Rotulá-lo `return` sugeriria uma regra `return` que o LinkGuard não escreve.

- [ ] **Step 4: Contadores honestos**

`has_counter === false` renderiza `—`, nunca `0`. Vale para grupo e para regra. Seletor bytes/bits reaproveitando o que `FirewallOverview.tsx` já tem.

- [ ] **Step 5: Arrastar para reordenar**

Arrastar no índice reordena grupos (`POST /groups/reorder`); arrastar na tabela reordena regras. **Obrigatório** chamar `e.dataTransfer.setData('text/plain', String(index))` no `onDragStart`: sem isso o Firefox não inicia a sessão de arrasto e o `drop` nunca dispara. Em falha da chamada, reverter o estado local para a ordem anterior.

- [ ] **Step 6: Selo "Configurada, não aplicada"**

No grupo, quando `enabled === true && applied === false`. Mesma cor e mesmo texto de `FirewallOverview.tsx`, para o operador reconhecer o estado que já conhece.

- [ ] **Step 7: Modal de grupo**

Nome, condição (origem / destino / interface), "e o que sobrar" (três opções), e **prévia do nft atualizando enquanto se digita** — a linha do `jump` e a linha final da chain. Erro de validação vindo da API exibido no padrão da tela.

- [ ] **Step 8: Verificar**

```bash
export PATH=$HOME/.nvm/versions/node/v22.21.1/bin:$PATH
cd web && npx tsc --noEmit && npm run build
```
Esperado: sem erro.

- [ ] **Step 9: Commit**

```bash
git add web/src/components/RuleGroups.tsx web/src/types.ts
git commit -m "feat(web): tela de grupos de regras em índice e detalhe"
```

---

### Task 10: Aba "Bloqueios e direcionamento" e integração

**Files:**
- Create: `web/src/components/BlocksAndRouting.tsx`
- Modify: `web/src/pages/Firewall.tsx`

- [ ] **Step 1: Mover as três seções**

Recortar de `Firewall.tsx` as seções **Direcionamento por WAN**, **Destinos bloqueados** e **Hosts bloqueados** para `BlocksAndRouting.tsx`, sem alterar comportamento nem endpoints.

- [ ] **Step 2: Aviso de precedência**

No topo da aba nova, faixa fixa: *"Tudo nesta aba é avaliado antes dos seus grupos de regras e sempre vence. Bloqueou aqui, nenhuma regra de grupo consegue liberar."* Mesmo aviso, em versão curta, no topo da aba de grupos.

- [ ] **Step 3: Reorganizar as abas**

`type Tab = 'overview' | 'groups' | 'blocks' | 'portforward' | 'ruleset' | 'backups'`, nesta ordem, com os rótulos: Visão geral, Grupos de regras, Bloqueios e direcionamento, Encaminhamento, Ruleset, Snapshots.

- [ ] **Step 4: Verificar**

```bash
cd web && npx tsc --noEmit && npm run build
```
Esperado: sem erro.

- [ ] **Step 5: Documentar a mudança de comportamento**

Em `README.md`, na seção de aviso de instalação, e em `FEATURES.md`: registrar que **hosts e destinos bloqueados passaram a ser avaliados antes das regras do admin** e que antes era o contrário. É a única mudança desta entrega que altera o comportamento de uma máquina já em operação.

- [ ] **Step 6: Commit**

```bash
git add web/ README.md FEATURES.md
git commit -m "feat(web): aba de bloqueios e direcionamento, e reorganização das abas do firewall"
```

---

## Validação final (antes do deploy)

1. `go build ./... && go vet ./... && go test -count=1 ./...` — tudo limpo.
2. `cd web && npx tsc --noEmit && npm run build`.
3. VM: `~/linkguard-testvm/recreate.sh`. **A VM nasce pelada, de propósito** — o
   cloud-init não instala nada. Instale com `apt install ./linkguard-fw_*.deb`
   (não `dpkg -i`), que resolve os `Depends` e prova que a lista está completa;
   o que está em `Recommends` é o LinkGuard que tem que trazer sob demanda, ou
   dizer claramente que não conseguiu. Uma VM pré-preparada testa um terreno
   arrumado por nós, não o que o cliente tem. Então provar, **contra o nft real**:
   - criar dois grupos com condições diferentes e conferir com `nft list chain inet linkguard forward` que os bloqueios vêm antes dos `jump`, e os `jump` na ordem configurada;
   - desligar um grupo e conferir que o `jump` sumiu **e** que a chain e as regras continuam lá;
   - arrastar no Firefox e conferir a nova ordem no `nft`;
   - apagar um grupo e conferir que a chain sumiu do ruleset;
   - reiniciar o serviço e conferir que tudo volta idêntico (idempotência).
4. Numa cópia do banco de produção, rodar a migração e conferir que as regras viraram "Minhas regras" na ordem certa e que a chain `user_rules` sumiu.

## Self-Review

**Cobertura da spec:** §2 → Tasks 1-2; §2.1 → Tasks 2-3; §3 → Task 3; §5 → fora de escopo (C2); §6 → Task 5; §7.1/7.2/7.3 → Tasks 9-10; §8 → distribuído (validação antes da escrita nas Tasks 3, 5, 7; contadores honestos na Task 9); §9 C1 → todas; §10 → testes em cada tarefa e a validação final.

**Sem placeholders:** os passos de frontend (Tasks 9-10) descrevem requisitos verificáveis em vez de JSX completo, porque o desenho está fixado na spec §7 e no mockup publicado — que são a especificação visual. Os passos de backend trazem o código real.

**Consistência de tipos:** `StoredGroup`, `GroupView`, `FirewallGroup`, `GroupChainName`, `ValidateGroup`, `ReconcileGroups`, `CheckGroups`, `MergeGroups` aparecem com a mesma assinatura no bloco de interfaces do topo desta parte 2 e nas tarefas 1-4 da parte 1.
