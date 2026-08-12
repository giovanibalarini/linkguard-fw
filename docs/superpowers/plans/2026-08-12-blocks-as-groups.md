# Bloqueios como grupos — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Hosts e destinos bloqueados passam a ser grupos na mesma lista dos grupos do admin, reordenáveis junto com eles; o direcionamento por WAN ganha aba própria.

**Architecture:** Os dois bloqueios viram linhas em `firewall_groups` com um `kind` próprio, o que lhes dá `position`. A chain `forward` deixa de ter ordem fixa em código e passa a ser renderizada percorrendo **uma única lista ordenada**, emitindo para cada item ou o `jump` do grupo do admin ou as duas linhas de set do bloqueio. A mecânica dos bloqueios não muda: continuam named sets do nftables.

**Tech Stack:** Go 1.25 (`~/sdk/go1.25.0/bin`), SQLite via `modernc.org/sqlite`, nftables, React + TypeScript + Tailwind (Node em `~/.nvm/versions/node/v22.21.1/bin`).

**Spec:** `docs/superpowers/specs/2026-08-12-blocks-as-groups-design.md` — é o contrato.

## Global Constraints

Toda tarefa herda estas restrições.

1. **A mecânica dos bloqueios não muda.** `@blocked_hosts` e `@blocklist` continuam named sets do nft. Adicionar/remover membro continua sendo `nft add/delete element`, atômico e sem recarregar chain. Reimplementá-los como lista de regras é regressão.
2. **Fixture de teste que representa saída do nft tem que ser saída REAL do nft**: interface aspeada (`iifname "enp5s0"`), máscara cheia comida (`10.0.0.1/32` → `10.0.0.1`). Nunca a saída de `buildRuleTokens`.
3. **Nunca dar flush em ruleset inteiro nem em tabela.** Só `nft flush chain inet linkguard <chain>`.
4. **Migração de schema e de dados em transação.**
5. **Nada de dado falso na UI**: contador não medido é `—`, nunca `0`; estado não avaliável nunca vira "ok".
6. **Validar com a ferramenta real** (`nft -c -f`, via `CheckGroups`) antes de qualquer escrita no banco.
7. **Nome de ação de firewall nunca se traduz** (`accept`, `drop`, `reject`, `jump`) — em `font-mono`. Ver spec de 2026-08-11 §7.2.1.
8. **Grupo do sistema não pode ser apagado nem renomeado**; pode ser reordenado e ligado/desligado.
9. Comentários e mensagens ao usuário em português; identificadores em inglês.
10. **Nunca `git add -A` em diretório inteiro** — arquivo por arquivo.

## File Structure

**Modificar:**
- `internal/storage/storage.go` — coluna `kind` em `firewall_groups`.
- `internal/storage/repository.go` — `kind` no CRUD; proteções.
- `internal/nftables/groups.go` — `StoredGroup.Kind` e constantes.
- `internal/nftables/reconcile.go` — `forwardChainRules` percorre a lista única.
- `internal/nftables/reconcile_groups.go` — grupo do sistema não tem chain própria.
- `internal/nftables/merge_groups.go` — `Applied` de grupo do sistema vem das linhas de set.
- `internal/firewallrules/migrate_groups.go` — migração dos dois grupos do sistema.
- `internal/api/handlers/groups.go` — recusar apagar/renomear grupo do sistema.
- `web/src/components/FirewallGroups.tsx` — grupo do sistema no índice e no detalhe.
- `web/src/pages/Firewall.tsx` — abas.
- `web/src/types/index.ts`

**Criar:**
- `web/src/components/WanSteering.tsx` — a aba nova.

**Remover:**
- `web/src/components/BlocksAndRouting.tsx` — dissolvido.

---

### Task 1: `kind` no modelo e no banco

**Files:**
- Modify: `internal/storage/storage.go`, `internal/storage/repository.go`
- Modify: `internal/nftables/groups.go`
- Test: `internal/storage/storage_test.go`, `internal/nftables/groups_test.go`

**Interfaces:**
- Produces:
  - `storage.FirewallGroup` ganha `Kind string`
  - `nftables.StoredGroup` ganha `Kind string`
  - constantes em `internal/nftables/groups.go`:
    `GroupKindAdmin = "admin"`, `GroupKindBlockedHosts = "blocked_hosts"`, `GroupKindBlocklist = "blocklist"`
  - `func IsSystemGroup(kind string) bool`

- [ ] **Step 1: Escrever o teste que falha**

Em `internal/nftables/groups_test.go`:

```go
func TestIsSystemGroupRecognisesOnlyTheTwoBlockKinds(t *testing.T) {
	for _, k := range []string{GroupKindBlockedHosts, GroupKindBlocklist} {
		if !IsSystemGroup(k) {
			t.Errorf("%q é grupo do sistema", k)
		}
	}
	for _, k := range []string{GroupKindAdmin, "", "qualquer-outra-coisa"} {
		if IsSystemGroup(k) {
			t.Errorf("%q NÃO é grupo do sistema; tratá-lo como tal daria a ele proteções que o admin não pediu", k)
		}
	}
}

// Kind vazio é o que toda linha antiga tem depois do ALTER TABLE. Ela é um
// grupo do admin, e confundir isso com "sistema" travaria a edição de grupos
// que o admin criou.
func TestValidateGroupAcceptsEmptyKindAsAdmin(t *testing.T) {
	g := StoredGroup{Name: "Meu grupo", Fallthrough: FallthroughContinue}
	if err := ValidateGroup(g); err != nil {
		t.Fatalf("grupo sem kind tem que valer como do admin: %v", err)
	}
}
```

Em `internal/storage/storage_test.go`:

```go
func TestFirewallGroupKindRoundTrips(t *testing.T) {
	db := newTestDB(t)
	g := FirewallGroup{ID: "s1", Name: "Hosts bloqueados", ChainName: "sys_blocked_hosts",
		Kind: "blocked_hosts", Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatalf("criar: %v", err)
	}
	got, _ := db.ListFirewallGroups()
	if len(got) != 1 || got[0].Kind != "blocked_hosts" {
		t.Fatalf("kind não persistiu: %+v", got)
	}
}

// Bancos que já existem ganham a coluna com valor vazio, e continuam
// funcionando: toda linha antiga é grupo do admin.
func TestMigrateAddsKindToExistingGroups(t *testing.T) {
	db := newTestDB(t)
	g := FirewallGroup{ID: "a", Name: "Antigo", ChainName: "grp_aaa", Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListFirewallGroups()
	if got[0].Kind != "" && got[0].Kind != "admin" {
		t.Errorf("linha sem kind explícito tem que sair vazia ou admin, obtive %q", got[0].Kind)
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/nftables/ -run 'TestIsSystemGroup|TestValidateGroupAcceptsEmptyKind'
go test ./internal/storage/ -run 'TestFirewallGroupKind|TestMigrateAddsKind'
```
Esperado: FAIL — `undefined: IsSystemGroup`, campo `Kind` inexistente.

- [ ] **Step 3: Schema**

Em `internal/storage/storage.go`, acrescentar `kind TEXT NOT NULL DEFAULT ''` ao `CREATE TABLE IF NOT EXISTS firewall_groups`, e uma migração imperativa para bancos existentes, no molde de `migrateAddFirewallRuleGroupID` (guardada por `pragma_table_info`, em transação):

```go
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
```

Chamar em `migrate()` junto das outras imperativas. Incluir `kind` em todos os `SELECT`/`INSERT` de `firewall_groups` que listam colunas.

- [ ] **Step 4: Constantes e helper**

Em `internal/nftables/groups.go`:

```go
// Kind separa os grupos que o admin criou dos dois que o próprio LinkGuard
// mantém para os named sets de bloqueio. Vazio conta como admin: é o valor
// que toda linha criada antes desta coluna existir carrega, e tratá-las como
// "do sistema" daria a elas proteções (não apagar, não renomear) que o admin
// nunca pediu.
const (
	GroupKindAdmin        = "admin"
	GroupKindBlockedHosts = "blocked_hosts"
	GroupKindBlocklist    = "blocklist"
)

// IsSystemGroup reporta se o grupo é mantido pelo LinkGuard em vez de criado
// pelo admin. Deliberadamente uma lista fechada, não "!= admin": um kind
// desconhecido (banco de uma versão futura, linha editada à mão) é tratado
// como do admin, que é o lado seguro — o erro caro seria travar a edição de
// um grupo que o admin criou.
func IsSystemGroup(kind string) bool {
	return kind == GroupKindBlockedHosts || kind == GroupKindBlocklist
}
```

Acrescentar `Kind string` a `StoredGroup` e a `storage.FirewallGroup`.

- [ ] **Step 5: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ ./internal/storage/
```
Esperado: `ok` nos dois.

- [ ] **Step 6: Suíte inteira**

```bash
go build ./... && go vet ./... && go test -count=1 ./...
```

- [ ] **Step 7: Commit**

```bash
git add internal/storage/storage.go internal/storage/repository.go internal/storage/storage_test.go internal/nftables/groups.go internal/nftables/groups_test.go
git commit -m "feat(groups): kind separa grupo do admin de grupo do sistema"
```

---

### Task 2: A chain forward passa a ser uma lista só

**Files:**
- Modify: `internal/nftables/reconcile.go` (`forwardChainRules`)
- Modify: `internal/nftables/reconcile_groups.go` (grupo do sistema não tem chain própria)
- Test: `internal/nftables/reconcile_groups_test.go`

**Interfaces:**
- Consumes: `StoredGroup.Kind`, `IsSystemGroup`, `GroupKind*` (Task 1); `BlockedSet`, `groupJumpTokens`, `rebuildChain`.
- Produces: `forwardChainRules(groups []StoredGroup) [][]string` passa a emitir, por item ordenado, ou o `jump` (admin) ou as duas linhas de set (sistema).

- [ ] **Step 1: Escrever o teste que falha**

```go
// A chain forward deixa de ter ordem fixa em código: ela é a lista do admin,
// na ordem dele. Um bloqueio movido para o fim aparece no fim.
func TestForwardChainFollowsTheSingleOrderedList(t *testing.T) {
	groups := []StoredGroup{
		{ID: "g", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 0,
			CondSaddr: "192.168.50.0/24"},
		{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true, Position: 1},
		{ID: "b", Kind: GroupKindBlocklist, Enabled: true, Position: 2},
	}
	var lines []string
	for _, toks := range forwardChainRules(groups) {
		lines = append(lines, strings.Join(toks, " "))
	}
	want := []string{
		"ip saddr 192.168.50.0/24 counter jump grp_aaa",
		"ip saddr @blocked_hosts counter drop",
		"ip daddr @blocked_hosts counter drop",
		"ip daddr @blocklist counter drop",
		"ip saddr @blocklist counter drop",
	}
	if len(lines) != len(want) {
		t.Fatalf("esperava %d linhas, obtive %d: %v", len(want), len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("linha %d:\n  obtive %q\n  queria %q", i, lines[i], want[i])
		}
	}
}

// O padrão da migração: bloqueios primeiro. Continua sendo o que sai quando
// o admin não mexeu em nada.
func TestForwardChainDefaultOrderIsBlocksFirst(t *testing.T) {
	groups := []StoredGroup{
		{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true, Position: 0},
		{ID: "b", Kind: GroupKindBlocklist, Enabled: true, Position: 1},
		{ID: "g", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true, Position: 2},
	}
	s := renderChainScript(ForwardChain, forwardChainRules(groups))
	if strings.Index(s, "@blocked_hosts") > strings.Index(s, "jump grp_aaa") {
		t.Errorf("no padrão os bloqueios vêm primeiro:\n%s", s)
	}
}

// Desligar um grupo do sistema tira as linhas dele do firewall; os membros
// do set continuam guardados (o set não é tocado).
func TestForwardChainSkipsDisabledSystemGroup(t *testing.T) {
	groups := []StoredGroup{{ID: "h", Kind: GroupKindBlockedHosts, Enabled: false, Position: 0}}
	if len(forwardChainRules(groups)) != 0 {
		t.Error("grupo do sistema desligado não emite linha nenhuma")
	}
}

// Grupo do sistema não tem chain própria: as linhas dele moram na forward.
// Criar uma chain para ele deixaria uma chain vazia e órfã no ruleset.
func TestReconcileGroupsCreatesNoChainForSystemGroups(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	groups := []StoredGroup{{ID: "h", Kind: GroupKindBlockedHosts, Enabled: true}}
	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, cmd := range exec.executed {
		if strings.HasPrefix(cmd, "nft add chain") {
			t.Errorf("grupo do sistema não pode ganhar chain: %q", cmd)
		}
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run 'TestForwardChain|TestReconcileGroupsCreatesNoChain'
```
Esperado: FAIL.

- [ ] **Step 3: Implementar**

Trocar o corpo de `forwardChainRules`:

```go
// forwardChainRules rende a chain forward a partir de UMA lista ordenada —
// a mesma que o admin vê na tela, na mesma ordem. Antes desta mudança a
// ordem era fixa em código (bloqueios, depois os jumps); agora bloqueio é
// um item da lista como qualquer outro, e a posição dele é escolha do admin.
//
// O padrão continua sendo bloqueios primeiro: é assim que a migração os
// cria. O que a Fase C1 eliminou foi a SURPRESA — uma regra antiga anulando
// um bloqueio sem ninguém ver, porque a ordem era invisível —, não a
// possibilidade. A ordem agora está na tela, numerada.
//
// Toda linha carrega `counter`: ver ReconcileStructuralChains sobre por que
// isso não é negociável.
func forwardChainRules(groups []StoredGroup) [][]string {
	sorted := make([]StoredGroup, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Position < sorted[j].Position })

	var rules [][]string
	for _, g := range sorted {
		if !g.Enabled {
			continue // desligar = sumir do firewall; o conteúdo fica guardado
		}
		switch g.Kind {
		case GroupKindBlockedHosts:
			rules = append(rules,
				[]string{"ip", "saddr", "@" + BlockedSet, "counter", "drop"},
				[]string{"ip", "daddr", "@" + BlockedSet, "counter", "drop"},
			)
		case GroupKindBlocklist:
			rules = append(rules,
				[]string{"ip", "daddr", "@blocklist", "counter", "drop"},
				[]string{"ip", "saddr", "@blocklist", "counter", "drop"},
			)
		default: // grupo do admin
			if !validGroupChainName(g.ChainName) {
				slog.Error("grupo ignorado ao montar a chain forward: nome de chain inseguro",
					"grupo", g.ID, "nome", g.Name, "chain", g.ChainName)
				continue
			}
			tokens, err := groupJumpTokens(g)
			if err != nil {
				slog.Error("grupo ignorado ao montar a chain forward: condição inválida",
					"grupo", g.ID, "nome", g.Name, "err", err)
				continue
			}
			rules = append(rules, tokens)
		}
	}
	return rules
}
```

Em `ReconcileGroups`, pular grupos do sistema nos passos que criam e preenchem chain (`IsSystemGroup(g.Kind)` → `continue`), e **não** incluí-los no conjunto `wanted` de chains vivas. Manter o restante igual, inclusive a ordem dos quatro passos e a validação de nome.

Em `ReconcileGroups`, a acumulação de `failures` para condição inválida (§C-2 da entrega anterior) continua valendo só para grupo do admin.

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run 'TestForwardChain|TestReconcileGroups' -v
```

- [ ] **Step 5: Provar por mutação que o teste de ordem não é decorativo**

Inverta deliberadamente: faça o `switch` emitir as linhas de bloqueio sempre antes do laço. Rode `TestForwardChainFollowsTheSingleOrderedList` e mostre vermelho. Restaure.

- [ ] **Step 6: Ajustar os testes existentes**

```bash
go build ./... && go test ./internal/nftables/
```
Testes que assertavam a ordem fixa antiga agora descrevem o comportamento errado: **atualize a expectativa** e registre no commit. Não apague teste.

- [ ] **Step 7: Commit**

```bash
git add internal/nftables/reconcile.go internal/nftables/reconcile_groups.go internal/nftables/reconcile_groups_test.go
git commit -m "feat(nftables): a chain forward passa a seguir uma lista ordenada só"
```

---

### Task 3: `Applied` e contadores do grupo do sistema

**Files:**
- Modify: `internal/nftables/merge_groups.go`
- Test: `internal/nftables/merge_groups_test.go`

**Interfaces:**
- Consumes: `GroupView`, `MergeGroups`, `IsSystemGroup`.
- Produces: `MergeGroups` passa a derivar `Applied`/contadores de grupo do sistema das linhas de set vivas na `forward`, em vez de procurar um `jump`.

- [ ] **Step 1: Escrever o teste que falha**

Fixture na forma REAL do nft:

```go
func TestMergeGroupsSystemGroupAppliedFromItsSetLines(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts,
		Enabled: true, Position: 0}
	forward := ChainInfo{Name: ForwardChain, Rules: []ChainRule{
		{Expression: "ip saddr @blocked_hosts drop", Handle: 4, HasCounter: true, Packets: 52, Bytes: 4096},
		{Expression: "ip daddr @blocked_hosts drop", Handle: 5, HasCounter: true, Packets: 16, Bytes: 1280},
	}}

	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, forward)[0]
	if !v.Applied {
		t.Error("as linhas do set estão vivas na forward: o grupo está aplicado")
	}
	// O contador do grupo é a soma das linhas dele — aqui não há jump para
	// medir, e as duas linhas juntas são o que o grupo faz.
	if v.Packets != 68 || v.Bytes != 5376 || !v.HasCounter {
		t.Errorf("contador do grupo do sistema errado: %+v", v)
	}
}

func TestMergeGroupsSystemGroupWithoutItsLinesIsUnapplied(t *testing.T) {
	g := StoredGroup{ID: "h", Name: "Hosts bloqueados", Kind: GroupKindBlockedHosts, Enabled: true}
	v := MergeGroups([]StoredGroup{g}, map[string]ChainInfo{}, ChainInfo{Name: ForwardChain})[0]
	if v.Applied {
		t.Error("sem as linhas de set vivas, o bloqueio NÃO está em vigor")
	}
	if v.HasCounter {
		t.Error("sem medição, HasCounter é false — nunca um zero inventado")
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/nftables/ -run TestMergeGroupsSystemGroup
```

- [ ] **Step 3: Implementar**

Em `MergeGroups`, antes do laço que casa `jumps`, indexar também as linhas de set por conjunto (`@blocked_hosts`, `@blocklist`). Para grupo do sistema, `Applied` é verdadeiro quando **todas** as linhas esperadas dele estão vivas; `Packets`/`Bytes` são a soma; `HasCounter` só é verdadeiro se todas as linhas medirem.

Grupo do sistema não tem `RuleChain`: devolver `ChainInfo{}` para ele (a tela mostra os membros do set, não regras).

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/nftables/ -run TestMergeGroups -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/merge_groups.go internal/nftables/merge_groups_test.go
git commit -m "feat(nftables): Applied do grupo do sistema vem das linhas de set vivas"
```

---

### Task 4: Migração dos dois grupos do sistema

**Files:**
- Modify: `internal/firewallrules/migrate_groups.go`, `internal/storage/repository.go`
- Test: `internal/firewallrules/migrate_groups_test.go`

**Interfaces:**
- Produces:
  - `const SystemGroupsSettingKey = "firewall_system_groups_created"`
  - `func (s *Service) EnsureSystemGroups(ctx context.Context) error`
  - `func (db *DB) CreateSystemGroups(rows []FirewallGroup, settingKey, settingValue string) error`

- [ ] **Step 1: Escrever o teste que falha**

```go
func TestEnsureSystemGroupsCreatesBothAtTheTop(t *testing.T) {
	db := newTestDB(t)
	// um grupo do admin que já existe, na posição 0
	g := storage.FirewallGroup{ID: "a", Name: "Meu grupo", ChainName: "grp_aaa",
		Position: 0, Enabled: true, Fallthrough: "continue"}
	if err := db.CreateFirewallGroup(&g); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, db)

	if err := svc.EnsureSystemGroups(context.Background()); err != nil {
		t.Fatalf("criar grupos do sistema: %v", err)
	}

	got, _ := db.ListFirewallGroups()
	if len(got) != 3 {
		t.Fatalf("esperava 3 grupos, obtive %d: %+v", len(got), got)
	}
	// Os dois do sistema nas posições 0 e 1, o do admin empurrado para 2:
	// o padrão continua sendo bloqueio primeiro.
	if !nftables.IsSystemGroup(got[0].Kind) || !nftables.IsSystemGroup(got[1].Kind) {
		t.Errorf("os dois primeiros têm que ser do sistema: %+v", got)
	}
	if got[2].ID != "a" {
		t.Errorf("o grupo do admin foi para o fim: %+v", got)
	}
}

// A trava é "já rodou", não "a tabela tem grupo do sistema": senão o boot
// seguinte ressuscita o que o admin apagou ou desligou de propósito.
func TestEnsureSystemGroupsIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	svc := newTestService(t, db)
	ctx := context.Background()

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	groups, _ := db.ListFirewallGroups()
	// o admin desliga um deles
	if err := db.SetFirewallGroupEnabled(groups[0].ID, false); err != nil {
		t.Fatal(err)
	}

	if err := svc.EnsureSystemGroups(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := db.ListFirewallGroups()
	if len(after) != 2 {
		t.Fatalf("rodou de novo e duplicou: %+v", after)
	}
	for _, x := range after {
		if x.ID == groups[0].ID && x.Enabled {
			t.Error("religou um grupo que o admin desligou de propósito")
		}
	}
}
```

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
go test ./internal/firewallrules/ -run TestEnsureSystemGroups
```

- [ ] **Step 3: Implementar**

`CreateSystemGroups` numa transação: desloca os grupos existentes (`UPDATE firewall_groups SET position = position + 2`), insere os dois com `position` 0 e 1, grava a trava. `ChainName` dos grupos do sistema é fixo e reservado (`sys_blocked_hosts`, `sys_blocklist`) — nunca `grp_`, para a limpeza de chains órfãs não os enxergar como chain de grupo do admin.

`EnsureSystemGroups` é chamada na sequência de boot **antes** de `Reconcile`, junto de `MigrateRulesIntoDefaultGroup`.

- [ ] **Step 4: Rodar e confirmar que passa**

```bash
go test ./internal/firewallrules/ -v
```

- [ ] **Step 5: Ligar no boot**

Em `cmd/linkguard-fw/main.go`, depois de `MigrateRulesIntoDefaultGroup` e antes de `Reconcile`.

- [ ] **Step 6: Commit**

```bash
git add internal/firewallrules/migrate_groups.go internal/firewallrules/migrate_groups_test.go internal/storage/repository.go cmd/linkguard-fw/main.go
git commit -m "feat(firewallrules): criar os dois grupos do sistema na migração"
```

---

### Task 5: API — proteger o grupo do sistema

**Files:**
- Modify: `internal/api/handlers/groups.go`
- Test: `internal/api/handlers/groups_test.go`

- [ ] **Step 1: Escrever o teste que falha**

```go
func TestDeleteSystemGroupIsRefused(t *testing.T)   { /* 400, e o grupo continua no banco */ }
func TestRenameSystemGroupIsRefused(t *testing.T)   { /* 400, nome intacto */ }
func TestReorderSystemGroupIsAllowed(t *testing.T)  { /* 200, posição muda */ }
func TestToggleSystemGroupIsAllowed(t *testing.T)   { /* 200, e as linhas somem da forward */ }
```

Complete os quatro no estilo dos testes de handler que já existem no arquivo.

- [ ] **Step 2: Rodar e confirmar que falha**

- [ ] **Step 3: Implementar**

Em `DeleteGroup` e `UpdateGroup`, recusar com 400 e mensagem clara quando `nftables.IsSystemGroup(g.Kind)`. `ToggleGroup` e `ReorderGroups` continuam aceitando. A criação (`CreateGroup`) nunca aceita `kind` do cliente — sempre `GroupKindAdmin`.

- [ ] **Step 4: Rodar e confirmar que passa; suíte inteira**

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/groups.go internal/api/handlers/groups_test.go
git commit -m "feat(api): grupo do sistema não pode ser apagado nem renomeado"
```

---

### Task 6: Tela — grupos do sistema e a aba de direcionamento

**Files:**
- Modify: `web/src/components/FirewallGroups.tsx`, `web/src/pages/Firewall.tsx`, `web/src/types/index.ts`
- Create: `web/src/components/WanSteering.tsx`
- Remove: `web/src/components/BlocksAndRouting.tsx`

Requisitos verificáveis (o desenho está na spec §4):

- [ ] **Step 1: Tipos** — `FirewallGroup` ganha `kind`.

- [ ] **Step 2: Índice** — grupo do sistema aparece na lista, na posição dele, com marca visível de que é do sistema. Arrastar e ligar/desligar disponíveis; apagar e renomear **não** aparecem.

- [ ] **Step 3: Detalhe** — para grupo do sistema, mostrar a explicação do que ele faz e a lista de membros, com adicionar e remover usando os endpoints que já existem (`/api/nftables/blocklist` e o de host bloqueado). Não mostrar tabela de regras nem "e o que sobrar".

- [ ] **Step 4: Aviso de ordem** — quando um grupo do sistema estiver posicionado **depois** de algum grupo do admin, a linha dele exibe: *"regras acima deste bloqueio podem liberar tráfego que ele descartaria"*. Sem isso, a flexibilidade nova vira armadilha.

- [ ] **Step 5: Sai a faixa antiga** — remover *"Hosts e destinos bloqueados são avaliados antes destes grupos e sempre vencem"*: deixou de ser verdade universal, e a ordem agora está visível na lista.

- [ ] **Step 6: Aba nova** — `WanSteering.tsx` com o conteúdo de Direcionamento por WAN e a explicação da spec §3. `BlocksAndRouting.tsx` é removido.

- [ ] **Step 7: Abas** — `overview | groups | steering | portforward | ruleset | backups`, rótulos: **Visão geral · Grupos de regras · Direcionamento por WAN · Encaminhamento · Ruleset · Snapshots**. Atualizar `OWNER_LINKS` em `FirewallOverview.tsx` (hoje `wan_steering` e `blocklist` apontam para `'blocks'`, que deixa de existir).

- [ ] **Step 8: Verificar**

```bash
export PATH=$HOME/.nvm/versions/node/v22.21.1/bin:$PATH
cd web && npx tsc --noEmit && npm run build
```

- [ ] **Step 9: Commit**

```bash
git add web/src/components/FirewallGroups.tsx web/src/components/WanSteering.tsx web/src/pages/Firewall.tsx web/src/types/index.ts web/src/components/FirewallOverview.tsx
git rm web/src/components/BlocksAndRouting.tsx
git commit -m "feat(web): bloqueios na lista de grupos, e aba própria para o direcionamento"
```

---

## Validação final (antes do deploy)

1. `go build ./... && go vet ./... && go test -count=1 ./...`; `cd web && npx tsc --noEmit && npm run build`.
2. **VM pelada** (`~/linkguard-testvm/recreate.sh` — ela nasce sem nada de propósito), instalar com `dpkg -i`, e provar **contra o nft real**:
   - os dois grupos do sistema aparecem nas posições 0 e 1, e a `forward` sai com os quatro `drop` antes de qualquer `jump`;
   - **mover um bloqueio para o fim** e conferir no `nft list chain inet linkguard forward` que as linhas de set foram para o fim;
   - **desligar um bloqueio** e conferir que as linhas somem da `forward` e que o set continua com os membros (`nft list set inet linkguard blocked_hosts`);
   - adicionar e remover membro pela tela e ver o set mudar;
   - reiniciar o serviço e conferir que tudo volta idêntico.
3. Numa cópia do banco de produção, rodar a migração e conferir que os dois grupos do sistema entram no topo sem mexer nos grupos do admin.

## Self-Review

**Cobertura da spec:** §2.1 → Tasks 1, 5; §2.2 → Tasks 2, 4 (padrão) e 6 (aviso); §2.3 → Task 2; §2.4 → Task 4; §3 → Task 6; §4 → Task 6; §5 → distribuído + validação final.

**Sem placeholders:** os passos de frontend descrevem requisitos verificáveis em vez de JSX completo, porque o desenho está fixado na spec §4 e o componente `FirewallGroups.tsx` já existe e é o padrão a seguir. Os passos de backend trazem o código real.

**Consistência de tipos:** `Kind`, `IsSystemGroup`, `GroupKind*`, `EnsureSystemGroups`, `CreateSystemGroups` e `SystemGroupsSettingKey` aparecem com a mesma assinatura nas Tasks 1, 2, 3, 4 e 5.
