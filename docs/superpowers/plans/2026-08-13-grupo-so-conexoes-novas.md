# Grupo que vale só para conexões novas

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps usam checkbox (`- [ ]`).

**Goal:** O operador pode marcar um grupo de regras como valendo **só para conexões novas** — cortar o que um host tenta abrir sem derrubar a transferência que ele já está fazendo.

**Architecture:** O grupo ganha um campo de dois valores. Quando é "só conexões novas", a linha de `jump` do grupo passa a carregar `ct state new`; o resto do produto não muda. Grupos do sistema ficam de fora. E a janela de confirmação de 90 segundos ganha um aviso obrigatório, porque com esta semântica a sessão do operador **não** cai e o teste de acesso passaria a mentir.

**Tech Stack:** Go 1.25 (`~/sdk/go1.25.0/bin`), SQLite via `modernc.org/sqlite`, nftables, React + TypeScript (Node em `~/.nvm/versions/node/v22.21.1/bin`).

**Spec:** `docs/superpowers/specs/2026-08-13-grupo-so-conexoes-novas-design.md` — é o contrato.

## Global Constraints

1. **Máquina existente não pode ver o firewall mudar por causa desta entrega.** Grupo em "toda conexão" (o padrão, e o valor de toda linha já gravada) tem que emitir a linha de hoje **byte a byte igual**.
2. **A chain `input` nasce e permanece com `policy accept`. Sempre.**
3. **Nunca `flush ruleset` nem flush de tabela** — só `nft flush chain inet linkguard <chain>`.
4. **Migração de schema em transação** (uma migração sem transação travou o boot de produção por 50+ min em 2026-07-24).
5. **Validar com `nft -c -f` antes de qualquer escrita no banco.**
6. **Fixture de teste que envolva saída do nft tem que ser a saída REAL do nft** (o binário está em `/usr/sbin/nft`, v1.1.3, fora do PATH padrão; use `unshare -rn` para não tocar no ruleset da máquina). Foi assim que um bug crítico passou por cinco testes verdes neste projeto.
7. **Nada de dado falso na UI.**
8. **Erro de banco é 500 sem SQL cru, nunca 400.**
9. Nome de ação do nftables (`accept`, `drop`, `reject`, `jump`) e `ct state new` **nunca** se traduzem, e aparecem em `font-mono`. Prosa em português; identificadores em inglês.
10. Nunca `git add -A` nem `git add <diretório>` — arquivo por arquivo.

## O que decide se esta entrega pode existir

Um grupo de escopo **input** com "só conexões novas" que bloqueie o painel **não
derruba a sessão do operador**. Ele vai testar durante os 90 segundos, ver tudo
funcionando, e confirmar um bloqueio que só vai morder na próxima reconexão —
quando não houver mais rede de proteção nenhuma.

**A Task 4 é o que torna as outras aceitáveis.** Nenhuma parte disto vai para
produção sem o aviso da janela funcionando e verificado na tela.

---

### Task 1: O campo, e a linha de jump

**Files:**
- Modify: `internal/storage/storage.go`, `internal/storage/repository.go`
- Modify: `internal/nftables/groups.go`, `internal/nftables/reconcile.go`
- Test: `internal/nftables/reconcile_groups_test.go`, `internal/storage/storage_test.go`

**Interfaces:**
- Produces:
  - `storage.FirewallGroup.ConnState string`, `nftables.StoredGroup.ConnState string`
  - `const ConnStateAny = "any"`, `ConnStateNew = "new"` (vazio conta como `any`)
  - `ValidateGroup` recusa valor fora de `""`, `any`, `new`

- [ ] **Step 1: Escrever o teste que falha**

```go
// A linha de jump ganha `ct state new` DEPOIS da condição de entrada e ANTES do
// counter. A posição não é estética: a condição de entrada é o que decide se o
// grupo é sequer considerado, e o counter tem que contar o que efetivamente
// saltou.
func TestNewOnlyGroupCarriesCtStateOnTheJump(t *testing.T) {
	g := StoredGroup{
		ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
		CondSaddr: "192.168.50.0/24", ConnState: ConnStateNew,
	}
	toks, err := groupJumpTokens(g)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	got := strings.Join(toks, " ")
	want := "ip saddr 192.168.50.0/24 ct state new counter jump grp_aaa"
	if got != want {
		t.Errorf("\n  obtive %q\n  queria %q", got, want)
	}
}

// A garantia que protege toda máquina que já existe: sem a escolha, a linha é
// exatamente a de antes. Se este teste quebrar, um upgrade muda o firewall de
// alguém sem que ninguém tenha pedido.
func TestDefaultGroupEmitsTheExactLineItAlwaysDid(t *testing.T) {
	for _, cs := range []string{"", ConnStateAny} {
		g := StoredGroup{
			ID: "a", Kind: GroupKindAdmin, ChainName: "grp_aaa", Enabled: true,
			CondSaddr: "192.168.50.0/24", ConnState: cs,
		}
		toks, err := groupJumpTokens(g)
		if err != nil {
			t.Fatalf("conn_state=%q: erro inesperado: %v", cs, err)
		}
		got := strings.Join(toks, " ")
		want := "ip saddr 192.168.50.0/24 counter jump grp_aaa"
		if got != want {
			t.Errorf("conn_state=%q:\n  obtive %q\n  queria %q", cs, got, want)
		}
		if strings.Contains(got, "ct state") {
			t.Errorf("conn_state=%q: vazou ct state para o padrão: %q", cs, got)
		}
	}
}

// Grupo do sistema (blocked_hosts, blocklist) é lista fechada e renderizado por
// um mapa próprio: bloqueio de host é justamente onde se quer a marreta.
func TestSystemGroupNeverGetsCtState(t *testing.T) {
	for _, kind := range []string{GroupKindBlockedHosts, GroupKindBlocklist} {
		g := StoredGroup{ID: "s", Kind: kind, Enabled: true, ConnState: ConnStateNew}
		for _, toks := range systemGroupExpressions(g) {
			if strings.Contains(strings.Join(toks, " "), "ct state") {
				t.Errorf("kind=%s: grupo do sistema não pode receber ct state", kind)
			}
		}
	}
}
```

Ajuste os nomes dos helpers de grupo do sistema aos que existirem no pacote.

- [ ] **Step 2: Rodar e confirmar que falha**

```bash
export PATH=$HOME/sdk/go1.25.0/bin:$PATH
go test ./internal/nftables/ -run 'TestNewOnlyGroup|TestDefaultGroupEmits|TestSystemGroupNever'
```

- [ ] **Step 3: Schema e modelo**

`conn_state TEXT NOT NULL DEFAULT ''` em `firewall_groups`, migração imperativa em transação no molde de `migrateAddFirewallGroupScope` (`internal/storage/storage.go`). Vazio conta como `any`.

- [ ] **Step 4: Implementar em `groupJumpTokens`**

- [ ] **Step 5: Verificar contra o `nft` REAL**

Extraia o script que o código gera, escreva num arquivo e rode `nft -c -f` de verdade dentro de `unshare -rn`, com a chain existindo e ausente, mais um controle negativo. Cole a saída. Registre **como o `nft` imprime a linha de volta** — é essa forma que o classificador do painel vai ler.

- [ ] **Step 6: Provar por mutação e commit**

Faça o padrão emitir `ct state new` e mostre `TestDefaultGroupEmitsTheExactLineItAlwaysDid` vermelho. Restaure.

---

### Task 2: A comparação com o firewall vivo

**Files:**
- Modify: `internal/nftables/service.go` (`normalizeExpression`), `internal/nftables/merge_groups.go`, `internal/nftables/classify.go`
- Test: os testes dos mesmos pacotes

**Por que esta task existe:** o painel compara a forma renderizada com a saída real do `nft` para decidir se um grupo está aplicado. Se `ct state new` não for reconhecido nessa comparação, todo grupo com a escolha nova aparece eternamente como **"Configurada, não aplicada"** — mentira na direção que o projeto proíbe. Foi exatamente o defeito M-1 da Fase C2, e ele volta aqui se ninguém olhar.

- [ ] **Step 1:** Teste: um grupo `ct state new` cujo jump está vivo no nft é reportado como **aplicado**. Fixture com a saída **real** do `nft`.
- [ ] **Step 2:** Rodar, vermelho.
- [ ] **Step 3:** Implementar. `describeRule` descreve a linha em português — algo como "só para conexões novas" —, nunca como expressão nft crua.
- [ ] **Step 4:** Provar por mutação que o grupo não volta a aparecer como não aplicado.
- [ ] **Step 5:** Commit.

---

### Task 3: API

**Files:**
- Modify: `internal/api/handlers/groups.go`, `internal/api/handlers/confirm.go`
- Test: `internal/api/handlers/groups_test.go`

- [ ] **Step 1:** `conn_state` no `groupBody` e no UPDATE do storage — **as duas pontas juntas**. Se só uma mudar, o operador troca a escolha na tela e nada acontece, com HTTP 200. Isso já aconteceu neste projeto com o campo `scope` e foi achado em revisão.
- [ ] **Step 2:** Campo **ausente significa manter o gravado** (mesmo contrato do `scope`), para cliente antigo não rebaixar em silêncio uma escolha do operador. Teste dedicado.
- [ ] **Step 3:** Grupo do sistema recusa o campo com 400.
- [ ] **Step 4:** Mudar `conn_state` de um grupo de escopo **input** abre a janela de confirmação, como qualquer outra mutação que alcance a chain input.
- [ ] **Step 5:** Provar por mutação que a ponta do storage está mesmo ligada (tire o campo do UPDATE e mostre o teste vermelho). Commit.

---

### Task 4: O aviso que torna isto aceitável

**Files:**
- Modify: `internal/api/handlers/confirm.go` (o `pendingView`), `web/src/components/FirewallGroups.tsx`, `web/src/components/PendingWindowBanner.tsx`, `web/src/types/index.ts`

**Interfaces:**
- Produces: `pendingView.new_connections_only bool`

- [ ] **Step 1:** O pendente aberto por um grupo com "só conexões novas" carrega o sinalizador. Teste de handler.
- [ ] **Step 2:** A faixa mostra, com estas palavras:

> Este grupo vale só para conexões novas. **A sua sessão atual não é afetada** — abra uma conexão nova (outro terminal SSH, uma aba anônima) para testar de verdade antes de confirmar.

- [ ] **Step 3:** A faixa de um grupo comum **não** mostra o aviso — senão ele vira ruído e ninguém lê.
- [ ] **Step 4:** No modal do grupo, a escolha entre "toda conexão" e "só conexões novas", com uma linha explicando a diferença **em termos do que acontece com o que já está de pé**, não em termos de conntrack.
- [ ] **Step 5:** Na lista e no detalhe, o grupo com "só conexões novas" carrega marca visível. Sem ela, dois grupos idênticos na tela se comportam de formas diferentes — que é exatamente o tipo de coisa que faz o operador desconfiar do software.
- [ ] **Step 6:** A pré-visualização mostra `ct state new` em `font-mono`, junto do resto da linha.
- [ ] **Step 7:** `npx tsc --noEmit` e `npm run build` limpos. Commit.

---

### Task 5: Validação na VM, com tráfego de verdade

Esta tarefa não escreve código de produção. Ela prova a afirmação central da
feature, que **não se prova com executor falso**.

- [ ] **Cenário 1 — a promessa.** Iniciar uma transferência longa de um host para o firewall (ou atravessando-o). Com ela em curso, aplicar um grupo que bloqueie esse tráfego, marcado como "só conexões novas". Provar que **a transferência sobrevive** e que **uma conexão nova é recusada**.
- [ ] **Cenário 2 — o contraste.** O mesmo grupo em "toda conexão" derruba a transferência na hora. Sem este contraste, o cenário 1 pode estar passando por acidente.
- [ ] **Cenário 3 — o aviso.** Grupo de escopo input com "só conexões novas" bloqueando o painel: a sessão atual continua funcionando, a faixa mostra o aviso, e uma conexão nova (aba anônima) **não** entra. Depois dos 90 s sem confirmar, a reversão devolve tudo.
- [ ] **Cenário 4 — nada mudou para quem não pediu.** Numa máquina com grupos existentes, `nft list ruleset` antes e depois do upgrade, ignorando contadores: **idêntico**.
- [ ] **Cenário 5 — a política.** `nft list chain inet linkguard input` continua `policy accept`.

Relatar cada um com a saída real do comando.

---

## Validação final (antes do deploy)

1. `go build ./... && go vet ./... && go test -race -count=1 ./...`; em `web/`: `npx tsc --noEmit && npm run build`.
2. Os cinco cenários da Task 5, na VM, com saída real.
3. Numa cópia do banco de produção, rodar a migração e conferir que todo grupo existente ficou em "toda conexão".
4. No deploy: `nft list ruleset` antes e depois, ignorando contadores.

## Self-Review

**Cobertura da spec:** §3 (a escolha, por grupo) → Task 1; §4 (o `ct state new` na linha de jump, os dois escopos, sistema fora) → Tasks 1, 3; §5 (o aviso da janela) → Task 4; §6 (persistência e compatibilidade) → Tasks 1, 3; §7 (tela) → Task 4; §8 (testes) → Tasks 1, 2, 5.

**Sem placeholders:** os testes da Task 1 estão por extenso — são a garantia de compatibilidade, que é o que protege toda máquina já instalada. A Task 2 existe porque a Fase C2 já cometeu exatamente esse erro uma vez.

**Consistência de tipos:** `ConnState`, `ConnStateAny`/`ConnStateNew`, `groupJumpTokens`, `pendingView.new_connections_only` aparecem com a mesma assinatura nas Tasks 1, 2, 3 e 4.
