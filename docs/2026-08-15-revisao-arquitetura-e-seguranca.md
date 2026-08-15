# Revisão de arquitetura e dependências — LinkGuard FW

**Data:** 15 de agosto de 2026
**Base:** `main` em `5360ce7`, v1.0.82-251 (a mesma que está em produção)
**Método:** quatro auditorias independentes (arquitetura, autenticação/RBAC, injeção e privilégio, superfície HTTP), cada achado reconferido no código antes de entrar neste documento. `govulncheck` e `npm audit` executados.

> **Sobre os achados de segurança.** A auditoria também produziu achados de
> segurança. Eles **não estão neste documento**, e são tratados pelo canal
> privado de *security advisories* do repositório — a política está em
> [`SECURITY.md`](../SECURITY.md). Publicar caminho de exploração antes de a
> correção estar em produção é o oposto do que este projeto deve fazer:
> instalações reais estão rodando neste momento. Os advisories são publicados
> depois do deploy da correção, virando registro público do que foi achado e
> corrigido.

---

## Resumo

O código está acima da média para um projeto deste porte: `go vet` limpo, `go test -race ./...` passa inteiro sem corrida detectada, sem ciclos de import, gating de permissão sistemático rota a rota, nenhuma chamada de sistema na camada HTTP, todo loop de fundo aceita `ctx`. Só existem **3 chamadas `exec.Command` no repositório inteiro**, todas no executor central com argv separado, nunca shell.

A dívida encontrada se concentra em dois lugares: `internal/api/handlers` (que virou depósito de lógica de domínio por não ter fronteira declarada) e `internal/storage/repository.go` (que virou depósito de tudo por ser a folha que todo mundo importa).

O item de maior alcance é o mais barato: **a versão do toolchain Go**.

### Ordem sugerida

| # | Item | Esforço | Issue |
|---|---|---|---|
| 1 | Bump do Go para 1.26.6 | ~10 min | #14 |
| 2 | Rodar os `.check.ts` e `-race` no CI | ~20 min | #18 |
| 3 | Runner de migração com tabela de versão | ~1 h | #19 |
| 4 | Conversão duplicada de grupo | ~1 h | #21 |
| 5 | Dependências Go diretas | ~1 h | #15 |
| 6 | `previewNft` volta para o backend | ~4 h | #22 |
| 7 | Extrair o confirmar-ou-reverte | ~1-2 dias | #20 |
| 8+ | O resto | dias | #23-#31 |

---

# Parte 1 — Dependências e versão do Go

## DEP-1 — A versão do Go é o item de maior alcance

O binário de produção é compilado com **go1.25.0**. O `govulncheck` encontrou **28 vulnerabilidades da biblioteca padrão que o código de fato alcança** — ele traça a cadeia de chamada, não são teóricas:

| Pacote | Onde entra |
|---|---|
| `crypto/tls`, `crypto/x509` | `ListenAndServeTLS` (`cmd/linkguard-fw/main.go:750`), `EnsureSelfSigned` (`internal/tlscert/tlscert.go:35`) |
| `net/http`, `net/url` | servidor do painel; `sendWhatsApp` (`internal/notify/notify.go:241`) |
| `net/textproto`, `encoding/asn1`, `encoding/pem`, `os`, `net` | parsing de cabeçalho, certificado e chave |

O patch mais novo da linha 1.25 é o **go1.25.13**; a estável atual é a **go1.26.6**.

**Os dois workflows usam `go-version-file: go.mod`**, e o `go.mod:3` diz `go 1.25.0` — ou seja, o CI instala exatamente 1.25.0 e o `.deb` de release sai com todas essas falhas embutidas.

**Correção:** subir a diretiva em `go.mod` para `go 1.26.6` (resolve CI e release de uma vez) e instalar o toolchain novo em `~/sdk/` para o build local. Depois, `go test -race ./...` e revalidação na VM antes de deployar — é troca de toolchain, merece o mesmo rigor de sempre.

## DEP-2 — Dependências Go diretas

Todas patch/minor, sem quebra de API esperada:

| Módulo | Atual | Nova |
|---|---|---|
| `golang.org/x/crypto` | v0.53.0 | **v0.55.0** |
| `modernc.org/sqlite` | v1.52.0 | **v1.56.0** |
| `prometheus/client_golang` | v1.23.2 | **v1.24.1** |
| `go-chi/chi/v5` | v5.3.0 | **v5.3.1** |
| `anthropics/anthropic-sdk-go` | v1.60.0 | **v1.63.1** |

Já na última: `go-chi/cors`, `golang-jwt/jwt/v5`, `google/uuid`.

## DEP-3 — npm: 6 vulnerabilidades, e nenhuma chega em produção

Vale ser honesto sobre isto em vez de alarmar. Rastreei a árvore de dependências: `nanoid` vem do `postcss`; `esbuild` vem do `vite`. Todas as três são **ferramenta de build** — o `postcss` é path traversal ao carregar source map, o `esbuild` é o servidor de desenvolvimento. O appliance embute `web/dist` já compilado via `go:embed`, então nenhuma roda na máquina de produção.

A única de runtime é o `react-router` (open redirect via backslash em `<Link>`/`useNavigate`). **Verifiquei e não se aplica:** todos os destinos de navegação são internos, construídos de constante ou com `encodeURIComponent`, e o app não usa SSR (o segundo advisory é de hidratação SSR).

Conclusão: `npm audit fix` sem `--force` é higiene de build, não urgência de segurança.

## DEP-4 — Upgrades maiores disponíveis: decisão, não urgência

React 18→19, react-router 6→7, Tailwind 3→4, Vite 5→8, TypeScript 5.9→7, recharts 2→3, lucide 0.344→1.31.

Tailwind 4 e Vite 8 são os que dão trabalho real (mudança de formato de config). **Recomendação: não misturar com correção de segurança.** Vira tarefa própria, com validação visual na VM tela a tela — do mesmo jeito que a reforma de UI foi feita.

---

# Parte 2 — Arquitetura

## ARQ-1 — O protocolo "confirmar-ou-reverte" é um script de transação recopiado 10 vezes na camada HTTP

**Arquivos:** `internal/api/handlers/nftables.go:462-523, 527, 614, 664, 743`; `internal/api/handlers/groups.go:180, 240, 350, 415, 485`

Toda mutação de regra/grupo executa à mão a mesma sequência de 8 passos:

```
validar campos → confirmWindowBlocks → requireGroup → checkPendingRules (pré-voo nft -c)
→ anyGroupReachesInput → openConfirmWindow → escrever no banco → auditAction → reconcileArmed
```

com `discardArmedWindow` no erro. São dez cópias da ordem, cada uma com um comentário explicando por que a ordem é aquela.

**Por que importa:** essa ordem é a rede de segurança que impede o admin de se trancar fora da máquina. Cada cópia é uma chance de inverter dois passos — e o código já documenta uma vez em que isso aconteceu (`groups.go:165`: "C-5: validar ANTES de qualquer leitura do banco").

Pior: como cada passo recebe `http.ResponseWriter` (`openConfirmWindow(w, r, needed, summary)`), o protocolo **só existe dentro de um handler HTTP**. Nenhum outro caminho de mutação — CLI de recuperação, apply agendado, restore de backup — consegue herdá-lo, e nenhum dos dez caminhos é testável sem montar uma requisição.

**Mudança:** mover a sequência para `internal/firewallrules` como função única:

```go
func (s *Service) ApplyGuarded(ctx context.Context, by string, m Mutation) (*storage.PendingChange, error)
```

onde `Mutation` traz `Validate() error`, `Candidate([]storage.FirewallRule) []storage.FirewallRule`, `TouchesInput() bool`, `Write() error` e `AuditAction() (string,string,string)`. Os handlers viram: decodificar corpo → montar `Mutation` → chamar → traduzir erro em status (`IsWindowConflict` já existe para isso).

## ARQ-2 — A conversão `FirewallGroup → StoredGroup` existe em dois lugares

**Arquivos:** `internal/api/handlers/groups.go:564` (`toStoredGroup`) e `internal/firewallrules/service.go:342`

Mapeamento campo a campo dos mesmos 12 campos, duplicado. O de `handlers` alimenta `ValidateGroup`; o de `firewallrules` alimenta `CheckGroups` e `ReconcileGroups`.

**Por que importa:** o comentário em `service.go:349-354` já descreve o estrago quando um campo é esquecido numa das cópias — `ConnState` gravado no banco, mostrado na tela e nunca renderizado no nft. Um campo novo tem 50% de chance de ser adicionado só numa delas, e o sintoma é **o firewall fazendo o contrário do que o painel afirma, com `apply_status: ok`**.

**Mudança:** exportar uma conversão única em `internal/firewallrules` (`func ToStoredGroup(...)`, ao lado do `ToStoredRules` que já existe em `service.go:562`), fazer `StoredGroupsWithRules` chamá-la, e apagar `toStoredGroup` de `handlers/groups.go` junto com o teste que cobre a cópia.

## ARQ-3 — `internal/storage` acumulou o catálogo de widgets e a política de RBAC do painel

**Arquivo:** `internal/storage/repository.go:2211-2380` — `DashboardWidgets`, `IsKnownDashboardWidget`, `DashboardWidgetPermission`, `DefaultDashboardLayout`, `SanitizeDashboardLayout`. Também `MigrateSettingsToSecrets` (`:924`).

O pacote de persistência declara quais widgets o produto tem, qual permissão RBAC cada um exige e onde ficam na grade de fábrica. Nada disso é persistência.

**Por que importa:** `internal/storage` é a folha que todo mundo importa — é o único lugar onde é "fácil" pôr qualquer coisa sem criar ciclo, e por isso vira depósito. Na prática, adicionar um widget exige mexer no arquivo de 2.378 linhas que também contém o schema de firewall, e a permissão de um widget está a 2.000 linhas do catálogo RBAC em `internal/auth/permissions.go` que ela precisa casar.

**Mudança:** criar `internal/dashboard` (folha) com catálogo, default e `Sanitize`. `storage` fica com `Get/Save/DeleteDashboardLayout` e o tipo `LayoutItem`. `MigrateSettingsToSecrets` vai para `internal/secrets` ou para o `run()`.

## ARQ-4 — `repository.go` com 2.378 linhas é grande **e** incoerente: 11 repositórios num arquivo

Contém, em sequência, os CRUDs de: links, alerts, audit log, failover events, iptables backups, RBAC inteiro (~400 linhas), inventário de hosts, DHCP/DNS, settings, políticas de roteamento, séries temporais, interfaces gerenciadas, relatórios de IA, regras+grupos de firewall, janela pendente e layout do painel.

**Por que importa:** não é estética. `ReplaceFirewallGroupsAndRules` (:2109), `ReorderFirewallRules` (:1615) e `missingSystemGroupKinds` (:2062) são as funções mais delicadas do produto e estão perdidas entre `UpsertHostSighting` e `PruneTrafficSamples`. Revisar o comportamento transacional do firewall exige rolar por 9 domínios não relacionados.

**Mudança:** quebrar por domínio, mesmo pacote, `git mv` puro sem mudança de API: `repo_links.go`, `repo_rbac.go`, `repo_firewall.go`, `repo_tsdb.go`, `repo_hosts.go`, `repo_netsvc.go`, `repo_settings.go`. As linhas de corte já existem — os blocos são contíguos.

## ARQ-5 — O restore de backup é lógica de domínio no handler, e escreve sem transação engolindo erro

**Arquivo:** `internal/api/handlers/backup.go:309-445`

`internal/backup` tem `Snapshot`/`EncryptSnapshot`/`DecryptRestore` (107 linhas). O lado inverso — validar cada blob restaurado, o lockout por força bruta, o mutex por usuário e a escrita no banco — está todo no handler.

Dois problemas somados:

1. **Assimetria de camada.** O restore é o espelho do snapshot e mora do outro lado da fronteira. Não existe caminho de restauração que não seja uma requisição HTTP autenticada — exatamente o que falta quando a máquina está quebrada e o painel não sobe (o cenário do incidente de 24/07).

2. **Escrita parcial silenciosa** (`backup.go:396-422`):
   ```go
   if err := h.db.SetSetting(k, v); err == nil { res.Settings++ }
   ```
   Um erro de banco no meio deixa metade das settings restauradas e devolve **HTTP 200** com contador menor. O comentário acima ainda promete "nada foi restaurado", o que só vale para a fase de validação. Num projeto cuja regra é "toda migração em transação", restaurar a configuração inteira sem transação é a inconsistência mais visível.

**Mudança:** mover `Restore` para `internal/backup` como `func Apply(db *storage.DB, data BackupData) (Result, error)`, com um `ApplyRestore(tx)` novo em `storage` gravando settings + reservas + blocklist numa transação só. O handler fica com auth, lockout e tradução de erro. Isso também abre caminho para um `linkguard-fw --restore arquivo.lgbak` sem tocar em HTTP.

## ARQ-6 — `run()` com 657 linhas é a única coisa que sabe montar o sistema

**Arquivo:** `cmd/linkguard-fw/main.go:101-758`

Uma função faz: parse de flags, `sysprep`, abertura do banco, migrações, seed de RBAC, construção de ~25 serviços, ligação de callbacks entre eles (`monitor.OnStatusChange` decidindo entre balancer e failover, `nftSvc.SetInputChainSources`, `nftSvc.SetPersistGuard`), start de 11 goroutines, e o `ListenAndServe`.

**Por que importa:** a ordem do boot é semanticamente carregada — há um `boot_order_test.go` de 667 linhas provando isso, com testes como `TestMainWiresThePersistGuard`. Esse teste existe porque a ligação é **opcional e silenciosa**: `nftables.NewService` devolve um `Service` que funciona sem o guard, só que sem a proteção que impede persistir uma regra não confirmada no `/etc/nftables.conf` (`service.go:185`: `if s.unconfirmedChange == nil { return false }`). Um teste de fumaça é uma rede pior do que um construtor que exige a dependência.

**Mudança:** duas coisas independentes, ambas pequenas:
- Quebrar `run()` em `openStore()`, `buildServices(cfg, db) (*services, error)`, `wireCallbacks(s)`, `startBackground(ctx, s)`, `serve(ctx, s)`. `buildServices` devolvendo struct nomeado é o que torna o `boot_order_test` capaz de testar a ligação em vez do `main`.
- Tornar as dependências obrigatórias do `nftables.Service` parâmetros de `NewService` em vez de `SetXxx` pós-construção. `confPath` pode continuar setter (é de teste); `PersistGuard` e `InputChainSources` não são opcionais em produção.

## ARQ-7 — O `previewNft` do frontend reimplementa o gerador de tokens do Go

**Arquivos:** `web/src/components/FirewallGroups.tsx:238` (`previewNft`) e `:261` (`jumpLine`) vs `internal/nftables/service.go:997` (`buildRuleTokens`) e `internal/nftables/groups.go:330` (`groupJumpTokens`)

A tela mostra ao admin a linha nft que a regra vai gerar. Essa linha é montada em TypeScript, à mão, espelhando a ordem de campos do Go. Os dois lados têm comentários dizendo "a ordem aqui não é estética — é a mesma linha, ou a pré-visualização vira paráfrase". **Nada verifica que continuam iguais.**

**Por que importa:** o princípio declarado do projeto é "nunca dado falso na UI". Uma pré-visualização que diverge do gerador não é bug cosmético — é a tela afirmando que a regra faz X enquanto o kernel recebe Y, no painel em que uma regra errada corta o SSH do operador. E a divergência é assintomática: nenhum teste, nenhum log, nenhum apply falha.

**Mudança:** o backend já sabe a resposta. Devolver a linha renderizada junto da regra — `nftables.ExpressionTokens` (já existe, `service.go:1057`) num campo `rendered` do JSON de `/api/nftables/rules` e `/api/nftables/groups`, mais um `POST /api/nftables/rules/preview` para o modal. Apagar `previewNft`/`jumpLine` do TSX.

## ARQ-8 — 1.300 linhas de asserções do frontend nunca rodam

**Arquivos:** `web/src/lib/series.check.ts` (633), `grid.check.ts` (405), `widgets.check.ts` (259)

São programas de teste escritos à mão de propósito, para não trazer um test runner — decisão coerente com a regra de cadeia de suprimentos. Rodam com `node --experimental-strip-types`.

**Confirmado por grep: nem o `Makefile`, nem `.github/workflows/test.yml`, nem o `package.json` os invocam.** `tsc --noEmit` só garante que compilam.

**Por que importa:** o `grid.check.ts` testa colisão e compactação de widgets — o comentário do próprio arquivo diz que "a primeira versão da grade não resolvia colisão, e arrastar um widget por cima de outro empilhava os dois". Essa regressão volta sem ninguém notar.

**É a coisa mais barata de consertar deste relatório.**

**Mudança:** em `web/package.json`:
```json
"check": "node --experimental-strip-types src/lib/series.check.ts && node --experimental-strip-types src/lib/grid.check.ts && node --experimental-strip-types src/lib/widgets.check.ts"
```
Chamar no job `web` do CI depois do `npm run build`, e adicionar `npm run lint` (o eslint está configurado e também não roda). No mesmo commit, trocar o `go test ./...` do CI por **`go test -race ./...`** — a suíte inteira passa com `-race` hoje, então é grátis.

## ARQ-9 — Não há tabela de versão de schema, e uma migração está fora de transação

**Arquivos:** `internal/storage/storage.go:54-118` (`migrate`), `:164-184` (`migrateAddPasswordVersion`)

Nove migrações imperativas rodam em todo boot, cada uma decidindo sozinha se já rodou. As sondas divergem: `migrateAddFirewallRuleGroupID` usa `SELECT COUNT(*) FROM pragma_table_info(...)`; `migrateAddPasswordVersion` faz `PRAGMA table_info(users)` e varre 6 colunas com `rows.Scan`; `migrateDashboardLayout` consulta `sqlite_master`.

E `migrateAddPasswordVersion` é **a única que executa o `ALTER TABLE` direto em `db.conn.Exec` (:181), fora de transação** — contra a regra que todas as outras documentam explicitamente ("toda migração deste projeto roda em transação desde o incidente de 2026-07-24").

**Por que importa:** o custo de acrescentar a próxima migração hoje é escrever de novo a sonda de "já rodei?" e lembrar do `Begin`/`Commit`. O incidente que motivou a regra foi exatamente uma migração que não seguiu o padrão. Sem registro de versão, também não há como o produto saber que um downgrade de binário está lendo um banco à frente dele.

**Mudança:** ~40 linhas, sem dependência nova. Tabela `schema_migrations(version INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)` e um runner:

```go
type migration struct{ version int; name string; up func(*sql.Tx) error }
func (db *DB) runMigrations(ms []migration) error  // abre tx, checa version, up(tx), INSERT, Commit
```

As nove existentes viram entradas na lista. **A transação passa a ser do runner, não de cada autor** — que é o ponto.

## ARQ-10 — `internal/api/handlers` é um pacote só, com 29 arquivos e 24 dependências internas

14.140 linhas fora de teste, importando `ai, alerts, auth, backup, balancer, dnslog, failover, firewallrules, hosts, hosttraffic, iptables, links, monitoring, netif, netsvc, nftables, notify, routes, secrets, storage, stresstest, system, sysupdates, timesync, tsdb, updater`.

Todo handler enxerga todo serviço e todo helper não exportado de todo outro handler. `writeJSON`, `auditAction`, `decodeJSON` são globais do pacote — e também são `groupReachesInput`, `newOnlyInputSignatures`, `mergeWithInvisibleStored`, `validateNetsvcConfigRestore`.

**Por que importa:** não é o tamanho, é a ausência de fronteira. É o que permitiu que a lógica dos achados ARQ-1, ARQ-2 e ARQ-5 acabasse aqui — não há nada que sinalize "isto não é HTTP".

**Mudança:** **não quebrar o pacote** (numa máquina só, dividir em `handlers/firewall`, `handlers/network`, `handlers/system` seria burocracia). Extrair o domínio (ARQ-1, 2, 5) e adicionar uma regra verificável: um teste que falha se um arquivo de `handlers` importar `database/sql`, `os/exec` ou `internal/firewall`. Barato (`go/parser` na pasta), e é o único mecanismo que impede a camada de voltar a inchar — o `vet` não pega isso.

## ARQ-11 — Onze goroutines de fundo, nenhuma esperada no shutdown

**Arquivos:** `cmd/linkguard-fw/main.go:707-731`, `internal/tsdb/service.go:268-284`

`go monitor.Run(ctx)`, `go metricsCollector.Run(...)`, `go rrdSvc.Run(ctx)`, `go balancerSvc.Run(ctx)`, `go backupSched.Run(ctx)`, `go journalSched.Run(ctx)`, `go updatesSched.Run(ctx)`, `go netifSvc.RunExpirySweep(...)`, `go frSvc.WatchPending(...)`, `go ai.RunDigest(...)`. Nenhum `sync.WaitGroup`. No SIGTERM, `httpServer.Shutdown` espera as requisições HTTP (10 s) e o processo sai; as goroutines são abandonadas onde estiverem.

`tsdb.Run` faz `case <-ctx.Done(): return` **sem flush final**. Os baldes já fechados em `s.closed` e o balde pendente da janela corrente vão embora.

**Por que importa:** o auto-update reinicia o serviço. Cada restart abre um buraco no gráfico de tráfego e nas séries de latência/perda — as séries que o vigia usa para dizer se um link estava ruim. É perda pequena e recorrente, e é o tipo de coisa que faz o operador desconfiar do gráfico.

**Mudança:** `tsdb.Run` ganha `defer s.tick(time.Now().Unix())` no ramo do `ctx.Done()` (ou um `flushAll()` explícito). O `main` passa a segurar um `sync.WaitGroup` para as goroutines que escrevem no banco (`rrdSvc`, `metricsCollector`, `backupSched`), esperando com timeout de ~3 s depois do `Shutdown` do HTTP. As de leitura pura (`monitor`, `journalSched`) podem continuar como estão.

## ARQ-12 — `Monitor.mu` protege o mapa, não o estado apontado por ele

**Arquivo:** `internal/links/monitor.go:45-46, 212-217, 243-250, 258, 280`

`checkAll` dispara uma goroutine por link. Cada uma pega `state := m.states[l.ID]` sob `m.mu`, **solta o lock**, e então chama `state.advance(...)` (que muta `consecutiveFails`, `consecutiveDegraded`, `degradedEpisodeFired`) e escreve `state.lastStatus = newStatus` — tudo fora do lock.

Hoje é benigno: uma goroutine por ID e `checkAll` faz `wg.Wait()` antes do próximo tick. O `-race` não acusa porque nenhum teste sobrepõe `Run` com `RunOnceForTest`.

**Por que importa:** o mutex existente *sugere* uma proteção que ele não dá. A próxima pessoa que quiser expor "há quantos ticks este link está degradado" num endpoint, ou rodar uma segunda cadência de probe, cria uma corrida de verdade sobre a máquina de estados que decide failover — e vai ler o `sync.Mutex` no struct e concluir que está coberta.

**Mudança:** escolher uma das duas e **escrever a escolha no código**. Ou (a) mover `advance` e a escrita de `lastStatus` para dentro do lock — o custo é aritmética em memória, os probes de rede já estão fora dele; ou (b) documentar no struct que cada `*linkState` pertence exclusivamente à goroutine daquele link durante o tick. A (a) é mais barata e à prova de futuro.

---

## Menções curtas

- **`internal/keaunbound/keaunbound.go:512, 546, 1007`** — o `dry-run` vaza do `firewall.Executor` para o código que grava arquivo: cada `os.WriteFile` precisa lembrar de um `if !s.exec.IsDryRun()`. É o mesmo buraco que `nftables.Persist` documenta em `service.go:41-49` (a suíte rodando como root chegou a sobrescrever o `/etc/nftables.conf` real). Um `exec.WriteFile(path, content, mode)` no `firewall.Executor` faria o tipo impor o que hoje é disciplina.
- **`internal/monitoring/healthchecks.go:429`, `journalcheck.go:80`, `updatescheck.go:86`, `backup/scheduler.go:138`** — marcadores de "última execução" gravados com `_ = db.SetSetting(...)`, sem log. Falha silenciosa muda o comportamento do detector (o de boot lento redispara). Os `_ = alertSvc.X(...)` espalhados **não** são problema: `alerts.Service` loga internamente.
- **`web/src/components/FirewallGroups.tsx`** (2.048 linhas, 26 hooks) é o único componente que passou do ponto. Linhas de corte claras: `PendingWindowBanner` já é separado; faltam `<GroupList>` (drag/drop + reorder), `<RuleModal>`, `<GroupModal>` e `<SystemGroupMembers>`. `Links.tsx` (719) e `Interfaces.tsx` (601) são grandes mas coesos — deixar como estão.
- **Modelos de `storage` são os DTOs da API** (tags `json`, servidos direto em `alerts.go:31`, `links.go:56`, `logs.go:30`, `nftables.go:300`). Para uma máquina só é a simplificação certa e eu não mexeria — só registre que renomear uma coluna quebra o frontend em silêncio, então o `types/index.ts` (783 linhas de espelho manual) merece um teste de contrato antes de qualquer refactor de schema.

---

## Método

Quatro auditorias independentes, em paralelo, cada uma com escopo fechado e instrução explícita de não reportar achado abaixo de 80% de confiança de ser real. Todo achado foi reconferido no código antes de entrar aqui — inclusive os que acabaram descartados.

O que foi verificado e considerado **correto** está registrado nas issues e nos advisories, para que uma auditoria futura não repita o mesmo caminho.
