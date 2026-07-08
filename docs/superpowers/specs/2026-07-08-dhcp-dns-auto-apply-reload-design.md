# DHCP/DNS: salvar aplica sozinho (auto-apply via reload gracioso)

**Data:** 2026-07-08
**Status:** Aprovado (aguardando revisão do spec)

## Problema

No fluxo atual de DHCP/DNS, salvar uma reserva (ou config/blocklist) só grava no
banco; é preciso um segundo clique em **"Aplicar"** para regenerar os configs e
reiniciar os serviços. Isso é um footgun: em 2026-07-08 o admin adicionou a
reserva `192.168.3.60`, ela ficou só no banco e não pegou porque faltou aplicar.
O admin quer que **salvar já aplique** (ver [[dhcp-save-should-autoapply]] e
[[ux-first-network-admin]]).

O motivo do dois-passos: `Apply()` hoje faz `systemctl restart
kea-dhcp4-server unbound` (piscada no serviço); o batch evita N restarts.

## Objetivo

Salvar qualquer mutação de DHCP/DNS passa a **aplicar automaticamente**, de forma
barata e segura (sem piscar o serviço), agrupando edições em rajada num único
apply.

Fora de escopo: mexer em units systemd, configurar kea-ctrl-agent ou
unbound-control (a solução usa sinais, sem depender deles).

## Contexto técnico (validado no prod firewall-DG)

- Kea **2.6.3**, binário `/usr/sbin/kea-dhcp4` (suporta `-t` para testar config).
- Kea recarrega a config com **SIGHUP** sem derrubar o serviço; se a config nova
  for inválida, mantém a antiga (não morre).
- unbound recarrega com SIGHUP.
- Leases em **memfile persistente** → sobrevivem a reload/restart.
- `CanReload=no`, sem control socket, sem `unbound-control` → por isso usamos
  `systemctl kill -s HUP <serviço>` (envia o sinal ao processo principal, sem
  precisar de ExecReload nos units).

## Decisões do admin

- Botão "Aplicar" mantido, rebaixado a **"Aplicar agora"** (secundário).
- Debounce do auto-apply: **~1,5s**.
- Escopo: **DHCP + DNS**.

## Arquitetura

### 1. Novo caminho de aplicação: reload validado (`ReloadConfigs`)

Novo método no `netsvc.Provider` e implementado em `keaunbound`:

```
ReloadConfigs(ctx, c Config, res []Reservation, blocked []string) (string, error)
```

Passos (keaunbound):
1. Gera os configs (função pura atual, inalterada).
2. **Valida a config do Kea**: escreve a candidata num arquivo temporário e roda
   `/usr/sbin/kea-dhcp4 -t <temp>`. Se falhar → **aborta** (não toca no arquivo
   de produção, não recarrega), retorna o erro.
3. Se ok → escreve os configs nos caminhos reais (Kea + unbound) e envia
   `systemctl kill -s HUP kea-dhcp4-server` e `systemctl kill -s HUP unbound`.
4. **Fallback**: se um serviço estiver parado (não apenas desatualizado), faz
   `systemctl restart` dele (reload não sobe serviço morto).

O `Apply()` atual (restart) permanece como fallback interno / primeira
instalação. O caminho normal (auto-apply e botão) passa a ser `ReloadConfigs`.

Para testabilidade, os caminhos de arquivo (`KeaConfPath`, `UnboundConfPath`)
passam a ser campos do `Service` (default = consts atuais), permitindo apontar
para `t.TempDir()` nos testes. O binário do Kea (`kea-dhcp4`) também vira campo
com default `/usr/sbin/kea-dhcp4`.

### 2. Auto-apply com coalescing

Um `autoApplier` no `NetsvcHandler`:

```
type autoApplier struct {
    mu    sync.Mutex
    timer *time.Timer
    delay time.Duration   // ~1,5s
    run   func()          // executa o apply de fato
}
func (a *autoApplier) schedule()  // (re)arma o timer; edições em rajada colapsam
```

`NetsvcHandler.scheduleApply()` chama `applier.schedule()`. As mutações passam a
chamá-lo ao final:
- `UpsertReservation`, `DeleteReservation`
- `UpdateDHCPConfig`
- `UpdateDNSConfig`, e as mutações de blocklist (add/remove)

O `run` do applier: junta config + reservas + blocklist atuais e chama
`provider.ReloadConfigs`; grava o **status da última aplicação** e alerta em caso
de erro (ver §3). Coalescing: 5 saves em <1,5s → 1 reload.

### 3. Erro assíncrono: status + alerta

Como o apply roda após o HTTP do "salvo" já ter retornado, falhas de validação
não voltam na resposta do save. Então:
- **Status da última aplicação** persistido (setting `netsvc_last_apply` =
  `{ok, msg, ts}`), exposto no `GetDHCP`/`GetDNS`. A UI mostra um banner quando
  `ok=false` ("Última aplicação falhou: …").
- **Alerta** via `alertSvc` em caso de falha (mesmo canal WhatsApp/e-mail). Exige
  injetar `alertSvc` no `NetsvcHandler` (novo parâmetro em `NewNetsvcHandler`;
  ajustar fiação no `main.go`).

Sucesso limpa/atualiza o status (ok=true, ts).

### 4. UI

- **Botão "Aplicar" → "Aplicar agora"** (secundário): força `ReloadConfigs`
  imediato (sem esperar o debounce); útil pós-restore/backup.
- **Banner de status** de última aplicação (erro) nas páginas DHCP e DNS.
- Texto curto informando que salvar já aplica automaticamente.

Arquivos: `web/src/pages/Dhcp.tsx`, `web/src/pages/Dns.tsx`, tipos em
`web/src/types/index.ts`.

## Fluxo de dados

```
UI salva reserva → POST /api/dhcp/reservations
  → db.UpsertDHCPReservation (grava)
  → h.scheduleApply()                 (arma debounce ~1,5s)
  → responde "salvo" na hora
       … (outras edições em rajada re-armam o timer) …
  → timer dispara → applier.run():
       gera+valida config (kea -t)
         ├─ inválida → grava status erro + alerta; NÃO recarrega
         └─ válida → escreve configs + SIGHUP kea + SIGHUP unbound
                     → grava status ok
```

## Tratamento de erros

- `kea-dhcp4 -t` falha → aborta reload, config de produção intacta, status=erro,
  alerta. Kea segue rodando com a config antiga.
- Serviço parado → `restart` (fallback), pois SIGHUP não sobe serviço morto.
- Dry-run (executor) → escritas puladas e comandos só logados (padrão atual).
- Erro ao escrever arquivo → retorna erro, status=erro, não sinaliza.

## Testes (TDD)

**`internal/keaunbound` (`ReloadConfigs`, fake exec + paths em TempDir):**
- Config válida → sequência: `kea-dhcp4 -t` → escreve arquivos → `systemctl kill
  -s HUP kea-dhcp4-server` → `... unbound`.
- `kea-dhcp4 -t` retorna erro → **nenhum** SIGHUP; retorna erro; arquivo de
  produção não sobrescrito.
- Serviço parado → usa `restart` como fallback (se detectável no cenário).

**`internal/api/handlers` (autoApplier):**
- N chamadas a `schedule()` dentro da janela → `run` executa **uma** vez.
- Mutação (upsert/delete/config/dns) chama `scheduleApply`.
- Status de última aplicação exposto no GET; erro dispara alerta (fake alertSvc).

## Arquivos afetados

- `internal/netsvc/netsvc.go` — método `ReloadConfigs` na interface `Provider`.
- `internal/keaunbound/keaunbound.go` — `ReloadConfigs` (validar + SIGHUP),
  paths/bin como campos do `Service`.
- `internal/api/handlers/netsvc.go` — `autoApplier`, `scheduleApply` nas
  mutações, status de última aplicação, injeção de `alertSvc`.
- `cmd/linkguard-fw/main.go` — fiação do `alertSvc` no `NewNetsvcHandler`.
- `web/src/pages/Dhcp.tsx`, `Dns.tsx`, `types/index.ts` — "Aplicar agora" +
  banner de status.
- Testes acima.

## Entrega / rollout

Só fica ativo após deploy do binário novo. Antes de confiar 100%, **verificar o
reload uma vez em produção**: aplicar uma mudança trivial e confirmar via log do
Kea que houve reconfigure via SIGHUP sem interrupção (e que os leases seguem).
Ver [[prod-firewall-server]].
