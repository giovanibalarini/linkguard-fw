# Design: "Vigia" — monitoramento abrangente, painel de saúde e alertas de queda

**Data:** 2026-07-02
**Status:** aprovado (design), pendente de plano de implementação
**Público-alvo:** admin caseiro / prosumer que acha o pfSense complicado — gosta de acompanhar dashboards **simples e objetivos**, não fica olhando o tempo todo, e precisa ser avisado no celular quando algo cai.

## Problema

Hoje o LinkGuard só alerta um subconjunto de eventos (link/failover/CPU/mem) e **não monitora os serviços que o compõem** (kea, unbound, nftables, o próprio `linkguard-fw`). Pior: descobrimos em produção que:

1. Uma queda de link simulada pelo stress-test refez a rota mas **não emitiu alerta** (o caminho de alerta não foi acionado) → o usuário não foi notificado.
2. A recuperação ("voltou") é severidade `info`, mas `min_severity=warning` **filtra** `info` → o aviso de recuperação nunca chegaria.
3. Alertas de CPU/mem re-disparam **a cada ciclo** (30s) enquanto acima do limiar — sem dedup, potencial de spam.

Isso quebra o JTBD emocional do produto ("durmo tranquilo"): a ferramenta promete vigiar e silenciosamente não vigia.

## Objetivo

Uma única camada de monitoramento que (1) dispara alertas por transição (queda 🔴 + recuperação 🟢) em WhatsApp/canais configurados e (2) alimenta um painel de saúde simples e objetivo. **Zero-config**: tudo ligado por padrão, sem o usuário montar nada.

## Não-objetivos (v2+)

- Agrupar N quedas simultâneas (ex.: reboot) num só alerta.
- Gráfico de uptime histórico por serviço.
- Alerta em `systemctl stop` limpo/intencional (só nos avisa de falha/crash — ver limitação abaixo).

## Arquitetura

**Uma camada, dois consumidores.** O `monitoring.Collector` (`internal/monitoring/collector.go`), que já roda `Run(ctx, interval)` a cada 30s com acesso a `alertSvc`, `sysCol`, `db` e `metrics`, passa a também:

- checar serviços systemd (`systemctl is-active <svc>`) via `firewall.Executor.ExecuteRead`;
- checar disco cheio (limiar configurável, default 90%);
- manter **estado anterior em memória** por item, emitindo alerta **só na transição**;
- expor um **snapshot de saúde** (getter) para um handler HTTP alimentar o painel.

Para manter o `collector.go` coeso, extrair as checagens novas para `internal/monitoring/healthchecks.go` (mesmo pacote).

```
                          ┌────────────────────────┐
 systemctl is-active ───▶ │                        │──▶ alertSvc.Create(...) ──▶ notify (WhatsApp)
 disco / cpu / mem  ────▶ │  monitoring.Collector  │      (só em transição)
 links (status DB)  ────▶ │  + healthchecks.go     │
                          │  estado anterior (map) │──▶ Snapshot() ──▶ GET /api/health ──▶ Dashboard
                          └────────────────────────┘
```

## Componentes e mudanças

### 1. Monitoramento de serviços systemd
- Novo: em `healthchecks.go`, para cada serviço configurado, rodar `systemctl is-active <svc>` (aceitar `active` como up; `inactive`/`failed`/`activating`/erro como down).
- Validar o nome do serviço contra um charset estrito antes de passar ao exec (defense-in-depth; já é padrão do projeto).
- Defaults zero-config: `kea-dhcp4-server`, `unbound`, `nftables`.
- Transição up→down: `alertSvc.ServiceOffline(nome)` (critical). down→up: `ServiceOnline(nome)` (recuperação).

### 2. O próprio `linkguard-fw` (auto-morte)
- O app não avisa da própria morte → usar **systemd `OnFailure=`**.
- Adicionar subcomando/flag `linkguard-fw --notify-down` em `cmd/linkguard-fw/main.go`: carrega config do DB (mesmo `--config`), envia uma notificação "LinkGuard caiu" pelos canais configurados e sai.
- Adicionar unit oneshot `deploy/linkguard-notify-down.service` e `OnFailure=linkguard-notify-down.service` em `deploy/linkguard-fw.service` (e replicar no `.deb` do `release.yml`, que monta o control/units inline — **não** via Makefile).
- **Limitação documentada:** `OnFailure` dispara em falha/crash/OOM/sinal, não em `systemctl stop` limpo. É o comportamento desejado (parada intencional não deve alertar).

### 3. WAN/gateways — fechar o buraco
- **Investigar (systematic-debugging)** por que a queda via stress-test (07:35) refez a rota sem emitir "link change"/alerta, enquanto a de 06:50 emitiu. Hipótese: o rebuild veio do reconcile periódico do balancer, não do `OnStatusChange` do monitor.
- **Requisito:** toda transição de link/gateway (online/offline/degraded), inclusive durante stress-test, cria exatamente um alerta.

### 4. Recursos do host
- Novo: disco cheio (transição cruzando o limiar, default 90%) → `alertSvc.DiskFull(pct)`.
- Ajuste: CPU/mem passam a ser **por transição** (alerta ao cruzar o limiar; resolve ao voltar), em vez de re-disparar a cada ciclo.

### 5. Comportamento dos alertas
- **Só na transição** (mudança de estado), nunca a cada checagem.
- **Anti-flap embutido (default, sem knob):** exigir **2 checagens consecutivas** no novo estado antes de alertar (≈30–60s com tick de 30s), pra link/serviço que "pisca" não spammar.
- **Queda = critical.** **Recuperação sempre entrega**, mesmo com `min_severity=warning`: a camada de notify ganha um caminho "entregar sempre" para recuperações pareadas a uma queda que já foi notificada (não depende do threshold). Detalhe exato fica no plano — opção preferida: método explícito no `Notifier` (ex.: `NotifyRecovery`) ou flag, sem depender de `severityRank`.

### 6. Painel de saúde (Dashboard)
- Novo endpoint `GET /api/health` (permissão de leitura) retornando o snapshot: por item `{nome, tipo: service|link|resource, up: bool, since}`.
- Novo componente `SystemHealth.tsx` no topo do Dashboard: **tiles verde/vermelho** para `Firewall (nftables)`, `DHCP (kea)`, `DNS (unbound)`, `LinkGuard`, e as WANs. Glanceability ("está tudo ok?" em 3s). Cada tile clica → Monitoring/Interfaces (information scent).
- **Gráficos reaproveitados**: histórico de tráfego (trafficrrd) e medidores CPU/mem/disco já existem — manter coesos e objetivos, sem inflar. Nenhum gráfico novo complexo nesta versão.

### 7. Configuração (mínima, fiel ao público)
- Nova chave de settings `monitoring` (JSON): `{ enabled: true, services: ["kea-dhcp4-server","unbound","nftables"], disk_threshold_pct: 90 }`.
- UI: um interruptor mestre **"Me avise de qualquer queda"** (ligado por padrão) na aba Notificações/Monitoramento; edição da lista de serviços só aparece no **modo Avançado**.
- Migração: se a chave não existir, usar defaults (comportamento ligado).

## Modelo de dados
- Novos tipos de alerta em `internal/alerts`: `service_offline`, `service_online`, `disk_full` (+ métodos `ServiceOffline/ServiceOnline/DiskFull`).
- Estado de saúde: em memória no Collector (`map[string]itemState{up, since, failCount}`), exposto por `Snapshot()`. Não persiste entre reinícios (aceitável: reidrata em ≤2 ciclos).
- Settings `monitoring` no DB (tabela `settings`).

## Erros e resiliência
- Checagens são best-effort: falha de `systemctl`/exec loga `warn` e não derruba o loop.
- Anti-flap evita tempestade de alertas; transição garante no máximo 1 alerta por mudança.
- `--notify-down` é best-effort e com timeout curto (não pode travar o shutdown do systemd).

## Testes
- Transição: up→down gera 1 alerta de queda; down→up gera 1 de recuperação; estado estável não gera nada.
- Anti-flap: uma piscada (down por 1 ciclo, up no próximo) **não** alerta.
- Recuperação entrega mesmo com `min_severity=warning`.
- Parse de `systemctl is-active` (active/inactive/failed/activating/erro).
- Disco: cruzar 90% alerta uma vez; voltar abaixo resolve.
- `--notify-down`: com canal configurado, monta e envia; sem canal, no-op silencioso.
- Handler `/api/health`: retorna snapshot coerente; exige permissão de leitura.
- WAN gap: teste de regressão garantindo que transição de status de link cria alerta.

## Rollout / deploy
- Segue a esteira documentada (`.claude/skills/deploy-to-prod`): merge na main → pipeline v1.0.x → download → scp → `dpkg -i`.
- Lembrete: o control/units do `.deb` são montados **inline no `release.yml`** — a nova unit `OnFailure` e a oneshot precisam ser adicionadas lá **e** no `deploy/` e no Makefile.
- Após deploy, validar com o "Testar" do canal WhatsApp e uma queda real de serviço (`systemctl stop unbound`) em janela controlada.

## Impacto no público
Admin caseiro liga o produto e, sem configurar nada, passa a: ver num relance se firewall/DHCP/DNS/WANs estão de pé, e receber no WhatsApp quando qualquer um cair e quando voltar. Simples, objetivo, e honesto — reforça "poderoso porém acessível e confiável".
