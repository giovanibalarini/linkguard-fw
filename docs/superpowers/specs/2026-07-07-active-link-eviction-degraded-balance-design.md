# Detecção mais forte + expulsão ativa de fluxos em link degradado (balance mode)

**Data:** 2026-07-07
**Status:** Aprovado (aguardando revisão do spec)
**Modo alvo:** balance (multi-WAN)

## Problema

Durante uma reunião, o WAN em uso oscilou forte (ping > 3000 ms por vários
segundos, intermitente). O LinkGuard **não** migrou o tráfego para o WAN
saudável. A investigação de causa-raiz encontrou três falhas encadeadas:

1. **Detecção rala e lenta.** O `Monitor` roda a cada 30 s e faz **1** connect
   TCP por host. A perda de pacote fica quantizada (com N hosts, só enxerga
   0 / 1·N⁻¹ / … / 100 %), então uma rajada curta que ainda fecha um handshake é
   lida como 0 % de perda. Rajadas de poucos segundos caem no vão entre amostras.

2. **"Degraded" nunca vira ação forte.** Um link a 3000 ms ainda responde ao
   connect (< 5 s de timeout), então é classificado `degraded`, nunca `offline`.
   Para virar `offline` são necessárias 3 checagens totalmente falhas seguidas =
   **90 s de blackout completo** (`probeFailThreshold=3 × 30 s`), que uma
   oscilação intermitente nunca acumula.

3. **Nenhuma expulsão de fluxos em curso.** Em balance mode o link degradado até
   é rebaixado a peso 1 em `selectNexthops`, mas isso só afeta conexões **novas**.
   A chamada de vídeo já estabelecida fica presa ao WAN ruim porque o kernel fixa
   o fluxo NAT'd (conntrack) no nexthop escolhido. Nenhum ajuste de peso puxa um
   fluxo vivo de volta.

O item 3 é o que teria salvado a reunião.

## Objetivo

Em balance mode:

- **Detectar** degradação de forma mais rápida e confiável (cadência menor +
  amostragem múltipla, medindo perda/latência reais).
- **Reagir** a um link sustentadamente ruim expulsando ativamente os fluxos em
  curso do WAN degradado, forçando-os a re-hashear para o WAN saudável — como
  uma **ação opcional, desligada por padrão**, com travas para evitar dano
  colateral e flapping.

Fora de escopo: mudar o comportamento do modo failover legado; expulsão seletiva
por protocolo/porta (pode vir depois); tornar os limiares de latência/perda
(300 ms / 25 %) configuráveis.

## Decisões do usuário

- Modo: **balance**.
- Reação: agir **só após X amostras ruins seguidas** (debounce), não a picos.
- Expulsão ativa: **sim**, como **toggle desligado por padrão**, com as 3 travas.
- O número de amostras sustentadas (`DegradedSustainSamples`) deve ser
  **editável pelo admin na página web**, default **3**.

## Arquitetura

Três partes, cada uma com responsabilidade única.

### Parte 1 — Detecção: loop de saúde dedicado + multi-probe

O `Monitor` deixa de compartilhar cadência com o coletor de métricas.

- **Config nova (arquivo, `internal/config/config.go`):**
  - `ProbeIntervalSeconds int` — cadência do `Monitor`. Default **10**.
  - `ProbeCount int` — connects por host, por tick. Default **3**.
  - `MonitorInterval` (30) permanece, agora só para o coletor de métricas/RRD.
- **`cmd/linkguard-fw/main.go`:** o `Monitor` passa a ser construído com
  `ProbeIntervalSeconds`; o `metricsCollector` continua com `MonitorInterval`.
- **`internal/links/monitor.go` (`checkLink`):** em vez de 1 `tcpCheck` por host,
  faz `ProbeCount` tentativas por host. Métricas passam a ser calculadas sobre
  `len(hosts) × ProbeCount` amostras:
  - `packetLoss = falhas / total × 100`
  - `avgLatency = média das amostras com sucesso`
  - Classificação `degraded` mantém os limiares atuais (`>300 ms` **ou**
    `>25 %` de perda).

Efeito: perda deixa de ser quantizada grosseiramente; um link ruim é flagrado em
~10–20 s em vez de até 30 s+, e rajadas que hoje somem entre amostras aparecem.

### Parte 2 — Debounce: episódio de "degradado sustentado"

O `linkState` (em `monitor.go`) ganha:

- `consecutiveDegraded int` — incrementa a cada tick classificado `degraded`,
  zera quando o link deixa de estar degradado.
- `degradedEpisodeFired bool` — garante disparo único por episódio.

O `Monitor` recebe, além do `OnStatusChange` atual, dois injetáveis:

- `sustainThreshold func() int` — provedor do limiar em runtime. Wired em
  `main.go` para `balancerSvc.LoadConfig().DegradedSustainSamples`. Mantém o
  `Monitor` desacoplado do `balancer` (ele só conhece "um provedor de int") e faz
  o valor refletir sempre o que o admin salvou na UI.
- `OnLinkDegradedSustained func(link *storage.Link)` — callback **edge-triggered**:
  dispara **uma vez** quando `consecutiveDegraded` cruza `sustainThreshold()` e só
  re-arma (`degradedEpisodeFired=false`) quando o link sai de `degraded`.

A **demissão de peso** (rebaixar o link para conexões novas) continua acontecendo
como hoje, na transição para `degraded`, via `OnStatusChange → balancer.OnLinkChange
→ Rebuild`. O debounce governa **apenas** a ação agressiva (Parte 3). O modelo de
4 estados (online/degraded/offline/unknown) não muda — nada de status novo
rippando por métricas/UI.

Guarda contra threshold inválido: se `sustainThreshold()` ≤ 0, tratar como 1.

### Parte 3 — Ação: expulsão ativa via conntrack, gated

Novo método `balancer.EvictDegraded(ctx, link)`, chamado pelo
`OnLinkDegradedSustained` **apenas quando `balancerSvc.Active()`**. Fiação em
`main.go` espelha o `OnStatusChange`:

```
monitor.OnLinkDegradedSustained(func(link) {
    if balancerSvc.Active() {
        balancerSvc.EvictDegraded(ctx, link)
    }
})
```

Passos e travas de `EvictDegraded`, na ordem:

1. **Toggle:** se `cfg.EvictOnDegrade` for false → retorna (nenhuma ação).
2. **Guard de alternativa saudável:** carrega os links; se **nenhum** outro link
   está `online` → loga e pula. Não faz sentido matar conexões para jogá-las em
   um link igualmente ruim.
3. **Cooldown:** mapa `evictCooldown[linkID]`; se dentro de `EvictCooldownSecs` →
   pula. Evita massacrar conexões num link que oscila.
4. **Rebuild primeiro:** chama `s.Rebuild(ctx)` (idempotente, no-op se a rota já
   está correta) para garantir que o link degradado já está demovido a peso 1
   antes do flush — assim os fluxos re-hasheados não recaem nele.
5. **Flush cirúrgico:** obtém o IPv4 do WAN degradado ao vivo
   (`ip -o -4 addr show dev <iface> scope global`, novo helper `interfaceIPv4`)
   e executa `conntrack -D -q <IP>`. Após o masquerade, o reply-dst dos fluxos
   que saíram por aquele WAN é o IP daquela interface, então `-q <IP>` mira só
   esses fluxos — não um flush global.
6. **Alerta + cooldown:** registra alerta informando a migração e grava
   `evictCooldown[linkID] = now + EvictCooldownSecs`.

Observações:

- Usa `s.exec.Execute` → em **dry-run** o `conntrack -D` é apenas logado, não
  aplicado. Coerente com o resto do balancer.
- Semântica real: flush de fluxo NAT'd **encerra** a conexão (o binding de NAT
  some); ela reconecta no WAN saudável. Não é migração suave. A reunião leva um
  tranco de ~1–2 s e volta boa; uploads/SSH que estavam no WAN ruim também
  reconectam. Por isso o default é **desligado**.
- Se `interfaceIPv4` não achar IP (interface sem IPv4 global) → loga e aborta a
  expulsão sem erro fatal.

### Parte 4 — Config do balancer + UI

`internal/balancer/service.go`, struct `Config` (persistida como JSON em
settings, já editada pela página do modo balance), ganha:

| Campo | Tipo | Default | Exposto na UI |
|-------|------|---------|---------------|
| `EvictOnDegrade` | bool | `false` | **sim** (toggle) |
| `DegradedSustainSamples` | int | `3` | **sim** (campo numérico) |
| `EvictCooldownSecs` | int | `120` | **sim** (campo numérico) |

`normalize()` do `Config` aplica os defaults quando zero/ausente
(`DegradedSustainSamples` ≤ 0 → 3; `EvictCooldownSecs` ≤ 0 → 120;
`EvictOnDegrade` false por ausência).

**Página web (modo balance):** adicionar uma seção "Reação a link degradado" com:

- Toggle **"Expulsar conexões de link degradado"**, com texto de aviso curto:
  "Ao migrar, as conexões ativas no link ruim são reiniciadas (reconectam no link
  saudável). Recomendado para chamadas/VoIP."
- Campo **"Amostras ruins consecutivas antes de agir"** (`DegradedSustainSamples`,
  default 3). Texto auxiliar: "A ~10 s por amostra, 3 ≈ 30 s de link ruim
  sustentado."
- Campo **"Intervalo mínimo entre migrações (s)"** (`EvictCooldownSecs`, default
  120).

Os knobs `ProbeIntervalSeconds` / `ProbeCount` ficam só no arquivo de config
(avançados), não vão à UI.

## Fluxo de dados

```
Monitor.Run (a cada ProbeIntervalSeconds=10s)
  └─ checkLink: ProbeCount probes/host → perda/latência reais
       ├─ classifica degraded (>300ms ou >25%)
       ├─ consecutiveDegraded++
       ├─ [transição de status] → OnStatusChange → balancer.OnLinkChange → Rebuild (demove p/ peso 1)
       └─ [consecutiveDegraded cruza sustainThreshold(), 1x/episódio]
             → OnLinkDegradedSustained
                  └─ balancer.EvictDegraded (se Active)
                       ├─ toggle EvictOnDegrade? ── não → fim
                       ├─ existe WAN online? ────── não → fim (loga)
                       ├─ dentro do cooldown? ───── sim → fim
                       ├─ Rebuild (garante demoção)
                       ├─ conntrack -D -q <IP do WAN degradado>
                       └─ alerta + arma cooldown
```

## Tratamento de erros

- `interfaceIPv4` sem resultado → aborta expulsão, loga warning, sem erro fatal.
- `conntrack -D` retornando erro (ex.: binário ausente) → loga; a demoção de peso
  (Rebuild) já protege conexões novas de qualquer forma.
- `sustainThreshold()` inválido (≤ 0) → tratado como 1.
- Dry-run → `conntrack -D` logado, não executado.

## Testes

**`internal/links/monitor_test.go`:**

- Cálculo multi-probe de perda/latência (table-driven): dado nº de sucessos/falhas
  por host, verificar `packetLoss` e `avgLatency`.
- Debounce edge-triggered: sequência de amostras degraded dispara
  `OnLinkDegradedSustained` **exatamente uma vez** ao cruzar o limiar; não dispara
  de novo enquanto permanece degraded; re-arma e dispara de novo após recuperar e
  degradar outra vez.
- `sustainThreshold()` ≤ 0 tratado como 1.

**`internal/balancer/service_test.go`** (com `Executor` fake capturando comandos):

- toggle off → nenhum `conntrack`.
- sem link `online` → nenhum `conntrack` (loga).
- cooldown ativo → nenhum `conntrack`.
- happy path → executa `conntrack -D -q <ip>` com o IP correto e arma cooldown.
- `normalize()` aplica defaults (3 / 120 / false).
- parser `interfaceIPv4` (saída de `ip -o -4 addr show`).

## Arquivos afetados

- `internal/config/config.go` — `ProbeIntervalSeconds`, `ProbeCount` + defaults.
- `internal/links/monitor.go` — multi-probe em `checkLink`; `linkState` com
  debounce; `sustainThreshold` + `OnLinkDegradedSustained`.
- `cmd/linkguard-fw/main.go` — fiação do probe interval, `sustainThreshold`,
  `OnLinkDegradedSustained → balancer.EvictDegraded`.
- `internal/balancer/service.go` — `Config` (3 campos + normalize);
  `EvictDegraded`; helper `interfaceIPv4`; mapa `evictCooldown`.
- Handler/JS da página do modo balance — expor os 3 campos novos.
- Testes acima.

## Efeito colateral positivo

Com a cadência do `Monitor` caindo para 10 s, o caminho `offline` também acelera:
`probeFailThreshold=3 × 10 s = 30 s` de blackout total (antes 90 s). O limiar em
si (`3`) não muda — só a cadência. É ganho, não regressão.
