# Substrato: série temporal unificada e linha do tempo de diagnóstico

**Data:** 2026-07-23
**Status:** desenho aprovado, pronto para plano de implementação
**Projeto 1 de 5** — ver `2026-07-23-observabilidade-decisao-e-ia-roadmap.md`

---

## 1. Problema

O LinkGuard mede a saúde de cada WAN a cada 10 s e **não guarda nada**. Latência,
perda e status existem apenas como "último valor" na tabela `links`. Serviços e
recursos idem.

A consequência apareceu em 2026-07-23: responder *"por que recebi 19 alertas
ontem?"* exigiu ler journal na mão, copiar o banco, correlacionar com
`node_exporter` e rodar instrumentação ad-hoc na produção. A pergunta deveria ter
sido respondida em 10 segundos num gráfico.

Três causas, todas endereçadas aqui:

1. **Nada é persistido.** Só tráfego por interface (`trafficrrd`) tem histórico.
2. **O que existe é subamostrado.** O monitor mede a 10 s; os gauges publicam a
   30 s ([collector.go:113-116](../../../internal/monitoring/collector.go#L113-L116)) —
   dois terços das medições são descartados, e um episódio de 8 s pode não deixar
   rastro.
3. **O rollup existente apaga o pico.** `trafficrrd` agrega só média
   ([service.go:188](../../../internal/trafficrrd/service.go#L188)); um pico de
   2000 ms num bucket de 60 s vira 43 ms.

## 2. Princípio norteador

A tela responde **"o que aconteceu às 22:31?"**. É diagnóstico de incidente, não
relatório de SLA — o relatório vem depois, no Projeto 4, em cima da mesma base.

Portanto: resolução fina na janela recente, correlação de várias faixas num eixo
comum, e **preservação do extremo** através de todos os degraus de agregação.

## 3. Escopo

### Dentro
- Pacote `internal/tsdb`, que **absorve** `internal/trafficrrd`
- Gauges com `min/avg/max` por bucket e rollup 10 s/30 s/1 s → 60 s → 900 s → 3600 s
- Estados (link, serviço) como **intervalos**, não amostras
- Endpoint único de linha do tempo + tela `/monitoring` estendida
- Deep-link do alerta para o instante (`?at=<ts>`)
- Publicação dos gauges Prometheus na cadência do probe (10 s)
- Job de scrape e dashboard Grafana versionados em `deploy/`
- Migração de `traffic_samples` → `metric_samples`

### Fora, explicitamente

| Item | Por quê |
|---|---|
| Relatório de SLA / percentis / export | Projeto 4; a base aqui já os sustenta |
| Prometheus como dependência | Invariante I1 |
| Correção da histerese do `degraded` | Projeto 2 — precisa desta série para calibrar |
| Séries por host / por VPN | YAGNI hoje; o modelo genérico já as acomoda |
| Alertar sobre a própria série | Projeto 4 |

## 4. Decisões e suas razões

| Decisão | Razão |
|---|---|
| Série **genérica** (`series` + `label`), não tabelas por domínio | Já se sabe que virão mais séries (por host, por VPN). Tabela tipada por domínio pede código novo a cada uma. Mapeia 1:1 para Prometheus. |
| Guardar **`min/avg/max`**, não só média | É a razão de existir do desenho. Com média, o histórico responde "a média estava boa" a uma pergunta que é sobre o pico. |
| Estados como **intervalos**, não amostras | Média de "up" não significa nada. *"SUMICITY degradado por 8 s"* vira uma linha; "quantos episódios ontem" vira um `COUNT`. |
| **Migrar** o `trafficrrd` em vez de conviver | Dois motores de série temporal é dívida permanente. O tráfego é só mais uma série. |
| Passo nativo **por série**, não denominador comum | Reamostrar para um passo único ou joga fora medição (link a 10 s) ou infla o banco (tudo a 1 s). |
| `Gauge()` **não faz I/O** | Invariante I4 — o produtor é o `checkLink`; I/O síncrono num disco mecânico faria a latência medida incluir o atraso do disco. |

## 5. Arquitetura

```
internal/tsdb/            modelo, Recorder, bucketização, rollup, prune, consultas
internal/tsdb/schema.go   registro de séries (nome → passo nativo, unidade)
```

O `tsdb` é o único dono de bucketização, rollup e retenção. Quem produz métrica
não sabe nada disso — toda a superfície pública é:

```go
type Recorder interface {
    Gauge(series, label string, v float64)  // ("link.latency_ms", "WAN SUMICITY", 10.8)
    State(kind, label, state string)        // ("link", "WAN SUMICITY", "degraded")
}
```

`Gauge` acumula no bucket corrente **em memória**. `State` só escreve quando o
estado **muda**: fecha o intervalo aberto e abre outro.

Produtores viram uma linha cada:

| Produtor | Chamada |
|---|---|
| `links.Monitor.checkLink` | `Gauge("link.latency_ms", …)`, `Gauge("link.loss_pct", …)`, `State("link", …)` |
| `monitoring.Collector` | `Gauge("sys.cpu_pct" / "sys.mem_pct" / "sys.disk_pct", "", …)` |
| `monitoring` healthchecks | `State("service", "unbound", "up"\|"down")` |
| `tsdb` (interno, 1 s) | `Gauge("if.rx_bps" / "if.tx_bps", "<iface>", …)` |

### 5.1 Modelo

```sql
CREATE TABLE metric_samples (
  series       TEXT NOT NULL,          -- link.latency_ms | sys.cpu_pct | if.rx_bps
  label        TEXT NOT NULL DEFAULT '',
  step_seconds INTEGER NOT NULL,
  ts_unix      INTEGER NOT NULL,
  v_min REAL NOT NULL, v_avg REAL NOT NULL, v_max REAL NOT NULL,
  PRIMARY KEY (series, label, step_seconds, ts_unix)
) WITHOUT ROWID;

CREATE TABLE state_intervals (
  kind       TEXT NOT NULL,            -- link | service
  label      TEXT NOT NULL,
  state      TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER,                  -- NULL = em curso
  PRIMARY KEY (kind, label, started_at)
);
CREATE INDEX idx_state_open ON state_intervals(kind, label) WHERE ended_at IS NULL;
```

**Propagação no rollup:** `max` → `max`, `min` → `min`, `avg` → média ponderada
pela contagem. O pico atravessa 10 s → 60 s → 900 s → 3600 s sem diluir.

### 5.2 Cadência e retenção

| Série | Passo nativo | Retenção do passo nativo (perfil 30d) |
|---|---|---|
| `if.rx_bps`, `if.tx_bps` | 1 s | 2 h (como hoje) |
| `link.latency_ms`, `link.loss_pct` | 10 s | 48 h |
| `sys.cpu_pct`, `sys.mem_pct`, `sys.disk_pct` | 30 s | 48 h |
| estados (link, serviço) | evento (sem bucket) | **90 d**, igual ao degrau mais longo |

Degraus derivados, comuns a todas as séries: **60 s** (7 d), **900 s** (30 d),
**3600 s** (90 d). Os perfis `1y` e `5y` existentes continuam valendo, esticando
os degraus longos.

**Custo em regime (perfil 30d):**

| Degrau | Séries | Linhas | Tamanho |
|---|---|---:|---:|
| 1 s | 12 | 86 k | ~7 MB |
| 10 s | 4 | 69 k | ~5,5 MB |
| 30 s | 3 | 17 k | ~1,4 MB |
| 60 s | 19 | 192 k | ~15 MB |
| 900 s | 19 | 55 k | ~4,4 MB |
| 3600 s | 19 | 41 k | ~3,3 MB |

**~37 MB** (o banco em produção hoje tem 7,4 MB). Escrita: o degrau de 1 s já
existe e domina; link e recursos somam **0,5 linha/s**. Não há carga nova
relevante para o disco mecânico.

### 5.3 Regras de integridade

Funções puras em `internal/tsdb` — são a maior fonte de bug neste tipo de código:

- um intervalo aberto por `(kind, label)`; abrir outro fecha o anterior no mesmo
  instante (sem sobreposição, sem buraco)
- `ended_at > started_at` sempre; `ended_at NULL` só no intervalo corrente
- bucket só é escrito quando fecha; bucket sem amostra não gera linha
- `prune` respeita o perfil por degrau e nunca apaga o bucket corrente
- série desconhecida em `Gauge()` é erro de programação — falha alto em teste,
  descarta com `slog.Warn` em produção

## 6. API

```
GET /api/monitoring/timeline?from=<unix>&to=<unix>&series=<csv>   perm: monitoring.read
→ {
    step_seconds,
    series: [{ name, label, points: [{ts, min, avg, max}] }],
    states: [{ kind, label, state, started_at, ended_at }],
    alerts: [{ ts, type, severity, title }]
  }
```

Um endpoint só, porque **correlação é o objetivo** — três chamadas separadas
devolveriam três eixos que o cliente teria de alinhar. `step_seconds` é escolhido
pela largura da janela (mesma lógica de `rangeToStepDuration`).

`GET /api/system/traffic-history` **permanece**, com a mesma resposta,
reimplementado sobre o `tsdb`. O frontend atual não muda.

## 7. Tela

`/monitoring` ganha seletor de período e o deep-link `?at=<ts>`, que centra uma
janela num instante — é para onde o alerta aponta. Faixas empilhadas num eixo X
comum:

```
estado dos links   ▓▓▓▓▓░░▓▓▓▓▓▓▓▓▓▓▓   ← intervalos
latência           ──╱‾╲────────────    ← linha avg + banda min–max
perda %            ────█──────────────
tráfego            ▁▂▁▃▂▁▁▂▁▃▂▁▂▁▂▁▂
cpu / mem / disco  ▁▁▁▂▁▁▁▁▂▁▁▁▁▁▁▁▁
serviços           ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
                        ↑ alerta 22:31:20
```

A **banda min–max** é o que faz o pico aparecer; com só a média o episódio de 8 s
continuaria invisível num bucket de 60 s.

## 8. Integração Prometheus (opcional, primeira classe)

- Gauges de link passam a ser publicados **na cadência do probe (10 s)**, no ponto
  onde o valor nasce, em vez de relidos do banco a cada 30 s.
- `deploy/prometheus/linkguard.yml` — job pronto para colar.
- `deploy/grafana/linkguard-dashboard.json` — dashboard versionado.
- README documenta a integração e **o target `bind` morto** que deve ser removido
  do `prometheus.yml` da produção (bind9 foi aposentado em junho).

Quem já roda Prometheus ganha histórico externo e alertas; quem não roda não
instala nada e não perde nada (invariante I1).

## 9. Migração

Idempotente, no startup:

1. `traffic_samples` → `metric_samples` como `if.rx_bps` / `if.tx_bps`, com
   `v_min = v_avg = v_max = valor`. O dado histórico não tem min/max — perda
   honesta, nunca teve.
2. `traffic_samples` é **renomeada**, não apagada; removida na versão seguinte.
3. `internal/trafficrrd` é excluído; `main.go` passa a instanciar `tsdb`.

O `trafficrrd` hoje **não está gofmt'd** (usa espaços em vez de tabs). Como o
código migra para um pacote novo, o problema desaparece junto — mas vale registrar
que o diff da remoção será grande por esse motivo, não por mudança semântica.

## 10. Testes

| Propriedade | Por que é a que importa |
|---|---|
| rollup preserva `max` e `min` de 10 s → 60 s → 900 s → 3600 s | é a razão de existir do desenho; se falhar, o histórico mente |
| `avg` no rollup é média **ponderada pela contagem** | média de médias com buckets desiguais distorce silenciosamente |
| intervalos de estado não se sobrepõem e não deixam buraco | senão a faixa de estado fica ambígua |
| `Gauge()` não toca disco | invariante I4 — protege a medição de contaminar a si mesma |
| `prune` respeita o perfil por degrau e poupa o bucket corrente | senão o banco cresce sem limite ou perde o dado mais recente |
| migração preserva contagem e valores | dado de produção de ~1 mês |
| `timeline` escolhe o degrau pela largura da janela | pedir 1 ano não pode varrer amostras de 1 s |

## 11. Riscos

| Risco | Mitigação |
|---|---|
| Migrar código estável de produção (`trafficrrd`) | Migração idempotente, tabela antiga renomeada e não apagada; `traffic-history` mantém contrato |
| Banco cresce mais que o previsto | `prune` a cada 2 min (como hoje) + estimativa de §5.2 verificada em produção antes de fechar |
| Publicar gauges a 10 s aumenta custo de scrape | 4 séries a mais por link; desprezível — e é opt-in via Prometheus |
