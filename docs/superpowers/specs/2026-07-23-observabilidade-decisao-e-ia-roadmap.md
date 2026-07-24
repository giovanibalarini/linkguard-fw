# Observabilidade, decisão e IA — decomposição e invariantes

**Data:** 2026-07-23
**Status:** decomposição aprovada; cada projeto tem spec próprio
**Origem:** investigação do spam de alertas de link em produção (2026-07-23)

---

## 1. Por que este documento existe

O objetivo declarado é: **o LinkGuard deve tomar a melhor decisão possível, sempre
focado em disponibilidade**, eventualmente com apoio de IA.

Isso não cabe num spec. São cinco projetos com dependências reais entre si. Este
documento fixa a decomposição, a ordem e — principalmente — **os invariantes**,
para que os specs seguintes os herdem em vez de re-litigá-los.

## 2. O achado que originou tudo

Investigação de 2026-07-23 sobre "estou recebendo notificações demais":

- **212 alertas de link** no banco (104 `degraded` + 108 `online`), ~38/dia nos
  últimos 3 dias, 58 de 67 na WAN Sumicity.
- Camada física **impecável**: 0 erro RX/TX, 0 CRC, nenhum flap de carrier desde
  03/jul. Confirmado por `node_exporter`: nos **85 eventos**, `carrier_down` em
  janela de 5 min teve mediana **e máximo** = 0.
- Caixa ociosa: `iowait` 0,172 no evento vs 0,171 na base; `load1` 0,070 vs 0,110.
- Links ociosos: média 0,04–0,32 Mbps, pico histórico de 14 Mbps.
- Episódios de **8 a 18 segundos**, distribuídos uniformemente pelas 24 h,
  inclusive 03–06 h com 0,0 Mbps.

**Conclusão:** o gatilho é upstream (microqueda da operadora), real mas
inconsequente. O defeito é a **amplificação**: `offline` exige 3 amostras ruins
consecutivas, `degraded` exige **uma** ([monitor.go:151-160](../../../internal/links/monitor.go#L151-L160)).
E `DegradedSustainSamples` (default 3), que seria a histerese natural, só está
ligado à expulsão de fluxos, não ao status.

Cada blip vira 2 notificações **e duas reescritas da rota default** (pesos
30/70 → 1/70 → 30/70), ~19×/dia. **A reescrita de rota é o dano; a notificação é
só o sintoma visível.**

> A maior ameaça à disponibilidade dessa caixa hoje é o próprio LinkGuard
> mexendo na rota sem motivo. Nenhuma camada de IA em cima consertaria isso —
> ela herdaria o mesmo sinal ruim e decidiria com mais confiança sobre dado errado.

## 3. Achado colateral: métricas coletadas e descartadas

O Prometheus **roda na caixa** (com Grafana), mas seus targets são `prometheus`,
`node` e `bind` — este último **down desde a migração de junho**, quando o bind9
foi aposentado. **Não existe job para o LinkGuard em `localhost:9997`.**

`linkguard_link_latency_ms`, `linkguard_link_packet_loss_percent` e
`linkguard_link_status` são calculados a cada 30 s e jogados fora. O journal
confirma: 0 requisições a `/metrics` em 24 h.

Pior: mesmo religando o scrape haveria subamostragem. O monitor mede a cada
**10 s** ([monitor.go:244](../../../internal/links/monitor.go#L244)); o coletor
publica a cada **30 s** ([collector.go:113-116](../../../internal/monitoring/collector.go#L113-L116)).
**O pipeline subamostra em 3× exatamente o fenômeno que precisa diagnosticar.**

## 4. Achado colateral: vazamento de segredos no backup

`GET /api/backup` chama `ExportSettings()`, que é
[`SELECT key, value FROM settings`](../../../internal/storage/repository.go#L881)
sem filtro, e serve o resultado como arquivo para download.

Já saem em texto puro nesse arquivo:

| Chave | Segredo |
|---|---|
| `github_update_token` | PAT do GitHub (repo privado) |
| `totp_<userID>` | **segredo TOTP de cada usuário** |
| `notifications` | senha SMTP, token do Telegram, token do zapvite |

O do TOTP é o mais grave: o 2FA foi adicionado como defesa e o botão de backup o
entrega. Não é explorável remotamente (exige admin autenticado), mas o arquivo de
backup é justamente o que se manda por e-mail e guarda em nuvem.

## 5. Invariantes do produto

Estes valem para **todos** os projetos abaixo. Não re-decidir por spec.

### I1 — Binário único
Sem daemon extra, sem segundo banco. Escala de série temporal se resolve com
*rollup*, não com outro motor. Prometheus é **integração opcional de primeira
classe**, nunca dependência. (Herda `FEATURES.md` F4.)

### I2 — Autonomia: recomendar, não agir
Queda inequívoca (sem carrier / 100% de perda sustentada) age sozinha, como hoje.
**Tudo que é julgamento** — "está ruim o bastante?", "mudo o peso?" — vira
recomendação com evidência e botão de aprovar.

### I3 — IA fora do laço de controle
O laço de controle é determinístico, testável e **funciona offline**. A IA é
assessora e degrada graciosamente.

> Razão concreta: a caixa é uma OptiPlex 3010 (4 cores, 3,7 GB, disco mecânico) —
> não roda LLM local de forma útil. IA aqui é chamada de API. Logo, *o firewall
> precisaria de internet para raciocinar sobre a internet estar caindo*. Quando as
> duas WANs caem — o momento em que a decisão mais vale — a IA está inalcançável.

### I4 — Medição não contamina a si mesma
Quem produz métrica nunca faz I/O no caminho crítico. `Gauge()` toca só memória;
a escrita acontece na goroutine do `tsdb`. Um `checkLink` que bloqueia em disco
passaria a medir o atraso do disco como se fosse latência de rede.

### I5 — Segredo não mora em tabela de configuração
Segredos vivem em tabela própria, cifrados. A separação importa mais que a cifra:
o vazamento aconteceu porque segredo e config dividiam tabela e o export varre a
tabela inteira. Em tabelas separadas o erro **deixa de ser possível por
construção**, em vez de depender de uma lista de exclusão que a próxima feature
esquece.

## 6. Os cinco projetos

| # | Projeto | Entrega | Depende de |
|---|---|---|---|
| **1** | **Substrato** — `tsdb` + linha do tempo | série histórica de link/serviço/recurso, tela de diagnóstico, scrape do Prometheus religado | — |
| **2** | **Higiene do controle** | histerese no `degraded`, valores medidos no alerta, não reescrever rota à toa | 1 (para calibrar com dado) |
| **3** | **Cofre de segredos** | tabela `secrets` cifrada (AES-256-GCM), migração dos 3 segredos existentes, backup deixa de exportá-los | — (independente) |
| **4** | **Motor de decisão** | SLO de disponibilidade explícito, política, *recomendar → aprovar*, preview e rollback | 1, 2 |
| **5** | **Camada de IA (BYOK)** | explicação de incidente, calibração sugerida, detecção de anomalia, laudo para a operadora | 1, 3, 4 |

**Ordem recomendada:** 1 → 3 → 2 → 4 → 5.
O cofre (3) sobe na fila em relação ao seu papel de pré-requisito porque corrige
vazamento que existe **agora** em produção.

### Projeto 1 — Substrato
Spec: `2026-07-23-tsdb-serie-temporal-e-linha-do-tempo-design.md`

### Projeto 2 — Higiene do controle
Aplicar `DegradedSustainSamples` à transição de status, espelhando o
`probeFailThreshold=3` do offline. Registrar perda e latência medidas na mensagem
do alerta (hoje é `"is experiencing high packet loss or latency"`, sem números —
foi essa lacuna que transformou uma pergunta simples em investigação forense).
Não reconstruir a rota quando o conjunto de nexthops não muda de fato.

Vem **depois** do substrato para que o limiar seja escolhido pela distribuição
real dos episódios, não por palpite.

### Projeto 3 — Cofre de segredos
Tabela `secrets` separada de `settings`. AES-256-GCM, chave de 32 bytes em
`/etc/linkguard-fw/secret.key` (`0600`), gerada no primeiro boot, **fora do
banco** e **não derivada do `jwt_secret`** (trocar o JWT secret é ação de
segurança normal e destruiria todos os segredos). Migração automática no boot dos
três segredos existentes. Backup nunca exporta segredo; após restaurar, a tela
lista o que precisa ser reinformado.

> Limite honesto: **não protege contra root na máquina** — o serviço roda como
> root e lê a chave. Protege contra backup vazado, `.db` copiado e disco
> descartado, que são os vetores reais aqui. Não é cofre de verdade e não deve ser
> vendido como tal.

### Projeto 4 — Motor de decisão
SLO de disponibilidade explícito por link. Política avaliada sobre a série do
`tsdb`. Saída é **recomendação** com evidência (o trecho da linha do tempo que a
justifica), preview do comando e rollback armado. Determinístico e testável.

### Projeto 5 — Camada de IA (BYOK)
Usuário informa a própria chave; é a conta dele. SDK oficial
`anthropic-sdk-go`, com `thinking: adaptive` e `output_config.effort`
configuráveis pelo painel.

Token **write-only**: `PUT /api/ai/token` grava, `GET /api/ai/status` devolve
`{configured, hint: "sk-ant-…7f2a", last_ok_at}`. Nunca volta pela API, nunca vai
para log, o `details` do audit registra "token atualizado" e não o token.

Seleção de modelo, com custo visível (a conta é do admin):

| Modelo | ID | Quando | in/out por MTok |
|---|---|---|---|
| Claude Opus 4.8 (padrão) | `claude-opus-4-8` | diagnóstico difícil, correlação | $5 / $25 |
| Claude Sonnet 5 | `claude-sonnet-5` | uso rotineiro | $3 / $15 |
| Claude Haiku 4.5 | `claude-haiku-4-5` | resumos curtos e frequentes | $1 / $5 |

Dois requisitos que BYOK obriga:

1. **Teto de gasto** — contador de chamadas/tokens no painel e limite mensal que
   corta a funcionalidade ao estourar. Um laço mal calibrado num firewall queima
   dinheiro em silêncio.
2. **Consentimento sobre o que sai da rede** — a camada manda telemetria (hostname,
   IP, MAC, possivelmente queries DNS) a um terceiro. Opt-in explícito, a tela diz
   **quais campos** são enviados, e identificadores são pseudonimizados por padrão.

Onde a IA ganha: traduzir a linha do tempo em explicação, sugerir limiar
calibrado pela distribuição real, detectar desvio contra a baseline do próprio
link, gerar laudo com evidência para cobrar a operadora. Onde não entra: decidir
failover, peso ou expulsão de fluxo (I3).

#### Acionamento — dois gatilhos

A frequência de disparo domina o custo, **não** a escolha de modelo. Numa análise
com evidência pré-computada (~800 tok in / ~400 out), a diferença entre Opus 4.8 e
Haiku 4.5 no volume real é ~$0,67/mês — otimizar isso é otimizar a variável errada.
O que corta custo de verdade é disparar pouco e mandar fato apurado, não série crua.

- **Imediato, raro** — só evento grave: link efetivamente offline, ou degradação
  **sustentada** acima de N minutos. É quando a análise na hora vale e quando o
  admin quer ser acordado.
- **Digest diário** — 1 chamada/dia sobre o padrão acumulado. É onde a IA ganha de
  verdade (o caso de 2026-07-23 só se resolveu vendo o *conjunto*: 19 episódios,
  todos fora de pico, mesma operadora, sem perda de carrier) e é o que vira laudo
  para a operadora. ~$0,72/mês no Opus 4.8.

> ⚠️ O gatilho imediato consome o sinal **pós-histerese** (Projeto 2), nunca o
> detector atual — senão a IA seria chamada ~19×/dia para explicar blips de 8 s que
> não significam nada. Mais uma razão para o Projeto 2 preceder o 5.

**Modelo padrão de fábrica: Opus 4.8** (o admin troca na tela). A diferença de
custo é irrelevante nesse volume; a feature existe pela qualidade do diagnóstico,
que é raciocínio de correlação multi-fator — exatamente o que os modelos menores
fazem pior.

**Não construir sobre cache de prompt.** A 1–2 chamadas/dia o TTL (5 min / 1 h)
sempre expira entre elas — nunca há hit. A economia real vem de pré-computar a
evidência (duração do episódio, min/avg/max na janela, condição que disparou,
estado do carrier, nível de tráfego) em vez de despejar a timeline crua: ~800 tok
contra ~7k, e melhor análise porque o modelo raciocina sobre fatos, não faz parse
de CSV.

**Detecção de anomalia contra baseline é estatística, não LLM.** Sai melhor e de
graça determinística; não gastar chamada de IA nisso.

## 7. Não-faça

- ❌ Prometheus como dependência do produto (I1).
- ❌ IA no caminho de ação (I3).
- ❌ Mais um segredo na tabela `settings` (I5).
- ❌ Escolher o limiar da histerese antes de ter a série (é o erro que se está
  corrigindo, cometido de novo).
- ❌ Rollup que guarda só média — apaga justamente o pico que se foi investigar.
- ❌ Escolher modelo de IA para economizar antes de corrigir a taxa de disparo — a
  frequência domina o custo em ~10×, o modelo em ~4×, e pós-histerese o gasto é
  irrelevante em qualquer modelo (< $1/mês).
- ❌ Gastar chamada de LLM em detecção de anomalia — é estatística, sai melhor
  determinística.
- ❌ Acionar a IA no detector atual (pré-histerese) — pagaria para explicar ruído.

## 8. Pendência operacional

Há um `/tmp/lg-probe-watch.py` rodando via `nohup` na produção (PID 1116647),
instrumentação ad-hoc criada durante a investigação. Deve ser removido quando o
Projeto 1 religar o scrape do Prometheus — ou antes, se incomodar.
