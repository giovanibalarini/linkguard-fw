# Camada de IA (BYOK)

**Data:** 2026-07-24
**Status:** desenho aprovado, pronto para plano de implementação
**Projeto 5 de 5** — ver `2026-07-23-observabilidade-decisao-e-ia-roadmap.md`
**Depende de:** Projeto 1 (`tsdb`), Projeto 2 (histerese calibrada), Projeto 3 (cofre)

---

## 1. Problema

O admin recebe um alerta de degradação e precisa interpretar a linha do tempo
sozinho — correlacionar latência, perda, tráfego, estado de serviço e o horário,
para decidir se é ruído ou algo que vale escalar para a operadora. É exatamente o
trabalho que a investigação de 2026-07-23 fez manualmente, lendo journal e
cruzando com métricas do node_exporter.

Este projeto oferece esse raciocínio como funcionalidade do produto — **assessora
da decisão humana, nunca decisora**, conforme o invariante I3.

## 2. Princípio norteador

> IA na interface humana da decisão, nunca no laço de controle.

O laço de controle (Projetos 2 e 4) é determinístico, testável e funciona
offline. A IA explica, sugere calibração e redige laudo — nunca decide failover,
peso ou expulsão de fluxo. A caixa é uma OptiPlex 3010 sem capacidade de LLM
local; IA aqui é sempre chamada de API externa, e portanto **não pode estar no
caminho crítico de disponibilidade**: se as duas WANs caem, a análise de IA fica
inalcançável, e o produto continua funcionando sem ela.

## 3. Escopo

### Dentro
- Token BYOK do usuário, write-only, cifrado via cofre (Projeto 3)
- Seleção de modelo (Opus 4.8 padrão, Sonnet 5, Haiku 4.5) e nível de esforço
- Dois gatilhos: imediato (evento grave) e digest diário
- Evidência pré-computada a partir do `tsdb` (Projeto 1), nunca série crua
- Teto de gasto mensal com corte automático
- Consentimento explícito e granular sobre o que sai da rede
- Botão "testar conexão"

### Fora, explicitamente
| Item | Por quê |
|---|---|
| IA decidindo failover/peso/expulsão de fluxo | Invariante I3 — é o motor do Projeto 4, determinístico |
| Detecção de anomalia via LLM | É estatística; sai melhor e de graça determinística (ver roadmap §7) |
| Cache de prompt | A 1–2 chamadas/dia o TTL sempre expira entre elas; não há hit a otimizar |
| Modelo local / self-hosted | Hardware não suporta (OptiPlex 3010, 4 cores, 3,7 GB) |
| Multi-tenant / múltiplas chaves | Uma instalação, um admin, uma chave — como o resto do produto |

## 4. Decisões e suas razões

| Decisão | Razão |
|---|---|
| **BYOK**, não chave do produto | É a conta do próprio admin; o produto não intermedeia custo nem passa por proxy próprio. Consequência direta: precisa de teto de gasto (§6) e de aviso claro do que sai da rede (§7), porque não há operador do produto controlando o outro lado. |
| Token **write-only** | Nunca há motivo legítimo para o token voltar pela API depois de gravado. Reduz a superfície: nem um bug de serialização de resposta pode vazá-lo. |
| **Opus 4.8 como padrão de fábrica** | Conta feita na conversa: pós-correção da histerese (Projeto 2), o volume de chamadas é baixo o bastante (~1–2/dia) para a diferença de custo entre Opus e Haiku ser irrelevante (~$0,67/mês) frente à diferença de qualidade em raciocínio de correlação multi-fator — que é exatamente o tipo de análise que esta feature existe para fazer. |
| **Dois gatilhos**, não um só | Episódio isolado raramente rende análise (o gráfico já mostra "degradou 8s"). O padrão acumulado é o que rendeu no caso real — 19 episódios, mesma operadora, fora de pico, sem perda de carrier. Um gatilho por evento pagaria para repetir o óbvio; o digest é onde a análise ganha. |
| Gatilho imediato consome sinal **pós-histerese** | Sem isso a IA seria chamada ~19×/dia para explicar ruído — o mesmo defeito que originou todo este roadmap, só que pago por chamada de API. |
| **Evidência pré-computada**, nunca série crua | ~800 tokens de fatos apurados contra ~7k de pontos crus — 9× mais barato, e o modelo raciocina sobre fatos em vez de fazer parsing de CSV, o que melhora a análise além de baratear. |
| SDK oficial `anthropic-sdk-go`, `thinking: adaptive` | Guia da própria skill: usar sempre o SDK oficial, nunca HTTP cru, quando existe binding pra linguagem. Adaptive thinking é o modo recomendado para modelos correntes. |

## 5. Arquitetura

```
internal/ai/                 Client (wrapper fino do anthropic-sdk-go), EvidenceBuilder
internal/ai/digest.go        job diário: agrega o dia, monta evidência, chama, grava
internal/ai/immediate.go     gatilho síncrono em evento grave pós-histerese
```

### 5.1 Configuração (nova tabela, não `secrets` nem `settings`)

```sql
CREATE TABLE ai_config (
  id                  INTEGER PRIMARY KEY CHECK (id = 1),  -- linha única
  enabled             INTEGER NOT NULL DEFAULT 0,
  model               TEXT NOT NULL DEFAULT 'claude-opus-4-8',
  effort              TEXT NOT NULL DEFAULT 'high',
  monthly_budget_usd  REAL NOT NULL DEFAULT 5.0,
  spent_this_month_usd REAL NOT NULL DEFAULT 0,
  budget_reset_at     DATETIME NOT NULL,
  telemetry_consent   TEXT NOT NULL DEFAULT '{}',  -- JSON: {hostname:bool, ip:bool, mac:bool, dns_queries:bool}
  updated_at          DATETIME NOT NULL
);
```

O token em si **não** mora aqui — mora em `secrets`, chave `ai_api_token`, via
`Secrets.Get("ai_api_token")` no ponto de chamada. `ai_config` é configuração
(modelo, orçamento, consentimento), não segredo — a separação segue o mesmo
princípio do Projeto 3.

### 5.2 Cliente

```go
type Client struct {
    sdk    anthropic.Client   // github.com/anthropics/anthropic-sdk-go
    cfg    func() Config      // lido a cada chamada — mudança na UI vale sem reiniciar
    budget BudgetGuard
}

func (c *Client) Analyze(ctx context.Context, ev Evidence) (Report, error)
```

`BudgetGuard.Check()` roda **antes** de montar a requisição — se
`spent_this_month_usd >= monthly_budget_usd`, retorna erro sem chamar a API. O
gasto é contabilizado a partir de `response.Usage` (tokens de entrada/saída ×
preço do modelo em uso), acumulado em `ai_config.spent_this_month_usd` a cada
chamada, e zerado em `budget_reset_at` (1º dia do mês).

### 5.3 Evidência (não série crua)

```go
type Evidence struct {
    Period        string          // "2026-07-23" ou "2026-07-23T22:20:00Z/2026-07-23T22:35:00Z"
    Links         []LinkSummary   // por link: episódios, duração min/max, causa (perda|latência|ambos)
    CarrierEvents int             // contagem de queda de carrier no período (0 = física intacta)
    TrafficLevel  string          // "ocioso" | "moderado" | "saturado", derivado do tsdb
    RecentAlerts  []AlertRef      // tipo, severidade, horário — não o texto completo
}
```

`EvidenceBuilder` consulta o `tsdb` (Projeto 1) e monta isso — é a mesma consulta
que alimenta a tela de linha do tempo, reaproveitada. Nunca serializa pontos
brutos para o prompt.

### 5.4 Gatilhos

**Imediato** — chamado por `balancer.OnLinkChange` (Projeto 2) quando a transição
para `degraded` ou `offline` é **confirmada pela histerese** (não a cada amostra).
Roda em goroutine própria, com timeout curto (10s) — nunca bloqueia o reconcile
de rota. Falha (rede fora, chave inválida, orçamento estourado) é silenciosa para
o laço de controle: loga e segue. O alerta determinístico já foi disparado antes
disso, independentemente.

**Digest** — goroutine própria, dispara 1×/dia em horário configurável (padrão
06:00 local). Agrega as últimas 24h do `tsdb`, monta `Evidence` por link, chama
uma vez, grava o `Report` como um novo tipo de registro (`ai_reports`, não
`alerts` — não é alerta, é leitura).

### 5.5 Prompt e saída

Prompt de sistema fixo, versionado no binário — não editável pelo admin (evita
prompt injection via configuração e mantém o comportamento auditável entre
versões). Pede resposta estruturada:

```go
type Report struct {
    Summary      string   // 1-2 frases, para o card do dashboard
    Findings     []string // achados específicos com evidência ("SUMICITY: 19 episódios, nenhum com perda de carrier")
    Recommendation string // texto livre; NUNCA um comando executável (I2/I3)
    Confidence   string   // "alta" | "média" | "baixa" — o próprio modelo se autoavalia
}
```

Usa `output_config.format` (structured output) para garantir que `Findings` e
`Recommendation` venham nesse formato, sem parsing frágil de texto livre.

> ⚠️ `Recommendation` é **sempre texto para humano ler**, nunca um payload que o
> backend possa interpretar como ação. Isso não é detalhe de implementação — é o
> invariante I3 em código: não existe caminho, nem acidental, de uma resposta da
> IA virar uma chamada a `balancer.Apply` ou equivalente.

## 6. Teto de gasto

Campo `monthly_budget_usd`, padrão **$5** (cobre o digest diário no Opus 4.8 com
folga de ~6×, e algumas dezenas de gatilhos imediatos). Ao estourar:

- `BudgetGuard.Check()` recusa a chamada seguinte
- Um alerta **determinístico** (não-IA) é disparado: `type=ai_budget_exceeded`
- A tela de Configurações mostra o consumo do mês e o corte, com botão para
  ampliar o teto

O corte é automático e sem exceção — nunca "estourar um pouco para não perder o
diagnóstico". É a mesma filosofia de "nunca deixar rota default vazia" do
balancer: um limite automático que protege contra o próprio produto sair de
controle, aplicado agora a gasto em vez de rede.

## 7. Consentimento e telemetria

A tela de ativação (`Configurações → Assistente de IA`) lista, com um toggle por
item, **exatamente** o que pode sair da rede:

| Campo | Enviado por padrão | Observação |
|---|---|---|
| Nome do link (`WAN VIVO`, `WAN SUMICITY`) | Sim | Definido pelo admin, não é PII |
| Estatísticas de latência/perda/duração de episódio | Sim | É o dado central da análise |
| Nível de tráfego (categórico: ocioso/moderado/saturado) | Sim | Não é o volume exato, só a faixa |
| Hostname / MAC de hosts da LAN | **Não** (opt-in) | Só relevante se a análise algum dia correlacionar com hosts específicos — hoje o `Evidence` não inclui isso |
| Queries DNS | **Não** (opt-in) | Mesmo racional |

O texto acima do toggle não é "aceito os termos" genérico — é a tabela em si,
renderizada na tela. Ativar a camada de IA exige confirmar essa tela; desativar
o toggle mestre para de enviar qualquer coisa, incluindo o digest.

## 8. Endpoints

```
GET  /api/ai/status              perm: system.read   {configured, hint, model, effort, spent_this_month_usd, monthly_budget_usd}
PUT  /api/ai/token                perm: system.write   grava o token no cofre (write-only)
DELETE /api/ai/token              perm: system.write   remove (desativa a camada)
POST /api/ai/token/test           perm: system.write   chamada barata de validação
PUT  /api/ai/config               perm: system.write   model, effort, monthly_budget_usd, telemetry_consent, digest_hour
GET  /api/ai/reports              perm: monitoring.read   histórico de digests
GET  /api/ai/reports/{id}         perm: monitoring.read
```

## 9. Testes

| Propriedade | Por que é a que importa |
|---|---|
| `BudgetGuard.Check()` recusa chamada quando `spent >= budget`, sem tocar a rede | é a garantia de "nunca gastar sem controle" |
| `Report.Recommendation` nunca é interpretado como ação em nenhum caminho de código | é o invariante I3 verificado por teste, não só por convenção |
| gatilho imediato não bloqueia `balancer.OnLinkChange` (roda em goroutine, timeout curto) | falha de IA não pode virar falha de failover |
| `Evidence` nunca contém hostname/MAC quando o consentimento correspondente está off | consentimento é reforçado no código, não só documentado na UI |
| token nunca aparece em `GET /api/ai/status` nem em nenhuma resposta HTTP | write-only de verdade |
| `EvidenceBuilder` consulta o `tsdb`, nunca lê `traffic_samples`/tabela antiga diretamente | acopla à interface certa desde o início |

## 10. Riscos

| Risco | Mitigação |
|---|---|
| Chave de API do admin vaza via log/erro | `Client` nunca loga o token; erros da SDK são filtrados antes de log (`slog` com redação) |
| Gatilho imediato em cascata (ex.: um link degradando/recuperando repetidamente) | Mesmo debounce de `DegradedSustainSamples` do Projeto 2 já resolve a origem; adicionalmente, cooldown de 1 chamada imediata por link a cada 30 min |
| Digest falha silenciosamente e ninguém percebe | Se o digest falhar 2 dias seguidos, dispara alerta determinístico `ai_digest_failing` |
| Modelo indisponível no meio da noite (gatilho imediato) | Timeout curto + falha silenciosa para o laço de controle (§5.4) — a disponibilidade da rede nunca depende da IA responder |
