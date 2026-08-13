# Painel com widgets e a tela de tráfego

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps usam checkbox (`- [ ]`).

**Goal:** Dar ao operador uma tela de tráfego em tempo real que faz jus ao dado que a máquina já coleta, e um painel que cada admin monta com os widgets que lhe interessam.

**Architecture:** Nenhuma coleta nova — `internal/tsdb.TrafficSampler` já amostra `/proc/net/dev` a cada segundo em quatro resoluções, e `GET /api/system/traffic-history` já serve os pontos. A Fase A constrói o gráfico grande (espelhado, redução por máximo, linear/log) como componente reusável. A Fase B monta a grade de 12 colunas com colisão resolvida em código próprio e persiste o layout por usuário, reusando o gráfico da Fase A como um dos widgets.

**Tech Stack:** Go 1.25 (`~/sdk/go1.25.0/bin`), SQLite via `modernc.org/sqlite`, React + TypeScript (Node em `~/.nvm/versions/node/v22.21.1/bin`), Tailwind.

**Spec:** `docs/superpowers/specs/2026-08-12-dashboard-widgets-e-trafego-design.md` — é o contrato.

**Mockups aprovados pelo operador** (referência de comportamento, não de código):
`/tmp/claude-1000/-home-gov-Documentos-Projetos-gbtech-repos-linkguard-fw/61a46606-3d44-41fd-9a28-d7e571d477a3/scratchpad/trafego.html` e `dash.html`.

## Global Constraints

1. **Nenhuma dependência nova de frontend.** Nem para grade, nem para gráfico. Num appliance de segurança, uma biblioteca de layout é superfície de cadeia de suprimentos por conveniência (spec §4.3).
2. **Nada de dado falso.** Widget sem fonte real de dado é omitido, nunca preenchido com estimativa. Intervalo sem amostra fica **em branco**, nunca em zero — `—` significa não medido; zero significa medido e deu zero.
3. **O ponto reduzido guarda o MÁXIMO do intervalo, nunca a média.** Média esconde rajada, e rajada é o que derruba link.
4. **Migração de schema em transação** (uma migração sem transação travou o boot de produção por 50+ min em 2026-07-24).
5. **Permissão por widget.** Widget que o usuário não pode ver não aparece nem para adicionar; layout salvo que referencie widget sem permissão não renderiza aquele widget, sem erro e sem buraco.
6. **Layout inválido nunca trava a tela.** Item que referencia widget inexistente é descartado **item a item** na leitura, e o resto renderiza.
7. Texto de interface em português; identificadores em inglês. Nome de ação do nftables (`accept`, `drop`, `reject`, `jump`) nunca se traduz, e aparece em `font-mono`.
8. Responsivo: em tela estreita vira uma coluna, na ordem que o admin definiu (por `y`, depois `x`). Não existe segundo layout para manter.
9. Nunca `git add -A` nem `git add <diretório>` — arquivo por arquivo.

## O que este plano NÃO constrói

Coleta nova de métrica (não é necessária — o dado existe e é farto); layout separado por tamanho de tela; widget configurável por dentro; layout compartilhado entre admins. Tudo isto está em §9 da spec, e sair dele é aumentar o risco sem pedido.

---

# FASE A — a tela de tráfego

### Task 1: O gráfico, e a redução que preserva o pico

**Files:**
- Create: `web/src/components/TrafficChart.tsx`, `web/src/lib/series.ts`
- Test: `web/src/lib/series.test.ts` (se o projeto ainda não tiver runner de teste de frontend, veja o Step 1)

**Interfaces:**
- Produces:
  - `type Point = { t: number; rx: number | null; tx: number | null }`
  - `function reduceToWidth(points: Point[], buckets: number): Point[]` — cada bucket guarda o **máximo**; bucket sem amostra devolve `null`, não `0`
  - `function niceScale(max: number, mode: 'linear' | 'log'): { ticks: number[]; project: (v: number) => number }`
  - `<TrafficChart points iface mode onModeChange />`

- [ ] **Step 1: Descobrir se há runner de teste de frontend**

```bash
cd web && cat package.json | grep -A5 '"scripts"'
```

Se houver (`vitest`, `jest`), escreva os testes nele. **Se não houver, não instale um** — a restrição 1 vale. Nesse caso, escreva `web/src/lib/series.check.ts`: um arquivo executável por `node --experimental-strip-types` que roda as mesmas asserções e sai com código ≠ 0 na falha, e documente no relatório como rodá-lo. A lógica de redução é a parte que erra silencioso; ela precisa de asserção automática de algum jeito.

- [ ] **Step 2: Escrever as asserções que falham**

```ts
// Média esconde rajada. Um pico de 84 Mbps dentro de um bucket cheio de tráfego
// baixo TEM que sobreviver à redução — é o pico que derruba link, e é ele que o
// operador está procurando quando abre esta tela.
{
  const pts = [
    { t: 0, rx: 1, tx: 0 }, { t: 1, rx: 1, tx: 0 },
    { t: 2, rx: 84_000_000, tx: 0 }, { t: 3, rx: 1, tx: 0 },
  ]
  const out = reduceToWidth(pts, 1)
  assert(out.length === 1, 'um bucket')
  assert(out[0].rx === 84_000_000, `o pico tem que sobreviver, obtive ${out[0].rx}`)
}

// Sem amostra não se desenha linha. Zero é uma medição; ausência não é.
// Desenhar zero faria um link fora do ar parecer um link ocioso.
{
  const pts = [{ t: 0, rx: 5, tx: 5 }, { t: 100, rx: 7, tx: 7 }]
  const out = reduceToWidth(pts, 10)
  const vazios = out.filter(p => p.rx === null)
  assert(vazios.length > 0, 'buckets sem amostra têm que vir null, não 0')
  assert(!out.some(p => p.rx === 0), 'nenhum bucket vazio pode virar zero')
}

// Log muda a projeção e o rótulo; linear continua sendo o padrão porque é ela
// que diz a verdade sobre magnitude.
{
  const lin = niceScale(10_200_000, 'linear')
  const log = niceScale(10_200_000, 'log')
  assert(lin.project(510_000) !== log.project(510_000), 'a projeção tem que mudar')
  assert(log.project(510_000) > lin.project(510_000),
    'em log o tráfego pequeno tem que subir na tela — é o defeito que o modo existe para resolver')
}

// O rótulo do eixo não pode ser cortado. Isto saiu de um defeito real do mockup:
// padL pequeno demais transformou "10.2" em "0.2" na tela.
{
  const s = niceScale(10_200_000, 'linear')
  const maiorRotulo = Math.max(...s.ticks.map(t => formatBps(t).length))
  assert(maiorRotulo <= AXIS_LABEL_MAX, 'o eixo tem que reservar largura para o maior rótulo')
}
```

- [ ] **Step 3: Rodar e confirmar que falha**

- [ ] **Step 4: Implementar `series.ts` e `TrafficChart.tsx`**

O gráfico é **espelhado**: descendo para cima, subindo para baixo, no mesmo eixo — num firewall com duas WANs, assimetria é o que se procura, e assim ela salta. Escala **linear por padrão**, log a um clique. Canvas ou SVG, à escolha; nada de biblioteca.

- [ ] **Step 5: Rodar, verde, e provar por mutação** — troque `max` por média na redução e mostre a asserção do pico vermelha; restaure.

- [ ] **Step 6: Commit**

---

### Task 2: A tela, com a faixa de interfaces

**Files:**
- Create: `web/src/pages/Traffic.tsx`
- Modify: `web/src/App.tsx` (rota), o componente de navegação lateral

**Interfaces:**
- Consumes: `TrafficChart`, `reduceToWidth` (Task 1)
- Produces: rota `/traffic`

**Atenção — dois erros que eu mesmo cometi ao investigar esta API, e que vão custar tempo se repetirem:**
- o parâmetro é **`iface`**, não `interface`
- os campos são **`rx_bps`/`tx_bps`**, não `rx`/`tx`

- [ ] **Step 1:** Faixa com uma entrada por interface: taxa atual, minigráfico, pico e total acumulado. Clicar troca o gráfico grande. Taxa atual vem de `/api/system/status`; o resto de `traffic-history`.
- [ ] **Step 2:** Seletor de janela (as quatro resoluções que o tsdb já mantém: 1s, 60s, 900s, 3600s). Escolher a resolução pela janela pedida, não sempre a mais fina.
- [ ] **Step 3:** Interface sem amostra nenhuma mostra `—`, não `0`.
- [ ] **Step 4:** `npx tsc --noEmit` e `npm run build` limpos.
- [ ] **Step 5:** Verificação visual com Playwright/**Firefox** contra o backend real, com screenshots. Mostrar: o gráfico com dado real, a alternância linear/log, e a tela a 390px.
- [ ] **Step 6:** Commit.

---

# FASE B — o painel com widgets

### Task 3: Onde o layout mora

**Files:**
- Modify: `internal/storage/storage.go`, `internal/storage/repository.go`
- Create: `internal/api/handlers/dashboard.go`
- Modify: `internal/api/server.go`
- Test: `internal/storage/storage_test.go`, `internal/api/handlers/dashboard_test.go`

**Interfaces:**
- Produces:
  - tabela `dashboard_layout` (uma linha por usuário)
  - `func (db *DB) GetDashboardLayout(userID string) ([]LayoutItem, error)`, `SaveDashboardLayout(userID string, items []LayoutItem) error`
  - `type LayoutItem struct { Widget string; X, Y, W, H int }`
  - `GET /api/dashboard/layout` e `PUT /api/dashboard/layout`, ambos gated pelo próprio usuário autenticado

- [ ] **Step 1: Escrever o teste que falha**

```go
// Layout inválido nunca trava a tela. Um item que aponta para um widget que não
// existe mais (versão anterior, widget removido do produto) é descartado item a
// item — o resto do painel do operador continua abrindo.
func TestUnknownWidgetIsDroppedItemByItemNotWholeLayout(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDashboardLayout("u1", []LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 6, H: 2},
		{Widget: "widget_que_nao_existe_mais", X: 6, Y: 0, W: 6, H: 2},
		{Widget: "wan_links", X: 0, Y: 2, W: 12, H: 3},
	}); err != nil {
		t.Fatalf("salvar: %v", err)
	}
	got, err := db.GetDashboardLayout("u1")
	if err != nil {
		t.Fatalf("ler: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 itens válidos, obtive %d: %+v", len(got), got)
	}
	for _, it := range got {
		if it.Widget == "widget_que_nao_existe_mais" {
			t.Error("o item desconhecido tinha que ter sido descartado")
		}
	}
}

// O layout é de quem o salvou. Um admin não vê nem sobrescreve o painel de outro.
func TestLayoutIsPerUser(t *testing.T) { /* salvar em u1, ler em u2, esperar o padrão */ }

// Widget fora da permissão do usuário não volta no layout nem aparece no catálogo.
func TestWidgetOutsidePermissionIsNotReturned(t *testing.T) { /* ... */ }
```

Escreva os dois últimos por extenso, no mesmo estilo.

- [ ] **Step 2:** Rodar, confirmar vermelho.
- [ ] **Step 3:** Migração transacional no molde de `migrateAddFirewallGroupScope` (`internal/storage/storage.go`).
- [ ] **Step 4:** Handlers. **Erro de banco é 500 sem SQL cru, nunca 400** — é dívida conhecida do projeto que não quero ampliar.
- [ ] **Step 5:** Provar por mutação que o descarte é item a item (faça-o rejeitar o layout inteiro e mostre o teste vermelho).
- [ ] **Step 6:** Commit.

---

### Task 4: A grade, e a colisão — o núcleo desta fase

**Files:**
- Create: `web/src/lib/grid.ts`, `web/src/components/WidgetGrid.tsx`
- Test: as asserções na forma decidida na Task 1, Step 1

**Interfaces:**
- Produces:
  - `function resolveCollisions(items: LayoutItem[], moved: LayoutItem): LayoutItem[]` — empurra em cascata
  - `function compactUp(items: LayoutItem[]): LayoutItem[]`
  - `function normalize(items: LayoutItem[], moved?: LayoutItem): LayoutItem[]` — as duas passadas, na ordem

**Isto é a parte difícil, e o mockup já provou que ela é real:** a primeira versão da grade não tinha resolução de colisão, e arrastar um widget por cima de outro **empilhava os dois no mesmo lugar**. É exatamente o que a biblioteca resolveria; o algoritmo é o mesmo que elas usam no núcleo.

- [ ] **Step 1: Escrever as asserções que falham**

```ts
// Arrastar por cima empurra em cascata: quem foi invadido desce para logo abaixo
// de quem invadiu, repetidamente, até ninguém mais colidir.
{
  const items = [
    { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
    { widget: 'b', x: 0, y: 2, w: 6, h: 2 },
    { widget: 'c', x: 0, y: 4, w: 6, h: 2 },
  ]
  const out = normalize(items, { widget: 'a', x: 0, y: 2, w: 6, h: 2 })
  assertNoOverlap(out)
}

// Remover no meio faz os de baixo subirem. Sem compactar, remover um widget
// deixa um buraco permanente no meio do painel.
{
  const out = normalize([
    { widget: 'a', x: 0, y: 0, w: 12, h: 2 },
    { widget: 'c', x: 0, y: 4, w: 12, h: 2 },
  ])
  assert(out.find(i => i.widget === 'c')!.y === 2, 'o de baixo tinha que subir')
}

// Prova por PROPRIEDADE, não só por caso: para uma sequência de operações
// aleatórias (mover, redimensionar, adicionar, remover), NUNCA existem dois
// itens ocupando a mesma célula. Sem isto, a grade passa nos casos que eu
// imaginei e falha no que o operador fizer.
{
  let items = layoutPadrao()
  for (let i = 0; i < 500; i++) {
    items = normalize(items, operacaoAleatoria(items, i))  // i como semente: sem Math.random
    assertNoOverlap(items)
    assert(items.every(it => it.x >= 0 && it.x + it.w <= 12), 'nada pode sair da grade')
  }
}

// Guarda contra laço infinito: uma configuração patológica não pode travar a aba
// do operador.
{
  const t0 = Date.now()
  normalize(configuracaoPatologica())
  assert(Date.now() - t0 < 1000, 'a normalização tem que terminar')
}
```

- [ ] **Step 2:** Rodar, confirmar vermelho.
- [ ] **Step 3:** Implementar. Grade de **12 colunas**, altura de linha fixa. As duas passadas (empurrar, depois compactar) rodam ao soltar o arrasto, ao redimensionar, ao adicionar e ao remover.
- [ ] **Step 4:** Rodar, verde.
- [ ] **Step 5: Provar por mutação** — desligue a compactação e mostre o teste do buraco vermelho; desligue a cascata e mostre a propriedade vermelha. Restaure.
- [ ] **Step 6:** Commit.

---

### Task 5: Os widgets e o catálogo

**Files:**
- Create: `web/src/components/widgets/` (um arquivo por widget), `web/src/lib/widgets.ts` (o catálogo)
- Modify: `web/src/pages/Dashboard.tsx`

**O catálogo, com a fonte e a permissão de cada um (spec §5):**

| Widget | Fonte | Permissão |
|---|---|---|
| Saúde do sistema | vigias já existentes | `monitoring.read` |
| Links WAN | `GET /api/links` | `links.read` |
| Tráfego das interfaces | `traffic-history` + `/api/system/status` | `monitoring.read` |
| Quem está consumindo | `GET /api/hosts/traffic` | `hosts.read` |
| Alertas abertos | `GET /api/alerts?unresolved=true` | `alerts.read` |
| CPU, memória, disco | `/api/system/status` + `metric_samples` | `monitoring.read` |
| Hosts na rede | `GET /api/hosts` | `hosts.read` |
| Primeiros passos | estado de onboarding | — |
| O que você quer fazer | estático | — |

- [ ] **Step 1:** Cada widget declara a permissão que exige. Widget fora da permissão **não aparece no catálogo, nem para adicionar**.
- [ ] **Step 2:** Modo de edição **explícito**: fora dele a tela é só leitura, sem alças e sem risco de mover algo sem querer.
- [ ] **Step 3:** "Restaurar padrão" sempre disponível, para quem se perdeu arrastando.
- [ ] **Step 4:** "Primeiros passos" **sai do painel quando os 6 passos terminam** — hoje ele ocupa os primeiros 60% da tela parado em 5 de 6 há meses, por causa do usuário padrão. Numa instalação nova ele aparece, como hoje. "O que você quer fazer?" vira widget como os outros, desligável.
- [ ] **Step 5:** Layout inicial para quem já passou do onboarding: saúde, WANs e alertas na primeira dobra; tráfego, consumo e recursos abaixo.
- [ ] **Step 6:** Em tela estreita, uma coluna na ordem `y` depois `x`.
- [ ] **Step 7:** `npx tsc --noEmit` e `npm run build` limpos. Commit.

---

### Task 6: Verificação visual e na VM

- [ ] **Playwright/Firefox contra backend real** (o HTML5 drag exige `dataTransfer.setData`, e só se prova no Firefox): arrastar, redimensionar, adicionar, remover, e **recarregar a página mantendo o layout**.
- [ ] Arrastar um widget por cima de outro e provar que **nenhum** fica empilhado.
- [ ] Remover um widget do meio e provar que os de baixo sobem.
- [ ] A 390px, tudo em uma coluna na ordem certa.
- [ ] Com um usuário sem `hosts.read`: os widgets de host não aparecem no catálogo, e um layout salvo que os contenha abre sem eles e **sem buraco**.
- [ ] "Restaurar padrão" volta ao layout de fábrica.
- [ ] A tela de tráfego com o dado real da máquina, nas quatro janelas.

Screenshots de cada um, com o caminho no relatório.

---

## Validação final (antes do deploy)

1. `go build ./... && go vet ./... && go test -count=1 ./...`; em `web/`: `npx tsc --noEmit && npm run build`.
2. Task 6 inteira, com saída e screenshots reais.
3. Numa cópia do banco de produção, rodar a migração do layout e conferir que o painel abre para um usuário sem layout salvo (tem que cair no padrão, não em branco).
4. Conferir que **nenhuma dependência nova** entrou: `git diff --stat web/package.json web/package-lock.json` tem que vir vazio.

## Self-Review

**Cobertura da spec:** §3 (tela de tráfego) → Tasks 1, 2; §4.1 (por usuário, com permissão) → Tasks 3, 5; §4.2 (grade livre) → Task 4; §4.3 (sem biblioteca, colisão e compactação) → Task 4 + restrição global 1; §4.4 (mobile) → Tasks 5, 6; §4.5 (onboarding some) → Task 5; §5 (catálogo) → Task 5; §6 (persistência, layout inválido, restaurar padrão) → Tasks 3, 5; §7 (testes) → Tasks 1, 3, 4, 6; §8 (fases) → a divisão A/B deste plano.

**Sem placeholders:** os testes das Tasks 1 e 4 estão por extenso — são o núcleo que erra silencioso. Na Task 3, o primeiro está completo e os dois seguintes nomeados com o que devem provar. Os passos de tela são requisitos verificáveis porque o desenho está fixado na spec e nos mockups aprovados.

**Consistência de tipos:** `Point`, `reduceToWidth`, `niceScale`, `LayoutItem`, `resolveCollisions`, `compactUp`, `normalize`, `GetDashboardLayout`/`SaveDashboardLayout` aparecem com a mesma assinatura nas Tasks 1, 2, 3, 4 e 5. Atenção deliberada: `LayoutItem` é a mesma forma no Go e no TS (`Widget/X/Y/W/H` ↔ `widget/x/y/w/h`), serializada em minúsculas.
