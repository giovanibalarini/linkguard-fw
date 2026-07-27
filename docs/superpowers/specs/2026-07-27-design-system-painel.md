# Sistema de design e reforma do Painel

**Data:** 2026-07-27
**Status:** desenho aprovado, pronto para plano de implementação

---

## 1. Problema

O mercado de firewalls/appliances de rede está carente de soluções que sejam ao mesmo tempo
poderosas e fáceis de entender visualmente. Ferramentas com gestão de regras complexa tendem a
afastar quem não é especialista; o LinkGuard quer o oposto — funcionalidade avançada sem exigir
que o admin decifre a tela pra usar.

Um protótipo navegável (HTML/CSS/JS standalone, artifact `fd8b4815`) foi construído como
referência de like-e-sinta para essa reforma: navegação agrupada por domínio, cards de status
("stat"), tags de severidade, painéis com sparkline, árvore de topologia, chassi de portas
físicas. É a linguagem visual alvo — mas ele é um mockup solto, não conectado a dado real, e
cobre 15 telas de uma vez.

Este documento cobre o primeiro pedaço executável desse esforço: **o sistema de componentes
visuais reutilizáveis, aplicado à casca de navegação (`Layout.tsx`) e ao Painel
(`Dashboard.tsx`)**. As demais 12+ páginas existentes (Links, Hosts, DHCP, DNS, Firewall, VPN,
Alertas, Monitoramento, Logs, Admin, Settings) e a feature nova de gerenciamento de interfaces
(spec separada, `2026-07-19-network-interface-management-design.md`) ficam para sub-projetos
seguintes, reusando o que este entrega.

## 2. Princípio norteador

Duas regras não negociáveis, vindas direto da conversa que originou este spec:

1. **Nunca dado fabricado.** Se um widget não tem fonte real de dado hoje, ele não aparece —
   não vira placeholder, estimativa ou número "de mentirinha". Um painel de firewall que inventa
   número é pior que um que admite o que ainda não sabe.
2. **Nada de regressão funcional.** O produto já tem alternância Simples/Avançado (esconde
   itens avançados do menu), idioma PT/EN, e blocos de onboarding guiado no Painel
   (`GettingStarted`, `Recipes`, `SystemHealth`/Vigia). Tudo isso continua existindo — só ganha a
   roupagem visual nova.

## 3. Escopo

### Dentro do v1

- Tokens de cor semânticos (`ok`/`warn`/`crit`/`idle`/`neutral`) no `tailwind.config`
- Componentes reutilizáveis em `web/src/components/ui/`: `Panel`, `Stat`/`StatStrip`, `Tag`,
  `Tabs`, `Sparkline` (SVG leve, sem lib nova)
- `Layout.tsx`: navegação reagrupada por domínio (Operação/Rede/Segurança/Sistema), preservando
  Simples/Avançado (granularidade por item, não por grupo) e PT/EN
- `Dashboard.tsx` (Painel): reconstruído com os componentes novos, mantendo
  `GettingStarted`/`Recipes`/`SystemHealth` restilizados, com conteúdo 100% orientado a dado real
  (ver §6)

### Fora do v1, explicitamente

| Item | Por quê |
|---|---|
| Tema claro | Produto é só escuro hoje (adequado a NOC/sala de rack); vira sub-projeto futuro se necessário |
| Re-skin das outras 12+ páginas | Sub-projeto(s) seguintes, reusando os componentes daqui |
| "Consumo por host" no Painel | Sem accounting de tráfego por host hoje (`internal/hosts/parser.go` documenta isso como adição futura via conntrack) |
| Stat "Deriva" (config mudou fora do painel) | Depende do sub-projeto de gerenciamento de interfaces (spec `2026-07-19`), zero código hoje |
| Stat "Portas lentas" (negociação ethtool) | Mesma dependência — diagnóstico físico é parte da spec de interfaces, não implementado ainda |
| Linha de "atualização disponível" na tabela de atenção | Endpoint existe (`/api/system/update/check`) mas é sob demanda, não status já calculado; YAGNI por ora |

## 4. Decisões e suas razões

| Decisão | Razão |
|---|---|
| Componentes React reutilizáveis sobre Tailwind, não CSS global do protótipo | Seguir o padrão já estabelecido no projeto (`MetricCard`, `StatusBadge` já são pequenos componentes reutilizáveis); evita dois sistemas de estilo convivendo no mesmo app |
| Tokens de cor semânticos no tema Tailwind | Hoje cada página escolhe a cor "à mão" (`emerald` vs `green` pro mesmo significado); tokens centralizam a decisão |
| `advanced` vira propriedade do item de nav, não do grupo | O protótipo agrupa por domínio (Rede junta Links WAN e Interfaces, por exemplo), mas Simples/Avançado precisa continuar escondendo itens avançados dentro de cada grupo, não só um grupo à parte |
| Sparkline via `/api/system/traffic-history` | Endpoint tsdb já existe e já é usado no gráfico de Interfaces — reuso direto, sem endpoint novo |
| Nenhum widget sem fonte real | Ver princípio §2.1 |

## 5. Arquitetura

```
web/src/components/ui/
  Panel.tsx       painel com cabeçalho + corpo, usado em WAN hero panels, listas, etc.
  Stat.tsx        card de estatística curto (rótulo, valor, subtítulo), variante ok/warn/crit
  Tag.tsx         badge de severidade/estado (ok/warn/crit/idle/neutral)
  Tabs.tsx        navegação em abas dentro de uma página
  Sparkline.tsx   SVG de série temporal curta, sem eixo, para uso inline em cards
```

`tailwind.config.*`: adiciona cores semânticas (`colors.ok`, `colors.warn`, `colors.crit`) que
mapeiam para a paleta já usada (`emerald`/`amber`/`red`), sem remover as classes Tailwind padrão
— são um alias semântico, não substituição.

## 6. Navegação (`Layout.tsx`)

Grupos por domínio, mapeados às rotas existentes (nenhuma rota muda):

- **Operação** — Painel (`/`), Alertas (`/alerts`), Monitoramento (`/monitoring`), Auditoria
  (`/logs`)
- **Rede** — Links WAN (`/links`), Interfaces (`/interfaces`, avançado), Rotas (`/routes`,
  avançado), Hosts (`/hosts`), DHCP (`/dhcp`), DNS (`/dns`)
- **Segurança** — Firewall (`/firewall`), VPN (`/vpn`)
- **Sistema** — Ajustes (`/settings`), Administração (`/admin`), Changelog (`/changelog`)

`NavItem` ganha `advanced?: boolean` (hoje é `NavGroup.advanced`). No modo Simples, itens
marcados `advanced` somem da lista do grupo em vez de o grupo inteiro colapsar — cada grupo
sempre aparece se tiver ao menos um item visível. Lógica de permissão (`itemVisible`) e i18n
(`t()`) não mudam.

## 7. Painel (`Dashboard.tsx`)

Do topo pro fim:

1. `GettingStarted`, `Recipes`, `SystemHealth` — mesma posição e comportamento, restilizados com
   `Panel`/`Tag` novos
2. **Tira de status** (`StatStrip` de 4 `Stat`): WAN ativas (`online/total` via `GET /api/links`)
   · Tráfego agora (soma das taxas atuais dos links WAN) · Hosts ativos (`GET /api/hosts`, vistos
   nos últimos 5 min) · Uptime (`sys.uptime_str`)
3. **Painéis WAN** — um `Panel` por link WAN (`GET /api/links`): nome, `Tag` de status
   (online/offline/degraded), taxa atual, latência/perda, `Sparkline` dos últimos 30 min via
   `GET /api/system/traffic-history?iface={link.interface}&range=30m`
4. **"Precisa de atenção"** — tabela com alertas ativos reais (`GET /api/alerts?unresolved=true`),
   severidade como `Tag`, tempo relativo, botão para `/alerts`

Taxa atual dos links reusa o mesmo padrão de cálculo já usado em `Interfaces.tsx` (buffer de
amostras recentes derivando bps), para não inventar um segundo jeito de calcular a mesma coisa.

## 8. Testes e verificação

- Componentes novos (`Panel`, `Stat`, `Tag`, `Tabs`, `Sparkline`): testes de render/props onde
  fizer sentido (poucos, são majoritariamente apresentacionais)
- Verificação visual obrigatória antes de considerar pronto: build local do frontend + dados
  reais/semeados + Playwright (screenshot e inspeção de layout), comparando com o protótipo —
  mesma técnica já usada nas últimas iterações de UI deste projeto
- QA manual: alternar Simples/Avançado e confirmar que os itens certos somem por grupo; alternar
  PT/EN e confirmar que nada quebra; Painel sem links WAN configurados e sem alertas (estado
  vazio) não deve quebrar nem mostrar dado fabricado

## 9. Fases de entrega

| Fase | Entrega |
|---|---|
| **1** | Tokens de cor + componentes base (`Panel`, `Stat`, `Tag`, `Tabs`, `Sparkline`) |
| **2** | `Layout.tsx` reagrupado, com `advanced` por item |
| **3** | `Dashboard.tsx` reconstruído com os componentes novos e conteúdo 100% real |

## 10. Riscos e armadilhas

- **Não** introduzir uma segunda forma de calcular taxa de link — reusar o padrão de
  `Interfaces.tsx`
- **Não** remover ou esconder `GettingStarted`/`Recipes`/`SystemHealth` — só restilizar
- **Não** deixar o Painel quebrar com zero links WAN ou zero alertas — são estados normais no dia
  zero
- **Não** vazar tokens de cor semânticos como substituição total do Tailwind padrão — é um alias
  por cima, o resto do app continua funcionando sem migração forçada
