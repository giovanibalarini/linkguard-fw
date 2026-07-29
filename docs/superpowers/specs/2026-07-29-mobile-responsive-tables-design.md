# Responsividade mobile das telas de listagem — Design

## Problema

O painel do LinkGuard FW está "ruim no mobile" de forma geral (feedback do usuário). Uma
investigação do frontend (`web/src/`) mostrou que o problema não é uniforme:

- O shell principal (`web/src/components/Layout.tsx`, sidebar + menu hamburguer) e os gráficos
  (Recharts, via `ResponsiveContainer width="100%"`) já são responsivos e não precisam de
  mudança.
- O `web/index.html` já tem a meta tag de viewport correta.
- O problema real está concentrado nas **páginas de listagem**: cada uma renderiza uma
  `<table>` HTML com 5-8 colunas dentro de um `<div className="overflow-x-auto">`. Isso evita
  que a página quebre, mas empurra o problema para rolagem horizontal de uma tabela densa,
  com texto pequeno e ícones de ação minúsculos — os três sintomas relatados pelo usuário
  (elementos cortados/estourando, botões difíceis de tocar, layout desalinhado).
- `web/src/pages/Hosts.tsx` já resolve isso corretamente: abaixo de `sm:` (640px, breakpoint
  padrão do Tailwind, sem customização em `tailwind.config.js`), cada linha vira um card
  empilhado (`<div className="sm:hidden space-y-2">`); a partir de `sm:`, a tabela tradicional
  aparece (`<table className="hidden sm:table ...">`). Esse padrão nunca foi replicado nas
  outras telas com tabela.
- Um segundo sintoma isolado: a linha de "regra personalizada" em `web/src/pages/Firewall.tsx`
  usa `<div className="flex items-center gap-3">` sem `flex-wrap`, empacotando setas de
  reordenar, badge de ação, texto da regra e botões de editar/excluir numa única linha rígida.
- Um terceiro sintoma sistêmico: os ícones de ação (`<Pencil>`/`<Trash2>` do `lucide-react`,
  tipicamente `w-4 h-4` sem padding) se repetem em praticamente toda tabela do app, sem área de
  toque ampliada — abaixo do alvo de toque recomendado (~44px).

## Escopo

**Telas que ganham o padrão cards-no-mobile/tabela-no-desktop** (todas as que hoje têm
`<table>` sem esse tratamento):

1. `web/src/pages/Links.tsx` — tabela de Links WAN (Nome, Interface, IP/Gateway, Peso,
   Latência, Perda, Status, Ações)
2. `web/src/pages/Routes.tsx` — tabela de rotas (Destino, Gateway, Interface, Protocolo,
   Métrica, Escopo, Ações)
3. `web/src/pages/Interfaces.tsx` — três tabelas na mesma página (Interfaces, e outras duas
   seções da tela)
4. `web/src/pages/Monitoring.tsx` — tabela de tráfego por interface (Interface, RX/TX total,
   RX/TX pacotes, Erros)
5. `web/src/pages/Firewall.tsx` — tabela de backups de regras (a lista de "regras
   personalizadas" em si não é uma `<table>`, ver correção separada abaixo)
6. `web/src/pages/Admin.tsx` — tabela de usuários/papéis
7. `web/src/pages/Dhcp.tsx` — tabela de reservas DHCP
8. `web/src/pages/Logs.tsx` — tabela de log de auditoria
9. `web/src/components/DnsQueryLog.tsx` — tabela de consultas DNS (usado dentro da tela de DNS)

`web/src/pages/Hosts.tsx` já está correto — usado como referência, não é modificado (a menos
que a implementação encontre uma melhoria pontual a fazer nele também, o que **não** é
esperado).

**Fora de escopo:** `web/src/components/Layout.tsx` (shell), gráficos Recharts,
`web/src/components/ui/Tabs.tsx` e `web/src/components/HttpsInfo.tsx` (o
`overflow-x-auto` encontrado neles não envolve uma tabela de dados no mesmo sentido — conferir
durante a implementação; se não houver problema real de mobile ali, não mexer).

## Abordagem

### Padrão de tabela responsiva (replicado, não abstraído)

Cada uma das 9 telas acima passa a renderizar dois blocos a partir dos mesmos dados, seguindo
o padrão já existente em `Hosts.tsx`:

- Abaixo de `sm:` (640px): `<div className="sm:hidden space-y-2">`, um card por linha,
  layout vertical com rótulo+valor para cada coluna que hoje existe na tabela, e os botões de
  ação (agora usando `IconButton`, ver abaixo) numa faixa própria dentro do card, não
  espremidos ao lado do texto.
- A partir de `sm:`: `<div className="hidden sm:block overflow-x-auto">` com a
  `<table className="hidden sm:table ...">` atual, sem mudança de comportamento/colunas.

Não haverá um componente genérico `<ResponsiveTable>` cobrindo as 9 telas: as colunas e o
conteúdo variam demais entre elas (badges de status, setas de reordenar, checkboxes de papel,
sparklines) para uma abstração única não virar mais complicada de usar do que replicar o
padrão two-block em cada arquivo. Isso segue a decisão já tomada em `Hosts.tsx`.

### Componente compartilhado: `IconButton`

Novo componente `web/src/components/ui/IconButton.tsx`: wrapper em volta de um ícone
`lucide-react` de ação (editar, excluir, etc.), com `min-w-[44px] min-h-[44px]` (ou
padding equivalente) e área de toque centralizada, mantendo o ícone visualmente do mesmo
tamanho de hoje (a área de toque cresce, o ícone não). Aceita `icon`, `onClick`, `label`
(para `aria-label`, hoje ausente nos botões de ícone crus), `variant` (`default` | `danger`,
para diferenciar visualmente editar de excluir, como já é feito com classes ad-hoc hoje).
Substitui os botões de ícone cru em todas as 9 telas do escopo, tanto nos cards mobile quanto
nas tabelas desktop, e também em `Hosts.tsx` (para consistência, já que o problema de área de
toque pequena existe lá também mesmo com o layout de card já responsivo).

### Correção pontual: linha de regra personalizada do Firewall

Em `web/src/pages/Firewall.tsx`, a linha de regra (`flex items-center gap-3`, sem `flex-wrap`)
ganha `flex-wrap` e, abaixo de `sm:`, reorganiza para duas linhas: conteúdo da regra
(setas + badge + descrição) numa linha, botões de ação (via `IconButton`) numa segunda linha
alinhada à direita. Acima de `sm:`, mantém o layout de linha única atual.

## Testes

Sem framework de teste automatizado no frontend (padrão já estabelecido no projeto —
verificação é via `npm run build` limpo). Verificação visual manual via Playwright local:
screenshot de cada uma das 9 telas em largura de celular (~390px, ex: viewport do iPhone 12)
antes e depois da mudança, comparando que:

- Nenhum conteúdo é cortado ou exige rolagem horizontal.
- Botões de ação têm espaço suficiente para toque sem ficar colados a elementos vizinhos.
- Nada aparece sobreposto ou desalinhado.

Também verificar em largura de desktop (ex: 1280px) que as tabelas tradicionais continuam
idênticas ao comportamento atual (nenhuma regressão visual acima de `sm:`).

## Fora de escopo (explicitamente)

- Não mexe no shell (`Layout.tsx`), nos gráficos, nem em telas sem tabela.
- Não introduz um framework/biblioteca de tabela nova (ex: react-table) — mantém `<table>` HTML
  cru, como já é o padrão do projeto.
- Não muda dados/colunas exibidos, comportamento de ordenação/filtro, nem endpoints — é uma
  mudança de apresentação (layout responsivo), não de funcionalidade.
- Rollout é em pacote único (decisão explícita do usuário), não incremental página-por-página
  como a reforma de UI anterior.
