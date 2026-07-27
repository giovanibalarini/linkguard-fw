# Sistema de design + reforma do Painel — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trazer a linguagem visual do protótipo navegável (`Panel`/`Stat`/`Tag`/`Sparkline`) para o LinkGuard como componentes reutilizáveis, aplicados primeiro à navegação (`Layout.tsx`) e ao Painel (`Dashboard.tsx`), com todo widget novo alimentado por dado real.

**Architecture:** Componentes de apresentação novos em `web/src/components/ui/`, construídos sobre as classes Tailwind já existentes (`.card` etc.) e cores semânticas adicionadas ao tema. `Layout.tsx` reagrupa a navegação por domínio sem mudar rotas. `Dashboard.tsx` é reconstruído usando os componentes novos; cada widget é ligado a um endpoint real já existente — nenhum endpoint novo é criado neste plano.

**Tech Stack:** React 18 + TypeScript + Vite + Tailwind CSS + Recharts (já em uso, sem libs novas).

## Global Constraints

- **Nenhum widget com dado fabricado.** Se a fonte real não existir ou vier vazia, o widget some — não mostra zero nem placeholder. (spec §2)
- **Sem regressão funcional.** Simples/Avançado, PT/EN, e os blocos `GettingStarted`/`Recipes`/`SystemHealth` continuam funcionando exatamente como hoje — só ganham a roupagem visual nova. (spec §2)
- **Tema só escuro** neste plano — nenhuma variável de tema claro é introduzida. (spec §3)
- **Nenhuma rota muda.** O reagrupamento de `Layout.tsx` é só visual/organizacional. (spec §6)
- **Sem framework de teste novo no frontend.** Este projeto não tem `vitest`/`jest`/`@testing-library` hoje (confirmado: nenhum `package.json` script de teste, nenhum arquivo `*.test.tsx` existe). Introduzir um framework de teste unitário só para este sub-projeto seria escopo desproporcional ao pedido. A verificação segue a prática já estabelecida neste projeto nas últimas iterações de UI: `npm run build` (type-check via `tsc -b` + `vite build`) a cada tarefa, e uma passada final de verificação visual com Playwright local (Tarefa 10) antes de considerar pronto.
- **Duas reduções de escopo em relação ao texto literal do spec**, decididas ao escrever este plano e sinalizadas aqui em vez de silenciosamente:
  - **`Tabs` não é construído neste plano.** O spec lista `Tabs` entre os componentes base, mas nem `Layout.tsx` nem o novo `Dashboard.tsx` têm uma única superfície com abas — o primeiro consumidor real é a tela de Interfaces (spec `2026-07-19-network-interface-management-design.md`, ainda não planejada). Construir um componente sem consumidor real, sem uso para provar a API certa, viola YAGNI. Fica para o sub-projeto que primeiro precisar dele.
  - **`useInterfaceRates` vira uma função pura (`web/src/lib/interfaceRates.ts`), não um hook.** `Interfaces.tsx` tem estado (pausa, buffer de 300 amostras, flag de primeiro carregamento) que um hook genérico teria que replicar ou ele não serviria para o próprio `Interfaces.tsx`. Extrair só a matemática pura (delta de bytes → bytes/s) e deixar cada página rodar seu próprio laço de polling é mais simples, mais seguro (não mexe na máquina de estado de `Interfaces.tsx`, um arquivo já debugado duas vezes nesta semana) e ainda cumpre "não duplicar o cálculo".
- **Grid de métricas do sistema (Uptime+load, CPU, Memória, Disco) continua existindo.** Nem o protótipo nem o spec mencionam isso explicitamente, mas removê-lo seria regressão funcional (dado real, já em produção, hoje visível no Painel). Fica abaixo dos painéis WAN, usando os componentes `MetricCard`/`ProgressCard` já existentes (não precisam de `Stat` — já mostram barra de progresso, o que `Stat` não faz).
- **A tabela "Links WAN" e a lista "Alertas Recentes" que existem hoje no Dashboard são substituídas**, não somem: os Painéis WAN cobrem o que a tabela mostrava (nome, status, latência, perda) e acrescentam sparkline; "Precisa de atenção" é a mesma lista de alertas com apresentação nova.

---

### Task 1: Tokens de cor semânticos + componente `Tag`

**Files:**
- Modify: `web/tailwind.config.js`
- Create: `web/src/components/ui/Tag.tsx`
- Modify: `web/src/components/StatusBadge.tsx`

**Interfaces:**
- Produces: `Tag` component — `export type TagVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral'`; `export default function Tag({ variant, children, dot, className }: { variant: TagVariant; children: ReactNode; dot?: boolean; className?: string })`

- [ ] **Step 1: Adicionar cores semânticas ao tema Tailwind**

Em `web/tailwind.config.js`, dentro de `theme.extend.colors`, adicione (mantendo o bloco `primary` já existente):

```js
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a',
        },
        ok: { DEFAULT: '#34d399', bg: 'rgba(52, 211, 153, 0.1)', border: 'rgba(52, 211, 153, 0.2)' },
        warn: { DEFAULT: '#fbbf24', bg: 'rgba(251, 191, 36, 0.1)', border: 'rgba(251, 191, 36, 0.2)' },
        crit: { DEFAULT: '#f87171', bg: 'rgba(248, 113, 113, 0.1)', border: 'rgba(248, 113, 113, 0.2)' },
      },
```

Essas cores são um alias por cima do Tailwind padrão (`emerald`/`amber`/`red` continuam funcionando em qualquer outro arquivo do app).

- [ ] **Step 2: Criar o componente `Tag`**

Crie `web/src/components/ui/Tag.tsx`:

```tsx
import type { ReactNode } from 'react';

export type TagVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral';

interface TagProps {
  variant: TagVariant;
  children: ReactNode;
  dot?: boolean;
  className?: string;
}

const variantStyles: Record<TagVariant, string> = {
  ok: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  warn: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  crit: 'bg-red-500/10 text-red-400 border-red-500/20',
  idle: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  neutral: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const dotStyles: Record<TagVariant, string> = {
  ok: 'bg-emerald-400',
  warn: 'bg-amber-400',
  crit: 'bg-red-400',
  idle: 'bg-gray-400',
  neutral: 'bg-blue-400',
};

export default function Tag({ variant, children, dot = false, className = '' }: TagProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${variantStyles[variant]} ${className}`}
    >
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotStyles[variant]} animate-pulse`} />}
      {children}
    </span>
  );
}
```

- [ ] **Step 3: Verificar visualmente**

Rode `npm run dev` (dentro de `web/`) e adicione temporariamente `<Tag variant="ok" dot>Teste</Tag>` em qualquer página para conferir no navegador que renderiza um badge verde com ponto pulsante. Remova a linha de teste antes de prosseguir.

- [ ] **Step 4: Refatorar `StatusBadge`/`AlertBadge` para usar `Tag`**

`StatusBadge` e `AlertBadge` já são, na prática, badges de severidade com cores manuais — viram wrappers finos sobre `Tag`, sem mudar a API que os outros arquivos já chamam (`<StatusBadge status={...} />`, `<AlertBadge severity={...} />` continuam funcionando sem alteração nos chamadores).

Substitua o conteúdo de `web/src/components/StatusBadge.tsx` por:

```tsx
import Tag, { type TagVariant } from './ui/Tag';
import type { LinkStatus, AlertSeverity } from '../types';

interface StatusBadgeProps {
  status: LinkStatus | string;
  className?: string;
}

const statusConfig: Record<string, { label: string; variant: TagVariant }> = {
  online: { label: 'Online', variant: 'ok' },
  offline: { label: 'Offline', variant: 'crit' },
  degraded: { label: 'Degradado', variant: 'warn' },
  unknown: { label: 'Desconhecido', variant: 'idle' },
};

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const cfg = statusConfig[status] ?? statusConfig.unknown;
  return (
    <Tag variant={cfg.variant} dot className={className}>
      {cfg.label}
    </Tag>
  );
}

interface AlertBadgeProps {
  severity: AlertSeverity | string;
}

const severityConfig: Record<string, { label: string; variant: TagVariant }> = {
  info: { label: 'Info', variant: 'neutral' },
  warning: { label: 'Aviso', variant: 'warn' },
  critical: { label: 'Crítico', variant: 'crit' },
};

export function AlertBadge({ severity }: AlertBadgeProps) {
  const cfg = severityConfig[severity] ?? severityConfig.info;
  return <Tag variant={cfg.variant}>{cfg.label}</Tag>;
}
```

- [ ] **Step 5: Checar que nada quebrou**

Rode `npm run build` (dentro de `web/`). Deve terminar sem erro de tipo. Abra as páginas que usam `StatusBadge`/`AlertBadge` hoje (Painel, Links WAN, Alertas) no `npm run dev` e confirme visualmente que os badges continuam com a mesma cor/aparência de antes (o ponto pulsante de `StatusBadge` deve continuar aparecendo; `AlertBadge` continua sem ponto).

- [ ] **Step 6: Commit**

```bash
git add web/tailwind.config.js web/src/components/ui/Tag.tsx web/src/components/StatusBadge.tsx
git commit -m "feat(web): componente Tag + tokens de cor semânticos, StatusBadge/AlertBadge migrados"
```

---

### Task 2: Componente `Panel`

**Files:**
- Create: `web/src/components/ui/Panel.tsx`

**Interfaces:**
- Consumes: classe `.card` já definida em `web/src/index.css`
- Produces: `export default function Panel({ title, action, children, className }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string })`

- [ ] **Step 1: Criar o componente**

Crie `web/src/components/ui/Panel.tsx`:

```tsx
import type { ReactNode } from 'react';

interface PanelProps {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

export default function Panel({ title, action, children, className = '' }: PanelProps) {
  return (
    <div className={`card ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-4">
          {title &&
            (typeof title === 'string' ? (
              <h2 className="text-white font-semibold">{title}</h2>
            ) : (
              title
            ))}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}
```

- [ ] **Step 2: Verificar visualmente**

No `npm run dev`, adicione temporariamente em qualquer página:

```tsx
<Panel title="Teste" action={<span className="text-gray-500 text-xs">ação</span>}>
  <p className="text-gray-400 text-sm">Conteúdo do painel.</p>
</Panel>
```

Confirme que renderiza como os `card` com cabeçalho já usados em `SystemHealth.tsx`/`Recipes.tsx` hoje. Remova a linha de teste.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Panel.tsx
git commit -m "feat(web): componente Panel"
```

---

### Task 3: Componente `Stat`

**Files:**
- Create: `web/src/components/ui/Stat.tsx`

**Interfaces:**
- Produces: `export type StatVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral'`; `export default function Stat({ label, value, sub, variant }: { label: string; value: string | number; sub?: string; variant?: StatVariant })`

- [ ] **Step 1: Criar o componente**

Crie `web/src/components/ui/Stat.tsx`:

```tsx
export type StatVariant = 'ok' | 'warn' | 'crit' | 'idle' | 'neutral';

interface StatProps {
  label: string;
  value: string | number;
  sub?: string;
  variant?: StatVariant;
}

const valueColor: Record<StatVariant, string> = {
  ok: 'text-emerald-400',
  warn: 'text-amber-400',
  crit: 'text-red-400',
  idle: 'text-gray-400',
  neutral: 'text-white',
};

export default function Stat({ label, value, sub, variant = 'neutral' }: StatProps) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-gray-400 text-xs font-medium uppercase tracking-wide">{label}</span>
      <span className={`text-2xl font-bold ${valueColor[variant]}`}>{value}</span>
      {sub && <span className="text-gray-500 text-xs">{sub}</span>}
    </div>
  );
}
```

- [ ] **Step 2: Verificar visualmente**

No `npm run dev`, teste temporariamente:

```tsx
<div className="grid grid-cols-4 gap-4">
  <Stat label="WAN ativas" value="2/2" sub="balanceando 60/40" variant="ok" />
  <Stat label="Portas" value="1 lenta" variant="warn" />
</div>
```

Confirme visualmente e remova a linha de teste.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Stat.tsx
git commit -m "feat(web): componente Stat"
```

---

### Task 4: Componente `Sparkline`

**Files:**
- Create: `web/src/components/ui/Sparkline.tsx`

**Interfaces:**
- Consumes: `recharts` (`LineChart`, `Line`, `ResponsiveContainer`) — já é dependência do projeto (`web/package.json`), mesmo padrão já usado em `web/src/pages/Interfaces.tsx` para o sparkline dos cards colapsados
- Produces: `export interface SparklinePoint { ts: number; rx: number; tx: number }`; `export default function Sparkline({ data, height }: { data: SparklinePoint[]; height?: number })`

- [ ] **Step 1: Criar o componente**

Crie `web/src/components/ui/Sparkline.tsx`:

```tsx
import { LineChart, Line, ResponsiveContainer } from 'recharts';

export interface SparklinePoint {
  ts: number;
  rx: number;
  tx: number;
}

interface SparklineProps {
  data: SparklinePoint[];
  height?: number;
}

export default function Sparkline({ data, height = 32 }: SparklineProps) {
  if (data.length < 2) {
    return (
      <div style={{ height }} className="flex items-center text-gray-600 text-xs">
        sem dados
      </div>
    );
  }
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
          <Line type="linear" dataKey="rx" stroke="#22d3ee" strokeWidth={1.5} dot={false} isAnimationActive={false} />
          <Line type="linear" dataKey="tx" stroke="#34d399" strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 2: Verificar visualmente**

No `npm run dev`, teste temporariamente com dados sintéticos:

```tsx
<div className="w-48">
  <Sparkline
    data={Array.from({ length: 20 }, (_, i) => ({ ts: i, rx: Math.random() * 100, tx: Math.random() * 50 }))}
  />
</div>
```

Confirme que desenha duas linhas (ciano/verde) sem eixos. Remova a linha de teste.

- [ ] **Step 3: Commit**

```bash
git add web/src/components/ui/Sparkline.tsx
git commit -m "feat(web): componente Sparkline"
```

---

### Task 5: Extrair cálculo de taxa para `web/src/lib/interfaceRates.ts`

**Files:**
- Create: `web/src/lib/interfaceRates.ts`
- Modify: `web/src/pages/Interfaces.tsx:99-138` (bloco de cálculo de taxa dentro de `fetchData`)

**Interfaces:**
- Produces: `export interface RateCounter { ts: number; rx: number; tx: number }`; `export interface InterfaceRate { rx: number; tx: number }`; `export function deriveRate(prev: RateCounter | undefined, current: { rx_bytes: number; tx_bytes: number }, now: number): InterfaceRate | null`
- Consumido por: `Interfaces.tsx` (Task 5) e `Dashboard.tsx` (Task 7)

- [ ] **Step 1: Criar o helper puro**

Crie `web/src/lib/interfaceRates.ts`:

```ts
export interface RateCounter {
  ts: number;
  rx: number;
  tx: number;
}

export interface InterfaceRate {
  rx: number;
  tx: number;
}

// Bytes/segundo desde a amostra de contador anterior, ou null se ainda não
// há amostra prévia ou o relógio não avançou. Função pura — mesma fórmula
// usada em Interfaces.tsx (detalhe por interface) e Dashboard.tsx (resumo
// WAN), para "taxa atual" significar a mesma coisa no app inteiro.
export function deriveRate(
  prev: RateCounter | undefined,
  current: { rx_bytes: number; tx_bytes: number },
  now: number,
): InterfaceRate | null {
  if (!prev) return null;
  const dt = (now - prev.ts) / 1000;
  if (dt <= 0) return null;
  const rxDelta = Math.max(0, current.rx_bytes - prev.rx);
  const txDelta = Math.max(0, current.tx_bytes - prev.tx);
  return { rx: rxDelta / dt, tx: txDelta / dt };
}
```

- [ ] **Step 2: Substituir o cálculo inline em `Interfaces.tsx` pelo helper**

Em `web/src/pages/Interfaces.tsx`, adicione o import no topo (junto aos outros imports):

```ts
import { deriveRate } from '../lib/interfaceRates';
```

Dentro de `fetchData`, o laço `for (const iface of res.data.interfaces ?? []) { ... }` (linhas ~109-123) calcula a taxa manualmente. Substitua o corpo do `if (prev)` por uma chamada ao helper, mantendo o resto do laço (inclusive `pushRateSample` e a atualização de `prevCountersRef`) idêntico:

```ts
      for (const iface of res.data.interfaces ?? []) {
        const prev = prevCountersRef[iface.name];
        const rate = deriveRate(prev, iface, now);
        if (rate) {
          nextRates[iface.name] = rate;
          pushRateSample(iface.name, now, rate.rx, rate.tx);
        }
        prevCountersRef[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
      }
```

Isso é uma substituição mecânica — mesma matemática, mesmo formato de retorno, mesmo laço ao redor. `pausedRef`, `firstLoadRef`, `secondHistoryRef` e o resto do arquivo não mudam.

- [ ] **Step 3: Verificar que Interfaces.tsx continua funcionando**

Rode `npm run build`. Depois `npm run dev`, abra a página Interfaces com o backend rodando (ou `client` apontando para um backend local), e confirme visualmente que as taxas RX/TX de cada interface continuam atualizando a cada poll, exatamente como antes da mudança.

- [ ] **Step 4: Commit**

```bash
git add web/src/lib/interfaceRates.ts web/src/pages/Interfaces.tsx
git commit -m "refactor(web): extrai cálculo de taxa de interface para helper puro reutilizável"
```

---

### Task 6: `Layout.tsx` — navegação reagrupada por domínio

**Files:**
- Modify: `web/src/components/Layout.tsx`
- Modify: `web/src/i18n/index.tsx`

**Interfaces:**
- Consumes: `useUIMode()` (`isSimple`, `mode`, `setMode`) de `web/src/context/UIModeContext.tsx` — API não muda
- Produces: `NavItem` ganha `advanced?: boolean` (antes era `NavGroup.advanced`)

- [ ] **Step 1: Adicionar as novas chaves de i18n**

Em `web/src/i18n/index.tsx`, no dicionário `pt` (perto das chaves `nav.*`/`group.*` existentes, linhas ~18-33), adicione:

```ts
  'group.operacao': 'Operação',
  'group.rede': 'Rede',
  'group.seguranca': 'Segurança',
```

E troque o rótulo de `nav.dashboard` de `'Dashboard'` para `'Painel'` (mesma linha, só o valor):

```ts
  'nav.dashboard': 'Painel',
```

No dicionário `en` (linhas ~58-74), adicione as mesmas três chaves traduzidas:

```ts
  'group.operacao': 'Operations',
  'group.rede': 'Network',
  'group.seguranca': 'Security',
```

`nav.dashboard` em inglês continua `'Dashboard'` (não precisa mudar). As chaves `dashboard.title`/`dashboard.subtitle` (usadas dentro da página, não no menu) também não mudam nesta tarefa — ficam para a Tarefa 7.

A chave `group.advanced` fica no dicionário sem uso (nenhum código mais referencia ela após esta tarefa) — deixe-a por ora; remover chaves não usadas de um dicionário de strings é limpeza de baixo risco que não precisa bloquear este plano.

- [ ] **Step 2: Reagrupar `navGroups` por domínio, com `advanced` por item**

Em `web/src/components/Layout.tsx`, substitua a interface `NavItem`, a interface `NavGroup` e a constante `navGroups` (linhas 12-62) por:

```ts
interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  perm: string[];
  end?: boolean;
  advanced?: boolean;
}

interface NavGroup {
  id: string;
  label: string | null;
  items: NavItem[];
}

// Grupos por domínio (Operação/Rede/Segurança/Sistema). `advanced` marca
// itens que somem no modo Simples — antes era uma propriedade do grupo
// inteiro; agora é por item, porque um mesmo grupo de domínio pode ter
// itens do dia a dia (Links WAN) ao lado de itens avançados (Interfaces).
// `perm` lista as permissões que revelam o item; aparece se o usuário tiver
// pelo menos uma. `label` guarda uma chave de i18n resolvida com t().
const navGroups: NavGroup[] = [
  {
    id: 'operacao', label: 'group.operacao',
    items: [
      { to: '/', label: 'nav.dashboard', icon: LayoutDashboard, end: true, perm: ['dashboard.read'] },
      { to: '/alerts', label: 'nav.alerts', icon: Bell, perm: ['monitoring.read'] },
      { to: '/monitoring', label: 'nav.monitoring', icon: Activity, perm: ['monitoring.read'], advanced: true },
      { to: '/logs', label: 'nav.logs', icon: FileText, perm: ['logs.read'], advanced: true },
    ],
  },
  {
    id: 'rede', label: 'group.rede',
    items: [
      { to: '/links', label: 'nav.links', icon: Network, perm: ['links.read'] },
      { to: '/interfaces', label: 'nav.interfaces', icon: Cable, perm: ['system.read'], advanced: true },
      { to: '/routes', label: 'nav.routes', icon: Route, perm: ['routes.read'], advanced: true },
      { to: '/hosts', label: 'nav.hosts', icon: MonitorSmartphone, perm: ['hosts.read'] },
      { to: '/dhcp', label: 'nav.dhcp', icon: Server, perm: ['dhcp.read'] },
      { to: '/dns', label: 'nav.dns', icon: Globe, perm: ['dns.read'] },
    ],
  },
  {
    id: 'seguranca', label: 'group.seguranca',
    items: [
      { to: '/firewall', label: 'nav.firewall', icon: Shield, perm: ['firewall.read'] },
      { to: '/vpn', label: 'nav.vpn', icon: Lock, perm: ['vpn.read'] },
    ],
  },
  {
    id: 'system', label: 'group.system',
    items: [
      { to: '/settings', label: 'nav.settings', icon: Settings, perm: ['system.read'] },
      { to: '/admin', label: 'nav.admin', icon: Users, perm: ['users.manage', 'roles.manage'] },
      { to: '/changelog', label: 'nav.changelog', icon: Sparkles, perm: ['dashboard.read'] },
    ],
  },
];

const allItems = navGroups.flatMap((g) => g.items);
```

`ChevronDown` deixa de ser usado no cabeçalho de grupo colapsável (isso muda no próximo passo) — não remova o import ainda, ele é usado de outro jeito a seguir.

- [ ] **Step 3: Atualizar a renderização — filtro por `advanced` dentro do grupo, sem grupo colapsável**

Ainda em `Layout.tsx`, dentro do componente `Layout`, a lógica de `onAdvancedRoute`/`advExpanded` (linhas ~92-97) referenciava um único grupo `advanced`. Substitua por um cálculo por item: um item avançado só aparece no modo Simples se a rota atual estiver dentro dele (para não esconder a página que o usuário já está vendo). Troque:

```ts
  // The advanced group expands automatically in advanced mode, when the active
  // route lives inside it, or when the user clicks to expand it.
  const onAdvancedRoute = navGroups
    .find((g) => g.advanced)!
    .items.some((i) => location.pathname.startsWith(i.to) && i.to !== '/');
  const advExpanded = !isSimple || advOpen || onAdvancedRoute;
```

por:

```ts
  const itemAdvancedVisible = (item: NavItem) => {
    if (!item.advanced) return true;
    if (!isSimple) return true;
    return location.pathname.startsWith(item.to) && item.to !== '/';
  };
```

Remova a variável de estado `advOpen`/`setAdvOpen` (linha ~74, `const [advOpen, setAdvOpen] = useState(false);`) — não é mais usada, já que não há mais um grupo inteiro para expandir/colapsar.

Agora troque o bloco de renderização de `navGroups.map` (linhas ~157-187), que tinha um caso especial para `group.advanced`, por uma versão única que filtra itens por permissão **e** por `itemAdvancedVisible`:

```tsx
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          {navGroups.map((group) => {
            const items = group.items.filter(itemVisible).filter(itemAdvancedVisible);
            if (items.length === 0) return null;

            return (
              <div key={group.id} className={group.label ? 'mt-4' : ''}>
                {group.label && (
                  <p className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-gray-600">{t(group.label)}</p>
                )}
                <ul className="space-y-1">{items.map(renderItem)}</ul>
              </div>
            );
          })}
        </nav>
```

Remova agora o import de `ChevronDown` de `lucide-react` (não é mais usado em lugar nenhum do arquivo) — confira com `grep -n ChevronDown web/src/components/Layout.tsx` que só resta a linha do import antes de removê-la.

- [ ] **Step 4: Checar tipos e comportamento**

Rode `npm run build`. Depois `npm run dev`: confirme que a barra lateral mostra os quatro grupos (Operação/Rede/Segurança/Sistema); alterne Simples/Avançado e confirme que Monitoramento/Logs/Interfaces/Rotas somem no modo Simples (mas continuam visíveis se você estiver na própria página deles); alterne PT/EN e confirme que os rótulos de grupo traduzem.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/Layout.tsx web/src/i18n/index.tsx
git commit -m "feat(web): navegação reagrupada por domínio (Operação/Rede/Segurança/Sistema)"
```

---

### Task 7: `Dashboard.tsx` — tira de status + painéis WAN

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`

**Interfaces:**
- Consumes: `Panel`, `Stat`, `Tag` (Tasks 1-2), `Sparkline`/`SparklinePoint` (Task 4), `deriveRate`/`RateCounter` (Task 5), tipos `WanLink`, `SystemMetrics`, `NetHost`, `TrafficHistoryResponse` de `web/src/types`
- Produces: nada consumido por outra tarefa deste plano — é o topo da árvore

- [ ] **Step 1: Substituir a tira de métricas de sistema + tabela de links por status strip + painéis WAN**

Este passo reescreve o corpo de `Dashboard.tsx` do início até a seção "WAN Links" (linhas 1-213 do arquivo atual), mantendo intactos `GettingStarted`, `Recipes`, `SystemHealth` (import e uso) e o grid de métricas de sistema (CPU/Memória/Disco/Uptime com `MetricCard`/`ProgressCard`), que continuam existindo — só mudam de posição, para abaixo dos painéis WAN.

Substitua todo o conteúdo de `web/src/pages/Dashboard.tsx` por:

```tsx
import { useEffect, useState, useCallback, useRef } from 'react';
import { Cpu, MemoryStick, HardDrive, Clock, AlertTriangle } from 'lucide-react';
import MetricCard, { ProgressCard } from '../components/MetricCard';
import GettingStarted from '../components/GettingStarted';
import Recipes from '../components/Recipes';
import SystemHealth from '../components/SystemHealth';
import Panel from '../components/ui/Panel';
import Stat from '../components/ui/Stat';
import Tag, { type TagVariant } from '../components/ui/Tag';
import Sparkline, { type SparklinePoint } from '../components/ui/Sparkline';
import { deriveRate, type RateCounter } from '../lib/interfaceRates';
import client from '../api/client';
import { useI18n } from '../i18n';
import type { SystemMetrics, WanLink, Alert, NetHost, TrafficHistoryResponse } from '../types';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

const statusVariant: Record<string, TagVariant> = {
  online: 'ok',
  offline: 'crit',
  degraded: 'warn',
  unknown: 'idle',
};

const statusLabel: Record<string, string> = {
  online: 'online',
  offline: 'offline',
  degraded: 'degradado',
  unknown: 'desconhecido',
};

export default function Dashboard() {
  const { t } = useI18n();
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [wanLinks, setWanLinks] = useState<WanLink[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hosts, setHosts] = useState<NetHost[]>([]);
  const [rates, setRates] = useState<Record<string, { rx: number; tx: number }>>({});
  const [sparklines, setSparklines] = useState<Record<string, SparklinePoint[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const prevCountersRef = useRef<Record<string, RateCounter>>({});

  const fetchData = useCallback(async () => {
    try {
      const [sysRes, linksRes, alertsRes, hostsRes] = await Promise.all([
        client.get<SystemMetrics>('/api/system/status'),
        client.get<WanLink[]>('/api/links'),
        client.get<Alert[]>('/api/alerts?unresolved=true'),
        client.get<NetHost[]>('/api/hosts'),
      ]);
      setSys(sysRes.data);
      setWanLinks(linksRes.data ?? []);
      setAlerts(alertsRes.data ?? []);
      setHosts(hostsRes.data ?? []);

      const now = Date.now();
      const nextRates: Record<string, { rx: number; tx: number }> = {};
      for (const iface of sysRes.data.interfaces ?? []) {
        const prev = prevCountersRef.current[iface.name];
        const rate = deriveRate(prev, iface, now);
        if (rate) nextRates[iface.name] = rate;
        prevCountersRef.current[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
      }
      setRates((prev) => ({ ...prev, ...nextRates }));

      setLastUpdated(new Date());
      setError(false);
    } catch (e) {
      console.error('Dashboard fetch error:', e);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Sparkline dos últimos 30 min por link WAN, via tsdb (mesmo endpoint usado
  // em Interfaces.tsx). Roda numa cadência mais espaçada — não precisa do
  // mesmo ritmo do polling de taxa/status.
  useEffect(() => {
    if (wanLinks.length === 0) return;
    let alive = true;
    const load = async () => {
      const results = await Promise.all(
        wanLinks.map(async (link) => {
          try {
            const { data } = await client.get<TrafficHistoryResponse>(
              `/api/system/traffic-history?iface=${encodeURIComponent(link.interface)}&range=30m`,
            );
            const points: SparklinePoint[] = data.points.map((p) => ({ ts: p.timestamp, rx: p.rx_bps, tx: p.tx_bps }));
            return [link.interface, points] as const;
          } catch {
            return [link.interface, []] as const;
          }
        }),
      );
      if (!alive) return;
      setSparklines(Object.fromEntries(results));
    };
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [wanLinks]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-gray-500 animate-pulse">Carregando...</div>
      </div>
    );
  }

  const onlineLinks = wanLinks.filter((l) => l.status === 'online').length;
  const criticalAlerts = alerts.filter((a) => a.severity === 'critical').length;
  const hostsOnline = hosts.filter((h) => h.online).length;
  const trafficNowBps = wanLinks.reduce((sum, l) => sum + (rates[l.interface]?.rx ?? 0) + (rates[l.interface]?.tx ?? 0), 0);

  return (
    <div className="p-6 space-y-6">
      <GettingStarted />
      <Recipes />
      <SystemHealth />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('dashboard.title')}</h1>
          <p className="text-gray-500 text-sm mt-0.5">{t('dashboard.subtitle')}</p>
        </div>
        <div className="text-xs">
          {error ? (
            <span className="text-amber-400">Dados desatualizados desde {lastUpdated.toLocaleTimeString()}</span>
          ) : (
            <span className="text-gray-600">Atualizado às {lastUpdated.toLocaleTimeString()}</span>
          )}
        </div>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between">
          <span>Falha ao carregar dados do firewall. Exibindo últimos dados conhecidos.</span>
          <button onClick={fetchData} className="btn-secondary">Tentar novamente</button>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat
          label="WAN ativas"
          value={`${onlineLinks}/${wanLinks.length}`}
          variant={wanLinks.length > 0 && onlineLinks === wanLinks.length ? 'ok' : wanLinks.length > 0 ? 'crit' : 'idle'}
        />
        <Stat label="Tráfego agora" value={formatRate(trafficNowBps)} />
        <Stat label="Hosts ativos" value={hostsOnline} sub={`${hosts.length} conhecidos`} />
        {sys && <Stat label="Uptime" value={sys.uptime_str || '—'} />}
      </div>

      {wanLinks.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {wanLinks.map((link) => {
            const rate = rates[link.interface];
            const variant = statusVariant[link.status] ?? 'idle';
            return (
              <Panel
                key={link.id}
                title={link.name}
                action={<Tag variant={variant} dot>{statusLabel[link.status] ?? link.status}</Tag>}
              >
                <div className="flex items-baseline justify-between mb-2">
                  <div className="text-2xl font-bold text-white font-mono">
                    {rate ? formatRate(rate.rx + rate.tx) : '—'}
                  </div>
                  <div className="text-gray-500 text-xs">
                    {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'} · {link.packet_loss > 0 ? `${link.packet_loss.toFixed(1)}%` : '0%'} perda
                  </div>
                </div>
                <Sparkline data={sparklines[link.interface] ?? []} height={48} />
              </Panel>
            );
          })}
        </div>
      )}

      {sys && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Uptime"
            value={sys.uptime_str || '—'}
            icon={Clock}
            iconColor="text-green-400"
            subtitle={`Load: ${(sys.load_avg?.[0] ?? 0).toFixed(2)} ${(sys.load_avg?.[1] ?? 0).toFixed(2)} ${(sys.load_avg?.[2] ?? 0).toFixed(2)}`}
          />
          <ProgressCard
            title="CPU"
            percent={sys.cpu_percent ?? 0}
            value={`${(sys.cpu_percent ?? 0).toFixed(1)}%`}
            icon={Cpu}
            iconColor="text-blue-400"
          />
          <ProgressCard
            title="Memória"
            percent={sys.mem_percent ?? 0}
            value={`${formatBytes(sys.mem_used_bytes ?? 0)} / ${formatBytes(sys.mem_total_bytes ?? 0)}`}
            icon={MemoryStick}
            iconColor="text-purple-400"
          />
          <ProgressCard
            title="Disco"
            percent={sys.disk_percent ?? 0}
            value={`${formatBytes(sys.disk_used_bytes ?? 0)} / ${formatBytes(sys.disk_total_bytes ?? 0)}`}
            icon={HardDrive}
            iconColor="text-orange-400"
          />
        </div>
      )}

      {criticalAlerts > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300 text-sm">
            {criticalAlerts} alerta{criticalAlerts !== 1 ? 's' : ''} crítico{criticalAlerts !== 1 ? 's' : ''} ativo{criticalAlerts !== 1 ? 's' : ''}.
            Verifique a aba de Alertas.
          </p>
        </div>
      )}
    </div>
  );
}
```

Este passo deixa o arquivo temporariamente sem os widgets "Top consumidores agora" e "Precisa de atenção" (viram as Tarefas 8 e 9) — o import de `hosts`/`Alert` já está aqui porque a tira de status precisa de `hosts` e o banner de alerta crítico precisa de `alerts`, mas a tabela detalhada de cada um entra nas próximas tarefas.

- [ ] **Step 2: Verificar visualmente**

Rode `npm run build` (deve passar sem erro de tipo — repare que `MetricCard`/`ProgressCard` e ícones não usados foram removidos do import, e `Wifi`/`Server`/`Activity`/`StatusBadge`/`AlertBadge` não são mais importados nesta versão do arquivo). Rode `npm run dev` com um backend real ou local e confirme: a tira de status aparece com 4 números reais; cada link WAN vira um painel com nome, tag de status, taxa atual e sparkline; o grid de CPU/Memória/Disco continua abaixo, com os mesmos valores de antes.

- [ ] **Step 3: Commit**

```bash
git add web/src/pages/Dashboard.tsx
git commit -m "feat(web): Painel reconstruído com Panel/Stat/Tag/Sparkline — tira de status e painéis WAN"
```

---

### Task 8: `Dashboard.tsx` — "Top consumidores agora"

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`

**Interfaces:**
- Consumes: tipo `HostTraffic` de `web/src/types`, endpoint `GET /api/hosts/traffic` (`internal/hosttraffic`), `hosts` já carregado na Tarefa 7 (join por `ip`, mesmo padrão de `web/src/pages/Hosts.tsx`)

- [ ] **Step 1: Buscar `/api/hosts/traffic` e guardar no estado**

Em `web/src/pages/Dashboard.tsx`, adicione `HostTraffic` ao import de tipos (linha do `import type { SystemMetrics, WanLink, Alert, NetHost, TrafficHistoryResponse } from '../types';` — vira `..., HostTraffic }`).

Adicione um novo estado, junto aos outros `useState` do componente:

```ts
  const [talkers, setTalkers] = useState<HostTraffic[]>([]);
```

Dentro de `fetchData`, adicione a chamada ao `Promise.all` existente (que hoje busca `sysRes, linksRes, alertsRes, hostsRes`) — o endpoint é best-effort (retorna vazio se `nf_conntrack_acct` estiver desligado), então busque separado, fora do `Promise.all` principal, para uma falha nele não derrubar o resto do Painel:

```ts
      client.get<HostTraffic[]>('/api/hosts/traffic').then(
        (res) => setTalkers(res.data ?? []),
        () => setTalkers([]),
      );
```

Adicione essa chamada logo após o bloco `const [sysRes, linksRes, alertsRes, hostsRes] = await Promise.all([...]);` dentro de `fetchData`.

- [ ] **Step 2: Renderizar o widget**

Ainda em `Dashboard.tsx`, adicione o import de `Panel` já existe; não precisa de novo import de componente. Insira o novo bloco entre o grid de CPU/Memória/Disco e o banner de alertas críticos (ou seja, logo depois do `</div>` que fecha o `grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4` do sistema, adicionado na Tarefa 7):

```tsx
      {talkers.length > 0 && (
        <Panel title="Top consumidores agora">
          <p className="text-gray-500 text-xs -mt-2 mb-3">Fluxos ativos no momento — não é total acumulado.</p>
          <div className="space-y-2">
            {talkers.slice(0, 8).map((tlk) => {
              const host = hosts.find((h) => h.ip === tlk.ip);
              const name = host?.alias || host?.hostname || tlk.ip;
              const total = tlk.rx_bytes + tlk.tx_bytes;
              const max = (talkers[0].rx_bytes + talkers[0].tx_bytes) || 1;
              const pct = Math.max(4, Math.round((total / max) * 100));
              return (
                <div key={tlk.ip} className="flex items-center gap-3">
                  <span className="text-gray-300 text-sm w-32 truncate flex-shrink-0">{name}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2">
                    <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-gray-500 text-xs font-mono w-20 text-right flex-shrink-0">{formatBytes(total)}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      )}
```

Repare no `{talkers.length > 0 && ...}`: se o accounting estiver desligado (`nf_conntrack_acct=0`), `/api/hosts/traffic` volta lista vazia e o card inteiro some — nada de "0 hosts consumindo" fabricado.

- [ ] **Step 3: Verificar visualmente**

`npm run build` sem erro. `npm run dev`: se o backend local não tiver `nf_conntrack_acct` ligado, confirme que o card simplesmente não aparece (sem quebrar o layout). Se possível testar contra um backend com accounting ligado (ex.: produção, só leitura), confirme que os nomes resolvem corretamente via alias/hostname e a barra proporcional bate com os valores.

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Dashboard.tsx
git commit -m "feat(web): Painel — Top consumidores agora (conntrack, best-effort)"
```

---

### Task 9: `Dashboard.tsx` — "Precisa de atenção" + restilizar blocos de onboarding

**Files:**
- Modify: `web/src/pages/Dashboard.tsx`
- Modify: `web/src/components/GettingStarted.tsx`
- Modify: `web/src/components/Recipes.tsx`
- Modify: `web/src/components/SystemHealth.tsx`

**Interfaces:**
- Consumes: `alerts` já carregado na Tarefa 7, `AlertBadge` (Task 1) ou `Tag` diretamente, `useI18n()` para o idioma do formatador de tempo relativo

- [ ] **Step 1: Adicionar tabela "Precisa de atenção" ao Painel**

Em `web/src/pages/Dashboard.tsx`, adicione uma função de tempo relativo no topo do arquivo (junto às outras funções auxiliares como `formatBytes`), usando `Intl.RelativeTimeFormat` para respeitar PT/EN automaticamente sem strings hardcoded:

```ts
function formatRelativeTime(iso: string, lang: 'pt' | 'en'): string {
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const diffMin = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
  if (Math.abs(diffMin) < 60) return rtf.format(diffMin, 'minute');
  const diffHour = Math.round(diffMin / 60);
  if (Math.abs(diffHour) < 24) return rtf.format(diffHour, 'hour');
  return rtf.format(Math.round(diffHour / 24), 'day');
}
```

No corpo do componente, troque `const { t } = useI18n();` por `const { t, lang } = useI18n();` (precisa do idioma atual para passar ao formatador).

Insira o bloco da tabela logo após o widget "Top consumidores agora" da Tarefa 8 (ou, se aquele widget não estiver visível por falta de dado, logo após o grid de sistema — a ordem no JSX não muda, `{talkers.length > 0 && (...)}` já lida com isso sozinho):

```tsx
      {alerts.length > 0 && (
        <Panel title="Precisa de atenção">
          <div className="space-y-2">
            {alerts.slice(0, 5).map((alert) => (
              <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-800 rounded-lg">
                <AlertBadge severity={alert.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium">{alert.title}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{alert.message}</p>
                </div>
                <span className="text-gray-600 text-xs flex-shrink-0">{formatRelativeTime(alert.created_at, lang)}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
```

Adicione o import de `AlertBadge`: `import { AlertBadge } from '../components/StatusBadge';` junto aos outros imports.

- [ ] **Step 2: Restilizar `GettingStarted`/`Recipes`/`SystemHealth` com `Panel`**

Em `web/src/components/SystemHealth.tsx`, troque:

```tsx
    <div className="card">
      <h2 className="text-white font-semibold mb-3">Saúde do sistema</h2>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
```

por (usando `Panel`, que já cuida do `.card` e do cabeçalho — repare que o `mb-3` do `<h2>` original vira o `mb-4` padrão do `Panel`, diferença visual mínima e aceitável):

```tsx
    <Panel title="Saúde do sistema">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
```

E troque o `</div>` de fechamento final do componente (o que fecha a `<div className="card">`) por `</Panel>`. Adicione `import Panel from './ui/Panel';` no topo do arquivo.

Em `web/src/components/Recipes.tsx`, na linha `<h2 className="text-white font-semibold">O que você quer fazer?</h2>` (linha ~153), o wrapper é `<div className="card">` (linha ~148) — aplique a mesma troca: `<div className="card">` → `<Panel title="O que você quer fazer?">`, remova o `<h2>` correspondente (o título passa a vir da prop `title` do `Panel`), e troque o `</div>` de fechamento do componente por `</Panel>`. Adicione `import Panel from './ui/Panel';`.

`GettingStarted.tsx` **não muda** nesta tarefa: seu wrapper (`<div className="card border border-blue-500/30 bg-gradient-to-b from-blue-500/5 to-transparent">`) é um destaque visual proposital (onboarding em primeiro plano), diferente do `Panel` genérico. Forçar esse caso dentro de `Panel` exigiria uma prop de variante só para um único consumidor — vale mais manter como está do que generalizar um componente por causa de um caso só (YAGNI).

- [ ] **Step 3: Verificar visualmente**

`npm run build` sem erro. `npm run dev`: confirme que "Saúde do sistema" e "O que você quer fazer?" continuam com a mesma posição/comportamento (Recipes navega para as páginas certas ao clicar, SystemHealth continua atualizando a cada 15s), só com o cabeçalho vindo do `Panel`. Confirme que "Precisa de atenção" mostra os alertas reais com tempo relativo (ex. "há 2 horas"), e que o card some por completo quando não há alertas ativos (sem "0 alertas" fabricado).

- [ ] **Step 4: Commit**

```bash
git add web/src/pages/Dashboard.tsx web/src/components/GettingStarted.tsx web/src/components/Recipes.tsx web/src/components/SystemHealth.tsx
git commit -m "feat(web): Painel — Precisa de atenção + onboarding restilizado com Panel"
```

---

### Task 10: Verificação visual final (Playwright, dados reais/semeados)

**Files:**
- Nenhum arquivo de produto — só verificação. Scripts temporários (se necessários) vão em `/tmp` ou na pasta de scratch da sessão, não no repositório.

**Interfaces:**
- Consumes: build completo do frontend (Tasks 1-9) + um backend local com dados semeados

- [ ] **Step 1: Build local do frontend e backend**

Siga a técnica já usada nas últimas iterações de UI deste projeto: build do frontend (`cd web && npm run build`) para uma pasta de saída, build do backend (`go build ./cmd/linkguard-fw`) apontando para um diretório de dados gravável, subida do binário para criar o schema, e depois novamente com `monitor_interval_seconds` alto para não sobrescrever dados semeados.

- [ ] **Step 2: Semear dados representativos**

Via SQLite direto (mesmo padrão de scripts anteriores desta sessão), garanta que o banco local tenha: 2 links WAN (um online, um degradado ou offline, para ver as duas variantes de `Tag`), histórico de tráfego recente para cada interface WAN (`metric_samples`, séries `if.rx_bps`/`if.tx_bps`, últimos 30 min, para o `Sparkline` ter o que desenhar), ao menos 3 hosts em `NetHost` (alguns `online=true`), e 2-3 alertas não resolvidos com severidades diferentes.

- [ ] **Step 3: Navegar e capturar com Playwright (chromium headless)**

Login como `admin`/`admin` (padrão documentado). Navegue para `/` (Painel) e capture screenshot em tela cheia. Confira via `getBoundingClientRect()`/inspeção do DOM:
- a tira de status mostra 4 números não vazios e coerentes com os dados semeados
- cada painel WAN mostra o nome do link, a tag de status com a cor certa (`ok`=verde para online, `warn`=amarelo para degradado, `crit`=vermelho para offline), e o sparkline desenha uma linha (não "sem dados")
- nenhum texto sobreposto, cortado ou invisível (repita a checagem de largura zero que pegou o bug de flexbox na iteração anterior desta semana — meça `getBoundingClientRect().width` dos nomes de link e do texto de "Top consumidores")
- o card "Top consumidores agora" aparece só se o backend de teste tiver dados de conntrack simulados (se não tiver, confirme que o card simplesmente não existe no DOM, não que existe vazio)
- "Precisa de atenção" mostra os alertas semeados com tempo relativo plausível
- alterne Simples/Avançado e confirme visualmente que Monitoramento/Logs/Interfaces/Rotas somem da barra lateral em modo Simples

- [ ] **Step 4: Corrigir o que a verificação encontrar**

Se algo estiver errado (texto cortado, sparkline não aparece, cor errada), a causa raiz deve ser investigada como qualquer bug — não silenciar com CSS de emergência. Ajuste o componente ou o dado correspondente e repita a Etapa 3 até a página bater com o esperado.

- [ ] **Step 5: Reverter qualquer patch temporário usado para o teste local**

Se algum caminho de arquivo (ex. `secret.key`) foi alterado temporariamente para viabilizar o build local, rode `git status` e `git checkout -- <arquivo>` nesses arquivos específicos antes de finalizar — nunca deixe um patch de teste local commitado.

- [ ] **Step 6: Commit (se a verificação exigiu correções)**

Se a Etapa 4 gerou mudanças de código:

```bash
git add -A
git commit -m "fix(web): ajustes encontrados na verificação visual do Painel"
```

Se nenhuma correção foi necessária, não há commit nesta tarefa — ela é só verificação.

---

## Auto-revisão do plano

**Cobertura do spec:** tokens de cor (Task 1) · `Panel`/`Stat`/`Tag`/`Sparkline` (Tasks 1-4) · `Layout.tsx` reagrupado com `advanced` por item (Task 6) · tira de status, painéis WAN com sparkline real (Task 7) · grid de sistema preservado (Task 7) · Top consumidores com rótulo correto e omissão honesta (Task 8) · Precisa de atenção (Task 9) · onboarding preservado e restilizado (Task 9) · verificação visual obrigatória (Task 10). `Tabs` fica de fora conforme justificado nas Global Constraints.

**Escaneamento de placeholder:** nenhum "TBD"/"implementar depois" — todo passo tem código completo.

**Consistência de tipos:** `TagVariant` é definido uma vez em `Tag.tsx` e reexportado/reusado por `StatusBadge.tsx` (Task 1) e `Dashboard.tsx` (Task 7) sem redefinição paralela. `RateCounter`/`InterfaceRate`/`deriveRate` definidos uma vez em `interfaceRates.ts` (Task 5), consumidos por `Interfaces.tsx` (Task 5) e `Dashboard.tsx` (Task 7) com a mesma assinatura. `SparklinePoint` definido em `Sparkline.tsx` (Task 4), mesmo formato usado ao montar os dados em `Dashboard.tsx` (Task 7).
