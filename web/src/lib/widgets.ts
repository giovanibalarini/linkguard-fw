// O catálogo de widgets do painel (spec §5).
//
// ⚠ Os nomes abaixo são CONTRATO com o backend (`storage.DashboardWidgets`, em
// `internal/storage/repository.go`). Um nome diferente aqui não dá erro em
// lugar nenhum: o item é descartado item a item na leitura, e o painel do
// operador abre VAZIO, sem mensagem. É o modo de falha mais provável desta
// fase, e é o que `widgets.check.ts` existe para travar — a lista dos nove
// nomes está repetida por extenso lá, para que renomear um deles aqui fique
// vermelho antes de chegar na máquina de alguém.
//
// Sem JSX neste arquivo, de propósito: ele é conferido por
// `node --experimental-strip-types`, que não entende JSX. Quem desenha cada
// widget é `components/widgets/registry.tsx`.

// Só o TIPO vem de `grid.ts`: `import type` é apagado pelo type-stripping do
// node, e assim `widgets.check.ts` roda sem esbarrar na resolução de módulo
// sem extensão que o resto do app usa.
import type { LayoutItem } from './grid';

/** Os nove nomes do catálogo. A ordem é a que o "adicionar widget" oferece. */
export const WIDGET_NAMES = [
  'system_health',
  'wan_links',
  'interface_traffic',
  'top_talkers',
  'open_alerts',
  'system_resources',
  'lan_hosts',
  'onboarding',
  'quick_actions',
] as const;

export type WidgetName = (typeof WIDGET_NAMES)[number];

export interface WidgetSpec {
  name: WidgetName;
  /** Rótulo em português, como aparece no catálogo e na etiqueta de edição. */
  title: string;
  /** Uma linha dizendo de onde vem o dado — é o que o operador lê para decidir. */
  description: string;
  /**
   * Permissão exigida; `''` quando o widget não exige nenhuma.
   *
   * Vale como documentação e como travamento no `widgets.check.ts`. Quem
   * DECIDE de verdade é o backend: `GET /api/dashboard/layout` já devolve em
   * `available` só o que este usuário pode ver, e é essa lista que o catálogo
   * usa. Filtrar por permissão no cliente seria uma segunda fonte de verdade,
   * livre para divergir da primeira.
   *
   * "Alertas abertos" exige `monitoring.read` e não um `alerts.read` que a spec
   * §5 menciona: essa chave não existe no catálogo do RBAC, e `GET /api/alerts`
   * é gated por `monitoring.read` hoje.
   */
  permission: string;
  defaultW: number;
  defaultH: number;
  minW: number;
  minH: number;
}

export const WIDGET_CATALOG: WidgetSpec[] = [
  {
    name: 'system_health',
    title: 'Saúde do sistema',
    description: 'Os vigias: firewall, DHCP, DNS, horário, disco e logs.',
    permission: 'monitoring.read',
    defaultW: 4,
    defaultH: 2,
    minW: 3,
    minH: 2,
  },
  {
    name: 'wan_links',
    title: 'Links WAN',
    description: 'Estado, latência, perda e taxa de cada link de internet.',
    permission: 'links.read',
    defaultW: 4,
    defaultH: 2,
    minW: 3,
    minH: 2,
  },
  {
    name: 'interface_traffic',
    title: 'Tráfego das interfaces',
    description: 'O gráfico espelhado dos últimos 30 minutos, em Mb/s.',
    permission: 'monitoring.read',
    defaultW: 8,
    defaultH: 3,
    minW: 4,
    minH: 3,
  },
  {
    name: 'top_talkers',
    title: 'Quem está consumindo',
    description: 'Os aparelhos com mais fluxo agora.',
    permission: 'hosts.read',
    defaultW: 4,
    defaultH: 3,
    minW: 3,
    minH: 2,
  },
  {
    name: 'open_alerts',
    title: 'Alertas abertos',
    description: 'O que ainda não foi resolvido, do mais grave para o menos.',
    permission: 'monitoring.read',
    defaultW: 4,
    defaultH: 2,
    minW: 3,
    minH: 2,
  },
  {
    name: 'system_resources',
    title: 'CPU, memória e disco',
    description: 'Uso da máquina, carga e tempo no ar.',
    permission: 'monitoring.read',
    defaultW: 12,
    defaultH: 2,
    minW: 4,
    minH: 2,
  },
  {
    name: 'lan_hosts',
    title: 'Hosts na rede',
    description: 'Quem está na LAN agora, e quem já esteve.',
    permission: 'hosts.read',
    defaultW: 4,
    defaultH: 3,
    minW: 3,
    minH: 2,
  },
  {
    name: 'onboarding',
    title: 'Primeiros passos',
    description: 'O guia de instalação. Sai do painel sozinho quando os 6 passos terminam.',
    permission: '',
    defaultW: 12,
    defaultH: 5,
    minW: 6,
    minH: 3,
  },
  {
    name: 'quick_actions',
    title: 'O que você quer fazer',
    description: 'Receitas passo a passo para as tarefas do dia a dia.',
    permission: '',
    defaultW: 12,
    defaultH: 3,
    minW: 6,
    minH: 2,
  },
];

/**
 * O layout de fábrica: saúde, WANs e alertas na primeira dobra; tráfego,
 * consumo e recursos abaixo (spec §5).
 *
 * É o MESMO de `storage.DefaultDashboardLayout()`, e existe aqui só como rede:
 * o backend já devolve o padrão para quem nunca salvou nada. Esta cópia é o que
 * a tela desenha quando o `GET` falha — e um painel de fábrica é melhor que uma
 * tela em branco com uma mensagem de erro.
 *
 * "Primeiros passos" NÃO está aqui de propósito: é justamente o widget que
 * motivou a entrega, parado em 5 de 6 há meses e ocupando os primeiros 60% da
 * tela. Quem instalou agora o vê porque o painel o acrescenta enquanto os 6
 * passos não terminam (spec §4.5), não porque o padrão o carregue para sempre.
 */
export const DEFAULT_LAYOUT: LayoutItem[] = [
  { widget: 'system_health', x: 0, y: 0, w: 4, h: 2 },
  { widget: 'wan_links', x: 4, y: 0, w: 4, h: 2 },
  { widget: 'open_alerts', x: 8, y: 0, w: 4, h: 2 },
  { widget: 'interface_traffic', x: 0, y: 2, w: 8, h: 3 },
  { widget: 'top_talkers', x: 8, y: 2, w: 4, h: 3 },
  { widget: 'system_resources', x: 0, y: 5, w: 12, h: 2 },
];

const PORNOME = new Map<string, WidgetSpec>(WIDGET_CATALOG.map((w) => [w.name, w]));

export function widgetSpec(name: string): WidgetSpec | undefined {
  return PORNOME.get(name);
}

export function isKnownWidget(name: string): boolean {
  return PORNOME.has(name);
}

/** Rótulo do widget; o próprio nome quando ele é desconhecido (nunca vazio). */
export function widgetTitle(name: string): string {
  return PORNOME.get(name)?.title ?? name;
}

/** Tamanho mínimo, para o redimensionamento não deixar um widget ilegível. */
export function widgetMinSize(name: string): { minW: number; minH: number } {
  const spec = PORNOME.get(name);
  return { minW: spec?.minW ?? 2, minH: spec?.minH ?? 1 };
}

/**
 * Descarta ITEM A ITEM o que a tela não sabe desenhar, do mesmo jeito que o
 * backend faz na leitura: nome fora do catálogo (versão anterior, widget
 * removido do produto) e nome fora da lista de permitidos deste usuário.
 *
 * Nunca rejeita o layout inteiro — o operador que perdesse o painel por causa
 * de uma linha ruim não teria como se recuperar pela própria tela (spec §6).
 */
export function keepRenderable(items: LayoutItem[], available: Set<string>): LayoutItem[] {
  return items.filter((it) => isKnownWidget(it.widget) && available.has(it.widget));
}
