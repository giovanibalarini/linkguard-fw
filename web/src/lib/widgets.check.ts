// Asserções do catálogo de widgets.
//
// Existem por um aviso explícito do autor do backend, e é o modo de falha mais
// provável desta fase: **nome de widget diferente no TypeScript = item
// descartado em silêncio na leitura, e o painel abre VAZIO, sem erro**. Não há
// 400, não há log na tela, não há nada — só um painel que some.
//
// Por isso a lista dos nove nomes está repetida aqui por extenso, copiada do
// contrato do backend (`dashboard.Catalog`), e não importada de
// `widgets.ts`: uma asserção que lesse a mesma constante que quer conferir
// passaria em verde justamente no dia em que alguém renomeasse o widget.
//
// Como rodar (a partir de `web/`):
//
//     node --experimental-strip-types src/lib/widgets.check.ts

import { GRID_COLUMNS, MAX_ROW_SPAN, normalize, overlaps } from './grid.ts';
import {
  DEFAULT_LAYOUT,
  WIDGET_CATALOG,
  WIDGET_NAMES,
  isKnownWidget,
  keepRenderable,
  widgetMinSize,
  widgetSpec,
  widgetTitle,
} from './widgets.ts';

let falhas = 0;
let total = 0;
let grupoAtual = '';

function grupo(nome: string) {
  grupoAtual = nome;
}

function assert(cond: boolean, msg: string) {
  total++;
  if (cond) return;
  falhas++;
  console.error(`  FALHOU [${grupoAtual}] ${msg}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Os nove nomes, copiados do contrato do backend
// ─────────────────────────────────────────────────────────────────────────────
// Fonte: `internal/dashboard/dashboard.go`, var Catalog, e o relatório
// da Task 3. Nunca renomeie um destes: o nome é o que está gravado no painel de
// quem já montou o dele.
const NOMES_DO_BACKEND = [
  'system_health',
  'wan_links',
  'interface_traffic',
  'top_talkers',
  'open_alerts',
  'system_resources',
  'lan_hosts',
  'onboarding',
  'quick_actions',
];

/** A permissão que o backend exige de cada widget (relatório da Task 3). */
const PERMISSAO_DO_BACKEND: Record<string, string> = {
  system_health: 'monitoring.read',
  wan_links: 'links.read',
  interface_traffic: 'monitoring.read',
  top_talkers: 'hosts.read',
  open_alerts: 'monitoring.read',
  system_resources: 'monitoring.read',
  lan_hosts: 'hosts.read',
  onboarding: '',
  quick_actions: '',
};

grupo('nomes = contrato com o backend');
{
  assert(
    WIDGET_NAMES.length === NOMES_DO_BACKEND.length,
    `o catálogo tem ${WIDGET_NAMES.length} widgets e o backend conhece ${NOMES_DO_BACKEND.length}`,
  );
  for (const nome of NOMES_DO_BACKEND) {
    assert(
      (WIDGET_NAMES as readonly string[]).includes(nome),
      `"${nome}" existe no backend e sumiu do catálogo do TypeScript — o widget nunca renderizaria`,
    );
    assert(isKnownWidget(nome), `"${nome}" tem que ser reconhecido por isKnownWidget`);
    assert(widgetSpec(nome) !== undefined, `"${nome}" precisa de uma entrada no catálogo`);
  }
  for (const nome of WIDGET_NAMES) {
    assert(
      NOMES_DO_BACKEND.includes(nome),
      `"${nome}" está no TypeScript e não existe no backend — todo item salvo com ele seria descartado em silêncio`,
    );
  }
}

grupo('permissões = as que o RBAC realmente tem');
{
  // A spec §5 fala em `alerts.read`, que NÃO existe no catálogo do RBAC. Se
  // alguém a escrevesse aqui, ela nunca casaria com a permissão de ninguém e
  // "Alertas abertos" sumiria do painel de TODOS os usuários, para sempre, sem
  // mensagem. Só estas quatro chaves são aceitas.
  const CHAVES_VALIDAS = ['', 'monitoring.read', 'links.read', 'hosts.read'];
  for (const spec of WIDGET_CATALOG) {
    assert(
      CHAVES_VALIDAS.includes(spec.permission),
      `"${spec.name}" exige "${spec.permission}", que não é uma permissão do RBAC deste projeto`,
    );
    assert(
      spec.permission === PERMISSAO_DO_BACKEND[spec.name],
      `"${spec.name}" exige "${spec.permission}" aqui e "${PERMISSAO_DO_BACKEND[spec.name]}" no backend`,
    );
  }
}

grupo('cada widget dá para desenhar e para escolher');
{
  for (const spec of WIDGET_CATALOG) {
    assert(spec.title.trim().length > 0, `"${spec.name}" precisa de rótulo em português`);
    assert(spec.description.trim().length > 0, `"${spec.name}" precisa de uma linha dizendo de onde vem o dado`);
    assert(spec.title !== spec.name, `"${spec.name}" está com o identificador como rótulo`);
    assert(
      spec.defaultW >= spec.minW && spec.defaultH >= spec.minH,
      `"${spec.name}" nasce menor que o próprio mínimo (${spec.defaultW}x${spec.defaultH} < ${spec.minW}x${spec.minH})`,
    );
    assert(
      spec.defaultW >= 1 && spec.defaultW <= GRID_COLUMNS,
      `"${spec.name}" nasce com largura ${spec.defaultW}, fora da grade de ${GRID_COLUMNS}`,
    );
    assert(
      spec.defaultH >= 1 && spec.defaultH <= MAX_ROW_SPAN,
      `"${spec.name}" nasce com altura ${spec.defaultH}, fora do limite de ${MAX_ROW_SPAN}`,
    );
    assert(
      spec.minW >= 1 && spec.minW <= GRID_COLUMNS,
      `"${spec.name}" tem mínimo de largura impossível (${spec.minW})`,
    );
    assert(widgetTitle(spec.name) === spec.title, 'widgetTitle devolve o rótulo do catálogo');
    const min = widgetMinSize(spec.name);
    assert(min.minW === spec.minW && min.minH === spec.minH, 'widgetMinSize devolve o mínimo do catálogo');
  }
  // Nome desconhecido não pode virar rótulo vazio na etiqueta de edição.
  assert(widgetTitle('widget_que_nao_existe') === 'widget_que_nao_existe', 'nome desconhecido vira o próprio nome');
  assert(!isKnownWidget('widget_que_nao_existe'), 'nome fora do catálogo não é conhecido');
}

// ─────────────────────────────────────────────────────────────────────────────
// O layout de fábrica
// ─────────────────────────────────────────────────────────────────────────────
grupo('layout de fábrica');
{
  // Cópia literal de `dashboard.Default()`. Se as duas divergirem,
  // quem falha no `GET` vê um painel diferente de quem não falha — e o defeito
  // só apareceria em quem estivesse com o backend fora do ar.
  const DO_BACKEND = [
    { widget: 'system_health', x: 0, y: 0, w: 4, h: 2 },
    { widget: 'wan_links', x: 4, y: 0, w: 4, h: 2 },
    { widget: 'open_alerts', x: 8, y: 0, w: 4, h: 2 },
    { widget: 'interface_traffic', x: 0, y: 2, w: 8, h: 3 },
    { widget: 'top_talkers', x: 8, y: 2, w: 4, h: 3 },
    { widget: 'system_resources', x: 0, y: 5, w: 12, h: 2 },
  ];
  assert(
    JSON.stringify(DEFAULT_LAYOUT) === JSON.stringify(DO_BACKEND),
    'o layout de fábrica do TypeScript divergiu do de `dashboard.Default()`',
  );

  for (const it of DEFAULT_LAYOUT) {
    assert(isKnownWidget(it.widget), `o padrão referencia "${it.widget}", que não está no catálogo`);
    assert(it.x >= 0 && it.x + it.w <= GRID_COLUMNS, `"${it.widget}" sai da grade no layout de fábrica`);
  }
  for (let a = 0; a < DEFAULT_LAYOUT.length; a++) {
    for (let b = a + 1; b < DEFAULT_LAYOUT.length; b++) {
      assert(
        !overlaps(DEFAULT_LAYOUT[a], DEFAULT_LAYOUT[b]),
        `no layout de fábrica, "${DEFAULT_LAYOUT[a].widget}" e "${DEFAULT_LAYOUT[b].widget}" ocupam a mesma célula`,
      );
    }
  }
  assert(
    JSON.stringify(normalize(DEFAULT_LAYOUT)) === JSON.stringify(DEFAULT_LAYOUT),
    'o layout de fábrica já tem que estar compacto: normalizá-lo não pode mexer nele',
  );

  // Primeiros passos fora do padrão (spec §4.5): é o widget que ocupava os
  // primeiros 60% da tela de uma máquina que roda há meses.
  assert(
    !DEFAULT_LAYOUT.some((it) => it.widget === 'onboarding'),
    '"Primeiros passos" não pode estar no layout de fábrica — ele entra só enquanto os 6 passos não terminam',
  );
  assert(
    !DEFAULT_LAYOUT.some((it) => it.widget === 'quick_actions'),
    '"O que você quer fazer" virou widget desligável, e não parte obrigatória do painel',
  );

  // Primeira dobra: saúde, WANs e alertas (spec §5).
  const primeiraDobra = DEFAULT_LAYOUT.filter((it) => it.y === 0).map((it) => it.widget);
  assert(
    primeiraDobra.join(',') === 'system_health,wan_links,open_alerts',
    `a primeira dobra tem que ser saúde, WANs e alertas, obtive ${primeiraDobra.join(',')}`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Permissão: o que o usuário não pode ver não renderiza, e não deixa buraco
// ─────────────────────────────────────────────────────────────────────────────
grupo('permissão');
{
  // Um usuário sem `hosts.read`: o backend não devolve os widgets de host em
  // `available`, e um layout salvo que os contenha tem que abrir sem eles.
  const semHosts = new Set([
    'system_health',
    'wan_links',
    'interface_traffic',
    'open_alerts',
    'system_resources',
    'onboarding',
    'quick_actions',
  ]);
  const salvo = [
    { widget: 'system_health', x: 0, y: 0, w: 4, h: 2 },
    { widget: 'top_talkers', x: 4, y: 0, w: 4, h: 2 },
    { widget: 'lan_hosts', x: 8, y: 0, w: 4, h: 2 },
    { widget: 'system_resources', x: 0, y: 2, w: 12, h: 2 },
  ];
  const visivel = keepRenderable(salvo, semHosts);
  assert(visivel.length === 2, `esperava 2 widgets visíveis, obtive ${visivel.length}`);
  assert(!visivel.some((it) => it.widget === 'top_talkers' || it.widget === 'lan_hosts'), 'os de host não podem aparecer');

  // E SEM BURACO: a compactação fecha o vazio que a filtragem deixou.
  const desenhado = normalize(visivel);
  assert(
    desenhado.find((it) => it.widget === 'system_resources')!.y === 2,
    'sem os widgets de host, o que estava abaixo tem que subir — sem buraco, sem erro',
  );

  // Item apontando para widget que não existe mais é descartado item a item, e
  // o resto do painel continua abrindo.
  const comLixo = keepRenderable(
    [
      { widget: 'system_health', x: 0, y: 0, w: 4, h: 2 },
      { widget: 'widget_que_nao_existe_mais', x: 4, y: 0, w: 4, h: 2 },
      { widget: 'wan_links', x: 8, y: 0, w: 4, h: 2 },
    ],
    new Set(['system_health', 'wan_links', 'widget_que_nao_existe_mais']),
  );
  assert(comLixo.length === 2, `o item desconhecido tinha que cair sozinho, sobraram ${comLixo.length}`);

  // Painel de um usuário que não pode ver NADA continua sendo uma tela, e não
  // um erro: vazio é um estado, com o catálogo à mão.
  assert(keepRenderable(salvo, new Set()).length === 0, 'sem permissão nenhuma, o painel abre vazio e não quebra');
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
