// Asserções de `grid.ts` — a colisão e a compactação do painel de widgets.
//
// Esta é a parte da entrega que erra em silêncio e que o mockup já pegou uma
// vez: a primeira versão da grade não resolvia colisão, e arrastar um widget
// por cima de outro empilhava os dois no mesmo lugar. É exatamente o que uma
// biblioteca de grade resolveria — e a restrição da spec §4.3 é justamente não
// trazer uma (num appliance de segurança, uma dependência de layout é
// superfície de cadeia de suprimentos por conveniência).
//
// Mesmo formato de `series.check.ts`: um programa comum, sem runner e sem
// dependência nova, executável pelo node que já está instalado.
//
// Como rodar (a partir de `web/`):
//
//     node --experimental-strip-types src/lib/grid.check.ts
//
// Não entra no bundle (nada em `main.tsx` o alcança), mas é, sim, verificado
// por `tsc --noEmit`.

import {
  GRID_COLUMNS,
  MAX_ROW_SPAN,
  compactUp,
  nextFreeSpot,
  normalize,
  overlaps,
  resolveCollisions,
  sortForColumn,
} from './grid.ts';
import type { LayoutItem } from './grid.ts';

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

/**
 * A invariante que dá nome a esta entrega: nunca dois widgets na mesma célula.
 *
 * Confere par a par, e não por varredura de células, porque a falha que se
 * quer pegar é a sobreposição parcial — dois itens que dividem uma coluna e
 * meia são tão quebrados quanto dois exatamente empilhados, e só o segundo
 * caso é óbvio na tela.
 */
function assertSemSobreposicao(items: LayoutItem[], contexto: string) {
  for (let i = 0; i < items.length; i++) {
    for (let j = i + 1; j < items.length; j++) {
      if (overlaps(items[i], items[j])) {
        assert(
          false,
          `${contexto}: "${items[i].widget}" (${items[i].x},${items[i].y} ${items[i].w}x${items[i].h}) e ` +
            `"${items[j].widget}" (${items[j].x},${items[j].y} ${items[j].w}x${items[j].h}) ocupam a mesma célula`,
        );
        return;
      }
    }
  }
  assert(true, `${contexto}: sem sobreposição`);
}

function assertDentroDaGrade(items: LayoutItem[], contexto: string) {
  const fora = items.find(
    (it) => it.x < 0 || it.y < 0 || it.w < 1 || it.h < 1 || it.x + it.w > GRID_COLUMNS || it.h > MAX_ROW_SPAN,
  );
  assert(
    fora === undefined,
    `${contexto}: "${fora?.widget}" saiu da grade (${fora?.x},${fora?.y} ${fora?.w}x${fora?.h})`,
  );
}

function layoutPadrao(): LayoutItem[] {
  // O mesmo layout de fábrica do backend (storage.DefaultDashboardLayout).
  return [
    { widget: 'system_health', x: 0, y: 0, w: 4, h: 2 },
    { widget: 'wan_links', x: 4, y: 0, w: 4, h: 2 },
    { widget: 'open_alerts', x: 8, y: 0, w: 4, h: 2 },
    { widget: 'interface_traffic', x: 0, y: 2, w: 8, h: 3 },
    { widget: 'top_talkers', x: 8, y: 2, w: 4, h: 3 },
    { widget: 'system_resources', x: 0, y: 5, w: 12, h: 2 },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Arrastar por cima empurra em cascata
// ─────────────────────────────────────────────────────────────────────────────
// Quem foi invadido desce para logo abaixo de quem invadiu, repetidamente, até
// ninguém mais colidir. Sem isso, soltar um widget sobre outro deixa os dois no
// mesmo lugar — o defeito exato que o mockup encontrou.
grupo('cascata');
{
  const items: LayoutItem[] = [
    { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
    { widget: 'b', x: 0, y: 2, w: 6, h: 2 },
    { widget: 'c', x: 0, y: 4, w: 6, h: 2 },
  ];
  const out = normalize(items, { widget: 'a', x: 0, y: 2, w: 6, h: 2 });
  assertSemSobreposicao(out, 'soltar "a" em cima de "b"');
  assertDentroDaGrade(out, 'soltar "a" em cima de "b"');
  assert(out.length === 3, `os três widgets continuam no painel, obtive ${out.length}`);

  // A cascata é cascata mesmo: "b" empurra "c", e não só "b" sai do lugar.
  const b = out.find((i) => i.widget === 'b')!;
  const c = out.find((i) => i.widget === 'c')!;
  assert(c.y >= b.y + b.h || b.y >= c.y + c.h, '"c" tinha que ter sido empurrado por "b", não ficado por cima dele');
}

{
  // Empurrão só desce em quem foi realmente invadido: um widget na outra metade
  // da tela não pode "pular" só porque alguém se mexeu do lado de cá.
  const items: LayoutItem[] = [
    { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
    { widget: 'b', x: 0, y: 2, w: 6, h: 2 },
    { widget: 'vizinho', x: 6, y: 0, w: 6, h: 4 },
  ];
  const out = normalize(items, { widget: 'a', x: 0, y: 2, w: 6, h: 2 });
  const vizinho = out.find((i) => i.widget === 'vizinho')!;
  assert(vizinho.x === 6 && vizinho.y === 0, `o vizinho não devia ter se mexido, foi para (${vizinho.x},${vizinho.y})`);
  assertSemSobreposicao(out, 'empurrão não contamina a coluna vizinha');
}

// ─────────────────────────────────────────────────────────────────────────────
// Remover no meio faz os de baixo subirem
// ─────────────────────────────────────────────────────────────────────────────
// Sem compactar, remover um widget deixa um buraco permanente no meio do
// painel — e o operador não tem como fechá-lo a não ser arrastando tudo.
grupo('compactar');
{
  const out = normalize([
    { widget: 'a', x: 0, y: 0, w: 12, h: 2 },
    { widget: 'c', x: 0, y: 4, w: 12, h: 2 },
  ]);
  assert(out.find((i) => i.widget === 'c')!.y === 2, `o de baixo tinha que subir, ficou em y=${out.find((i) => i.widget === 'c')!.y}`);
}

{
  // Subir é subir até encostar, não subir uma linha só.
  const out = compactUp([{ widget: 'sozinho', x: 3, y: 9, w: 3, h: 2 }]);
  assert(out[0].y === 0, `um item sozinho tinha que subir até o topo, ficou em y=${out[0].y}`);
  assert(out[0].x === 3, 'compactar é vertical: a coluna não muda');
}

{
  // Compactar não passa por cima de ninguém: o de baixo sobe até encostar, e
  // para. E quem está em outra coluna sobe independentemente.
  const out = compactUp([
    { widget: 'topo', x: 0, y: 0, w: 6, h: 2 },
    { widget: 'abaixo', x: 0, y: 7, w: 6, h: 2 },
    { widget: 'ao_lado', x: 6, y: 7, w: 6, h: 2 },
  ]);
  assert(out.find((i) => i.widget === 'abaixo')!.y === 2, 'sobe até encostar em quem está por cima');
  assert(out.find((i) => i.widget === 'ao_lado')!.y === 0, 'em outra coluna, sobe até o topo');
  assertSemSobreposicao(out, 'compactação');
}

// ─────────────────────────────────────────────────────────────────────────────
// Redimensionar para maior empurra
// ─────────────────────────────────────────────────────────────────────────────
grupo('redimensionar');
{
  const items: LayoutItem[] = [
    { widget: 'a', x: 0, y: 0, w: 4, h: 2 },
    { widget: 'b', x: 4, y: 0, w: 4, h: 2 },
    { widget: 'c', x: 0, y: 2, w: 12, h: 2 },
  ];
  const out = normalize(items, { widget: 'a', x: 0, y: 0, w: 4, h: 5 });
  assertSemSobreposicao(out, 'crescer "a" na vertical');
  assert(out.find((i) => i.widget === 'a')!.h === 5, 'o tamanho pedido é o que vale');
  assert(out.find((i) => i.widget === 'c')!.y >= 5, `"c" tinha que descer, ficou em y=${out.find((i) => i.widget === 'c')!.y}`);
}

{
  // Crescer para além da borda direita não vaza da grade: o pedido é atendido
  // até onde cabe.
  const out = normalize([{ widget: 'a', x: 8, y: 0, w: 4, h: 2 }], { widget: 'a', x: 8, y: 0, w: 9, h: 2 });
  assertDentroDaGrade(out, 'crescer além da borda');
  assert(out[0].x + out[0].w <= GRID_COLUMNS, 'nada pode ultrapassar a coluna 12');
}

// ─────────────────────────────────────────────────────────────────────────────
// Higiene da entrada: o layout vem do banco, e o banco pode ter qualquer coisa
// ─────────────────────────────────────────────────────────────────────────────
grupo('higiene');
{
  const out = normalize([
    { widget: 'negativo', x: -5, y: -3, w: 4, h: 2 },
    { widget: 'gigante', x: 0, y: 0, w: 99, h: 999 },
    { widget: 'zerado', x: 2, y: 1, w: 0, h: 0 },
  ]);
  assertDentroDaGrade(out, 'entrada suja');
  assertSemSobreposicao(out, 'entrada suja');
  assert(out.length === 3, 'higiene não é descarte: nenhum item some por estar torto');
}

{
  // O mesmo widget duas vezes seriam duas cópias disputando o mesmo dado e a
  // mesma alça. O backend já descarta a segunda (SanitizeDashboardLayout); a
  // grade não pode depender disso para não se perder no `findIndex`.
  const out = normalize([
    { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
    { widget: 'a', x: 6, y: 0, w: 6, h: 2 },
  ]);
  assert(out.length === 1, `widget repetido tem que virar um só, obtive ${out.length}`);
}

{
  const out = normalize([{ widget: 'nan', x: NaN, y: NaN, w: NaN, h: NaN }]);
  assertDentroDaGrade(out, 'valor não numérico');
}

{
  const out = normalize([]);
  assert(out.length === 0, 'painel vazio é uma escolha, não um erro');
}

// ─────────────────────────────────────────────────────────────────────────────
// Ordem para a tela estreita
// ─────────────────────────────────────────────────────────────────────────────
// No celular vira uma coluna, na ordem que o admin definiu: por `y`, depois por
// `x` (spec §4.4). Não existe um segundo layout para manter.
grupo('coluna única');
{
  const ordem = sortForColumn([
    { widget: 'direita', x: 8, y: 0, w: 4, h: 2 },
    { widget: 'abaixo', x: 0, y: 2, w: 12, h: 2 },
    { widget: 'esquerda', x: 0, y: 0, w: 4, h: 2 },
    { widget: 'meio', x: 4, y: 0, w: 4, h: 2 },
  ]).map((i) => i.widget);
  assert(
    ordem.join(',') === 'esquerda,meio,direita,abaixo',
    `a ordem tinha que ser por y e depois x, obtive ${ordem.join(',')}`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Onde um widget novo cai
// ─────────────────────────────────────────────────────────────────────────────
grupo('adicionar');
{
  const items = layoutPadrao();
  const spot = nextFreeSpot(items, 4, 2);
  const comNovo = normalize([...items, { widget: 'lan_hosts', ...spot, w: 4, h: 2 }]);
  assertSemSobreposicao(comNovo, 'adicionar widget');
  assertDentroDaGrade(comNovo, 'adicionar widget');
  assert(comNovo.length === 7, 'o widget novo entrou');
}

{
  // Painel vazio: o primeiro widget vai para o canto superior esquerdo, e não
  // para o fim de uma fila que não existe.
  const spot = nextFreeSpot([], 6, 2);
  assert(spot.x === 0 && spot.y === 0, `o primeiro widget vai para (0,0), obtive (${spot.x},${spot.y})`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Prova por PROPRIEDADE, não só por caso
// ─────────────────────────────────────────────────────────────────────────────
// Para uma sequência de 500 operações pseudoaleatórias (mover, redimensionar,
// adicionar, remover), NUNCA existem dois itens ocupando a mesma célula e nada
// sai da grade. Sem isto, a grade passa nos casos que alguém imaginou e falha
// no que o operador fizer.
//
// A semente vem do índice, nunca de `Math.random()`: uma falha aqui tem que ser
// reproduzível na mesma iteração, não uma vez a cada dez execuções.
grupo('propriedade');

/** PRNG determinístico (mulberry32) — semeado, para a falha ser reproduzível. */
function prngDe(semente: number): () => number {
  let a = semente >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

{
  let items = layoutPadrao();
  let iteracoes = 0;

  for (let i = 0; i < 500; i++) {
    const rnd = prngDe(i + 1);
    const inteiro = (n: number) => Math.floor(rnd() * n);
    const op = inteiro(4);

    if (op === 0 && items.length > 1) {
      // remover
      items = normalize(items.filter((_, k) => k !== inteiro(items.length)));
    } else if (op === 1 && items.length < 16) {
      // adicionar
      const w = 1 + inteiro(GRID_COLUMNS);
      const h = 1 + inteiro(4);
      const spot = nextFreeSpot(items, w, h);
      items = normalize([...items, { widget: `novo_${i}`, x: spot.x, y: spot.y, w, h }]);
    } else if (op === 2) {
      // redimensionar
      const alvo = items[inteiro(items.length)];
      items = normalize(items, { ...alvo, w: 1 + inteiro(GRID_COLUMNS), h: 1 + inteiro(6) });
    } else {
      // mover
      const alvo = items[inteiro(items.length)];
      items = normalize(items, { ...alvo, x: inteiro(GRID_COLUMNS), y: inteiro(10) });
    }

    iteracoes++;
    for (let a = 0; a < items.length; a++) {
      for (let b = a + 1; b < items.length; b++) {
        if (overlaps(items[a], items[b])) {
          assert(false, `iteração ${i}: "${items[a].widget}" e "${items[b].widget}" ocupam a mesma célula`);
          i = 500;
          a = items.length;
          break;
        }
      }
    }
    const fora = items.find((it) => it.x < 0 || it.x + it.w > GRID_COLUMNS || it.y < 0 || it.w < 1 || it.h < 1);
    if (fora) {
      assert(false, `iteração ${i}: "${fora.widget}" saiu da grade (${fora.x},${fora.y} ${fora.w}x${fora.h})`);
      break;
    }
  }
  assert(iteracoes === 500, `a sequência tinha que rodar as 500 operações, parou em ${iteracoes}`);
  assert(true, '500 operações pseudoaleatórias sem uma única sobreposição');
}

// ─────────────────────────────────────────────────────────────────────────────
// Guarda contra laço infinito
// ─────────────────────────────────────────────────────────────────────────────
// Uma configuração patológica não pode travar a aba do operador. A aba travada
// é pior que o painel torto: do painel torto ele sai com "Restaurar padrão".
grupo('terminação');
{
  const patologico: LayoutItem[] = [];
  for (let i = 0; i < 64; i++) {
    // Todos no mesmo lugar, do tamanho máximo: o pior caso da cascata.
    patologico.push({ widget: `p${i}`, x: 0, y: 0, w: GRID_COLUMNS, h: MAX_ROW_SPAN });
  }
  const t0 = Date.now();
  const out = normalize(patologico);
  const gasto = Date.now() - t0;
  assert(gasto < 1000, `a normalização tem que terminar, levou ${gasto}ms`);
  assertSemSobreposicao(out, 'configuração patológica');
  assert(out.length === 64, 'nenhum item se perde na configuração patológica');
}

{
  // Cascata longa em coluna estreita: 40 itens de uma coluna, todos pedindo a
  // mesma célula. É o caso que faz um algoritmo ingênuo reprocessar a lista
  // inteira a cada empurrão.
  const items: LayoutItem[] = [];
  for (let i = 0; i < 40; i++) items.push({ widget: `q${i}`, x: i % GRID_COLUMNS, y: 0, w: 1, h: 3 });
  const t0 = Date.now();
  const out = normalize(items, { widget: 'q0', x: 0, y: 0, w: GRID_COLUMNS, h: 3 });
  assert(Date.now() - t0 < 1000, 'cascata longa tem que terminar');
  assertSemSobreposicao(out, 'cascata longa');
}

// ─────────────────────────────────────────────────────────────────────────────
// Identidade: normalizar não inventa nem perde widget
// ─────────────────────────────────────────────────────────────────────────────
grupo('identidade');
{
  const items = layoutPadrao();
  const out = normalize(items);
  assert(out.length === items.length, 'nenhum widget some ao normalizar');
  for (const it of items) {
    assert(out.some((o) => o.widget === it.widget), `"${it.widget}" continua no painel`);
  }
  // Um layout já compacto e sem colisão passa igual — normalizar duas vezes dá
  // o mesmo resultado que normalizar uma (idempotência).
  const duas = normalize(out);
  assert(JSON.stringify(duas) === JSON.stringify(out), 'normalizar de novo não pode mexer num layout já normalizado');
}

{
  // `resolveCollisions` não compacta (é a outra passada), mas já não deixa
  // sobreposição: as duas passadas são independentes e testáveis à parte.
  const out = resolveCollisions(
    [
      { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
      { widget: 'b', x: 0, y: 0, w: 6, h: 2 },
    ],
    { widget: 'a', x: 0, y: 0, w: 6, h: 2 },
  );
  assertSemSobreposicao(out, 'só a resolução de colisão');
  assert(out.find((i) => i.widget === 'a')!.y === 0, 'quem invadiu fica com o lugar');
  assert(out.find((i) => i.widget === 'b')!.y === 2, 'quem foi invadido desce para logo abaixo');
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
