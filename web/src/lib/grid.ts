// A grade do painel de widgets: colisão resolvida e compactação para cima.
//
// Funções puras, sem React e sem DOM, de propósito — pelo mesmo motivo de
// `series.ts`: é aqui que mora a lógica que erra em silêncio, e só sendo pura
// ela dá para ser conferida por asserção automática (veja `grid.check.ts`, que
// inclui uma prova por propriedade sobre 500 operações pseudoaleatórias).
//
// **Sem biblioteca de grade**, por decisão da spec §4.3: num appliance de
// segurança, uma dependência de layout é superfície de cadeia de suprimentos
// por conveniência. O que uma biblioteca traria de essencial são as duas
// passadas abaixo, e elas cabem neste arquivo.

/** Colunas da grade. É o mesmo 12 do backend (storage.DashboardGridColumns). */
export const GRID_COLUMNS = 12;

/** Altura máxima de um item, em linhas. Espelha storage.DashboardMaxRowSpan. */
export const MAX_ROW_SPAN = 24;

/**
 * Um widget posicionado na grade.
 *
 * É a MESMA forma do `storage.LayoutItem` do Go, serializada em minúsculas: o
 * painel manda de volta o que leu, sem tradução de campo pelo caminho. Renomear
 * um campo aqui faria o backend descartar o item **em silêncio**, e o painel
 * abriria vazio sem nenhuma mensagem.
 */
export interface LayoutItem {
  widget: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

/** true se os dois itens dividem ao menos uma célula. */
export function overlaps(a: LayoutItem, b: LayoutItem): boolean {
  if (a === b) return false;
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

/** true se os dois itens dividem ao menos uma coluna (ignorando a linha). */
function overlapsHorizontally(a: LayoutItem, b: LayoutItem): boolean {
  return a.x < b.x + b.w && b.x < a.x + a.w;
}

function inteiro(v: number, padrao: number): number {
  return Number.isFinite(v) ? Math.round(v) : padrao;
}

/**
 * Põe um item dentro da grade sem descartá-lo.
 *
 * Higiene, não descarte: o layout vem do banco, e um item torto (versão
 * anterior, edição manual, bug de cliente) tem que virar um item desenhável, e
 * não sumir da tela do operador sem explicação. Quem descarta de verdade é o
 * catálogo — nome de widget que não existe mais.
 */
export function clampToGrid(item: LayoutItem): LayoutItem {
  const w = Math.max(1, Math.min(GRID_COLUMNS, inteiro(item.w, 1)));
  const h = Math.max(1, Math.min(MAX_ROW_SPAN, inteiro(item.h, 1)));
  const x = Math.max(0, Math.min(GRID_COLUMNS - w, inteiro(item.x, 0)));
  const y = Math.max(0, inteiro(item.y, 0));
  return { widget: item.widget, x, y, w, h };
}

/** O mesmo widget duas vezes seriam duas cópias disputando o mesmo dado. */
function dedupe(items: LayoutItem[]): LayoutItem[] {
  const vistos = new Set<string>();
  const out: LayoutItem[] = [];
  for (const it of items) {
    if (vistos.has(it.widget)) continue;
    vistos.add(it.widget);
    out.push(it);
  }
  return out;
}

function bottomOf(items: LayoutItem[]): number {
  let b = 0;
  for (const it of items) b = Math.max(b, it.y + it.h);
  return b;
}

/**
 * Teto de empurrões por item. Não é o que garante a terminação — a garantia é
 * que cada empurrão leva o item estritamente para baixo, e o fundo da pilha já
 * colocada é finito. É a rede de segurança: se algum dia uma mudança quebrar
 * essa garantia, o operador perde o alinhamento do painel, e não a aba.
 */
const MAX_PUSHES = 1000;

/**
 * Empurra em cascata: quem foi invadido desce para logo abaixo de quem
 * invadiu, repetidamente, até ninguém mais colidir.
 *
 * `moved` é o item que o operador acabou de soltar ou redimensionar — ele
 * **ganha** o lugar que pediu, e todo o resto se acomoda em volta. Sem `moved`
 * (adicionar, remover, ou abrir um layout salvo) vale a ordem de leitura: de
 * cima para baixo, da esquerda para a direita.
 *
 * Não compacta: essa é a outra passada, e as duas são independentes de
 * propósito, para cada uma poder ser conferida à parte.
 */
export function resolveCollisions(items: LayoutItem[], moved?: LayoutItem): LayoutItem[] {
  const base = dedupe(items).map(clampToGrid);

  let lista = base;
  if (moved) {
    const m = clampToGrid(moved);
    const i = lista.findIndex((it) => it.widget === m.widget);
    lista = i >= 0 ? lista.map((it, k) => (k === i ? m : it)) : [...lista, m];
  }

  const ordem = lista.slice().sort((a, b) => {
    if (moved) {
      // Quem invadiu é colocado primeiro, e por isso fica com o lugar.
      if (a.widget === moved.widget) return -1;
      if (b.widget === moved.widget) return 1;
    }
    return a.y - b.y || a.x - b.x;
  });

  const colocados: LayoutItem[] = [];
  const porWidget = new Map<string, LayoutItem>();

  for (const it of ordem) {
    let atual = it;
    let empurroes = 0;
    for (;;) {
      const batida = colocados.find((p) => overlaps(p, atual));
      if (!batida) break;
      if (++empurroes > MAX_PUSHES) {
        // Rede de segurança: abaixo de tudo é sempre livre.
        atual = { ...atual, y: bottomOf(colocados) };
        break;
      }
      atual = { ...atual, y: batida.y + batida.h };
    }
    colocados.push(atual);
    porWidget.set(atual.widget, atual);
  }

  // A ordem do array de entrada é preservada: quem chama guarda esta lista como
  // estado e a manda inteira para o backend, e uma reordenação a cada arrasto
  // faria o `PUT` "mudar" sem nada ter mudado.
  return lista.map((it) => porWidget.get(it.widget) as LayoutItem);
}

/**
 * Compacta para cima: cada item sobe enquanto não encostar em ninguém.
 *
 * **Sem isto, remover um widget deixa um buraco permanente no meio do painel** —
 * e o operador não teria como fechá-lo a não ser rearrastando tudo.
 *
 * Sobe direto para a linha certa em vez de subir de uma em uma: o resultado é o
 * mesmo, e uma tela com um item em y=1500 (o que uma cascata patológica produz)
 * não vira 1500 voltas de laço.
 */
export function compactUp(items: LayoutItem[]): LayoutItem[] {
  const ordem = items.slice().sort((a, b) => a.y - b.y || a.x - b.x);
  const colocados: LayoutItem[] = [];
  const porWidget = new Map<string, LayoutItem>();

  for (const it of ordem) {
    let y = 0;
    for (const p of colocados) {
      if (overlapsHorizontally(p, it)) y = Math.max(y, p.y + p.h);
    }
    const compacto = { ...it, y };
    colocados.push(compacto);
    porWidget.set(compacto.widget, compacto);
  }

  return items.map((it) => porWidget.get(it.widget) as LayoutItem);
}

/**
 * As duas passadas, na ordem: empurrar, depois compactar.
 *
 * É esta função que roda ao soltar o arrasto, ao redimensionar, ao adicionar e
 * ao remover — os quatro momentos em que a grade pode ficar inconsistente.
 */
export function normalize(items: LayoutItem[], moved?: LayoutItem): LayoutItem[] {
  return compactUp(resolveCollisions(items, moved));
}

/**
 * A ordem da tela estreita: por `y`, depois por `x` (spec §4.4).
 *
 * A posição salva vale no desktop; no celular os widgets empilham **na ordem
 * que o admin definiu**. Não existe um segundo layout para manter.
 */
export function sortForColumn(items: LayoutItem[]): LayoutItem[] {
  return items.slice().sort((a, b) => a.y - b.y || a.x - b.x);
}

/**
 * Onde um widget novo cabe: a primeira posição livre lendo de cima para baixo,
 * da esquerda para a direita.
 *
 * Preencher buraco é melhor que enfileirar no fim — quem acabou de remover um
 * widget e adicionou outro espera que o novo ocupe o espaço que sobrou, e não
 * que apareça depois de uma rolagem.
 */
export function nextFreeSpot(items: LayoutItem[], w: number, h: number): { x: number; y: number } {
  const largura = Math.max(1, Math.min(GRID_COLUMNS, Math.round(w)));
  const altura = Math.max(1, Math.min(MAX_ROW_SPAN, Math.round(h)));
  const fundo = bottomOf(items);

  for (let y = 0; y <= fundo; y++) {
    for (let x = 0; x + largura <= GRID_COLUMNS; x++) {
      const candidato = { widget: '', x, y, w: largura, h: altura };
      if (!items.some((it) => overlaps(it, candidato))) return { x, y };
    }
  }
  return { x: 0, y: fundo };
}
