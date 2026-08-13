import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { GripVertical, X } from 'lucide-react';
import { GRID_COLUMNS, MAX_ROW_SPAN, normalize, sortForColumn } from '../lib/grid';
import type { LayoutItem } from '../lib/grid';

// A grade do painel, sem biblioteca (spec §4.3). Este arquivo cuida só de
// POSIÇÃO e GESTO: quem desenha cada widget é quem chama, por `renderItem`.
// A aritmética de colisão mora em `lib/grid.ts`, pura e conferida por asserção
// automática (`lib/grid.check.ts`) — aqui não se decide onde nada cai, só se
// traduz pixel em célula e se chama `normalize`.

/** Altura de uma linha da grade, em pixels. */
export const ROW_HEIGHT = 96;
/** Espaço entre células, em pixels. Vale nos dois eixos. */
export const GRID_GAP = 16;

/**
 * Abaixo disto o painel vira uma coluna só (spec §4.4). É o `md` do Tailwind,
 * o mesmo ponto de quebra que o resto do app já usa.
 */
export const NARROW_QUERY = '(max-width: 767px)';

/** true enquanto a tela está estreita. */
export function useNarrowScreen(): boolean {
  const [narrow, setNarrow] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(NARROW_QUERY).matches
      : false,
  );
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia(NARROW_QUERY);
    const onChange = () => setNarrow(mq.matches);
    onChange();
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return narrow;
}

export interface WidgetSize {
  minW: number;
  minH: number;
}

interface WidgetGridProps {
  items: LayoutItem[];
  /** Fora do modo de edição a tela é só leitura: sem alças e sem arrasto. */
  editing: boolean;
  /** Chamado ao SOLTAR o arrasto e ao TERMINAR o redimensionamento. */
  onChange: (items: LayoutItem[]) => void;
  onRemove: (widget: string) => void;
  renderItem: (item: LayoutItem) => ReactNode;
  /** Rótulo do widget, para a etiqueta do modo de edição. */
  titleOf: (widget: string) => string;
  minSizeOf?: (widget: string) => WidgetSize;
}

const MIN_PADRAO: WidgetSize = { minW: 2, minH: 1 };

function mesmaLista(a: LayoutItem[], b: LayoutItem[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (x.widget !== y.widget || x.x !== y.x || x.y !== y.y || x.w !== y.w || x.h !== y.h) return false;
  }
  return true;
}

interface Grab {
  widget: string;
  /** Em qual célula DO PRÓPRIO widget o operador pegou. */
  grabCol: number;
  grabRow: number;
}

interface Resize {
  widget: string;
  startX: number;
  startY: number;
  startW: number;
  startH: number;
}

export default function WidgetGrid({
  items,
  editing,
  onChange,
  onRemove,
  renderItem,
  titleOf,
  minSizeOf,
}: WidgetGridProps) {
  const narrow = useNarrowScreen();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const grabRef = useRef<Grab | null>(null);
  const resizeRef = useRef<Resize | null>(null);
  // Enquanto o operador está na alça de redimensionar, o arrasto HTML5 do
  // widget inteiro não pode começar — senão o gesto vira mover em vez de
  // redimensionar, e ele nunca consegue mudar o tamanho.
  const noDragRef = useRef(false);
  const previewRef = useRef<LayoutItem[] | null>(null);

  const [preview, setPreviewState] = useState<LayoutItem[] | null>(null);
  const [active, setActive] = useState<string | null>(null);

  const setPreview = useCallback((next: LayoutItem[] | null) => {
    previewRef.current = next;
    setPreviewState(next);
  }, []);

  const shown = preview ?? items;

  /** Largura de uma coluna em pixels, medida do container de verdade. */
  const colWidth = useCallback((): number => {
    const rect = containerRef.current?.getBoundingClientRect();
    const largura = rect?.width ?? 0;
    return (largura - GRID_GAP * (GRID_COLUMNS - 1)) / GRID_COLUMNS;
  }, []);

  const cellFromPointer = useCallback(
    (clientX: number, clientY: number): { col: number; row: number } => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return { col: 0, row: 0 };
      const cw = colWidth();
      return {
        col: Math.floor((clientX - rect.left) / (cw + GRID_GAP)),
        row: Math.floor((clientY - rect.top) / (ROW_HEIGHT + GRID_GAP)),
      };
    },
    [colWidth],
  );

  // ── Arrastar ──────────────────────────────────────────────────────────────
  // HTML5 drag and drop, e não pointer events, porque é o gesto nativo: o
  // cursor, o "fantasma" e o cancelamento com Esc vêm de graça do navegador.
  // `dataTransfer.setData` é OBRIGATÓRIO — sem ele o Firefox simplesmente não
  // inicia o arrasto, e o defeito só aparece nele.

  const handleDragStart = (e: React.DragEvent<HTMLDivElement>, item: LayoutItem) => {
    if (!editing || narrow || noDragRef.current) {
      e.preventDefault();
      return;
    }
    e.dataTransfer.setData('text/plain', item.widget);
    e.dataTransfer.effectAllowed = 'move';
    const rect = e.currentTarget.getBoundingClientRect();
    const cw = colWidth();
    grabRef.current = {
      widget: item.widget,
      grabCol: Math.max(0, Math.min(item.w - 1, Math.floor((e.clientX - rect.left) / (cw + GRID_GAP)))),
      grabRow: Math.max(0, Math.min(item.h - 1, Math.floor((e.clientY - rect.top) / (ROW_HEIGHT + GRID_GAP)))),
    };
    setActive(item.widget);
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    const grab = grabRef.current;
    if (!grab) return;
    // Sem `preventDefault` o navegador recusa o alvo e não há `drop`.
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';

    const atual = items.find((it) => it.widget === grab.widget);
    if (!atual) return;
    const { col, row } = cellFromPointer(e.clientX, e.clientY);
    // A prévia é sempre calculada a partir da lista ORIGINAL, nunca da prévia
    // anterior: normalizar sobre o resultado da normalização faria o painel
    // "derreter" para baixo enquanto o operador move o mouse sem soltar.
    const proximo = normalize(items, { ...atual, x: col - grab.grabCol, y: row - grab.grabRow });
    if (!previewRef.current || !mesmaLista(previewRef.current, proximo)) setPreview(proximo);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    if (!grabRef.current) return;
    e.preventDefault();
    const final = previewRef.current;
    grabRef.current = null;
    setPreview(null);
    setActive(null);
    if (final) onChange(final);
  };

  const handleDragEnd = () => {
    // Arrasto abandonado (Esc, ou solto fora da grade): a prévia é descartada e
    // o layout salvo continua valendo. Um cancelamento nunca move nada.
    grabRef.current = null;
    setPreview(null);
    setActive(null);
  };

  // ── Redimensionar ─────────────────────────────────────────────────────────
  // Pointer events aqui, e não HTML5 drag: redimensionar é um gesto contínuo, e
  // o arrasto nativo não entrega posição durante o movimento em todos os
  // navegadores.

  useEffect(() => {
    if (!resizeRef.current) return;

    const onMove = (e: PointerEvent) => {
      const r = resizeRef.current;
      if (!r) return;
      const atual = items.find((it) => it.widget === r.widget);
      if (!atual) return;
      const cw = colWidth();
      const dw = Math.round((e.clientX - r.startX) / (cw + GRID_GAP));
      const dh = Math.round((e.clientY - r.startY) / (ROW_HEIGHT + GRID_GAP));
      const min = minSizeOf ? minSizeOf(r.widget) : MIN_PADRAO;
      const w = Math.max(min.minW, Math.min(GRID_COLUMNS - atual.x, r.startW + dw));
      const h = Math.max(min.minH, Math.min(MAX_ROW_SPAN, r.startH + dh));
      const proximo = normalize(items, { ...atual, w, h });
      if (!previewRef.current || !mesmaLista(previewRef.current, proximo)) setPreview(proximo);
    };

    const onUp = () => {
      const final = previewRef.current;
      resizeRef.current = null;
      noDragRef.current = false;
      setPreview(null);
      setActive(null);
      if (final) onChange(final);
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
    // `active` entra na lista para que o efeito seja montado quando um
    // redimensionamento começa e desmontado quando termina.
  }, [active, items, colWidth, minSizeOf, onChange, setPreview]);

  const startResize = (e: React.PointerEvent<HTMLButtonElement>, item: LayoutItem) => {
    if (!editing || narrow) return;
    e.preventDefault();
    e.stopPropagation();
    noDragRef.current = true;
    resizeRef.current = {
      widget: item.widget,
      startX: e.clientX,
      startY: e.clientY,
      startW: item.w,
      startH: item.h,
    };
    setActive(item.widget);
  };

  // ── Tela estreita: uma coluna, na ordem que o admin definiu ───────────────
  // A posição salva vale no desktop. Não existe um segundo layout para manter
  // (spec §4.4), e por isso a ordem sai de `sortForColumn` — a mesma função
  // conferida por asserção.
  if (narrow) {
    return (
      <div className="flex flex-col gap-4" data-testid="widget-grid" data-narrow="true">
        {sortForColumn(items).map((item) => (
          <div key={item.widget} data-widget={item.widget} className="min-w-0">
            {renderItem(item)}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      data-testid="widget-grid"
      data-narrow="false"
      onDragOver={handleDragOver}
      onDragEnter={(e) => {
        if (grabRef.current) e.preventDefault();
      }}
      onDrop={handleDrop}
      className="grid"
      style={{
        gridTemplateColumns: `repeat(${GRID_COLUMNS}, minmax(0, 1fr))`,
        gridAutoRows: `${ROW_HEIGHT}px`,
        gap: `${GRID_GAP}px`,
      }}
    >
      {shown.map((item) => {
        const emGesto = active === item.widget;
        return (
          <div
            key={item.widget}
            data-widget={item.widget}
            data-x={item.x}
            data-y={item.y}
            data-w={item.w}
            data-h={item.h}
            draggable={editing}
            onDragStart={(e) => handleDragStart(e, item)}
            onDragEnd={handleDragEnd}
            className={`relative min-w-0 min-h-0 ${emGesto ? 'opacity-70' : ''}`}
            style={{
              gridColumn: `${item.x + 1} / span ${item.w}`,
              gridRow: `${item.y + 1} / span ${item.h}`,
            }}
          >
            <div className="h-full min-h-0 overflow-hidden">{renderItem(item)}</div>

            {editing && (
              // A cobertura é o que torna o modo de edição seguro: enquanto ela
              // está aí, nenhum clique chega ao conteúdo do widget, e o painel
              // inteiro é só superfície de arrasto. Fora do modo de edição ela
              // não existe, e a tela volta a ser a tela.
              <div className="absolute inset-0 z-10 flex flex-col rounded-xl border-2 border-dashed border-blue-500/50 bg-gray-950/60 cursor-move">
                <div className="flex items-start justify-between gap-2 p-2">
                  <span className="flex min-w-0 items-center gap-1.5 rounded-md bg-gray-900/95 px-2 py-1 text-xs text-gray-200">
                    <GripVertical className="h-3.5 w-3.5 shrink-0 text-gray-500" />
                    <span className="truncate">{titleOf(item.widget)}</span>
                  </span>
                  <button
                    type="button"
                    data-testid={`widget-remove-${item.widget}`}
                    onClick={() => onRemove(item.widget)}
                    onPointerDown={(e) => e.stopPropagation()}
                    title={`Remover ${titleOf(item.widget)}`}
                    aria-label={`Remover ${titleOf(item.widget)}`}
                    className="shrink-0 rounded-md bg-gray-900/95 p-1 text-gray-400 transition-colors hover:bg-red-500/20 hover:text-red-400"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
                <div className="flex flex-1 items-end justify-end p-1">
                  <button
                    type="button"
                    data-testid={`widget-resize-${item.widget}`}
                    onPointerDown={(e) => startResize(e, item)}
                    onDragStart={(e) => e.preventDefault()}
                    title="Redimensionar"
                    aria-label={`Redimensionar ${titleOf(item.widget)}`}
                    className="h-5 w-5 cursor-se-resize rounded-br-lg border-b-2 border-r-2 border-blue-400/70 bg-transparent"
                  />
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
