import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowUpToLine } from 'lucide-react';
import {
  axisPadLeft,
  contiguousRuns,
  formatBps,
  formatTime,
  isEmptySeries,
  niceScale,
  reduceToWidth,
  seriesMax,
} from '../lib/series';
import type { Point, ScaleMode } from '../lib/series';
import { useI18n } from '../i18n';

// SVG à mão, de propósito: nenhuma dependência nova de gráfico. Num appliance
// de segurança uma biblioteca é superfície de cadeia de suprimentos por
// conveniência (spec §4.3), e o que este gráfico precisa — espelhar, reduzir
// preservando pico, e não desenhar o que não foi medido — é justamente o que
// as bibliotecas prontas não fazem do jeito certo sem briga.

/** Largura mínima, em pixels, de cada coluna reduzida. */
const PX_PER_BUCKET = 3;
const PAD_RIGHT = 12;
const PAD_TOP = 12;
const PAD_BOTTOM = 22;
const AXIS_FONT = 10;

const RX_COLOR = '#22d3ee';
const TX_COLOR = '#34d399';

interface TrafficChartProps {
  points: Point[];
  /** Nome da interface, para o cabeçalho e para a leitura do tooltip. */
  iface: string;
  mode: ScaleMode;
  onModeChange: (mode: ScaleMode) => void;
  /** Altura da área de desenho em pixels. */
  height?: number;
  /** Enquanto a janela está sendo buscada, para não piscar "sem amostras". */
  loading?: boolean;
}

interface Hover {
  index: number;
  x: number;
}

function pathFor(
  values: (number | null)[],
  x: (i: number) => number,
  y: (v: number) => number,
  baseY: number,
): { line: string; area: string; dots: { x: number; y: number }[] } {
  const line: string[] = [];
  const area: string[] = [];
  const dots: { x: number; y: number }[] = [];

  for (const run of contiguousRuns(values)) {
    if (run.length === 1) {
      // Uma amostra isolada entre dois buracos não vira linha nem área: sem o
      // ponto ela sumiria da tela, e some medição é tão errado quanto
      // inventar zero.
      dots.push({ x: x(run[0]), y: y(values[run[0]] as number) });
      continue;
    }
    const seg = run
      .map((i, k) => `${k === 0 ? 'M' : 'L'}${x(i).toFixed(2)},${y(values[i] as number).toFixed(2)}`)
      .join(' ');
    line.push(seg);
    const first = x(run[0]).toFixed(2);
    const last = x(run[run.length - 1]).toFixed(2);
    area.push(`${seg} L${last},${baseY.toFixed(2)} L${first},${baseY.toFixed(2)} Z`);
  }

  return { line: line.join(' '), area: area.join(' '), dots };
}

export default function TrafficChart({
  points,
  iface,
  mode,
  onModeChange,
  height = 300,
  loading = false,
}: TrafficChartProps) {
  const { t } = useI18n();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  const [hover, setHover] = useState<Hover | null>(null);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) setWidth(e.contentRect.width);
    });
    ro.observe(el);
    setWidth(el.getBoundingClientRect().width);
    return () => ro.disconnect();
  }, []);

  const padL = axisPadLeft();
  const plotW = Math.max(0, width - padL - PAD_RIGHT);
  const plotH = Math.max(0, height - PAD_TOP - PAD_BOTTOM);
  const half = plotH / 2;
  const axisY = PAD_TOP + half;

  const buckets = Math.max(1, Math.floor(plotW / PX_PER_BUCKET));

  const reduced = useMemo(() => reduceToWidth(points, buckets), [points, buckets]);
  const vazio = reduced.length === 0 || isEmptySeries(reduced);

  const scale = useMemo(() => niceScale(seriesMax(reduced), mode), [reduced, mode]);

  const step = reduced.length > 0 ? plotW / reduced.length : plotW;
  const x = useCallback((i: number) => padL + (i + 0.5) * step, [padL, step]);
  const yUp = useCallback((v: number) => axisY - scale.project(v) * half, [axisY, half, scale]);
  const yDown = useCallback((v: number) => axisY + scale.project(v) * half, [axisY, half, scale]);

  const rxVals = useMemo(() => reduced.map((p) => p.rx), [reduced]);
  const txVals = useMemo(() => reduced.map((p) => p.tx), [reduced]);

  const rxPath = useMemo(() => pathFor(rxVals, x, yUp, axisY), [rxVals, x, yUp, axisY]);
  const txPath = useMemo(() => pathFor(txVals, x, yDown, axisY), [txVals, x, yDown, axisY]);

  const picoRx = useMemo(() => {
    const medidos = rxVals.filter((v): v is number => v !== null);
    return medidos.length > 0 ? Math.max(...medidos) : null;
  }, [rxVals]);
  const picoTx = useMemo(() => {
    const medidos = txVals.filter((v): v is number => v !== null);
    return medidos.length > 0 ? Math.max(...medidos) : null;
  }, [txVals]);

  const spanMs = reduced.length > 1 ? reduced[reduced.length - 1].t - reduced[0].t : 0;

  // Rótulos de tempo: quantos couberem sem se encavalar, nunca mais que isso.
  const timeTicks = useMemo(() => {
    if (reduced.length === 0 || plotW <= 0) return [] as { i: number; label: string }[];
    const quantos = Math.max(2, Math.min(6, Math.floor(plotW / 74)));
    const out: { i: number; label: string }[] = [];
    for (let k = 0; k < quantos; k++) {
      const i = Math.round((k / (quantos - 1)) * (reduced.length - 1));
      out.push({ i, label: formatTime(reduced[i].t, spanMs) });
    }
    return out;
  }, [reduced, plotW, spanMs]);

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (reduced.length === 0 || step <= 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - rect.left;
    let i = Math.floor((px - padL) / step);
    if (i < 0) i = 0;
    if (i >= reduced.length) i = reduced.length - 1;
    setHover({ index: i, x: x(i) });
  };

  const ponto = hover ? reduced[hover.index] : null;

  return (
    <div className="card">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-white font-semibold truncate" title={iface}>
            {t('mon.chart.traffic.titlePrefix')}<span className="font-mono">{iface}</span>
          </h2>
          <p className="text-gray-500 text-xs mt-0.5">
            {t('mon.chart.traffic.hint')}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-3 font-mono text-[11px]">
            <span className="text-cyan-300 inline-flex items-center gap-1">
              <ArrowDownToLine className="w-3 h-3" /> {t('mon.chart.peak')} {formatBps(picoRx)}
            </span>
            <span className="text-emerald-300 inline-flex items-center gap-1">
              <ArrowUpToLine className="w-3 h-3" /> {t('mon.chart.peak')} {formatBps(picoTx)}
            </span>
          </div>

          <div
            className="flex items-center rounded-lg border border-gray-700 bg-gray-900/70 p-1 text-xs"
            role="group"
            aria-label={t('mon.chart.scale.aria')}
          >
            <button
              type="button"
              onClick={() => onModeChange('linear')}
              aria-pressed={mode === 'linear'}
              title={t('mon.chart.scale.linear.title')}
              className={`px-2 py-1 rounded ${
                mode === 'linear' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {t('mon.chart.scale.linear')}
            </button>
            <button
              type="button"
              onClick={() => onModeChange('log')}
              aria-pressed={mode === 'log'}
              title={t('mon.chart.scale.log.title')}
              className={`px-2 py-1 rounded ${
                mode === 'log' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {t('mon.chart.scale.log')}
            </button>
          </div>
        </div>
      </div>

      <div ref={wrapRef} className="relative mt-3" style={{ height }}>
        {/* Sem amostra não se desenha nem o eixo: uma escala de "1.0 b/s" a
            "0.3 b/s" inventada a partir do nada é dado falso na tela, mesmo
            sendo só o eixo. O que se mostra é que não há medição. */}
        {width > 0 && !vazio && (
          <svg
            width={width}
            height={height}
            role="img"
            aria-label={t(mode === 'log' ? 'mon.chart.aria.log' : 'mon.chart.aria.linear', { iface })}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
            className="block"
          >
            {/* Traços do eixo, espelhados: o mesmo valor vale para cima e para
                baixo, e por isso o rótulo aparece dos dois lados. */}
            {scale.ticks.map((t, i) => {
              if (t <= 0) return null;
              const f = scale.project(t);
              const yA = axisY - f * half;
              const yB = axisY + f * half;
              const label = formatBps(t);
              return (
                <g key={`tick-${i}`}>
                  <line x1={padL} x2={padL + plotW} y1={yA} y2={yA} stroke="#1f2937" strokeDasharray="3 3" />
                  <line x1={padL} x2={padL + plotW} y1={yB} y2={yB} stroke="#1f2937" strokeDasharray="3 3" />
                  <text x={padL - 6} y={yA + 3} textAnchor="end" fontSize={AXIS_FONT} fill="#6b7280" className="font-mono">
                    {label}
                  </text>
                  <text x={padL - 6} y={yB + 3} textAnchor="end" fontSize={AXIS_FONT} fill="#6b7280" className="font-mono">
                    {label}
                  </text>
                </g>
              );
            })}

            {/* Linha do zero. */}
            <line x1={padL} x2={padL + plotW} y1={axisY} y2={axisY} stroke="#4b5563" />

            {/* A área preenchida só existe em linear, onde ela quer dizer
                alguma coisa. Em log a distância até o eixo é arbitrária (o
                piso é a década escolhida, não o zero) e o preenchimento vira
                um bloco sólido que sugere volume onde não há. */}
            {mode === 'linear' && (
              <>
                <path d={rxPath.area} fill={RX_COLOR} fillOpacity={0.16} />
                <path d={txPath.area} fill={TX_COLOR} fillOpacity={0.16} />
              </>
            )}

            <path d={rxPath.line} fill="none" stroke={RX_COLOR} strokeWidth={1.5} strokeLinejoin="round" />
            {rxPath.dots.map((d, i) => (
              <circle key={`rxd-${i}`} cx={d.x} cy={d.y} r={1.6} fill={RX_COLOR} />
            ))}

            <path d={txPath.line} fill="none" stroke={TX_COLOR} strokeWidth={1.5} strokeLinejoin="round" />
            {txPath.dots.map((d, i) => (
              <circle key={`txd-${i}`} cx={d.x} cy={d.y} r={1.6} fill={TX_COLOR} />
            ))}

            {/* Rótulos de tempo. */}
            {timeTicks.map((tt, k) => (
              <text
                key={`time-${k}`}
                x={Math.min(Math.max(x(tt.i), padL), padL + plotW)}
                y={height - 6}
                textAnchor={k === 0 ? 'start' : k === timeTicks.length - 1 ? 'end' : 'middle'}
                fontSize={AXIS_FONT}
                fill="#6b7280"
                className="font-mono"
              >
                {tt.label}
              </text>
            ))}

            {hover && (
              <line x1={hover.x} x2={hover.x} y1={PAD_TOP} y2={PAD_TOP + plotH} stroke="#4b5563" strokeDasharray="2 3" />
            )}
          </svg>
        )}

        {vazio && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
            {loading ? (
              <p className="text-gray-500 text-sm animate-pulse">{t('mon.chart.loadingHistory')}</p>
            ) : (
              <>
                <p className="text-gray-500 text-sm">{t('mon.chart.noSamples')}</p>
                <p className="text-gray-600 text-xs mt-1">
                  <span className="font-mono">—</span>{t('mon.chart.noSamples.suffix')}
                </p>
              </>
            )}
          </div>
        )}

        {ponto && !vazio && (
          <div
            className="pointer-events-none absolute top-1 rounded-lg border border-gray-700 bg-gray-950/95 px-2.5 py-1.5 text-[11px] shadow-xl"
            style={{
              left: Math.min(Math.max(hover!.x + 10, 0), Math.max(0, width - 150)),
            }}
          >
            <div className="text-gray-400 font-mono">{formatTime(ponto.t, spanMs)}</div>
            <div className="text-cyan-300 font-mono">↓ {formatBps(ponto.rx)}</div>
            <div className="text-emerald-300 font-mono">↑ {formatBps(ponto.tx)}</div>
          </div>
        )}
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-gray-500">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block w-3 h-0.5 rounded" style={{ background: RX_COLOR }} /> {t('mon.chart.legend.rx')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block w-3 h-0.5 rounded" style={{ background: TX_COLOR }} /> {t('mon.chart.legend.tx')}
        </span>
        <span className="sm:hidden font-mono text-cyan-300">{t('mon.chart.peak')} ↓ {formatBps(picoRx)}</span>
        <span className="sm:hidden font-mono text-emerald-300">{t('mon.chart.peak')} ↑ {formatBps(picoTx)}</span>
        {!vazio && reduced.length > 0 && (
          <span className="ml-auto">
            {t('mon.chart.coverage', {
              n: reduced.filter((p) => p.rx !== null || p.tx !== null).length,
              total: reduced.length,
            })}
          </span>
        )}
      </div>
    </div>
  );
}
