import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowUpToLine, Network } from 'lucide-react';
import client from '../api/client';
import TrafficChart from '../components/TrafficChart';
import { deriveRate, type RateCounter } from '../lib/interfaceRates';
import {
  TRAFFIC_WINDOWS,
  contiguousRuns,
  formatBps,
  formatVolume,
  isEmptySeries,
  niceScale,
  pointsFromHistory,
  reduceToWidth,
  seriesPeak,
  totalBytes,
  windowFor,
} from '../lib/series';
import type { Point, ScaleMode } from '../lib/series';
import type { SystemMetrics, TrafficHistoryResponse } from '../types';
import { useI18n } from '../i18n';

// Tudo que vem da API passa por `lib/series.ts` — `pointsFromHistory` para o
// histórico, `bitsFromBytes` (dentro de `deriveRate`) para os contadores de
// `/api/system/status`. Nenhum campo da API é lido na mão aqui: os três erros
// já cometidos com este endpoint (o parâmetro é `iface`, não `interface`; os
// campos são `rx_bps`/`tx_bps`, não `rx`/`tx`; e, apesar do nome `_bps`, o
// backend grava BYTES por segundo) nasceram todos de mapear campo dentro de
// uma tela.

// O rótulo da janela é texto de tela, mas a lista TRAFFIC_WINDOWS é dado
// compartilhado (lib/series.ts, também lido pelos widgets): traduzi-la lá
// obrigaria a biblioteca a conhecer o idioma. Então o range — que é id — vira
// chave aqui, e o rótulo cru fica de reserva caso alguém acrescente uma janela
// sem passar por esta tabela.
const WINDOW_LABEL_KEY: Record<string, string> = {
  '30m': 'mon.traffic.window.label.30m',
  '12h': 'mon.traffic.window.label.12h',
  '30d': 'mon.traffic.window.label.30d',
  '1y': 'mon.traffic.window.label.1y',
};

/** De quanto em quanto tempo se relê o histórico, por janela. */
function refreshMs(range: string): number {
  return range === '30m' ? 10_000 : 60_000;
}

/** Uma linha da faixa: o que a tela precisa saber de cada interface. */
interface Faixa {
  name: string;
  alias?: string;
  /** Taxa atual em bits/s; `null` enquanto não há duas leituras de contador. */
  rateRx: number | null;
  rateTx: number | null;
  /** Série da janela, já em bits/s. */
  points: Point[];
  /** `true` enquanto o histórico desta janela ainda não voltou. */
  loading: boolean;
}

/**
 * Minigráfico da faixa: a mesma redução por máximo do gráfico grande, no
 * mesmo desenho espelhado. Sem amostra ele não desenha nada — nem uma linha
 * reta no zero, que é a forma mais fácil de fazer um link fora do ar parecer
 * um link ocioso.
 */
function Mini({ points, mode }: { points: Point[]; mode: ScaleMode }) {
  const W = 120;
  const H = 28;
  const reduced = useMemo(() => reduceToWidth(points, 40), [points]);

  if (reduced.length === 0 || isEmptySeries(reduced)) {
    return (
      <div className="flex items-center justify-center font-mono text-gray-600" style={{ width: W, height: H }}>
        —
      </div>
    );
  }

  const scale = niceScale(
    reduced.reduce((m, p) => Math.max(m, p.rx ?? 0, p.tx ?? 0), 0),
    mode,
  );
  const half = H / 2;
  const step = W / reduced.length;
  const x = (i: number) => (i + 0.5) * step;

  const draw = (values: (number | null)[], up: boolean) =>
    contiguousRuns(values)
      .filter((run) => run.length > 1)
      .map((run) =>
        run
          .map((i, k) => {
            const v = scale.project(values[i] as number) * half;
            return `${k === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${(up ? half - v : half + v).toFixed(1)}`;
          })
          .join(' '),
      )
      .join(' ');

  return (
    <svg width={W} height={H} className="block" aria-hidden="true">
      <line x1={0} x2={W} y1={half} y2={half} stroke="#374151" strokeWidth={0.5} />
      <path d={draw(reduced.map((p) => p.rx), true)} fill="none" stroke="#22d3ee" strokeWidth={1.2} />
      <path d={draw(reduced.map((p) => p.tx), false)} fill="none" stroke="#34d399" strokeWidth={1.2} />
    </svg>
  );
}

export default function Traffic() {
  const { t } = useI18n();
  const [range, setRange] = useState<string>(TRAFFIC_WINDOWS[0].range);
  const [mode, setMode] = useState<ScaleMode>('linear');
  const [selected, setSelected] = useState<string | null>(null);

  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [rates, setRates] = useState<Record<string, { rx: number; tx: number }>>({});
  const [history, setHistory] = useState<Record<string, Point[]>>({});
  const [histLoading, setHistLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const prevCounters = useRef<Record<string, RateCounter>>({});
  const win = windowFor(range);

  // `lo` fica de fora porque o coletor do tsdb também a pula
  // (internal/tsdb/traffic.go): mostrá-la seria uma linha que nunca teria
  // histórico nenhum, por construção — e a faixa ficaria com um `—` que não
  // quer dizer "link caído", só "nunca foi medida".
  const interfaces = useMemo(
    () => (sys?.interfaces ?? []).filter((i) => i.name !== 'lo'),
    [sys],
  );

  // ─── Taxa atual: contadores de /api/system/status ──────────────────────────
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { data } = await client.get<SystemMetrics>('/api/system/status');
        if (!alive) return;
        const now = Date.now();
        const next: Record<string, { rx: number; tx: number }> = {};
        for (const iface of data.interfaces ?? []) {
          const rate = deriveRate(prevCounters.current[iface.name], iface, now);
          if (rate) next[iface.name] = rate;
          prevCounters.current[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
        }
        setRates((prev) => ({ ...prev, ...next }));
        setSys(data);
        setLastUpdated(new Date());
        setError(false);
      } catch {
        if (alive) setError(true);
      }
    };
    load();
    const t = setInterval(load, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // ─── Histórico da janela, por interface ────────────────────────────────────
  const names = useMemo(() => interfaces.map((i) => i.name).join(','), [interfaces]);

  const loadHistory = useCallback(async () => {
    const list = names ? names.split(',') : [];
    if (list.length === 0) return;
    const results = await Promise.all(
      list.map(async (name) => {
        try {
          const { data } = await client.get<TrafficHistoryResponse>(
            `/api/system/traffic-history?iface=${encodeURIComponent(name)}&range=${range}`,
          );
          return [name, pointsFromHistory(data.points ?? [])] as const;
        } catch {
          // Falha de leitura não é ausência de tráfego: sem série, a faixa
          // mostra `—`, que é o que se sabe.
          return [name, [] as Point[]] as const;
        }
      }),
    );
    setHistory(Object.fromEntries(results));
    setHistLoading(false);
  }, [names, range]);

  useEffect(() => {
    setHistLoading(true);
    setHistory({});
    loadHistory();
    const t = setInterval(loadHistory, refreshMs(range));
    return () => clearInterval(t);
  }, [loadHistory, range]);

  // A seleção segue o operador; sem escolha, abre na primeira interface.
  const active = selected && interfaces.some((i) => i.name === selected) ? selected : interfaces[0]?.name ?? null;

  const faixas: Faixa[] = interfaces.map((i) => ({
    name: i.name,
    alias: i.alias,
    rateRx: rates[i.name]?.rx ?? null,
    rateTx: rates[i.name]?.tx ?? null,
    points: history[i.name] ?? [],
    loading: histLoading,
  }));

  const activePoints = active ? history[active] ?? [] : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-xl font-bold text-white">{t('mon.traffic.title')}</h1>
          <p className="text-gray-500 text-sm mt-0.5">
            {t('mon.traffic.unit.prefix')}<span className="font-mono">Mb/s</span>{t('mon.traffic.unit.rest')}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div
            className="flex items-center rounded-lg border border-gray-700 bg-gray-900/70 p-1 text-xs"
            role="group"
            aria-label={t('mon.traffic.window.aria')}
          >
            {TRAFFIC_WINDOWS.map((w) => {
              const labelKey = WINDOW_LABEL_KEY[w.range];
              const label = labelKey ? t(labelKey) : w.label;
              return (
              <button
                key={w.range}
                type="button"
                onClick={() => setRange(w.range)}
                aria-pressed={range === w.range}
                title={t('mon.traffic.window.title', { label, step: w.stepLabel })}
                className={`px-2 py-1 rounded whitespace-nowrap ${
                  range === w.range ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {label}
              </button>
              );
            })}
          </div>
          <span className="text-xs text-gray-600">
            {t('mon.traffic.step.prefix')}<span className="font-mono">{win.stepLabel}</span>
            {lastUpdated && <> · {lastUpdated.toLocaleTimeString()}</>}
          </span>
        </div>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('mon.traffic.error')}
        </div>
      )}

      {/* ─── A faixa ─────────────────────────────────────────────────────── */}
      {interfaces.length === 0 ? (
        <div className="card text-center py-10">
          <Network className="w-10 h-10 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">{t('mon.traffic.noIfaces')}</p>
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <ul className="divide-y divide-gray-800">
            {faixas.map((f) => {
              const pico = seriesPeak(f.points);
              const total = totalBytes(f.points, win.step);
              const semAmostra = f.points.length === 0 || isEmptySeries(f.points);
              const isActive = f.name === active;
              return (
                <li key={f.name}>
                  <button
                    type="button"
                    onClick={() => setSelected(f.name)}
                    aria-pressed={isActive}
                    className={`w-full text-left px-4 py-3 transition-colors ${
                      isActive ? 'bg-blue-500/10' : 'hover:bg-gray-800/50'
                    }`}
                  >
                    {/* Em tela estreita as três informações empilham numa
                        ordem fixa (nome, taxa, pico/total). Deixar o flex-wrap
                        decidir sozinho fazia cada linha da faixa quebrar num
                        lugar diferente, conforme o tamanho do número — duas
                        interfaces lado a lado ficavam desalinhadas. */}
                    <div className="flex flex-col gap-1.5 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-4 sm:gap-y-2">
                      <div className="min-w-0 sm:flex-1 sm:basis-40">
                        <div className="flex items-center gap-2 min-w-0">
                          <span
                            className={`h-2 w-2 rounded-full shrink-0 ${isActive ? 'bg-blue-400' : 'bg-gray-700'}`}
                            aria-hidden="true"
                          />
                          <span className="text-white text-sm font-medium truncate">{f.alias || f.name}</span>
                          {f.alias && <span className="text-gray-600 text-xs font-mono truncate">{f.name}</span>}
                        </div>
                      </div>

                      <div className="font-mono text-xs whitespace-nowrap">
                        <span className="text-cyan-300 inline-flex items-center gap-1">
                          <ArrowDownToLine className="w-3 h-3" />
                          {formatBps(f.rateRx)}
                        </span>
                        <span className="text-emerald-300 inline-flex items-center gap-1 ml-3">
                          <ArrowUpToLine className="w-3 h-3" />
                          {formatBps(f.rateTx)}
                        </span>
                      </div>

                      <div className="hidden sm:block shrink-0">
                        {f.loading ? (
                          <div className="w-[120px] h-[28px] flex items-center justify-center text-gray-600 text-[11px] animate-pulse">
                            ...
                          </div>
                        ) : (
                          <Mini points={f.points} mode={mode} />
                        )}
                      </div>

                      <div className="flex items-center gap-4 text-[11px] whitespace-nowrap sm:ml-auto">
                        <span className="text-gray-500">
                          {t('mon.traffic.peak')} <span className="font-mono text-gray-300">{f.loading ? '…' : formatBps(pico)}</span>
                        </span>
                        <span className="text-gray-500">
                          {t('mon.traffic.total')} <span className="font-mono text-gray-300">{f.loading ? '…' : formatVolume(total)}</span>
                        </span>
                      </div>
                    </div>

                    {/* `—` quer dizer não medido, e a faixa diz isso por
                        extenso: um link fora do ar não pode passar por um
                        link ocioso só porque a coluna mostraria zero. */}
                    {!f.loading && semAmostra && (
                      <p className="mt-1 text-[11px] text-gray-600">
                        {t('mon.traffic.noSample.prefix')}<span className="font-mono">—</span>{t('mon.traffic.noSample.suffix')}
                      </p>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* ─── O gráfico grande ────────────────────────────────────────────── */}
      {active && (
        <TrafficChart
          points={activePoints}
          iface={active}
          mode={mode}
          onModeChange={setMode}
          loading={histLoading}
        />
      )}
    </div>
  );
}
