import { useEffect, useMemo, useRef, useState } from 'react';
import { Network, ArrowDownToLine, ArrowUpToLine, Pencil, Pause, Play, ChevronDown, ChevronUp } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine, Brush } from 'recharts';
import client from '../api/client';
import type { SystemMetrics, TrafficHistoryResponse } from '../types';
import { deriveRate } from '../lib/interfaceRates';

interface RatePoint {
  ts: number;
  label: string;
  rx: number;
  tx: number;
}

interface RateStats {
  last: number;
  avg: number;
  max: number;
  min: number;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatUptime(seconds: number): string {
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (days > 0) return `${days}d ${hours}h ${minutes}m ${secs}s`;
  if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function calcStats(values: number[]): RateStats {
  if (values.length === 0) {
    return { last: 0, avg: 0, max: 0, min: 0 };
  }
  let sum = 0;
  let min = values[0];
  let max = values[0];
  for (const v of values) {
    sum += v;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  return {
    last: values[values.length - 1],
    avg: sum / values.length,
    max,
    min,
  };
}

export default function Interfaces() {
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [aliasSaving, setAliasSaving] = useState<string>('');
  const [aliasFor, setAliasFor] = useState<string | null>(null);
  const [aliasValue, setAliasValue] = useState('');
  const [aliasError, setAliasError] = useState('');
  const [range, setRange] = useState<'5m' | '30m' | '12h' | '30d' | '1y' | '5y'>('5m');
  const [currentRates, setCurrentRates] = useState<Record<string, { rx: number; tx: number }>>({});
  const [rrdHistory, setRrdHistory] = useState<Record<string, RatePoint[]>>({});
  const [rrdLoading, setRrdLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [paused, setPaused] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const firstLoadRef = useRef(true);
  const pausedRef = useRef(false);

  const toggleExpanded = (name: string) => {
    setExpanded((prev) => ({ ...prev, [name]: !prev[name] }));
  };

  const prevCountersRef = useState<Record<string, { ts: number; rx: number; tx: number }>>({})[0];
  const secondHistoryRef = useState<Record<string, RatePoint[]>>({})[0];

  // Feeds the '5m' live tail only -- every other range reads real persisted
  // history from the backend (see chartDataFor), so there's no need to keep
  // building 5s/1min client-side rollups for them.
  const pushRateSample = (iface: string, ts: number, rxRate: number, txRate: number) => {
    const label = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const point: RatePoint = { ts, label, rx: rxRate, tx: txRate };

    const secondSeries = secondHistoryRef[iface] ?? [];
    secondSeries.push(point);
    if (secondSeries.length > 300) secondSeries.splice(0, secondSeries.length - 300);
    secondHistoryRef[iface] = secondSeries;
  };

  const fetchData = async () => {
    const firstLoad = firstLoadRef.current;
    if (firstLoad) {
      setLoading(true);
    }
    try {
      const res = await client.get<SystemMetrics>('/api/system/status');
      const now = Date.now();
      const nextRates: Record<string, { rx: number; tx: number }> = {};

      for (const iface of res.data.interfaces ?? []) {
        const prev = prevCountersRef[iface.name];
        const rate = deriveRate(prev, iface, now);
        if (rate) {
          nextRates[iface.name] = rate;
          pushRateSample(iface.name, now, rate.rx, rate.tx);
        }
        prevCountersRef[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
      }

      setCurrentRates((prev) => ({ ...prev, ...nextRates }));
      setSys(res.data);
      setLastUpdated(new Date());
      setError(false);
      firstLoadRef.current = false;
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      if (firstLoad) {
        setLoading(false);
      }
    }
  };

  const loadRrdHistory = async (showLoading = false) => {
    if (!sys || range === '5m') {
      return;
    }
    if (showLoading) setRrdLoading(true);
    try {
      const visible = (sys.interfaces ?? []).filter((i) => i.name !== 'lo');
      const results = await Promise.all(
        visible.map((iface) =>
          client.get<TrafficHistoryResponse>(`/api/system/traffic-history?iface=${encodeURIComponent(iface.name)}&range=${range}`)
        )
      );

      const next: Record<string, RatePoint[]> = {};
      for (const res of results) {
        const points = (res.data.points ?? []).map((p) => ({
          ts: p.timestamp * 1000,
          label: new Date(p.timestamp * 1000).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: range === '30d' ? undefined : '2-digit',
          }),
          rx: p.rx_bps,
          tx: p.tx_bps,
        }));
        next[res.data.interface] = points;
      }
      setRrdHistory(next);
      setError(false);
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      if (showLoading) setRrdLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      if (!pausedRef.current) fetchData();
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (range !== '5m') {
      loadRrdHistory(true);
      const interval = setInterval(() => {
        if (!pausedRef.current) loadRrdHistory();
      }, 30000);
      return () => clearInterval(interval);
    }
  }, [range, sys]);

  const togglePaused = () => {
    setPaused((p) => {
      const next = !p;
      pausedRef.current = next;
      return next;
    });
  };

  const openAlias = (ifaceName: string, currentAlias?: string) => {
    setAliasFor(ifaceName);
    setAliasValue(currentAlias || '');
    setAliasError('');
  };

  const saveAlias = async () => {
    if (!aliasFor) return;
    const ifaceName = aliasFor;
    setAliasSaving(ifaceName);
    setAliasError('');
    try {
      await client.put('/api/system/interface-aliases', {
        interface: ifaceName,
        alias: aliasValue.trim(),
      });
      setAliasFor(null);
      await fetchData();
    } catch (e) {
      console.error(e);
      setAliasError('Erro ao salvar apelido da interface');
    } finally {
      setAliasSaving('');
    }
  };

  const interfaces = useMemo(() => {
    return (sys?.interfaces ?? []).filter((iface) => iface.name !== 'lo');
  }, [sys]);

  // '5m' is a genuinely live tail — fed directly from the 1s poll below, no
  // round trip needed. Every other range (including 30m/12h, which used to
  // read from a client-side buffer that started empty on every page load —
  // "só reflete o tempo real" was the exact bug report) now reads real
  // persisted history from the backend, same as 30d/1y/5y always did.
  const chartDataFor = (ifaceName: string): RatePoint[] => {
    if (range === '5m') {
      return secondHistoryRef[ifaceName] ?? [];
    }
    return rrdHistory[ifaceName] ?? [];
  };

  const formatRate = (bytesPerSecond: number): string => `${formatBytes(bytesPerSecond)}/s`;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Interfaces</h1>
          <p className="text-gray-500 text-sm">
            Métricas vêm de /proc com histórico RRD persistente
            {sys && <> · uptime do host <span className="font-mono text-gray-400">{formatUptime(sys.uptime_seconds || 0)}</span></>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center rounded-lg border border-gray-700 bg-gray-900/70 p-1 text-xs">
            <button
              onClick={() => setRange('5m')}
              title="Janela de 5 minutos, amostra a cada 1s"
              className={`px-2 py-1 rounded ${range === '5m' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              5m (1s)
            </button>
            <button
              onClick={() => setRange('30m')}
              title="Janela de 30 minutos, amostra a cada 5s"
              className={`px-2 py-1 rounded ${range === '30m' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              30m (5s)
            </button>
            <button
              onClick={() => setRange('12h')}
              title="Janela de 12 horas, amostra a cada 1m"
              className={`px-2 py-1 rounded ${range === '12h' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              12h (1m)
            </button>
            <button
              onClick={() => setRange('30d')}
              title="Histórico de 30 dias (RRD persistente)"
              className={`px-2 py-1 rounded ${range === '30d' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              30d
            </button>
            <button
              onClick={() => setRange('1y')}
              title="Histórico de 1 ano (RRD persistente)"
              className={`px-2 py-1 rounded ${range === '1y' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              1y
            </button>
            <button
              onClick={() => setRange('5y')}
              title="Histórico de 5 anos (RRD persistente)"
              className={`px-2 py-1 rounded ${range === '5y' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              5y
            </button>
          </div>

          <div className="text-xs text-gray-600">
            {paused ? 'Pausado' : `Atualizado às ${lastUpdated.toLocaleTimeString()}`}
          </div>
          <button
            onClick={togglePaused}
            title={paused ? 'Retomar atualização automática (1s)' : 'Pausar atualização automática (1s)'}
            className="btn-secondary flex items-center gap-2"
          >
            {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            {paused ? 'Retomar' : 'Pausar'}
          </button>
        </div>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={() => { fetchData(); loadRrdHistory(true); }} className="underline">Tentar novamente</button></div>}

      {loading ? (
        <div className="card text-center py-10 text-gray-500 animate-pulse">Carregando interfaces...</div>
      ) : interfaces.length === 0 ? (
        <div className="card text-center py-10">
          <Network className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400">Nenhuma interface detectada</p>
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 2xl:grid-cols-6 gap-3">
          {interfaces.map((iface) => {
            const isOpen = !!expanded[iface.name];
            const rates = currentRates[iface.name] ?? { rx: 0, tx: 0 };
            const chartData = chartDataFor(iface.name);
            const plotData = chartData.map((p) => ({ ...p, tx_neg: -p.tx }));
            const rxStats = calcStats(chartData.map((p) => p.rx));
            const txStats = calcStats(chartData.map((p) => p.tx));
            const chartMax = Math.max(1, ...chartData.map((p) => Math.max(p.rx, p.tx)));
            const rxTrouble = iface.rx_errors > 0 || iface.rx_dropped > 0;
            const txTrouble = iface.tx_errors > 0 || iface.tx_dropped > 0;
            return (
              <div
                key={iface.name}
                className={`relative overflow-hidden rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-900 via-gray-900 to-gray-950 shadow-xl ${isOpen ? 'col-span-full' : ''}`}
              >
                <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-blue-500 via-cyan-400 to-green-400 opacity-70" />

                {/* Always-visible summary — click anywhere to expand/collapse.
                    Stacked (name on its own row), not crammed alongside the
                    rate numbers/sparkline/chevron: a narrow tile squeezing
                    all of that into one flex row collapsed the name's box to
                    zero width (reproduced and confirmed locally — looked like
                    a font bug, a flex-1/min-w-0 sizing issue). The name now
                    always gets the tile's full width. */}
                <button
                  onClick={() => toggleExpanded(iface.name)}
                  className="w-full text-left p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 text-blue-300 border border-blue-500/20">
                      <Network className="w-3 h-3" />
                    </span>
                    <h2 title={iface.alias || iface.name} className="min-w-0 flex-1 text-white font-semibold text-sm truncate">
                      {iface.alias || iface.name}
                    </h2>
                    {isOpen ? <ChevronUp className="w-4 h-4 text-gray-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" />}
                  </div>
                  {iface.alias && (
                    <p title={iface.name} className="ml-8 text-gray-500 text-[11px] font-mono truncate">{iface.name}</p>
                  )}
                  <div className="mt-1.5 flex items-center gap-3">
                    {!isOpen && chartData.length >= 2 && (
                      <div className="hidden sm:block flex-1 h-6 min-w-0">
                        <ResponsiveContainer width="100%" height="100%">
                          <LineChart data={chartData} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
                            <Line type="linear" dataKey="rx" stroke="#22d3ee" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                            <Line type="linear" dataKey="tx" stroke="#34d399" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                          </LineChart>
                        </ResponsiveContainer>
                      </div>
                    )}
                    <div className="ml-auto shrink-0 font-mono text-[11px] whitespace-nowrap">
                      <span className="text-cyan-300">↓{formatRate(rates.rx)}</span>
                      <span className="text-emerald-300 ml-2">↑{formatRate(rates.tx)}</span>
                    </div>
                  </div>
                </button>

                {isOpen && (
                  <div className="px-4 pb-4">
                    <div className="mb-3 flex justify-end">
                      <button
                        onClick={(e) => { e.stopPropagation(); openAlias(iface.name, iface.alias); }}
                        disabled={aliasSaving === iface.name}
                        className="rounded-lg border border-gray-700 bg-gray-900/80 px-3 py-1.5 text-xs text-gray-300 hover:border-blue-500/50 hover:text-blue-300 disabled:opacity-50"
                      >
                        <span className="inline-flex items-center gap-2">
                          <Pencil className="w-3.5 h-3.5" />
                          {aliasSaving === iface.name ? 'Salvando...' : iface.alias ? 'Editar apelido' : 'Adicionar apelido'}
                        </span>
                      </button>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div className="rounded-lg border border-gray-800 bg-gray-950/70 px-3 py-2">
                        <div className="flex items-center gap-1.5 text-gray-500 text-[11px] uppercase tracking-wide">
                          <ArrowDownToLine className="w-3 h-3 text-cyan-400" />
                          RX <span className="ml-auto text-cyan-300 font-mono normal-case">{formatRate(rates.rx)}</span>
                        </div>
                        <div className="text-white font-mono text-sm mt-0.5">{formatBytes(iface.rx_bytes)}</div>
                        <div className="text-gray-500 text-[11px] mt-0.5">
                          {iface.rx_packets.toLocaleString()} pacotes
                          {rxTrouble && (
                            <span className="text-amber-400"> · {iface.rx_errors} erros, {iface.rx_dropped} descartes</span>
                          )}
                        </div>
                      </div>

                      <div className="rounded-lg border border-gray-800 bg-gray-950/70 px-3 py-2">
                        <div className="flex items-center gap-1.5 text-gray-500 text-[11px] uppercase tracking-wide">
                          <ArrowUpToLine className="w-3 h-3 text-green-400" />
                          TX <span className="ml-auto text-emerald-300 font-mono normal-case">{formatRate(rates.tx)}</span>
                        </div>
                        <div className="text-white font-mono text-sm mt-0.5">{formatBytes(iface.tx_bytes)}</div>
                        <div className="text-gray-500 text-[11px] mt-0.5">
                          {iface.tx_packets.toLocaleString()} pacotes
                          {txTrouble && (
                            <span className="text-amber-400"> · {iface.tx_errors} erros, {iface.tx_dropped} descartes</span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="mt-2 rounded-lg border border-gray-800 bg-gray-900/70 p-2.5">
                      <div className="mb-1 flex items-center justify-between">
                        <p className="text-gray-500 text-[11px] uppercase tracking-wide">Consumo ({range})</p>
                        {chartData.length >= 2 && <p className="text-[11px] text-gray-600">arraste pra dar zoom</p>}
                      </div>
                      {chartData.length < 2 ? (
                        <p className="text-gray-500 text-sm py-6 text-center">
                          {range !== '5m' && rrdLoading
                            ? 'Carregando histórico...'
                            : 'Aguardando amostras...'}
                        </p>
                      ) : (
                        <ResponsiveContainer width="100%" height={160}>
                          <LineChart data={plotData} margin={{ left: 0, right: 4, top: 4, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                            <XAxis dataKey="label" tick={{ fill: '#6b7280', fontSize: 10 }} minTickGap={range === '5m' ? 36 : 20} />
                            <YAxis
                              domain={[-chartMax, chartMax]}
                              tick={{ fill: '#6b7280', fontSize: 10 }}
                              tickFormatter={(v) => formatBytes(Math.abs(Number(v)))}
                              width={60}
                            />
                            <ReferenceLine y={0} stroke="#4b5563" strokeDasharray="6 6" />
                            <Tooltip
                              contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
                              formatter={(value: number, name: string) => [formatRate(Math.abs(Number(value))), name === 'rx' ? 'RX' : 'TX']}
                            />
                            <Line type="linear" dataKey="rx" stroke="#22d3ee" strokeWidth={2} dot={false} isAnimationActive={false} />
                            <Line type="linear" dataKey="tx_neg" name="tx" stroke="#34d399" strokeWidth={2} dot={false} isAnimationActive={false} />
                            <Brush dataKey="label" height={18} travellerWidth={6} stroke="#374151" fill="#111827" />
                          </LineChart>
                        </ResponsiveContainer>
                      )}

                      {chartData.length >= 2 && (
                        <div className="mt-2 rounded-md border border-gray-800 bg-gray-950/70 px-2 py-1.5 font-mono text-[11px]">
                          <div className="grid grid-cols-5 gap-1 text-gray-600">
                            <span></span><span>LAST</span><span>AVG</span><span>MAX</span><span>MIN</span>
                          </div>
                          <div className="grid grid-cols-5 gap-1 text-cyan-300">
                            <span className="text-gray-500">RX</span>
                            <span>{formatRate(rxStats.last)}</span>
                            <span>{formatRate(rxStats.avg)}</span>
                            <span>{formatRate(rxStats.max)}</span>
                            <span>{formatRate(rxStats.min)}</span>
                          </div>
                          <div className="grid grid-cols-5 gap-1 text-emerald-300">
                            <span className="text-gray-500">TX</span>
                            <span>{formatRate(txStats.last)}</span>
                            <span>{formatRate(txStats.avg)}</span>
                            <span>{formatRate(txStats.max)}</span>
                            <span>{formatRate(txStats.min)}</span>
                          </div>
                        </div>
                      )}
                    </div>

                    {iface.addresses && iface.addresses.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {iface.addresses.map((addr) => (
                          <span
                            key={`${iface.name}-${addr.cidr}`}
                            title={addr.family}
                            className="rounded-md border border-gray-800 bg-gray-900/70 px-2 py-1 text-[11px] font-mono text-gray-300"
                          >
                            {addr.ip}<span className="text-gray-600">/{addr.subnet.split('/')[1] ?? addr.subnet}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {aliasFor && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-sm">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Apelido da interface</h2>
              <p className="text-gray-500 text-xs mt-1 font-mono">{aliasFor}</p>
            </div>
            <div className="p-6 space-y-4">
              <input
                className="input w-full"
                placeholder="Ex.: WAN, LAN, Fibra"
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                autoFocus
              />
              <p className="text-gray-500 text-xs">Deixe vazio para remover o apelido.</p>
              {aliasError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{aliasError}</div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={saveAlias}
                  disabled={aliasSaving === aliasFor}
                  className="btn-primary flex-1 disabled:opacity-50"
                >
                  {aliasSaving === aliasFor ? 'Salvando...' : 'Salvar'}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}