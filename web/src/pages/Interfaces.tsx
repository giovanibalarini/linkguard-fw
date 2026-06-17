import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Activity, Network, ArrowDownToLine, ArrowUpToLine, Pencil } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import client from '../api/client';
import type { SystemMetrics } from '../types';

interface RatePoint {
  ts: number;
  label: string;
  rx: number;
  tx: number;
}

interface PendingMinute {
  bucketStart: number;
  sumRx: number;
  sumTx: number;
  count: number;
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

export default function Interfaces() {
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [aliasSaving, setAliasSaving] = useState<string>('');
  const [range, setRange] = useState<'30m' | '12h'>('30m');
  const [historyTick, setHistoryTick] = useState(0);
  const [currentRates, setCurrentRates] = useState<Record<string, { rx: number; tx: number }>>({});
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const prevCountersRef = useState<Record<string, { ts: number; rx: number; tx: number }>>({})[0];
  const rawHistoryRef = useState<Record<string, RatePoint[]>>({})[0];
  const minuteHistoryRef = useState<Record<string, RatePoint[]>>({})[0];
  const pendingMinuteRef = useState<Record<string, PendingMinute>>({})[0];

  const pushRateSample = (iface: string, ts: number, rxRate: number, txRate: number) => {
    const label = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const point: RatePoint = { ts, label, rx: rxRate, tx: txRate };

    const raw = rawHistoryRef[iface] ?? [];
    raw.push(point);
    if (raw.length > 360) raw.splice(0, raw.length - 360);
    rawHistoryRef[iface] = raw;

    const bucketStart = Math.floor(ts / 60000) * 60000;
    const pending = pendingMinuteRef[iface];
    if (!pending) {
      pendingMinuteRef[iface] = {
        bucketStart,
        sumRx: rxRate,
        sumTx: txRate,
        count: 1,
      };
      return;
    }

    if (pending.bucketStart === bucketStart) {
      pending.sumRx += rxRate;
      pending.sumTx += txRate;
      pending.count += 1;
      return;
    }

    const minutePoint: RatePoint = {
      ts: pending.bucketStart,
      label: new Date(pending.bucketStart).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      rx: pending.sumRx / Math.max(pending.count, 1),
      tx: pending.sumTx / Math.max(pending.count, 1),
    };
    const minSeries = minuteHistoryRef[iface] ?? [];
    minSeries.push(minutePoint);
    if (minSeries.length > 720) minSeries.splice(0, minSeries.length - 720);
    minuteHistoryRef[iface] = minSeries;

    pendingMinuteRef[iface] = {
      bucketStart,
      sumRx: rxRate,
      sumTx: txRate,
      count: 1,
    };
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await client.get<SystemMetrics>('/api/system/status');
      const now = Date.now();
      const nextRates: Record<string, { rx: number; tx: number }> = {};

      for (const iface of res.data.interfaces ?? []) {
        const prev = prevCountersRef[iface.name];
        if (prev) {
          const dt = (now - prev.ts) / 1000;
          if (dt > 0) {
            const rxDelta = Math.max(0, iface.rx_bytes - prev.rx);
            const txDelta = Math.max(0, iface.tx_bytes - prev.tx);
            const rxRate = rxDelta / dt;
            const txRate = txDelta / dt;
            nextRates[iface.name] = { rx: rxRate, tx: txRate };
            pushRateSample(iface.name, now, rxRate, txRate);
          }
        }
        prevCountersRef[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
      }

      setCurrentRates((prev) => ({ ...prev, ...nextRates }));
      setSys(res.data);
      setLastUpdated(new Date());
      setHistoryTick((v) => v + 1);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const editAlias = async (ifaceName: string, currentAlias?: string) => {
    const nextAlias = window.prompt(
      `Apelido para ${ifaceName} (deixe vazio para remover):`,
      currentAlias || ''
    );
    if (nextAlias === null) return;

    setAliasSaving(ifaceName);
    try {
      await client.put('/api/system/interface-aliases', {
        interface: ifaceName,
        alias: nextAlias.trim(),
      });
      await fetchData();
    } catch (e) {
      console.error(e);
      alert('Erro ao salvar apelido da interface');
    } finally {
      setAliasSaving('');
    }
  };

  const interfaces = useMemo(() => {
    return (sys?.interfaces ?? []).filter((iface) => iface.name !== 'lo');
  }, [sys]);

  const chartDataFor = (ifaceName: string): RatePoint[] => {
    if (range === '30m') {
      return rawHistoryRef[ifaceName] ?? [];
    }
    return minuteHistoryRef[ifaceName] ?? [];
  };

  const formatRate = (bytesPerSecond: number): string => `${formatBytes(bytesPerSecond)}/s`;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Interfaces</h1>
          <p className="text-gray-500 text-sm">Métricas vêm de /proc do Linux e são exibidas com taxa estilo ifstat + histórico em memória.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center rounded-lg border border-gray-700 bg-gray-900/70 p-1 text-xs">
            <button
              onClick={() => setRange('30m')}
              className={`px-2 py-1 rounded ${range === '30m' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              30m
            </button>
            <button
              onClick={() => setRange('12h')}
              className={`px-2 py-1 rounded ${range === '12h' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}
            >
              12h
            </button>
          </div>
          <div className="text-xs text-gray-600">Atualizado às {lastUpdated.toLocaleTimeString()}</div>
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Atualizar
          </button>
        </div>
      </div>

      {loading ? (
        <div className="card text-center py-10 text-gray-500 animate-pulse">Carregando interfaces...</div>
      ) : interfaces.length === 0 ? (
        <div className="card text-center py-10">
          <Network className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400">Nenhuma interface detectada</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {interfaces.map((iface, index) => {
            const rates = currentRates[iface.name] ?? { rx: 0, tx: 0 };
            const chartData = chartDataFor(iface.name);
            return (
              <div key={iface.name} className="relative overflow-hidden rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-900 via-gray-900 to-gray-950 p-5 shadow-xl">
                <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-blue-500 via-cyan-400 to-green-400 opacity-70" />
                <div className="flex items-start justify-between gap-4 mb-5">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="inline-flex h-8 w-8 items-center justify-center rounded-xl bg-blue-500/15 text-blue-300 border border-blue-500/20">
                        <Network className="w-4 h-4" />
                      </span>
                      <div>
                        <h2 className="text-white font-semibold text-lg">{iface.alias || iface.name}</h2>
                        {iface.alias && <p className="text-gray-500 text-xs font-mono">{iface.name}</p>}
                        <p className="text-gray-500 text-xs">Interface ativa</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 rounded-full border border-gray-700 bg-gray-900/80 px-3 py-1 text-xs text-gray-300">
                    <Activity className="w-3.5 h-3.5 text-green-400" />
                    RX {formatBytes(iface.rx_bytes)}
                  </div>
                </div>

                <div className="mb-4 flex justify-end">
                  <button
                    onClick={() => editAlias(iface.name, iface.alias)}
                    disabled={aliasSaving === iface.name}
                    className="rounded-lg border border-gray-700 bg-gray-900/80 px-3 py-1.5 text-xs text-gray-300 hover:border-blue-500/50 hover:text-blue-300 disabled:opacity-50"
                  >
                    <span className="inline-flex items-center gap-2">
                      <Pencil className="w-3.5 h-3.5" />
                      {aliasSaving === iface.name ? 'Salvando...' : iface.alias ? 'Editar apelido' : 'Adicionar apelido'}
                    </span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-xl border border-gray-800 bg-gray-950/70 p-4">
                    <div className="flex items-center gap-2 text-gray-400 text-xs uppercase tracking-wide mb-3">
                      <ArrowDownToLine className="w-3.5 h-3.5 text-cyan-400" />
                      Recebido
                    </div>
                    <div className="text-2xl font-semibold text-white">{formatBytes(iface.rx_bytes)}</div>
                    <div className="mt-3 space-y-1 text-sm text-gray-400">
                      <div className="flex items-center justify-between gap-3"><span>Pacotes</span><span className="font-mono text-gray-200">{iface.rx_packets.toLocaleString()}</span></div>
                      <div className="flex items-center justify-between gap-3"><span>Erros</span><span className="font-mono text-gray-200">{iface.rx_errors.toLocaleString()}</span></div>
                      <div className="flex items-center justify-between gap-3"><span>Descartes</span><span className="font-mono text-gray-200">{iface.rx_dropped.toLocaleString()}</span></div>
                    </div>
                  </div>

                  <div className="rounded-xl border border-gray-800 bg-gray-950/70 p-4">
                    <div className="flex items-center gap-2 text-gray-400 text-xs uppercase tracking-wide mb-3">
                      <ArrowUpToLine className="w-3.5 h-3.5 text-green-400" />
                      Enviado
                    </div>
                    <div className="text-2xl font-semibold text-white">{formatBytes(iface.tx_bytes)}</div>
                    <div className="mt-3 space-y-1 text-sm text-gray-400">
                      <div className="flex items-center justify-between gap-3"><span>Pacotes</span><span className="font-mono text-gray-200">{iface.tx_packets.toLocaleString()}</span></div>
                      <div className="flex items-center justify-between gap-3"><span>Erros</span><span className="font-mono text-gray-200">{iface.tx_errors.toLocaleString()}</span></div>
                      <div className="flex items-center justify-between gap-3"><span>Descartes</span><span className="font-mono text-gray-200">{iface.tx_dropped.toLocaleString()}</span></div>
                    </div>
                  </div>
                </div>

                <div className="mt-4 rounded-xl border border-gray-800 bg-gray-950/70 p-4">
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <span className="text-gray-400 text-xs uppercase tracking-wide">Resumo estilo ifstat</span>
                    <span className={`rounded-full px-2 py-1 text-xs font-medium ${index % 2 === 0 ? 'bg-blue-500/15 text-blue-300' : 'bg-cyan-500/15 text-cyan-300'}`}>
                      {iface.alias || iface.name}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
                    <div>
                      <p className="text-gray-500 text-xs mb-1">RX atual</p>
                      <p className="text-white font-mono">{formatRate(rates.rx)}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs mb-1">TX atual</p>
                      <p className="text-white font-mono">{formatRate(rates.tx)}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs mb-1">Uptime do host</p>
                      <p className="text-white font-mono">{formatUptime(sys?.uptime_seconds || 0)}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs mb-1">Estado</p>
                      <p className="text-white font-mono">UP</p>
                    </div>
                  </div>

                  <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900/70 p-3">
                    <div className="mb-2 flex items-center justify-between">
                      <p className="text-gray-500 text-xs uppercase tracking-wide">Consumo de rede ({range})</p>
                      <p className="text-xs text-gray-500">RRD em memória: 5s (30m) e 1m (12h)</p>
                    </div>
                    {chartData.length < 2 ? (
                      <p className="text-gray-500 text-sm">Aguardando amostras para desenhar o gráfico...</p>
                    ) : (
                      <ResponsiveContainer width="100%" height={180} key={`${iface.name}-${range}-${historyTick}`}>
                        <LineChart data={chartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="label" tick={{ fill: '#6b7280', fontSize: 10 }} minTickGap={20} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickFormatter={(v) => formatBytes(Number(v))} width={72} />
                          <Tooltip
                            contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                            formatter={(value: number, name: string) => [formatRate(Number(value)), name === 'rx' ? 'RX' : 'TX']}
                          />
                          <Line type="monotone" dataKey="rx" stroke="#22d3ee" dot={false} strokeWidth={2} />
                          <Line type="monotone" dataKey="tx" stroke="#34d399" dot={false} strokeWidth={2} />
                        </LineChart>
                      </ResponsiveContainer>
                    )}
                  </div>

                  <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900/70 p-3">
                    <p className="text-gray-500 text-xs mb-2 uppercase tracking-wide">Enderecos IP / Subnet</p>
                    {!iface.addresses || iface.addresses.length === 0 ? (
                      <p className="text-gray-500 text-sm">Sem endereco configurado</p>
                    ) : (
                      <div className="space-y-2">
                        {iface.addresses.map((addr) => (
                          <div key={`${iface.name}-${addr.cidr}`} className="grid grid-cols-3 gap-2 text-sm">
                            <span className="text-gray-400 uppercase">{addr.family}</span>
                            <span className="text-white font-mono">{addr.ip}</span>
                            <span className="text-cyan-300 font-mono">{addr.subnet}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {iface.rx_bytes + iface.tx_bytes > 0 && (
                    <div className="mt-4 h-2 rounded-full bg-gray-800 overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-blue-500 via-cyan-400 to-green-400" style={{ width: `${Math.min(100, ((iface.rx_bytes + iface.tx_bytes) / Math.max((sys?.disk_total_bytes || 1), 1)) * 100)}%` }} />
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}