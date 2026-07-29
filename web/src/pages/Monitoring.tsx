import { useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, RefreshCw } from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  ComposedChart, Area, Brush, ReferenceArea,
} from 'recharts';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import type { WanLink, SystemMetrics, TimelineResponse } from '../types';

interface HistoryPoint {
  time: string;
  [key: string]: number | string;
}

export default function Monitoring() {
  const [links, setLinks] = useState<WanLink[]>([]);
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [latencyHistory, setLatencyHistory] = useState<HistoryPoint[]>([]);
  const [cpuHistory, setCpuHistory] = useState<HistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const tickRef = useRef(0);
  const [searchParams] = useSearchParams();
  const [periodHours, setPeriodHours] = useState(1);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);

  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];

  const fetchData = async () => {
    setLoading(true);
    try {
      const [linksRes, sysRes] = await Promise.all([
        client.get<WanLink[]>('/api/links'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      const newLinks = linksRes.data ?? [];
      const newSys = sysRes.data;
      setLinks(newLinks);
      setSys(newSys);

      // Accumulate history (last 20 points)
      const timeLabel = new Date().toLocaleTimeString();
      tickRef.current++;

      const latencyPoint: HistoryPoint = { time: timeLabel };
      newLinks.forEach(l => { latencyPoint[l.name] = l.latency_ms; });
      setLatencyHistory(prev => [...prev.slice(-19), latencyPoint]);

      const cpuPoint: HistoryPoint = { time: timeLabel, CPU: newSys?.cpu_percent ?? 0, Memória: newSys?.mem_percent ?? 0 };
      setCpuHistory(prev => [...prev.slice(-19), cpuPoint]);
      setLastUpdated(new Date());
      setError(false);
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  const fetchTimeline = async () => {
    setTimelineLoading(true);
    try {
      const at = searchParams.get('at');
      const centerSec = at ? Math.floor(new Date(at).getTime() / 1000) : Math.floor(Date.now() / 1000);
      const halfWindow = (periodHours * 3600) / 2;
      const from = centerSec - halfWindow;
      const to = centerSec + halfWindow;
      const series = links.map(l => `link.latency_ms:${l.name}`).join(',');
      const states = links.map(l => `link:${l.name}`).join(',');
      const res = await client.get<TimelineResponse>('/api/monitoring/timeline', {
        params: { from, to, series, states },
      });
      setTimeline(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setTimelineLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (links.length > 0) {
      fetchTimeline();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [links.length, periodHours, searchParams]);

  // Tick once per second to refresh the "atualizado há Xs" caption
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const secondsAgo = lastUpdated ? Math.max(0, Math.floor((now - lastUpdated.getTime()) / 1000)) : null;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Monitoramento</h1>
          <p className="text-gray-500 text-sm">Métricas em tempo real</p>
          <p className="text-gray-600 text-xs mt-0.5">
            Atualização automática a cada 10s
            {secondsAgo !== null && ` · atualizado há ${secondsAgo}s`}
          </p>
        </div>
        <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Atualizar
        </button>
      </div>

      {/* Error banner */}
      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between"><span>Falha ao carregar dados do firewall. Exibindo últimos dados conhecidos.</span><button onClick={fetchData} className="btn-secondary">Tentar novamente</button></div>}

      {/* Initial loading skeleton */}
      {loading && links.length === 0 && !sys && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[0, 1, 2].map(i => (
            <div key={i} className="card text-gray-500 text-sm animate-pulse">Carregando...</div>
          ))}
        </div>
      )}

      {/* Link status cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {links.map((link, i) => (
          <div key={link.id} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-white font-medium">{link.name}</span>
              <span title={link.status} className={`w-2 h-2 rounded-full ${
                link.status === 'online' ? 'bg-green-400' :
                link.status === 'offline' ? 'bg-red-400' :
                link.status === 'degraded' ? 'bg-yellow-400' : 'bg-gray-400'
              } animate-pulse`} />
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Interface</span>
                <span className="text-gray-300 font-mono">{link.interface}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Latência</span>
                <span style={{ color: COLORS[i % COLORS.length] }} className="font-mono">
                  {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Perda de pacotes</span>
                <span className={`font-mono ${link.packet_loss > 10 ? 'text-red-400' : 'text-gray-300'}`}>
                  {link.packet_loss.toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Última verificação</span>
                <span className="text-gray-400 text-xs">
                  {link.last_check ? new Date(link.last_check).toLocaleTimeString() : '—'}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Latency chart */}
      {links.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Latência por Link (ms)</span></span>}>
          {latencyHistory.length > 1 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={latencyHistory}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
                <Legend />
                {links.map((link, i) => (
                  <Line key={link.id} type="monotone" dataKey={link.name} stroke={COLORS[i % COLORS.length]} dot={false} strokeWidth={2} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-gray-500 text-sm text-center py-12">Coletando dados…</p>
          )}
        </Panel>
      )}

      {/* CPU / Memory chart */}
      <Panel title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-purple-400" /><span className="text-white font-semibold">CPU e Memória (%)</span></span>}>
        {cpuHistory.length > 1 ? (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={cpuHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
              <Legend />
              <Line type="monotone" dataKey="CPU" stroke="#3b82f6" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="Memória" stroke="#8b5cf6" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-gray-500 text-sm text-center py-12">Coletando dados…</p>
        )}
      </Panel>

      {/* Correlated diagnostic timeline */}
      <Panel
        title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-emerald-400" /><span className="text-white font-semibold">Linha do tempo</span></span>}
        action={
          <div className="flex gap-2">
            {[1, 6, 24].map(h => (
              <button
                key={h}
                onClick={() => setPeriodHours(h)}
                className={`px-3 py-1 rounded text-xs ${periodHours === h ? 'bg-blue-600 text-white' : 'btn-secondary'}`}
              >
                {h === 1 ? '1h' : h === 6 ? '6h' : '24h'}
              </button>
            ))}
          </div>
        }
      >
        {timelineLoading && !timeline && (
          <p className="text-gray-500 text-sm text-center py-12">Carregando linha do tempo…</p>
        )}
        {timeline && timeline.series.every(s => s.points.length === 0) && (
          <p className="text-gray-500 text-sm text-center py-12">Sem dados no período selecionado.</p>
        )}
        {timeline && timeline.series.some(s => s.points.length > 0) && (
          <div className="space-y-6">
            {links.map((link, i) => {
              const latSeries = timeline.series.find(s => s.name === 'link.latency_ms' && s.label === link.name);
              if (!latSeries || latSeries.points.length === 0) return null;
              const data = latSeries.points.map(p => ({
                ts: p.ts * 1000, min: p.min, avg: p.avg, max: p.max,
              }));
              const episodes = timeline.states.filter(s => s.label === link.name && s.state !== 'online');
              const color = COLORS[i % COLORS.length];
              return (
                <div key={link.id}>
                  <p className="text-gray-400 text-xs mb-1">
                    {link.name} — latência (ms), faixa min–max · arraste na régua abaixo do gráfico pra dar zoom
                  </p>
                  <ResponsiveContainer width="100%" height={180}>
                    <ComposedChart data={data} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                      <XAxis
                        dataKey="ts" type="number" scale="time"
                        domain={['dataMin', 'dataMax']}
                        tickFormatter={formatTickTime}
                        tick={{ fill: '#6b7280', fontSize: 10 }}
                      />
                      <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} unit=" ms" width={56} />
                      <Tooltip content={<LatencyTooltip />} />
                      {episodes.map((s, idx) => (
                        <ReferenceArea
                          key={idx}
                          x1={s.started_at * 1000}
                          x2={s.ended_at ? s.ended_at * 1000 : Date.now()}
                          fill={s.state === 'offline' ? '#ef4444' : '#f59e0b'}
                          fillOpacity={0.12}
                          strokeOpacity={0}
                        />
                      ))}
                      <Area type="monotone" dataKey={(d: { min: number; max: number }) => [d.min, d.max]}
                        stroke="none" fill={color} fillOpacity={0.15} isAnimationActive={false} />
                      <Line type="monotone" dataKey="avg" stroke={color} dot={false} strokeWidth={2} isAnimationActive={false} />
                      <Brush
                        dataKey="ts" height={22} travellerWidth={8}
                        stroke="#374151" fill="#111827"
                        tickFormatter={formatTickTime}
                      />
                    </ComposedChart>
                  </ResponsiveContainer>
                </div>
              );
            })}
            {timeline.states.filter(s => s.state !== 'online').length > 0 && (
              <div>
                <p className="text-gray-400 text-xs mb-1">Episódios no período</p>
                <ul className="text-xs text-gray-300 space-y-1">
                  {timeline.states
                    .filter(s => s.state !== 'online')
                    .map((s, idx) => (
                      <li key={idx} className="flex justify-between">
                        <span>{s.label} → {s.state}</span>
                        <span className="text-gray-500">
                          {new Date(s.started_at * 1000).toLocaleTimeString()}
                          {s.ended_at ? ` – ${new Date(s.ended_at * 1000).toLocaleTimeString()}` : ' (em curso)'}
                        </span>
                      </li>
                    ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Panel>

      {/* Interface traffic */}
      {sys && sys.interfaces && sys.interfaces.length > 0 && (
        <Panel title="Tráfego por Interface">
          {/* Mobile: stacked cards (< sm) */}
          <div className="sm:hidden space-y-2">
            {sys.interfaces.filter(i => i.name !== 'lo').map(iface => (
              <div key={iface.name} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                <div className="text-white font-mono font-medium truncate">{iface.name}</div>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                  <dt className="text-gray-500">RX total</dt>
                  <dd className="text-gray-400 font-mono">{formatBytes(iface.rx_bytes)}</dd>
                  <dt className="text-gray-500">TX total</dt>
                  <dd className="text-gray-400 font-mono">{formatBytes(iface.tx_bytes)}</dd>
                  <dt className="text-gray-500">RX Pacotes</dt>
                  <dd className="text-gray-400 font-mono">{iface.rx_packets.toLocaleString()}</dd>
                  <dt className="text-gray-500">TX Pacotes</dt>
                  <dd className="text-gray-400 font-mono">{iface.tx_packets.toLocaleString()}</dd>
                  <dt className="text-gray-500">Erros</dt>
                  <dd className="text-gray-400 font-mono">{iface.rx_errors + iface.tx_errors}</dd>
                </dl>
              </div>
            ))}
          </div>

          {/* Desktop: table (>= sm) */}
          <div className="hidden sm:block overflow-x-auto">
            <table className="hidden sm:table w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Interface</th>
                  <th className="pb-3 pr-4 font-medium">RX total</th>
                  <th className="pb-3 pr-4 font-medium">TX total</th>
                  <th className="pb-3 pr-4 font-medium">RX Pacotes</th>
                  <th className="pb-3 pr-4 font-medium">TX Pacotes</th>
                  <th className="pb-3 font-medium">Erros</th>
                </tr>
              </thead>
              <tbody>
                {sys.interfaces.filter(i => i.name !== 'lo').map(iface => (
                  <tr key={iface.name} className="table-row">
                    <td className="py-3 pr-4 text-white font-mono">{iface.name}</td>
                    <td className="py-3 pr-4 text-gray-400">{formatBytes(iface.rx_bytes)}</td>
                    <td className="py-3 pr-4 text-gray-400">{formatBytes(iface.tx_bytes)}</td>
                    <td className="py-3 pr-4 text-gray-400">{iface.rx_packets.toLocaleString()}</td>
                    <td className="py-3 pr-4 text-gray-400">{iface.tx_packets.toLocaleString()}</td>
                    <td className="py-3 text-gray-400">{iface.rx_errors + iface.tx_errors}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// Short tick label for chart axes/brush: just the time for today, date+time
// otherwise, so browsing a longer period (or an alert deep-link into an
// older day) doesn't lose date context.
function formatTickTime(ms: number): string {
  const d = new Date(ms);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

interface LatencyTooltipProps {
  active?: boolean;
  payload?: { payload: { ts: number; min: number; avg: number; max: number } }[];
}

function LatencyTooltip({ active, payload }: LatencyTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-xs shadow-lg">
      <p className="text-gray-400 mb-1">{new Date(p.ts).toLocaleString()}</p>
      <p className="text-white font-mono">
        {p.avg.toFixed(1)} ms <span className="text-gray-500">média</span>
      </p>
      <p className="text-gray-400 font-mono">
        faixa {p.min.toFixed(1)}–{p.max.toFixed(1)} ms
      </p>
    </div>
  );
}
