import { useEffect, useState, useCallback, useRef } from 'react';
import { Cpu, MemoryStick, HardDrive, Clock, AlertTriangle } from 'lucide-react';
import MetricCard, { ProgressCard } from '../components/MetricCard';
import GettingStarted from '../components/GettingStarted';
import Recipes from '../components/Recipes';
import SystemHealth from '../components/SystemHealth';
import Panel from '../components/ui/Panel';
import Stat from '../components/ui/Stat';
import Tag, { type TagVariant } from '../components/ui/Tag';
import Sparkline, { type SparklinePoint } from '../components/ui/Sparkline';
import { AlertBadge } from '../components/StatusBadge';
import { deriveRate, type RateCounter } from '../lib/interfaceRates';
import client from '../api/client';
import { useI18n } from '../i18n';
import type { SystemMetrics, WanLink, Alert, NetHost, TrafficHistoryResponse, HostTraffic } from '../types';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

function formatRelativeTime(iso: string, lang: 'pt' | 'en'): string {
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const diffMin = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
  if (Math.abs(diffMin) < 60) return rtf.format(diffMin, 'minute');
  const diffHour = Math.round(diffMin / 60);
  if (Math.abs(diffHour) < 24) return rtf.format(diffHour, 'hour');
  return rtf.format(Math.round(diffHour / 24), 'day');
}

const statusVariant: Record<string, TagVariant> = {
  online: 'ok',
  offline: 'crit',
  degraded: 'warn',
  unknown: 'idle',
};

const statusLabel: Record<string, string> = {
  online: 'online',
  offline: 'offline',
  degraded: 'degradado',
  unknown: 'desconhecido',
};

export default function Dashboard() {
  const { t, lang } = useI18n();
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [wanLinks, setWanLinks] = useState<WanLink[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hosts, setHosts] = useState<NetHost[]>([]);
  const [talkers, setTalkers] = useState<HostTraffic[]>([]);
  const [rates, setRates] = useState<Record<string, { rx: number; tx: number }>>({});
  const [sparklines, setSparklines] = useState<Record<string, SparklinePoint[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const prevCountersRef = useRef<Record<string, RateCounter>>({});

  const fetchData = useCallback(async () => {
    try {
      const [sysRes, linksRes, alertsRes, hostsRes] = await Promise.all([
        client.get<SystemMetrics>('/api/system/status'),
        client.get<WanLink[]>('/api/links'),
        client.get<Alert[]>('/api/alerts?unresolved=true'),
        client.get<NetHost[]>('/api/hosts'),
      ]);
      setSys(sysRes.data);
      setWanLinks(linksRes.data ?? []);
      setAlerts(alertsRes.data ?? []);
      setHosts(hostsRes.data ?? []);

      client.get<HostTraffic[]>('/api/hosts/traffic').then(
        (res) => setTalkers(res.data ?? []),
        () => setTalkers([]),
      );

      const now = Date.now();
      const nextRates: Record<string, { rx: number; tx: number }> = {};
      for (const iface of sysRes.data.interfaces ?? []) {
        const prev = prevCountersRef.current[iface.name];
        const rate = deriveRate(prev, iface, now);
        if (rate) nextRates[iface.name] = rate;
        prevCountersRef.current[iface.name] = { ts: now, rx: iface.rx_bytes, tx: iface.tx_bytes };
      }
      setRates((prev) => ({ ...prev, ...nextRates }));

      setLastUpdated(new Date());
      setError(false);
    } catch (e) {
      console.error('Dashboard fetch error:', e);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Sparkline dos últimos 30 min por link WAN, via tsdb (mesmo endpoint usado
  // em Interfaces.tsx). Roda numa cadência mais espaçada — não precisa do
  // mesmo ritmo do polling de taxa/status.
  useEffect(() => {
    if (wanLinks.length === 0) return;
    let alive = true;
    const load = async () => {
      const results = await Promise.all(
        wanLinks.map(async (link) => {
          try {
            const { data } = await client.get<TrafficHistoryResponse>(
              `/api/system/traffic-history?iface=${encodeURIComponent(link.interface)}&range=30m`,
            );
            const points: SparklinePoint[] = data.points.map((p) => ({ ts: p.timestamp, rx: p.rx_bps, tx: p.tx_bps }));
            return [link.interface, points] as const;
          } catch {
            return [link.interface, []] as const;
          }
        }),
      );
      if (!alive) return;
      setSparklines(Object.fromEntries(results));
    };
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [wanLinks]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-gray-500 animate-pulse">Carregando...</div>
      </div>
    );
  }

  const onlineLinks = wanLinks.filter((l) => l.status === 'online').length;
  const criticalAlerts = alerts.filter((a) => a.severity === 'critical').length;
  const hostsOnline = hosts.filter((h) => h.online).length;
  const trafficNowBps = wanLinks.reduce((sum, l) => sum + (rates[l.interface]?.rx ?? 0) + (rates[l.interface]?.tx ?? 0), 0);
  const hasTrafficSample = wanLinks.some((l) => rates[l.interface]);

  return (
    <div className="p-6 space-y-6">
      <GettingStarted />
      <Recipes />
      <SystemHealth />

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('dashboard.title')}</h1>
          <p className="text-gray-500 text-sm mt-0.5">{t('dashboard.subtitle')}</p>
        </div>
        <div className="text-xs">
          {error ? (
            <span className="text-amber-400">Dados desatualizados desde {lastUpdated.toLocaleTimeString()}</span>
          ) : (
            <span className="text-gray-600">Atualizado às {lastUpdated.toLocaleTimeString()}</span>
          )}
        </div>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between">
          <span>Falha ao carregar dados do firewall. Exibindo últimos dados conhecidos.</span>
          <button onClick={fetchData} className="btn-secondary">Tentar novamente</button>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {sys && (
          <Stat
            label="WAN ativas"
            value={`${onlineLinks}/${wanLinks.length}`}
            variant={wanLinks.length > 0 && onlineLinks === wanLinks.length ? 'ok' : wanLinks.length > 0 ? 'crit' : 'idle'}
          />
        )}
        {sys && <Stat label="Tráfego agora" value={hasTrafficSample ? formatRate(trafficNowBps) : '—'} />}
        <Stat label="Hosts ativos" value={hostsOnline} sub={`${hosts.length} conhecidos`} />
        {sys && <Stat label="Uptime" value={sys.uptime_str || '—'} />}
      </div>

      {wanLinks.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {wanLinks.map((link) => {
            const rate = rates[link.interface];
            const variant = statusVariant[link.status] ?? 'idle';
            return (
              <Panel
                key={link.id}
                title={link.name}
                action={<Tag variant={variant} dot>{statusLabel[link.status] ?? link.status}</Tag>}
              >
                <div className="flex items-baseline justify-between mb-2">
                  <div className="text-2xl font-bold text-white font-mono">
                    {rate ? formatRate(rate.rx + rate.tx) : '—'}
                  </div>
                  <div className="text-gray-500 text-xs">
                    {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'} · {link.packet_loss > 0 ? `${link.packet_loss.toFixed(1)}%` : '0%'} perda
                  </div>
                </div>
                <Sparkline data={sparklines[link.interface] ?? []} height={48} />
              </Panel>
            );
          })}
        </div>
      )}

      {sys && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Uptime"
            value={sys.uptime_str || '—'}
            icon={Clock}
            iconColor="text-green-400"
            subtitle={`Load: ${(sys.load_avg?.[0] ?? 0).toFixed(2)} ${(sys.load_avg?.[1] ?? 0).toFixed(2)} ${(sys.load_avg?.[2] ?? 0).toFixed(2)}`}
          />
          <ProgressCard
            title="CPU"
            percent={sys.cpu_percent ?? 0}
            value={`${(sys.cpu_percent ?? 0).toFixed(1)}%`}
            icon={Cpu}
            iconColor="text-blue-400"
          />
          <ProgressCard
            title="Memória"
            percent={sys.mem_percent ?? 0}
            value={`${formatBytes(sys.mem_used_bytes ?? 0)} / ${formatBytes(sys.mem_total_bytes ?? 0)}`}
            icon={MemoryStick}
            iconColor="text-purple-400"
          />
          <ProgressCard
            title="Disco"
            percent={sys.disk_percent ?? 0}
            value={`${formatBytes(sys.disk_used_bytes ?? 0)} / ${formatBytes(sys.disk_total_bytes ?? 0)}`}
            icon={HardDrive}
            iconColor="text-orange-400"
          />
        </div>
      )}

      {talkers.length > 0 && (
        <Panel title="Top consumidores agora">
          <p className="text-gray-500 text-xs -mt-2 mb-3">Fluxos ativos no momento — não é total acumulado.</p>
          <div className="space-y-2">
            {talkers.slice(0, 8).map((tlk) => {
              const host = hosts.find((h) => h.ip === tlk.ip);
              const name = host?.alias || host?.hostname || tlk.ip;
              const total = tlk.rx_bytes + tlk.tx_bytes;
              const max = (talkers[0].rx_bytes + talkers[0].tx_bytes) || 1;
              const pct = Math.max(4, Math.round((total / max) * 100));
              return (
                <div key={tlk.ip} className="flex items-center gap-3">
                  <span className="text-gray-300 text-sm w-32 truncate flex-shrink-0">{name}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2">
                    <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-gray-500 text-xs font-mono w-20 text-right flex-shrink-0">{formatBytes(total)}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {alerts.length > 0 && (
        <Panel title="Precisa de atenção">
          <div className="space-y-2">
            {alerts.slice(0, 5).map((alert) => (
              <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-800 rounded-lg">
                <AlertBadge severity={alert.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium">{alert.title}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{alert.message}</p>
                </div>
                <span className="text-gray-600 text-xs flex-shrink-0">{formatRelativeTime(alert.created_at, lang)}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {criticalAlerts > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300 text-sm">
            {criticalAlerts} alerta{criticalAlerts !== 1 ? 's' : ''} crítico{criticalAlerts !== 1 ? 's' : ''} ativo{criticalAlerts !== 1 ? 's' : ''}.
            Verifique a aba de Alertas.
          </p>
        </div>
      )}
    </div>
  );
}
