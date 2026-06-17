import { useEffect, useState, useCallback } from 'react';
import { Cpu, MemoryStick, HardDrive, Clock, Wifi, AlertTriangle, Activity, Server } from 'lucide-react';
import MetricCard, { ProgressCard } from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import { AlertBadge } from '../components/StatusBadge';
import client from '../api/client';
import type { SystemMetrics, WanLink, Alert } from '../types';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function Dashboard() {
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [wanLinks, setWanLinks] = useState<WanLink[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchAll = useCallback(async () => {
    try {
      const [sysRes, linksRes, alertsRes] = await Promise.all([
        client.get<SystemMetrics>('/api/system/status'),
        client.get<WanLink[]>('/api/links'),
        client.get<Alert[]>('/api/alerts?unresolved=true'),
      ]);
      setSys(sysRes.data);
      setWanLinks(linksRes.data ?? []);
      setAlerts(alertsRes.data ?? []);
      setLastUpdated(new Date());
    } catch (e) {
      console.error('Dashboard fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-gray-500 animate-pulse">Carregando...</div>
      </div>
    );
  }

  const onlineLinks = wanLinks.filter(l => l.status === 'online').length;
  const offlineLinks = wanLinks.filter(l => l.status === 'offline').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-500 text-sm mt-0.5">Visão geral do sistema</p>
        </div>
        <div className="text-gray-600 text-xs">
          Atualizado às {lastUpdated.toLocaleTimeString()}
        </div>
      </div>

      {/* Critical alerts banner */}
      {criticalAlerts > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300 text-sm">
            {criticalAlerts} alerta{criticalAlerts !== 1 ? 's' : ''} crítico{criticalAlerts !== 1 ? 's' : ''} ativo{criticalAlerts !== 1 ? 's' : ''}.
            Verifique a aba de Alertas.
          </p>
        </div>
      )}

      {/* System metrics */}
      {sys && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Uptime"
            value={sys.uptime_str || '—'}
            icon={Clock}
            iconColor="text-green-400"
            subtitle={`Load: ${sys.load_avg[0].toFixed(2)} ${sys.load_avg[1].toFixed(2)} ${sys.load_avg[2].toFixed(2)}`}
          />
          <ProgressCard
            title="CPU"
            percent={sys.cpu_percent}
            value={`${sys.cpu_percent.toFixed(1)}%`}
            icon={Cpu}
            iconColor="text-blue-400"
          />
          <ProgressCard
            title="Memória"
            percent={sys.mem_percent}
            value={`${formatBytes(sys.mem_used_bytes)} / ${formatBytes(sys.mem_total_bytes)}`}
            icon={MemoryStick}
            iconColor="text-purple-400"
          />
          <ProgressCard
            title="Disco"
            percent={sys.disk_percent}
            value={`${formatBytes(sys.disk_used_bytes)} / ${formatBytes(sys.disk_total_bytes)}`}
            icon={HardDrive}
            iconColor="text-orange-400"
          />
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricCard
          title="Links Online"
          value={onlineLinks}
          icon={Wifi}
          iconColor="text-green-400"
          subtitle={`${wanLinks.length} total configurados`}
        />
        <MetricCard
          title="Links Offline"
          value={offlineLinks}
          icon={Server}
          iconColor={offlineLinks > 0 ? 'text-red-400' : 'text-gray-400'}
          subtitle={offlineLinks > 0 ? 'Ação necessária' : 'Todos os links operacionais'}
        />
        <MetricCard
          title="Alertas Ativos"
          value={alerts.length}
          icon={AlertTriangle}
          iconColor={alerts.length > 0 ? 'text-yellow-400' : 'text-gray-400'}
          subtitle={`${criticalAlerts} crítico(s)`}
        />
      </div>

      {/* WAN Links */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-white font-semibold">Links WAN</h2>
          <Activity className="w-4 h-4 text-gray-500" />
        </div>
        {wanLinks.length === 0 ? (
          <p className="text-gray-500 text-sm text-center py-4">
            Nenhum link WAN configurado. Acesse a seção Links WAN para adicionar.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Link</th>
                  <th className="pb-3 pr-4 font-medium">Interface</th>
                  <th className="pb-3 pr-4 font-medium">IP</th>
                  <th className="pb-3 pr-4 font-medium">Gateway</th>
                  <th className="pb-3 pr-4 font-medium">Latência</th>
                  <th className="pb-3 pr-4 font-medium">Perda</th>
                  <th className="pb-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {wanLinks.map(link => (
                  <tr key={link.id} className="table-row">
                    <td className="py-3 pr-4 text-white font-medium">{link.name}</td>
                    <td className="py-3 pr-4 text-gray-400 font-mono">{link.interface}</td>
                    <td className="py-3 pr-4 text-gray-400 font-mono">{link.ip_address || '—'}</td>
                    <td className="py-3 pr-4 text-gray-400 font-mono">{link.gateway || '—'}</td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'}
                    </td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.packet_loss > 0 ? `${link.packet_loss.toFixed(1)}%` : '0%'}
                    </td>
                    <td className="py-3">
                      <StatusBadge status={link.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Recent alerts */}
      {alerts.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold">Alertas Recentes</h2>
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="space-y-2">
            {alerts.slice(0, 5).map(alert => (
              <div key={alert.id} className="flex items-start gap-3 p-3 bg-gray-800 rounded-lg">
                <AlertBadge severity={alert.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium">{alert.title}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{alert.message}</p>
                </div>
                <span className="text-gray-600 text-xs flex-shrink-0">
                  {new Date(alert.created_at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
