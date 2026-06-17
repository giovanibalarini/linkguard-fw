import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Activity, Network, ArrowDownToLine, ArrowUpToLine, Pencil } from 'lucide-react';
import client from '../api/client';
import type { SystemMetrics } from '../types';

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
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await client.get<SystemMetrics>('/api/system/status');
      setSys(res.data);
      setLastUpdated(new Date());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Interfaces</h1>
          <p className="text-gray-500 text-sm">Visão de rede no estilo ifconfig, com apresentação mais limpa.</p>
        </div>
        <div className="flex items-center gap-3">
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
            const rxRate = sys ? Math.max(iface.rx_bytes / Math.max(sys.uptime_seconds || 1, 1), 0) : 0;
            const txRate = sys ? Math.max(iface.tx_bytes / Math.max(sys.uptime_seconds || 1, 1), 0) : 0;
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
                    <span className="text-gray-400 text-xs uppercase tracking-wide">Resumo estilo ifconfig</span>
                    <span className={`rounded-full px-2 py-1 text-xs font-medium ${index % 2 === 0 ? 'bg-blue-500/15 text-blue-300' : 'bg-cyan-500/15 text-cyan-300'}`}>
                      {iface.alias || iface.name}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
                    <div>
                      <p className="text-gray-500 text-xs mb-1">RX rate média</p>
                      <p className="text-white font-mono">{formatBytes(rxRate)}/s</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs mb-1">TX rate média</p>
                      <p className="text-white font-mono">{formatBytes(txRate)}/s</p>
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