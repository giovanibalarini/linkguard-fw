import { useEffect, useState } from 'react';
import { RefreshCw, FileText } from 'lucide-react';
import client from '../api/client';
import type { AuditLog } from '../types';

export default function Logs() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '200' });
      if (filter) params.append('filter', filter);
      const res = await client.get<AuditLog[]>(`/api/logs?${params}`);
      setLogs(res.data ?? []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, []);

  const actionColors: Record<string, string> = {
    create: 'text-green-400',
    update: 'text-blue-400',
    delete: 'text-red-400',
    login: 'text-purple-400',
    failover: 'text-yellow-400',
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Logs de Auditoria</h1>
          <p className="text-gray-500 text-sm">{logs.length} entradas</p>
        </div>
        <button onClick={fetchLogs} className="btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Atualizar
        </button>
      </div>

      <div className="flex gap-2">
        <input
          className="input flex-1"
          placeholder="Filtrar por ação..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && fetchLogs()}
        />
        <button onClick={fetchLogs} className="btn-secondary">Buscar</button>
      </div>

      <div className="card">
        {loading ? (
          <div className="text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">Nenhum log disponível</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Data/Hora</th>
                  <th className="pb-3 pr-4 font-medium">Usuário</th>
                  <th className="pb-3 pr-4 font-medium">Ação</th>
                  <th className="pb-3 pr-4 font-medium">Recurso</th>
                  <th className="pb-3 font-medium">Detalhes</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} className="table-row">
                    <td className="py-3 pr-4 text-gray-500 text-xs">{new Date(log.created_at).toLocaleString()}</td>
                    <td className="py-3 pr-4 text-gray-300">{log.user}</td>
                    <td className="py-3 pr-4">
                      <span className={`font-mono text-xs ${actionColors[log.action.toLowerCase()] ?? 'text-gray-400'}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-400 font-mono text-xs">{log.resource || '—'}</td>
                    <td className="py-3 text-gray-500 text-xs max-w-xs truncate">{log.details || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
