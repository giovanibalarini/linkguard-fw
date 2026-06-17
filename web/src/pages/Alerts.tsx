import { useEffect, useState } from 'react';
import { RefreshCw, Bell, CheckCircle } from 'lucide-react';
import { AlertBadge } from '../components/StatusBadge';
import client from '../api/client';
import type { Alert } from '../types';

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'unresolved'>('unresolved');

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const res = await client.get<Alert[]>(`/api/alerts${filter === 'unresolved' ? '?unresolved=true' : ''}`);
      setAlerts(res.data ?? []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAlerts(); }, [filter]);

  const handleResolve = async (id: string) => {
    try {
      await client.put(`/api/alerts/${id}/resolve`);
      await fetchAlerts();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Alertas</h1>
          <p className="text-gray-500 text-sm">{alerts.length} alerta{alerts.length !== 1 ? 's' : ''}</p>
        </div>
        <button onClick={fetchAlerts} className="btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Atualizar
        </button>
      </div>

      <div className="flex gap-2">
        {(['unresolved', 'all'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              filter === f ? 'bg-blue-600/20 text-blue-400' : 'bg-gray-800 text-gray-400 hover:text-gray-200'
            }`}
          >
            {f === 'unresolved' ? 'Não resolvidos' : 'Todos'}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {loading ? (
          <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
        ) : alerts.length === 0 ? (
          <div className="card text-center py-12">
            <Bell className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">Sem alertas</p>
            <p className="text-gray-600 text-sm mt-1">O sistema está operando normalmente</p>
          </div>
        ) : (
          alerts.map(alert => (
            <div key={alert.id} className={`card flex items-start gap-4 ${alert.resolved ? 'opacity-60' : ''}`}>
              <AlertBadge severity={alert.severity} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-4">
                  <p className="text-white font-medium">{alert.title}</p>
                  <span className="text-gray-600 text-xs flex-shrink-0">
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-gray-400 text-sm mt-1">{alert.message}</p>
                {alert.resolved && alert.resolved_at && (
                  <p className="text-green-600 text-xs mt-1">
                    Resolvido em {new Date(alert.resolved_at).toLocaleString()}
                  </p>
                )}
              </div>
              {!alert.resolved && (
                <button
                  onClick={() => handleResolve(alert.id)}
                  className="text-gray-500 hover:text-green-400 transition-colors flex-shrink-0"
                  title="Marcar como resolvido"
                >
                  <CheckCircle className="w-5 h-5" />
                </button>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
