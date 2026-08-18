import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, Bell, CheckCircle, Loader2, Clock } from 'lucide-react';
import { AlertBadge } from '../components/StatusBadge';
import client from '../api/client';
import type { Alert } from '../types';
import { useI18n } from '../i18n';

export default function Alerts() {
  const { t } = useI18n();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'unresolved'>('unresolved');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await client.get<Alert[]>(`/api/alerts${filter === 'unresolved' ? '?unresolved=true' : ''}`);
      setAlerts(res.data ?? []);
      setError(false);
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleResolve = async (id: string) => {
    setResolvingId(id);
    try {
      await client.put(`/api/alerts/${id}/resolve`);
      await fetchData();
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      setResolvingId(null);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('mon.alerts.title')}</h1>
          <p className="text-gray-500 text-sm">
            {t(
              filter === 'unresolved'
                ? (alerts.length !== 1 ? 'mon.alerts.count.unresolved.many' : 'mon.alerts.count.unresolved.one')
                : (alerts.length !== 1 ? 'mon.alerts.count.all.many' : 'mon.alerts.count.all.one'),
              { n: alerts.length },
            )}
          </p>
          <p className="text-gray-600 text-xs mt-0.5">{t('mon.alerts.autoRefresh.30s')}</p>
        </div>
        <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {t('mon.refresh')}
        </button>
      </div>

      {/* Error banner */}
      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between"><span>{t('mon.error.load')}</span><button onClick={fetchData} className="btn-secondary">{t('mon.error.retry')}</button></div>}

      <div className="flex gap-2">
        {(['unresolved', 'all'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              filter === f ? 'bg-blue-600/20 text-blue-400' : 'bg-gray-800 text-gray-400 hover:text-gray-200'
            }`}
          >
            {f === 'unresolved' ? t('mon.alerts.filter.unresolved') : t('mon.alerts.filter.all')}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {loading && alerts.length === 0 ? (
          <div className="card text-center py-8 text-gray-500 animate-pulse">{t('mon.loading')}</div>
        ) : alerts.length === 0 && error ? (
          <div className="card text-center py-12">
            <Bell className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">{t('mon.alerts.loadFail.title')}</p>
            <p className="text-gray-600 text-sm mt-1">{t('mon.alerts.loadFail.hint')}</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="card text-center py-12">
            <Bell className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">{t('mon.alerts.empty.title')}</p>
            <p className="text-gray-600 text-sm mt-1">{t('mon.alerts.empty.hint')}</p>
          </div>
        ) : (
          alerts.map(alert => (
            <div key={alert.id} className={`card flex items-start gap-4 ${alert.resolved ? 'opacity-60' : ''}`}>
              <AlertBadge severity={alert.severity} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-4">
                  <p className="text-white font-medium">{alert.title}</p>
                  <span className="text-gray-600 text-xs shrink-0">
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-gray-400 text-sm mt-1">{alert.message}</p>
                {alert.resolved && alert.resolved_at && (
                  <p className="text-green-600 text-xs mt-1">
                    {t('mon.alerts.resolvedAt', { when: new Date(alert.resolved_at).toLocaleString() })}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Link
                  to={`/monitoring?at=${encodeURIComponent(alert.created_at)}`}
                  className="text-gray-500 hover:text-blue-400 transition-colors"
                  title={t('mon.alerts.timeline.title')}
                  aria-label={t('mon.alerts.timeline.aria')}
                >
                  <Clock className="w-5 h-5" />
                </Link>
                {!alert.resolved && (
                  <button
                    onClick={() => handleResolve(alert.id)}
                    disabled={resolvingId === alert.id}
                    className="text-gray-500 hover:text-green-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    title={t('mon.alerts.resolve.title')}
                    aria-label={t('mon.alerts.resolve.aria')}
                  >
                    {resolvingId === alert.id
                      ? <Loader2 className="w-5 h-5 animate-spin" />
                      : <CheckCircle className="w-5 h-5" />}
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
