import { useEffect, useState } from 'react';
import { RefreshCw, FileText, X } from 'lucide-react';
import client from '../api/client';
import type { AuditLog } from '../types';
import Panel from '../components/ui/Panel';
import { useI18n } from '../i18n';

const ACTIONS = ['create', 'update', 'delete', 'login', 'failover'] as const;
const LIMIT = 200;

export default function Logs() {
  const { t } = useI18n();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [filter, setFilter] = useState('');
  const [action, setAction] = useState('');

  const fetchData = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(LIMIT) });
      const term = [action, filter].filter(Boolean).join(' ').trim();
      if (term) params.append('filter', term);
      const res = await client.get<AuditLog[]>(`/api/logs?${params}`);
      setLogs(res.data ?? []);
      setError(false);
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const hasFilter = filter !== '' || action !== '';

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
          <h1 className="text-xl font-bold text-white">{t('mon.logs.title')}</h1>
          <p className="text-gray-500 text-sm">
            {t(
              logs.length !== 1
                ? (hasFilter ? 'mon.logs.count.many.filtered' : 'mon.logs.count.many')
                : (hasFilter ? 'mon.logs.count.one.filtered' : 'mon.logs.count.one'),
              { n: logs.length },
            )}
          </p>
        </div>
        <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {t('mon.refresh')}
        </button>
      </div>

      {/* Error banner */}
      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between"><span>{t('mon.error.load')}</span><button onClick={fetchData} className="btn-secondary">{t('mon.error.retry')}</button></div>}

      <div className="flex flex-col sm:flex-row gap-2">
        <select
          className="input sm:w-48"
          value={action}
          onChange={e => { setAction(e.target.value); }}
        >
          <option value="">{t('mon.logs.action.all')}</option>
          {ACTIONS.map(a => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <div className="relative flex-1">
          <input
            className="input w-full pr-9"
            placeholder={t('mon.logs.search.placeholder')}
            value={filter}
            onChange={e => setFilter(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && fetchData()}
          />
          {filter && (
            <button
              type="button"
              onClick={() => setFilter('')}
              aria-label={t('mon.logs.search.clear')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <button onClick={fetchData} className="btn-secondary">{t('mon.logs.search.submit')}</button>
      </div>

      <Panel>
        {loading && logs.length === 0 ? (
          <div className="text-center py-8 text-gray-500 animate-pulse">{t('mon.loading')}</div>
        ) : logs.length === 0 && error ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">{t('mon.logs.loadFail.title')}</p>
            <p className="text-gray-600 text-sm mt-1">{t('mon.logs.loadFail.hint')}</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">{t('mon.logs.empty')}</p>
          </div>
        ) : (
          <div>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {logs.map(log => (
                <div key={log.id} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <span className={`font-mono text-xs font-medium ${actionColors[log.action.toLowerCase()] ?? 'text-gray-400'}`}>
                        {log.action}
                      </span>
                      <div className="text-white font-medium truncate">{log.resource || '—'}</div>
                    </div>
                    <div className="text-gray-500 text-xs shrink-0 text-right">{new Date(log.created_at).toLocaleString()}</div>
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('mon.logs.col.user')}</dt>
                    <dd className="text-gray-300">{log.user}</dd>
                    <dt className="text-gray-500">{t('mon.logs.col.details')}</dt>
                    <dd className="text-gray-400">{log.details || '—'}</dd>
                  </dl>
                </div>
              ))}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">{t('mon.logs.col.datetime')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('mon.logs.col.user')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('mon.logs.col.action')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('mon.logs.col.resource')}</th>
                    <th className="pb-3 font-medium">{t('mon.logs.col.details')}</th>
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
                      <td className="py-3 text-gray-500 text-xs max-w-xs truncate" title={log.details}>{log.details || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {logs.length >= LIMIT && (
              <p className="text-gray-600 text-xs text-center mt-4">
                {t('mon.logs.limit', { n: LIMIT })}
              </p>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
