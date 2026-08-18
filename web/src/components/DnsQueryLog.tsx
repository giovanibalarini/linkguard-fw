import { useCallback, useEffect, useState } from 'react';
import { Search, RefreshCw, Ban, ScrollText, Info } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import Panel from './ui/Panel';
import IconButton from './ui/IconButton';

interface DNSQuery { time: string; client: string; name: string; type: string }

interface Props {
  loggingEnabled: boolean;
  canBlock: boolean;
  onBlock: (domain: string) => void | Promise<void>;
}

/**
 * DnsQueryLog shows recent resolved domains (from the unbound journal) so the
 * admin can see what each device is accessing and block a domain in one click.
 * Only meaningful when DNS query logging is enabled.
 */
export default function DnsQueryLog({ loggingEnabled, canBlock, onBlock }: Props) {
  const { t } = useI18n();
  const [queries, setQueries] = useState<DNSQuery[]>([]);
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(false);

  const fetchQueries = useCallback(async (filter: string) => {
    setLoading(true);
    try {
      const { data } = await client.get<DNSQuery[]>('/api/dns/queries', { params: { limit: 200, q: filter } });
      setQueries(data ?? []);
    } catch { setQueries([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchQueries(''); }, [fetchQueries]);

  const fmtTime = (t: string) => {
    const d = new Date(t);
    return isNaN(d.getTime()) ? t : d.toLocaleTimeString();
  };

  return (
    <Panel
      title={<span className="flex items-center gap-2"><ScrollText className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('svc.dnslog.title')}</span></span>}
      action={
        <div className="flex gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchQueries(q)}
              placeholder={t('svc.dnslog.filter.placeholder')}
              className="input pl-8 text-sm"
            />
          </div>
          <button onClick={() => fetchQueries(q)} className="btn-secondary flex items-center gap-1.5 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> {t('svc.common.refresh')}
          </button>
        </div>
      }
    >
      {!loggingEnabled && (
        <div className="flex items-start gap-2 rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-amber-300 text-sm mb-3">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{t('svc.dnslog.off.prefix')} <b>{t('svc.dnslog.off.word')}</b>{t('svc.dnslog.off.tail')}</span>
        </div>
      )}

      {queries.length === 0 ? (
        <p className="text-gray-600 text-sm py-2">{loggingEnabled ? t('svc.dnslog.empty') : t('svc.dnslog.noData')}</p>
      ) : (
        <>
          {/* Mobile: stacked cards (< sm) */}
          <div className="sm:hidden max-h-96 overflow-y-auto space-y-2">
            {queries.map((row, i) => (
              <div key={i} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-white font-mono font-medium truncate">{row.name}</div>
                    <div className="text-gray-500 text-xs whitespace-nowrap">{fmtTime(row.time)}</div>
                  </div>
                  {canBlock && (
                    <div className="flex shrink-0 gap-1">
                      <IconButton icon={Ban} onClick={() => onBlock(row.name)} label={t('svc.dnslog.blockDomain')} variant="danger" />
                    </div>
                  )}
                </div>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                  <dt className="text-gray-500">{t('svc.dnslog.col.source')}</dt>
                  <dd className="text-gray-400 font-mono">{row.client}</dd>
                  <dt className="text-gray-500">{t('svc.dnslog.col.type')}</dt>
                  <dd className="text-gray-400">{row.type}</dd>
                </dl>
              </div>
            ))}
          </div>

          {/* Desktop: table (>= sm) */}
          <div className="hidden sm:block overflow-x-auto max-h-96 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-2 pr-4 font-medium">{t('svc.dnslog.col.time')}</th>
                  <th className="pb-2 pr-4 font-medium">{t('svc.dnslog.col.source')}</th>
                  <th className="pb-2 pr-4 font-medium">{t('svc.dnslog.col.domain')}</th>
                  <th className="pb-2 pr-4 font-medium">{t('svc.dnslog.col.type')}</th>
                  {canBlock && <th className="pb-2 font-medium"></th>}
                </tr>
              </thead>
              <tbody>
                {queries.map((row, i) => (
                  <tr key={i} className="table-row">
                    <td className="py-1.5 pr-4 text-gray-500 whitespace-nowrap">{fmtTime(row.time)}</td>
                    <td className="py-1.5 pr-4 text-gray-400 font-mono">{row.client}</td>
                    <td className="py-1.5 pr-4 text-white font-mono truncate max-w-xs">{row.name}</td>
                    <td className="py-1.5 pr-4 text-gray-500 text-xs">{row.type}</td>
                    {canBlock && (
                      <td className="py-1.5">
                        <IconButton icon={Ban} onClick={() => onBlock(row.name)} label={t('svc.dnslog.blockDomain')} variant="danger" />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  );
}
