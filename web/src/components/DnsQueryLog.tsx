import { useCallback, useEffect, useState } from 'react';
import { Search, RefreshCw, Ban, ScrollText, Info } from 'lucide-react';
import client from '../api/client';

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
    <div className="card">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <ScrollText className="w-4 h-4 text-blue-400" />
          <h3 className="text-white font-semibold">Consultas recentes</h3>
        </div>
        <div className="flex gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchQueries(q)}
              placeholder="Filtrar por domínio ou IP"
              className="input pl-8 text-sm"
            />
          </div>
          <button onClick={() => fetchQueries(q)} className="btn-secondary flex items-center gap-1.5 text-sm">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Atualizar
          </button>
        </div>
      </div>

      {!loggingEnabled && (
        <div className="flex items-start gap-2 rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-amber-300 text-sm mb-3">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <span>O registro de consultas está <b>desligado</b>. Ative "Registrar consultas" acima e clique em Aplicar para começar a ver os acessos. (Tem custo de I/O em redes grandes.)</span>
        </div>
      )}

      {queries.length === 0 ? (
        <p className="text-gray-600 text-sm py-2">{loggingEnabled ? 'Nenhuma consulta encontrada ainda.' : 'Sem dados.'}</p>
      ) : (
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-gray-900">
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-2 pr-4 font-medium">Hora</th>
                <th className="pb-2 pr-4 font-medium">Origem</th>
                <th className="pb-2 pr-4 font-medium">Domínio</th>
                <th className="pb-2 pr-4 font-medium">Tipo</th>
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
                      <button onClick={() => onBlock(row.name)} className="text-gray-500 hover:text-red-400 inline-flex items-center gap-1 text-xs" title="Bloquear este domínio">
                        <Ban className="w-3.5 h-3.5" /> Bloquear
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
