import { useEffect, useState } from 'react';
import { RefreshCw, Globe, Ban, Plus, X, Play } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import DnsQueryLog from '../components/DnsQueryLog';
import Panel from '../components/ui/Panel';
import type { DNSData, NetsvcConfig } from '../types';

export default function Dns() {
  const { can } = useAuth();
  const canWrite = can('dns.write');
  const [data, setData] = useState<DNSData | null>(null);
  const [cfg, setCfg] = useState<NetsvcConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [newDomain, setNewDomain] = useState('');

  const fetchData = async () => {
    setLoading(true); setError(false);
    try {
      const res = await client.get<DNSData>('/api/dns');
      setData(res.data); setCfg(res.data.config);
    } catch { setError(true); } finally { setLoading(false); }
  };
  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true); setMsg('');
    try { await fn(); if (ok) setMsg(ok); await fetchData(); }
    catch (e: any) { setMsg(`Erro: ${e.response?.data?.error || e.message}`); }
    finally { setBusy(false); }
  };

  const saveConfig = () => cfg && run(() => client.put('/api/dns/config', { upstreams: cfg.upstreams, log_queries: cfg.log_queries }), 'Config DNS salva — aplicando automaticamente.');
  const addDomain = () => newDomain.trim() && run(() => client.post('/api/dns/blocklist', { domain: newDomain.trim() }), 'Domínio bloqueado — aplicando automaticamente.').then(() => setNewDomain(''));
  const delDomain = (d: string) => run(() => client.delete('/api/dns/blocklist', { data: { domain: d } }), 'Domínio desbloqueado — aplicando automaticamente.');
  const apply = () => run(() => client.post('/api/netsvc/apply'), 'Aplicado com sucesso.');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">DNS</h1>
          <p className="text-gray-500 text-sm">Resolver {data?.backend === 'kea-unbound' ? '(unbound)' : ''} — upstreams, log e filtro</p>
        </div>
        <div className="flex gap-2">
          {canWrite && <button onClick={apply} disabled={busy} title="Salvar já aplica sozinho; use para forçar agora" className="btn-secondary flex items-center gap-2 disabled:opacity-50"><Play className="w-4 h-4" /> Aplicar agora</button>}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Atualizar</button>
        </div>
      </div>

      {data?.last_apply && !data.last_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Última aplicação automática falhou: {data.last_apply.error || 'erro desconhecido'}. Corrija e use "Aplicar agora".
        </div>
      )}

      {/* I-7: o apply funcionou, mas o backend teve que descartar entradas
          que a tela continua exibindo (domínio de bloqueio inválido,
          upstream malformado, servidor NTP que não parseia). "Aplicado" e
          "tudo o que você configurou está em vigor" não são a mesma
          afirmação — esta faixa é a diferença entre as duas. */}
      {data?.last_apply?.warning && (
        <div className="card border border-amber-500/30 bg-amber-500/10 text-amber-400 text-sm">
          Aplicado, mas nem tudo entrou em vigor: {data.last_apply.warning} Revise os valores marcados e salve de novo.
        </div>
      )}
      <p className="text-gray-500 text-xs">Salvar config ou filtro já aplica automaticamente (sem reiniciar o serviço).</p>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={fetchData} className="underline">Tentar novamente</button></div>}
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {loading || !cfg ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : (
        <>
          <Panel title={<span className="flex items-center gap-2"><Globe className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Resolução</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="label">Upstreams / forwarders (separados por vírgula)</label>
                <input className="input w-full" placeholder="1.1.1.1, 8.8.8.8 (vazio = recursivo)" value={cfg.upstreams.join(', ')} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, upstreams: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
                <p className="text-xs text-gray-600 mt-1">Vazio = unbound resolve recursivamente da raiz.</p>
              </div>
              <div>
                <label className="label">Log de queries</label>
                <label className="flex items-center gap-2 mt-2 cursor-pointer">
                  <input type="checkbox" className="w-4 h-4" checked={cfg.log_queries} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, log_queries: e.target.checked })} />
                  <span className="text-gray-300 text-sm">Registrar cada consulta (visibilidade por host — custo de I/O)</span>
                </label>
              </div>
            </div>
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>

          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">Filtro / blocklist</span></span>}>
            <p className="text-gray-500 text-xs mb-3">Domínios bloqueados resolvem para NXDOMAIN (estilo Pi-hole). Lembre: DNS é visibilidade/filtro, não enforcement — o bloqueio real é no firewall.</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder="dominio.com" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addDomain()} />
                <button onClick={addDomain} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> Bloquear</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {(data?.blocklist.length ?? 0) === 0 && <span className="text-gray-600 text-sm">Nenhum domínio bloqueado.</span>}
              {data?.blocklist.map((d) => (
                <span key={d} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{d}{canWrite && <button onClick={() => delDomain(d)} className="text-gray-500 hover:text-green-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </Panel>

          <DnsQueryLog
            loggingEnabled={!!cfg?.log_queries}
            canBlock={canWrite}
            onBlock={(domain) => run(() => client.post('/api/dns/blocklist', { domain }), `Domínio ${domain} bloqueado.`)}
          />
        </>
      )}
    </div>
  );
}
