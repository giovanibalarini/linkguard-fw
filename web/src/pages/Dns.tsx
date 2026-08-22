import { useEffect, useState } from 'react';
import { RefreshCw, Globe, Ban, Plus, X, Play } from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import DnsQueryLog from '../components/DnsQueryLog';
import Panel from '../components/ui/Panel';
import type { DNSData, NetsvcConfig } from '../types';

export default function Dns() {
  const { can } = useAuth();
  const { t } = useI18n();
  const canWrite = can('dns.write');
  const [data, setData] = useState<DNSData | null>(null);
  const [cfg, setCfg] = useState<NetsvcConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  // A cor da faixa sai de um booleano, e não de farejar o prefixo de `msg`.
  // `msg` guarda a frase já traduzida no idioma em que foi criada, e o seletor
  // de idioma mora no Layout, que não desmonta esta página: trocar de idioma
  // com a faixa na tela faria o teste de prefixo falhar e pintar de verde um
  // erro. O timeout continua NÃO sendo erro — ele diz que a aplicação segue
  // rodando em segundo plano.
  const [msgError, setMsgError] = useState(false);
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
    setBusy(true); setMsg(''); setMsgError(false);
    try { await fn(); if (ok) setMsg(ok); await fetchData(); }
    catch (e: any) {
      // Desistir de esperar não é o mesmo que ter falhado: se o LinkGuard
      // estiver instalando kea/unbound, o apt continua rodando fora do
      // ciclo de vida desta requisição (unidade transiente do systemd-run) e
      // o resultado real fica registrado em last_apply.
      const timeout = isTimeout(e);
      setMsgError(!timeout);
      setMsg(timeout
        ? t('svc.netsvc.applyTimeout')
        : `${t('svc.common.errorPrefix')}: ${e.response?.data?.error || e.message}`);
    }
    finally { setBusy(false); }
  };

  const saveConfig = () => cfg && run(() => client.put('/api/dns/config', {
    upstreams: cfg.upstreams,
    log_queries: cfg.log_queries,
    dnstap_enabled: cfg.dnstap_enabled,
    force_local_dns: cfg.force_local_dns,
    block_dot: cfg.block_dot,
    dns_except_ips: cfg.dns_except_ips ?? [],
  }), t('svc.dns.msg.configSaved'));
  const addDomain = () => newDomain.trim() && run(() => client.post('/api/dns/blocklist', { domain: newDomain.trim() }), t('svc.dns.msg.domainBlocked')).then(() => setNewDomain(''));
  const delDomain = (d: string) => run(() => client.delete('/api/dns/blocklist', { data: { domain: d } }), t('svc.dns.msg.domainUnblocked'));
  const apply = () => run(() => client.post('/api/netsvc/apply', null, { timeout: INSTALL_TIMEOUT_MS }), t('svc.common.applied'));

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">DNS</h1>
          <p className="text-gray-500 text-sm">{t('svc.dns.subtitle', { backend: data?.backend === 'kea-unbound' ? '(unbound)' : '' })}</p>
        </div>
        <div className="flex gap-2">
          {canWrite && <button onClick={apply} disabled={busy} title={t('svc.common.applyNow.title')} className="btn-secondary flex items-center gap-2 disabled:opacity-50"><Play className="w-4 h-4" /> {t('svc.common.applyNow')}</button>}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> {t('svc.common.refresh')}</button>
        </div>
      </div>

      {data?.last_apply && !data.last_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('svc.common.lastApplyFailed', { error: data.last_apply.error || t('svc.common.unknownError') })}
        </div>
      )}

      {/* I-7: o apply funcionou, mas o backend teve que descartar entradas
          que a tela continua exibindo (domínio de bloqueio inválido,
          upstream malformado, servidor NTP que não parseia). "Aplicado" e
          "tudo o que você configurou está em vigor" não são a mesma
          afirmação — esta faixa é a diferença entre as duas. */}
      {data?.last_apply?.warning && (
        <div className="card border border-amber-500/30 bg-amber-500/10 text-amber-400 text-sm">
          {t('svc.common.appliedWithWarnings', { warning: data.last_apply.warning })}
        </div>
      )}
      <p className="text-gray-500 text-xs">{t('svc.dns.autoApplyHint')}</p>

      {busy && (
        <div className="card border border-blue-500/30 bg-blue-500/10 text-blue-300 text-sm">
          {t('svc.netsvc.applying')}
        </div>
      )}
      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{t('svc.common.loadFailed')} <button onClick={fetchData} className="underline">{t('svc.common.tryAgain')}</button></div>}
      {msg && <div className={`card border text-sm ${msgError ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {loading || !cfg ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">{t('common.loading')}</div>
      ) : (
        <>
          <Panel title={<span className="flex items-center gap-2"><Globe className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('svc.dns.section.resolution')}</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="label">{t('svc.dns.field.upstreams')}</label>
                <input className="input w-full" placeholder={t('svc.dns.placeholder.upstreams')} value={cfg.upstreams.join(', ')} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, upstreams: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
                <p className="text-xs text-gray-600 mt-1">{t('svc.dns.hint.upstreams')}</p>
              </div>
              <div>
                <label className="label">{t('svc.dns.field.queryLog')}</label>
                <label className="flex items-center gap-2 mt-2 cursor-pointer">
                  <input type="checkbox" className="w-4 h-4" checked={cfg.log_queries} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, log_queries: e.target.checked })} />
                  <span className="text-gray-300 text-sm">{t('svc.dns.check.logQueries')}</span>
                </label>
                {/* Mapa endereço → nome (#116). Fica ao lado do log de consultas
                    porque é a mesma escolha: o que o resolver registra, e o que
                    isso custa. Um guarda o que foi PERGUNTADO; este, o que foi
                    RESPONDIDO — que é o que falta para toda tela do produto
                    parar de mostrar destino como número. */}
                <label className="flex items-center gap-2 mt-2 cursor-pointer">
                  <input type="checkbox" className="w-4 h-4" checked={!!cfg.dnstap_enabled} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, dnstap_enabled: e.target.checked })} />
                  <span className="text-gray-300 text-sm">{t('svc.dns.check.dnstap')}</span>
                </label>
                <p className="text-xs text-gray-600 mt-1">{t('svc.dns.hint.dnstap')}</p>
              </div>
            </div>
            {/* Fuga de DNS (#124). O texto abaixo é parte da feature: sem ele
                a tela venderia como controle o que é apenas redução. */}
            <div className="mt-5 pt-4 border-t border-gray-800">
              <label className="label">{t('svc.dns.field.leak')}</label>
              <p className="text-gray-500 text-xs mt-1">{t('svc.dns.leak.explain')}</p>
              <label className="flex items-center gap-2 mt-3 cursor-pointer">
                <input type="checkbox" className="w-4 h-4" checked={!!cfg.force_local_dns} disabled={!canWrite}
                  onChange={(e) => setCfg({ ...cfg, force_local_dns: e.target.checked })} />
                <span className="text-gray-300 text-sm">{t('svc.dns.check.forceLocal')}</span>
              </label>
              <label className="flex items-center gap-2 mt-2 cursor-pointer">
                <input type="checkbox" className="w-4 h-4" checked={!!cfg.block_dot} disabled={!canWrite}
                  onChange={(e) => setCfg({ ...cfg, block_dot: e.target.checked })} />
                <span className="text-gray-300 text-sm">{t('svc.dns.check.blockDot')}</span>
              </label>
              {(cfg.force_local_dns || cfg.block_dot) && (
                <label className="block mt-3">
                  <span className="text-gray-400 text-xs">{t('svc.dns.field.except')}</span>
                  <input
                    className="input mt-1 w-full font-mono text-sm"
                    disabled={!canWrite}
                    value={(cfg.dns_except_ips ?? []).join(', ')}
                    placeholder="192.168.3.9, 192.168.3.10"
                    onChange={(e) => setCfg({
                      ...cfg,
                      dns_except_ips: e.target.value.split(',').map((v) => v.trim()).filter(Boolean),
                    })}
                  />
                  <span className="text-gray-600 text-[11px]">{t('svc.dns.except.hint')}</span>
                </label>
              )}
              {(cfg.force_local_dns || cfg.block_dot) && (
                <p className="text-amber-300/80 text-xs mt-3">{t('svc.dns.leak.warning')}</p>
              )}
            </div>

            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">{t('svc.common.saveConfig')}</button></div>}
          </Panel>

          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">{t('svc.dns.section.blocklist')}</span></span>}>
            <p className="text-gray-500 text-xs mb-3">{t('svc.dns.blocklist.hint')}</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder={t('svc.dns.placeholder.domain')} value={newDomain} onChange={(e) => setNewDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addDomain()} />
                <button onClick={addDomain} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> {t('svc.dns.block')}</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {(data?.blocklist.length ?? 0) === 0 && <span className="text-gray-600 text-sm">{t('svc.dns.blocklist.empty')}</span>}
              {data?.blocklist.map((d) => (
                <span key={d} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{d}{canWrite && <button onClick={() => delDomain(d)} className="text-gray-500 hover:text-green-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </Panel>

          <DnsQueryLog
            loggingEnabled={!!cfg?.log_queries}
            canBlock={canWrite}
            onBlock={(domain) => run(() => client.post('/api/dns/blocklist', { domain }), t('svc.dns.msg.domainBlockedNamed', { domain }))}
          />
        </>
      )}
    </div>
  );
}
