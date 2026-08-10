import { useEffect, useState } from 'react';
import { RefreshCw, Clock, Play, Download } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import Panel from '../components/ui/Panel';
import type { NTPData, NTPConfig } from '../types';

export default function Ntp() {
  const { can } = useAuth();
  const canWrite = can('ntp.write');
  const [data, setData] = useState<NTPData | null>(null);
  const [cfg, setCfg] = useState<NTPConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const fetchData = async () => {
    setLoading(true); setError(false);
    try {
      const res = await client.get<NTPData>('/api/ntp');
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

  const saveConfig = () => cfg && run(() => client.put('/api/ntp/config', { servers: cfg.servers, timezone: cfg.timezone }), 'Config de NTP salva — aplicando automaticamente.');
  const apply = () => run(() => client.post('/api/ntp/apply'), 'Aplicado com sucesso.');
  const installChrony = () => run(() => client.post('/api/ntp/install-chrony'), 'chrony instalado.');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">NTP</h1>
          <p className="text-gray-500 text-sm">Sincronização de horário — servidores, fuso horário e status</p>
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

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={fetchData} className="underline">Tentar novamente</button></div>}
      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {loading || !cfg ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : (
        <>
          <Panel title={<span className="flex items-center gap-2"><Clock className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Status</span></span>}>
            {!data?.status.installed ? (
              <div className="space-y-3">
                <p className="text-gray-400 text-sm">O chrony (serviço de sincronização NTP) não está instalado nesta máquina.</p>
                {canWrite && (
                  <button onClick={installChrony} disabled={busy} className="btn-primary flex items-center gap-2 disabled:opacity-50"><Download className="w-4 h-4" /> Instalar chrony</button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="text-gray-500">Sincronizado</div>
                  <div className={data?.status.synced ? 'text-green-400' : 'text-red-400'}>{data?.status.synced ? 'Sim' : 'Não'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Stratum</div>
                  <div className="text-white">{data?.status.stratum ?? '—'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Offset</div>
                  <div className="text-white font-mono">{data?.status.offset_secs != null ? `${(data.status.offset_secs * 1000).toFixed(3)} ms` : '—'}</div>
                </div>
                <div>
                  <div className="text-gray-500">Fonte</div>
                  <div className="text-white font-mono truncate">{data?.status.source || '—'}</div>
                </div>
              </div>
            )}
          </Panel>

          <Panel title={<span className="flex items-center gap-2"><Clock className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Configuração</span></span>}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="label">Servidores NTP (separados por vírgula)</label>
                <input className="input w-full" placeholder="a.ntp.br, b.ntp.br (vazio = pool padrão do Debian)" value={cfg.servers.join(', ')} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, servers: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
                <p className="text-xs text-gray-600 mt-1">Vazio = usa o pool padrão do Debian, sem gerenciar nada.</p>
              </div>
              <div>
                <label className="label">Fuso horário</label>
                <select className="input w-full" value={cfg.timezone} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, timezone: e.target.value })}>
                  <option value="">Não gerenciar (mantém o que já está configurado)</option>
                  {data?.timezones.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
                </select>
              </div>
            </div>
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>
        </>
      )}
    </div>
  );
}
