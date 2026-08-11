import { useEffect, useState } from 'react';
import { RefreshCw, Clock, Play, Download, Wifi } from 'lucide-react';
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

  const saveConfig = () => cfg && run(() => client.put('/api/ntp/config', {
    servers: cfg.servers,
    timezone: cfg.timezone,
    serve_lan: cfg.serve_lan,
    allowed_networks: cfg.allowed_networks,
  }), 'Config de NTP salva — aplicando automaticamente.');
  const apply = () => run(() => client.post('/api/ntp/apply'), 'Aplicado com sucesso.');
  const installChrony = () => run(() => client.post('/api/ntp/install-chrony'), 'chrony instalado.');

  // Toggling serve_lan on for the first time (list still empty) pre-fills
  // "Redes autorizadas" from the suggested DHCP subnet right away, so the
  // admin sees the common case populated instantly instead of waiting on
  // the auto-apply round trip — the API applies the same default on its
  // own if this client-side prefill is ever skipped (e.g. a future caller).
  const toggleServeLAN = (on: boolean) => {
    if (!cfg) return;
    const allowed = on && cfg.allowed_networks.length === 0 && data?.suggested_network
      ? [data.suggested_network]
      : cfg.allowed_networks;
    setCfg({ ...cfg, serve_lan: on, allowed_networks: allowed });
  };

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

          <Panel title={<span className="flex items-center gap-2"><Wifi className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Servir horário para a rede local</span></span>}>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4"
                checked={cfg.serve_lan}
                disabled={!canWrite}
                onChange={(e) => toggleServeLAN(e.target.checked)}
              />
              <span className="text-gray-300 text-sm">Este firewall também serve NTP para a rede local (via chrony, protegido por firewall)</span>
            </label>

            {cfg.serve_lan && (
              <div className="mt-4 space-y-3">
                <div>
                  <label className="label">Redes autorizadas (CIDR, separadas por vírgula)</label>
                  <input
                    className="input w-full"
                    placeholder={data?.suggested_network || '192.168.3.0/24'}
                    value={cfg.allowed_networks.join(', ')}
                    disabled={!canWrite}
                    onChange={(e) => setCfg({ ...cfg, allowed_networks: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                  />
                  <p className="text-xs text-gray-600 mt-1">
                    Escolha quais redes podem sincronizar o horário aqui — LAN, VLANs, Wi-Fi ou rede de convidados. Vazio = nenhuma rede liberada (não é "liberar tudo").
                  </p>
                </div>

                <div className="text-xs text-gray-500 border border-gray-800 rounded p-3 bg-gray-900/40">
                  {cfg.allowed_networks.length > 0 ? (
                    <>Em vigor: servindo NTP para <span className="text-gray-300 font-mono">{cfg.allowed_networks.join(', ')}</span>, anunciado via DHCP (opção 42) e negado para qualquer outra origem.</>
                  ) : (
                    <>Em vigor: nenhuma rede autorizada ainda — NTP negado para todo mundo até uma rede ser adicionada acima.</>
                  )}
                </div>
              </div>
            )}

            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </Panel>
        </>
      )}
    </div>
  );
}
