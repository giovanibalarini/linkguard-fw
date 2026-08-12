import { useEffect, useState } from 'react';
import { RefreshCw, Clock, Play, Download, Wifi } from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../api/client';
import { useAuth } from '../context/AuthContext';
import Panel from '../components/ui/Panel';
import type { NTPData, NTPConfig } from '../types';

// parseList turns the comma-separated text of a "list" field (NTP servers,
// allowed networks) into a trimmed, non-empty string array. Called only at
// save/blur time now — see the servers/networks text-state comment below
// for why it must never run on every keystroke.
const parseList = (raw: string): string[] =>
  raw.split(',').map((s) => s.trim()).filter(Boolean);

export default function Ntp() {
  const { can } = useAuth();
  const canWrite = can('ntp.write');
  const [data, setData] = useState<NTPData | null>(null);
  const [cfg, setCfg] = useState<NTPConfig | null>(null);
  // serversText/networksText hold the raw, as-typed text of their
  // comma-separated fields — the single source of truth while editing.
  // Before this, the input's onChange re-parsed (split -> trim -> filter ->
  // join) the field on every keystroke and fed the rejoined value straight
  // back in, so typing a comma was swallowed: "192.168.3.0/24" + ", " + "1"
  // landed as "192.168.3.0/241" because the trailing ", " (an empty
  // trimmed segment) never made it into the rejoined string for the next
  // keystroke to land after. Parsing now happens only at save (and on
  // blur, so other on-page logic that reads cfg — the pending-changes
  // indicator, the first-enable prefill check — sees an up to date list
  // without requiring a save first).
  const [serversText, setServersText] = useState('');
  const [networksText, setNetworksText] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const fetchData = async () => {
    setLoading(true); setError(false);
    try {
      const res = await client.get<NTPData>('/api/ntp');
      setData(res.data); setCfg(res.data.config);
      setServersText(res.data.config.servers.join(', '));
      setNetworksText(res.data.config.allowed_networks.join(', '));
    } catch { setError(true); } finally { setLoading(false); }
  };
  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true); setMsg('');
    try { await fn(); if (ok) setMsg(ok); await fetchData(); }
    catch (e: any) {
      // Instalar o chrony é um download: desistir de esperar não quer dizer
      // que falhou (o apt segue numa unidade transiente do systemd).
      setMsg(isTimeout(e)
        ? 'A instalação está demorando mais que o normal e continua em segundo plano. Atualize a página em alguns minutos para ver o resultado.'
        : `Erro: ${e.response?.data?.error || e.message}`);
    }
    finally { setBusy(false); }
  };

  // Parses both text fields fresh from their raw state at save time —
  // never from cfg.servers/cfg.allowed_networks, which onBlur may not have
  // synced yet if the admin clicks "Salvar" straight from the field
  // without losing focus first (e.g. a mouse click still fires blur before
  // the click's own handler in React, but this makes the save path
  // correct independent of that ordering detail).
  const saveConfig = () => {
    if (!cfg) return;
    const servers = parseList(serversText);
    const allowedNetworks = parseList(networksText);
    return run(() => client.put('/api/ntp/config', {
      servers,
      timezone: cfg.timezone,
      serve_lan: cfg.serve_lan,
      allowed_networks: allowedNetworks,
    }), 'Config de NTP salva — aplicando automaticamente.');
  };
  const apply = () => run(() => client.post('/api/ntp/apply'), 'Aplicado com sucesso.');
  const installChrony = () => run(() => client.post('/api/ntp/install-chrony', null, { timeout: INSTALL_TIMEOUT_MS }), 'chrony instalado.');

  // Syncs cfg.allowed_networks from the raw text field on blur, so logic
  // that reads cfg (the pending-changes indicator, toggleServeLAN's
  // first-enable check below) reflects what the admin actually typed
  // without requiring a save first. Parsing here is safe — unlike
  // onChange, blur only fires once editing has paused.
  const syncNetworksFromText = () => {
    if (!cfg) return;
    setCfg({ ...cfg, allowed_networks: parseList(networksText) });
  };
  const syncServersFromText = () => {
    if (!cfg) return;
    setCfg({ ...cfg, servers: parseList(serversText) });
  };

  // Toggling serve_lan on for the first time (list still empty) pre-fills
  // "Redes autorizadas" from the suggested DHCP subnet right away, so the
  // admin sees the common case populated instantly instead of waiting on
  // the auto-apply round trip — the API applies the same default on its
  // own if this client-side prefill is ever skipped (e.g. a future caller).
  // Reads the freshly-typed list via parseList(networksText), not
  // cfg.allowed_networks, so this check is correct even if the admin typed
  // into the field and toggled off/on again without the field losing focus
  // in between.
  const toggleServeLAN = (on: boolean) => {
    if (!cfg) return;
    const currentlyTyped = parseList(networksText);
    const allowed = on && currentlyTyped.length === 0 && data?.suggested_network
      ? [data.suggested_network]
      : currentlyTyped;
    setCfg({ ...cfg, serve_lan: on, allowed_networks: allowed });
    setNetworksText(allowed.join(', '));
  };

  // ─── "Em vigor" (Fix 3): reflects the server's saved state + the last
  // firewall-apply outcome, never the local unsaved draft — editing a
  // field must never claim the new state is already live. savedNetworks
  // is data.config (what the server actually persisted and, if
  // firewall_apply.ok, reconciled into nftables); draftNetworks is the
  // as-typed field, used only to detect and flag unsaved changes.
  const savedServing = data?.config.serve_lan ?? false;
  const savedNetworks = data?.config.allowed_networks ?? [];
  const draftNetworks = parseList(networksText);
  const hasPendingChanges = !!cfg && (
    cfg.serve_lan !== savedServing ||
    draftNetworks.join(',') !== savedNetworks.join(',')
  );

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

      {/* firewall_apply (Fix 2): the nftables input-chain reconcile is a
          separate step from the chrony apply above and can fail on its
          own — this is the one state where NTP protection is genuinely
          absent, so it gets its own banner rather than being folded into
          last_apply's message. */}
      {data?.firewall_apply && !data.firewall_apply.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Última aplicação da proteção de firewall (nftables) falhou: {data.firewall_apply.error || 'erro desconhecido'}. O NTP pode estar exposto além das redes autorizadas. Corrija e use "Aplicar agora".
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
                <input className="input w-full" placeholder="a.ntp.br, b.ntp.br (vazio = pool padrão do Debian)" value={serversText} disabled={!canWrite} onChange={(e) => setServersText(e.target.value)} onBlur={syncServersFromText} />
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

            {(cfg.serve_lan || savedServing) && (
              <div className="mt-4 space-y-3">
                {cfg.serve_lan && (
                  <div>
                    <label className="label">Redes autorizadas (CIDR, separadas por vírgula)</label>
                    <input
                      className="input w-full"
                      placeholder={data?.suggested_network || '192.168.3.0/24'}
                      value={networksText}
                      disabled={!canWrite}
                      onChange={(e) => setNetworksText(e.target.value)}
                      onBlur={syncNetworksFromText}
                    />
                    <p className="text-xs text-gray-600 mt-1">
                      Escolha quais redes podem sincronizar o horário aqui — LAN, VLANs, Wi-Fi ou rede de convidados. Vazio = nenhuma rede liberada (não é "liberar tudo").
                    </p>
                  </div>
                )}

                {/* "Em vigor" (Fix 3): always the server's last-saved state
                    (data.config) plus the last firewall-apply outcome —
                    never cfg/networksText, the local draft — so editing a
                    field without saving can never claim the new state is
                    already live. */}
                <div className="text-xs text-gray-500 border border-gray-800 rounded p-3 bg-gray-900/40 space-y-1">
                  {!savedServing ? (
                    <div>Em vigor: NTP não está sendo servido para a rede local.</div>
                  ) : savedNetworks.length > 0 ? (
                    <div>
                      Em vigor: servindo NTP para <span className="text-gray-300 font-mono">{savedNetworks.join(', ')}</span>, anunciado via DHCP (opção 42) e negado para qualquer outra origem.
                    </div>
                  ) : (
                    <div>Em vigor: nenhuma rede autorizada — NTP negado para todo mundo até uma rede ser adicionada e salva.</div>
                  )}
                  {hasPendingChanges && (
                    <div className="text-yellow-400">Há alterações não salvas acima — clique em "Salvar config" para aplicá-las.</div>
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
