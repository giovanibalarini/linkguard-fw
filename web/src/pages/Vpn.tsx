import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  KeyRound,
  Lock,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import Panel from '../components/ui/Panel';
import type { HostGroup } from '../types';

interface VPNConfig {
  enabled: boolean;
  listen_port: number;
  address: string;
  endpoint_host: string;
  endpoint_link_id: string;
}

interface VPNPeer {
  user_id: string;
  username: string;
  public_key: string;
  address: string;
  firewall_group_id: string;
  access_mode?: 'full' | 'restricted';
  allowed_host_groups?: string[];
  allowed_ports?: string;
  created_at?: number;
  rotated_at?: number;
  online?: boolean;
  endpoint?: string;
  latest_handshake?: number;
  transfer_rx?: number;
  transfer_tx?: number;
  latency_ms?: number;
}

interface VPNOverview {
  config: VPNConfig;
  public_key?: string;
  peers: VPNPeer[];
  running: boolean;
  last_apply_ok: boolean;
  last_apply_error?: string;
  last_applied_at?: number;
}

interface VPNEnrollment {
  peer: VPNPeer;
  client_config: string;
  qr_data_url?: string;
  apply_error?: string;
  warning?: string;
}

interface DDNSOption {
  link_id: string;
  link_name: string;
  enabled: boolean;
  hostname: string;
}

const defaultConfig: VPNConfig = {
  enabled: false,
  listen_port: 51820,
  address: '10.7.0.1/24',
  endpoint_host: '',
  endpoint_link_id: '',
};

export default function Vpn() {
  const { user, can, permsLoaded } = useAuth();
  const { t } = useI18n();
  const canRead = can('vpn.read');
  const canWrite = can('vpn.write');
  const canEnroll = can('vpn.enroll');
  const [overview, setOverview] = useState<VPNOverview | null>(null);
  const [draft, setDraft] = useState<VPNConfig>(defaultConfig);
  const [ddns, setDDNS] = useState<DDNSOption[]>([]);
  const [enrollment, setEnrollment] = useState<VPNEnrollment | null>(null);
  const [hostGroups, setHostGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: 'ok' | 'error' | 'warn'; text: string } | null>(null);

  // ZTNA Access Modal state
  const [accessPeer, setAccessPeer] = useState<VPNPeer | null>(null);
  const [accessMode, setAccessMode] = useState<'full' | 'restricted'>('full');
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [allowedPorts, setAllowedPorts] = useState('');
  const [savingAccess, setSavingAccess] = useState(false);

  const load = useCallback(async () => {
    if (!permsLoaded) return;
    setLoading(true);
    try {
      if (canRead) {
        const { data } = await client.get<VPNOverview>('/api/vpn');
        setOverview(data);
        setDraft(data.config);
        const [vpnRes, hgRes] = await Promise.all([
          client.get<VPNOverview>('/api/vpn'),
          client.get<HostGroup[]>('/api/hostgroups').catch(() => ({ data: [] })),
        ]);
        setOverview(vpnRes.data);
        setDraft(vpnRes.data.config);
        setHostGroups(hgRes.data ?? []);
      }
      if (canWrite) {
        const { data } = await client.get<DDNSOption[]>('/api/ddns');
        setDDNS((data ?? []).filter((row) => row.enabled && row.hostname));
      }
    } catch (e) {
      setMessage({ kind: 'error', text: apiError(e, t('vpn.error.load')) });
    } finally {
      setLoading(false);
    }
  }, [canRead, canWrite, permsLoaded, t]);

  const openAccessModal = (peer: VPNPeer) => {
    setAccessPeer(peer);
    setAccessMode(peer.access_mode === 'restricted' ? 'restricted' : 'full');
    setSelectedGroups(peer.allowed_host_groups || []);
    setAllowedPorts(peer.allowed_ports || '');
  };

  const toggleGroup = (groupId: string) => {
    setSelectedGroups((prev) =>
      prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
    );
  };

  const handleSaveAccess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessPeer) return;
    setSavingAccess(true);
    try {
      await client.put(`/api/vpn/peers/${accessPeer.user_id}/access`, {
        access_mode: accessMode,
        allowed_host_groups: accessMode === 'restricted' ? selectedGroups : [],
        allowed_ports: accessMode === 'restricted' ? allowedPorts.trim() : '',
      });
      setMessage({ kind: 'ok', text: t('vpn.peer.accessSaved') });
      setAccessPeer(null);
      await load();
    } catch (err) {
      setMessage({ kind: 'error', text: apiError(err, t('vpn.error.operation')) });
    } finally {
      setSavingAccess(false);
    }
  };

  useEffect(() => { load(); }, [load]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setMessage(null);
    try {
      await work();
    } catch (e) {
      setMessage({
        kind: isTimeout(e) ? 'warn' : 'error',
        text: isTimeout(e) ? t('vpn.error.timeout') : apiError(e, t('vpn.error.operation')),
      });
    } finally {
      setBusy(false);
    }
  };

  const save = () => run(async () => {
    await client.put('/api/vpn', draft, { timeout: INSTALL_TIMEOUT_MS });
    setMessage({ kind: 'ok', text: t('vpn.saved') });
    await load();
  });

  const ownPeer = overview?.peers.find((peer) => peer.user_id === user?.id);

  const enroll = () => {
    if (ownPeer && !window.confirm(t('vpn.enrollment.rotateConfirm'))) return;
    run(async () => {
      const { data } = await client.post<VPNEnrollment>('/api/vpn/enrollment', null, {
        timeout: INSTALL_TIMEOUT_MS,
      });
      // Kept only in component memory. It is never written to localStorage,
      // query strings, logs or a follow-up GET response.
      setEnrollment(data);
      setMessage({ kind: data.apply_error ? 'warn' : 'ok', text: t('vpn.enrollment.created') });
      await load();
    });
  };

  const revoke = (peer: VPNPeer, self: boolean) => {
    if (!window.confirm(t('vpn.peer.revokeConfirm', { user: peer.username }))) return;
    run(async () => {
      if (self) await client.delete('/api/vpn/enrollment', { timeout: INSTALL_TIMEOUT_MS });
      else await client.delete(`/api/vpn/peers/${encodeURIComponent(peer.user_id)}`, { timeout: INSTALL_TIMEOUT_MS });
      if (self) setEnrollment(null);
      setMessage({ kind: 'ok', text: t('vpn.peer.revoked') });
      await load();
    });
  };

  const download = () => {
    if (!enrollment) return;
    const url = URL.createObjectURL(new Blob([enrollment.client_config], { type: 'text/plain;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `linkguard-${safeName(enrollment.peer.username || user?.username || 'client')}.conf`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const copy = async () => {
    if (!enrollment) return;
    try {
      await navigator.clipboard.writeText(enrollment.client_config);
      setMessage({ kind: 'ok', text: t('vpn.enrollment.copied') });
    } catch {
      setMessage({ kind: 'error', text: t('vpn.enrollment.copyFailed') });
    }
  };

  if (!permsLoaded || loading) {
    return <div className="p-6"><div className="card text-center py-8 text-gray-500 animate-pulse">{t('common.loading')}</div></div>;
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2"><Shield className="w-5 h-5 text-blue-400" /> WireGuard</h1>
          <p className="text-gray-500 text-sm">{t('vpn.subtitle')}</p>
        </div>
        {canRead && (
          <button onClick={load} disabled={busy} className="btn-secondary flex items-center gap-2 disabled:opacity-50">
            <RefreshCw className="w-4 h-4" /> {t('vpn.refresh')}
          </button>
        )}
      </div>

      {message && (
        <div className={`card border text-sm ${message.kind === 'error'
          ? 'border-red-500/30 bg-red-500/10 text-red-400'
          : message.kind === 'warn'
            ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
            : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>
          {message.text}
        </div>
      )}

      {overview && !overview.last_apply_ok && overview.last_apply_error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('vpn.lastApplyFailed', { error: overview.last_apply_error })}
        </div>
      )}

      {canRead && overview && (
        <Panel title={<span className="text-white font-semibold">{t('vpn.status.title')}</span>}>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-gray-500">{t('vpn.status.desired')}</div>
              <div className={overview.config.enabled ? 'text-green-400' : 'text-gray-400'}>
                {overview.config.enabled ? t('vpn.status.enabled') : t('vpn.status.disabled')}
              </div>
            </div>
            <div>
              <div className="text-gray-500">{t('vpn.status.service')}</div>
              <div className={overview.running ? 'text-green-400' : 'text-gray-400'}>
                {overview.running ? t('vpn.status.running') : t('vpn.status.stopped')}
              </div>
            </div>
            <div>
              <div className="text-gray-500">{t('vpn.status.peers')}</div>
              <div className="text-white">{overview.peers.length}</div>
            </div>
          </div>
          {overview.public_key && (
            <div className="mt-4">
              <div className="text-gray-500 text-xs">{t('vpn.status.publicKey')}</div>
              <code className="block mt-1 text-xs text-gray-300 break-all">{overview.public_key}</code>
            </div>
          )}
        </Panel>
      )}

      {canWrite && overview && (
        <Panel title={<span className="text-white font-semibold">{t('vpn.config.title')}</span>}>
          <div className="space-y-4">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
              {t('vpn.config.enable')}
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label>
                <span className="label">{t('vpn.config.address')}</span>
                <input className="input w-full font-mono" value={draft.address} onChange={(e) => setDraft({ ...draft, address: e.target.value })} />
              </label>
              <label>
                <span className="label">{t('vpn.config.port')}</span>
                <input type="number" min={1} max={65535} className="input w-full" value={draft.listen_port} onChange={(e) => setDraft({ ...draft, listen_port: Number(e.target.value) })} />
              </label>
              <label>
                <span className="label">{t('vpn.config.ddnsLink')}</span>
                <select className="input w-full" value={draft.endpoint_link_id} onChange={(e) => setDraft({ ...draft, endpoint_link_id: e.target.value })}>
                  <option value="">{t('vpn.config.noDDNS')}</option>
                  {ddns.map((row) => <option key={row.link_id} value={row.link_id}>{row.link_name} — {row.hostname}</option>)}
                </select>
              </label>
              <label>
                <span className="label">{t('vpn.config.explicitEndpoint')}</span>
                <input className="input w-full" placeholder="vpn.example.com" value={draft.endpoint_host} onChange={(e) => setDraft({ ...draft, endpoint_host: e.target.value })} />
              </label>
            </div>
            <p className="text-xs text-gray-500">{t('vpn.config.endpointHint')}</p>
            <button onClick={save} disabled={busy} className="btn-primary disabled:opacity-50">{t('vpn.config.save')}</button>
          </div>
        </Panel>
      )}

      {canEnroll && (
        <Panel title={<span className="flex items-center gap-2 text-white font-semibold"><KeyRound className="w-4 h-4 text-blue-400" /> {t('vpn.enrollment.title')}</span>}>
          <p className="text-sm text-gray-400">{t('vpn.enrollment.explain')}</p>
          {ownPeer && <p className="mt-2 text-xs text-gray-500">{t('vpn.enrollment.current', { address: ownPeer.address })}</p>}
          <div className="mt-4 flex flex-wrap gap-2">
            <button onClick={enroll} disabled={busy || overview?.config.enabled === false} className="btn-primary disabled:opacity-50">
              {ownPeer ? t('vpn.enrollment.rotate') : t('vpn.enrollment.create')}
            </button>
            {ownPeer && (
              <button onClick={() => revoke(ownPeer, true)} disabled={busy} className="btn-secondary text-red-400 disabled:opacity-50">
                <Trash2 className="w-4 h-4" /> {t('vpn.peer.revokeMine')}
              </button>
            )}
          </div>
        </Panel>
      )}

      {enrollment && (
        <Panel title={<span className="flex items-center gap-2 text-amber-300 font-semibold"><AlertTriangle className="w-4 h-4" /> {t('vpn.enrollment.onceTitle')}</span>}>
          <div className="space-y-4">
            <p className="text-sm text-amber-200">{t('vpn.enrollment.onceWarning')}</p>
            {enrollment.apply_error && <p className="text-sm text-red-400">{enrollment.apply_error}</p>}
            {enrollment.warning && <p className="text-sm text-amber-300">{enrollment.warning}</p>}
            <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_16rem] gap-4">
              <textarea readOnly rows={12} value={enrollment.client_config} className="input w-full font-mono text-xs resize-y" />
              {enrollment.qr_data_url ? (
                <div className="rounded-lg bg-white p-3 self-start">
                  <img src={enrollment.qr_data_url} alt={t('vpn.enrollment.qrAlt')} className="w-full aspect-square" />
                </div>
              ) : <p className="text-gray-500 text-sm">{t('vpn.enrollment.noQR')}</p>}
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={download} className="btn-primary flex items-center gap-2"><Download className="w-4 h-4" /> {t('vpn.enrollment.download')}</button>
              <button onClick={copy} className="btn-secondary flex items-center gap-2"><Copy className="w-4 h-4" /> {t('vpn.enrollment.copy')}</button>
              <button onClick={() => setEnrollment(null)} className="btn-secondary flex items-center gap-2"><X className="w-4 h-4" /> {t('vpn.enrollment.close')}</button>
            </div>
            <p className="flex items-start gap-2 text-xs text-gray-500"><CheckCircle2 className="w-3.5 h-3.5 mt-0.5 text-green-400 shrink-0" /> {t('vpn.enrollment.vaultNote')}</p>
          </div>
        </Panel>
      )}

      {canWrite && overview && (
        <Panel title={<span className="text-white font-semibold">{t('vpn.peers.title')}</span>}>
          {overview.peers.length === 0 ? (
            <p className="text-sm text-gray-500">{t('vpn.peers.empty')}</p>
          ) : (
            <div className="overflow-x-auto -mx-4 sm:mx-0">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-xs font-semibold text-gray-400">
                    <th className="pb-3 px-3">{t('vpn.peer.status')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.user')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.vpnIp')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.access')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.latency')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.endpoint')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.handshake')}</th>
                    <th className="pb-3 px-3">{t('vpn.peer.transfer')}</th>
                    <th className="pb-3 px-3 text-right"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {overview.peers.map((peer) => {
                    const isSelf = peer.user_id === user?.id;
                    const isRestricted = peer.access_mode === 'restricted';
                    return (
                      <tr key={peer.user_id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3.5 px-3 whitespace-nowrap">
                          {peer.online ? (
                            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              {t('vpn.peer.online')}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-gray-500" />
                              {t('vpn.peer.offline')}
                            </span>
                          )}
                        </td>

                        <td className="py-3.5 px-3 min-w-[140px]">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-white">{peer.username}</span>
                            {isSelf && (
                              <span className="text-[10px] uppercase tracking-wider bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded font-semibold">
                                {t('vpn.peer.you')}
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-gray-500">{t('vpn.peer.firewallGroup')}</div>
                        </td>

                        <td className="py-3.5 px-3 whitespace-nowrap">
                          <code className="font-mono text-xs text-blue-300 bg-blue-950/40 px-2 py-0.5 rounded border border-blue-800/30">
                            {peer.address}
                          </code>
                        </td>

                        <td className="py-3.5 px-3 min-w-[160px]">
                          {isRestricted ? (
                            <div className="space-y-1">
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/15 text-purple-300 border border-purple-500/30">
                                <Shield className="w-3 h-3 text-purple-400" />
                                {t('vpn.peer.accessRestricted')}
                              </span>
                              {peer.allowed_host_groups && peer.allowed_host_groups.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {peer.allowed_host_groups.map((hgId) => {
                                    const hg = hostGroups.find((g) => g.id === hgId);
                                    return (
                                      <span
                                        key={hgId}
                                        className="text-[10px] font-medium bg-gray-900 text-gray-300 px-1.5 py-0.5 rounded border border-gray-800"
                                        title={hg?.hosts ? hg.hosts.join(', ') : ''}
                                      >
                                        {hg ? hg.name : hgId.slice(0, 8)}
                                      </span>
                                    );
                                  })}
                                </div>
                              ) : (
                                <div className="text-[10px] text-amber-400/80 italic">
                                  Bloqueio total (sem grupos)
                                </div>
                              )}
                              {peer.allowed_ports && (
                                <div className="text-[10px] font-mono text-gray-400">
                                  portas: {peer.allowed_ports}
                                </div>
                              )}
                            </div>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <ShieldCheck className="w-3 h-3" />
                              {t('vpn.peer.accessFull')}
                            </span>
                          )}
                        </td>

                        <td className="py-3.5 px-3 whitespace-nowrap">
                          {peer.online && peer.latency_ms && peer.latency_ms > 0 ? (
                            <span className={`inline-flex items-center gap-1 font-mono text-xs font-medium ${
                              peer.latency_ms < 30
                                ? 'text-emerald-400'
                                : peer.latency_ms < 100
                                  ? 'text-amber-300'
                                  : 'text-orange-400'
                            }`}>
                              <Activity className="w-3.5 h-3.5" />
                              {peer.latency_ms.toFixed(1)} ms
                            </span>
                          ) : peer.online ? (
                            <span className="text-xs text-gray-400" title="ICMP não respondeu">&lt; 1 ms</span>
                          ) : (
                            <span className="text-xs text-gray-600">—</span>
                          )}
                        </td>

                        <td className="py-3.5 px-3 whitespace-nowrap">
                          {peer.endpoint ? (
                            <code className="font-mono text-xs text-gray-300 bg-gray-800/40 px-2 py-0.5 rounded border border-gray-700/30">
                              {peer.endpoint}
                            </code>
                          ) : (
                            <span className="text-xs text-gray-500">—</span>
                          )}
                        </td>

                        <td className="py-3.5 px-3 whitespace-nowrap text-xs text-gray-300">
                          {formatHandshake(peer.latest_handshake, t)}
                        </td>

                        <td className="py-3.5 px-3 whitespace-nowrap">
                          <div className="text-xs font-mono text-gray-300">
                            <span className="text-emerald-400">↓ {formatBytes(peer.transfer_rx || 0)}</span>
                            <span className="text-gray-600 mx-1">/</span>
                            <span className="text-blue-400">↑ {formatBytes(peer.transfer_tx || 0)}</span>
                          </div>
                        </td>

                        <td className="py-3.5 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => revoke(peer, isSelf)}
                            disabled={busy}
                            className="btn-secondary text-xs text-red-400 hover:text-red-300 disabled:opacity-50 inline-flex items-center gap-1"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            {t('vpn.peer.revoke')}
                          </button>
                          <div className="inline-flex items-center gap-1.5">
                            {canWrite && (
                              <button
                                onClick={() => openAccessModal(peer)}
                                disabled={busy}
                                className="btn-secondary text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50 inline-flex items-center gap-1 py-1 px-2.5"
                                title={t('vpn.peer.manageAccess')}
                              >
                                <Lock className="w-3 h-3" />
                                <span className="hidden lg:inline">{t('vpn.peer.manageAccess')}</span>
                              </button>
                            )}
                            <button
                              onClick={() => revoke(peer, isSelf)}
                              disabled={busy}
                              className="btn-secondary text-xs text-red-400 hover:text-red-300 disabled:opacity-50 inline-flex items-center gap-1 py-1 px-2.5"
                              title={t('vpn.peer.revoke')}
                            >
                              <Trash2 className="w-3 h-3" />
                              <span className="hidden lg:inline">{t('vpn.peer.revoke')}</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {/* Modal Perfil de Acesso ZTNA */}
      {accessPeer && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-gray-950 border border-gray-800 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Shield className="w-4 h-4 text-purple-400" />
                {t('vpn.peer.accessModalTitle', { user: accessPeer.username })}
              </h3>
              <button
                onClick={() => setAccessPeer(null)}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveAccess} className="p-5 space-y-4">
              <p className="text-xs text-gray-400">
                {t('vpn.peer.accessModalDesc')}
              </p>

              <div className="space-y-2">
                <label
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    accessMode === 'full'
                      ? 'border-emerald-500/40 bg-emerald-500/5 text-white'
                      : 'border-gray-800 bg-gray-900/50 text-gray-300 hover:border-gray-700'
                  }`}
                >
                  <input
                    type="radio"
                    name="accessMode"
                    value="full"
                    checked={accessMode === 'full'}
                    onChange={() => setAccessMode('full')}
                    className="mt-1 text-emerald-500 focus:ring-emerald-500"
                  />
                  <div>
                    <div className="text-xs font-semibold flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      {t('vpn.peer.modeFull')}
                    </div>
                    <div className="text-[11px] text-gray-400 mt-0.5">
                      {t('vpn.peer.modeFullDesc')}
                    </div>
                  </div>
                </label>

                <label
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    accessMode === 'restricted'
                      ? 'border-purple-500/40 bg-purple-500/5 text-white'
                      : 'border-gray-800 bg-gray-900/50 text-gray-300 hover:border-gray-700'
                  }`}
                >
                  <input
                    type="radio"
                    name="accessMode"
                    value="restricted"
                    checked={accessMode === 'restricted'}
                    onChange={() => setAccessMode('restricted')}
                    className="mt-1 text-purple-500 focus:ring-purple-500"
                  />
                  <div>
                    <div className="text-xs font-semibold flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-purple-400" />
                      {t('vpn.peer.modeRestricted')}
                    </div>
                    <div className="text-[11px] text-gray-400 mt-0.5">
                      {t('vpn.peer.modeRestrictedDesc')}
                    </div>
                  </div>
                </label>
              </div>

              {accessMode === 'restricted' && (
                <div className="space-y-4 pt-2 border-t border-gray-800 animate-in fade-in duration-150">
                  <div>
                    <label className="block text-xs font-medium text-gray-300 mb-1.5">
                      {t('vpn.peer.allowedGroupsLabel')}
                    </label>
                    {hostGroups.length === 0 ? (
                      <div className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs text-amber-400/90">
                        {t('vpn.peer.noGroupsAvailable')}
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                        {hostGroups.map((g) => {
                          const checked = selectedGroups.includes(g.id);
                          return (
                            <label
                              key={g.id}
                              className={`flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-colors ${
                                checked
                                  ? 'border-purple-500/50 bg-purple-950/20'
                                  : 'border-gray-800 bg-gray-900/40 hover:border-gray-700'
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleGroup(g.id)}
                                className="mt-0.5 rounded text-purple-600 focus:ring-purple-500"
                              />
                              <div className="min-w-0 flex-1">
                                <div className="text-xs font-medium text-white flex items-center justify-between">
                                  <span>{g.name}</span>
                                  <span className="text-[10px] text-gray-500 font-mono">
                                    {g.hosts?.length || 0} hosts
                                  </span>
                                </div>
                                {g.description && (
                                  <div className="text-[11px] text-gray-400 truncate">
                                    {g.description}
                                  </div>
                                )}
                                <div className="text-[10px] font-mono text-gray-500 truncate mt-0.5">
                                  {g.hosts?.join(', ')}
                                </div>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-300 mb-1">
                      {t('vpn.peer.allowedPortsLabel')}
                    </label>
                    <input
                      type="text"
                      value={allowedPorts}
                      onChange={(e) => setAllowedPorts(e.target.value)}
                      placeholder={t('vpn.peer.allowedPortsPlaceholder')}
                      className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
                    />
                    <p className="text-[11px] text-gray-500 mt-1">
                      {t('vpn.peer.allowedPortsHelp')}
                    </p>
                  </div>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
                <button
                  type="button"
                  onClick={() => setAccessPeer(null)}
                  disabled={savingAccess}
                  className="btn-secondary text-xs px-3 py-1.5"
                >
                  {t('common.cancel') || 'Cancelar'}
                </button>
                <button
                  type="submit"
                  disabled={savingAccess}
                  className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5 bg-purple-600 hover:bg-purple-500"
                >
                  {savingAccess && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  {t('vpn.peer.saveAccess')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatHandshake(epoch: number | undefined, t: (key: string) => string): string {
  if (!epoch || epoch <= 0) return t('vpn.peer.neverConnected');
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.max(0, now - epoch);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  return `${Math.floor(diff / 86400)}d`;
}

function apiError(error: unknown, fallback: string): string {
  const value = error as { response?: { data?: { error?: string } } };
  return value.response?.data?.error || fallback;
}

function safeName(value: string): string {
  return value.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'client';
}
