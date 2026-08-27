import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle, CheckCircle2, Copy, Download, KeyRound, RefreshCw, Shield,
  Trash2, X,
} from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import Panel from '../components/ui/Panel';

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
  created_at?: number;
  rotated_at?: number;
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
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: 'ok' | 'error' | 'warn'; text: string } | null>(null);

  const load = useCallback(async () => {
    if (!permsLoaded) return;
    setLoading(true);
    try {
      if (canRead) {
        const { data } = await client.get<VPNOverview>('/api/vpn');
        setOverview(data);
        setDraft(data.config);
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
          {overview.peers.length === 0 ? <p className="text-sm text-gray-500">{t('vpn.peers.empty')}</p> : (
            <ul className="divide-y divide-gray-800">
              {overview.peers.map((peer) => (
                <li key={peer.user_id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm text-white font-medium">{peer.username}</div>
                    <div className="text-xs text-gray-500 font-mono">{peer.address} · {t('vpn.peer.firewallGroup')}</div>
                  </div>
                  <button onClick={() => revoke(peer, peer.user_id === user?.id)} disabled={busy} className="btn-secondary text-xs text-red-400 disabled:opacity-50">
                    <Trash2 className="w-3.5 h-3.5" /> {t('vpn.peer.revoke')}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  );
}

function apiError(error: unknown, fallback: string): string {
  const value = error as { response?: { data?: { error?: string } } };
  return value.response?.data?.error || fallback;
}

function safeName(value: string): string {
  return value.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'client';
}
