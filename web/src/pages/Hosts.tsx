import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Pencil, Ban, ShieldCheck, Circle, TrendingUp, ArrowDown, ArrowUp } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { NetHost, HostTraffic } from '../types';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
}

export default function Hosts() {
  const { can } = useAuth();
  const canManage = can('hosts.block');
  const [hosts, setHosts] = useState<NetHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [filter, setFilter] = useState('');
  const [aliasFor, setAliasFor] = useState<NetHost | null>(null);
  const [aliasValue, setAliasValue] = useState('');
  const [aliasError, setAliasError] = useState('');
  const [saving, setSaving] = useState(false);
  const [confirmFor, setConfirmFor] = useState<NetHost | null>(null);
  const [confirmError, setConfirmError] = useState('');
  const [confirming, setConfirming] = useState(false);

  const [talkers, setTalkers] = useState<HostTraffic[]>([]);

  const fetchHosts = async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await client.get<NetHost[]>('/api/hosts');
      setHosts(res.data ?? []);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
    // Top talkers — best-effort (requires conntrack accounting).
    try {
      const t = await client.get<HostTraffic[]>('/api/hosts/traffic');
      setTalkers(t.data ?? []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetchHosts(); }, []);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return hosts;
    return hosts.filter((h) =>
      [h.ip, h.mac, h.alias, h.hostname, h.interface].some((v) => v?.toLowerCase().includes(q)),
    );
  }, [hosts, filter]);

  const onlineCount = useMemo(() => hosts.filter((h) => h.online).length, [hosts]);

  const openAlias = (h: NetHost) => {
    setAliasFor(h);
    setAliasValue(h.alias ?? '');
    setAliasError('');
  };

  const saveAlias = async () => {
    if (!aliasFor) return;
    setSaving(true);
    setAliasError('');
    try {
      await client.put('/api/hosts/alias', { mac: aliasFor.mac, alias: aliasValue.trim() });
      setAliasFor(null);
      await fetchHosts();
    } catch (err: any) {
      setAliasError(err.response?.data?.error || 'Erro ao salvar apelido');
    } finally {
      setSaving(false);
    }
  };

  const openConfirm = (h: NetHost) => {
    setConfirmFor(h);
    setConfirmError('');
  };

  const confirmToggleBlock = async () => {
    const h = confirmFor;
    if (!h) return;
    const verb = h.blocked ? 'desbloquear' : 'bloquear';
    setConfirming(true);
    setConfirmError('');
    try {
      await client.post('/api/hosts/block', { mac: h.mac, blocked: !h.blocked });
      setConfirmFor(null);
      await fetchHosts();
    } catch (err: any) {
      setConfirmError(err.response?.data?.error || `Erro ao ${verb} host`);
    } finally {
      setConfirming(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Hosts da rede</h1>
          <p className="text-gray-500 text-sm">
            {onlineCount} online de {hosts.length} conhecidos
          </p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <input
            className="input flex-1 sm:w-64"
            placeholder="Filtrar por IP, MAC, apelido..."
            aria-label="Filtrar hosts"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button onClick={fetchHosts} disabled={loading} className="btn-secondary flex items-center gap-2 whitespace-nowrap disabled:opacity-50">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Atualizar
          </button>
        </div>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={fetchHosts} className="underline">Tentar novamente</button></div>}

      {talkers.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><TrendingUp className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Top consumidores</span><span className="text-xs text-gray-600 font-normal">— quem está usando a banda agora (fluxos ativos)</span></span>}>
          <div className="space-y-2.5">
            {talkers.slice(0, 8).map((t) => {
              const total = t.rx_bytes + t.tx_bytes;
              const max = (talkers[0].rx_bytes + talkers[0].tx_bytes) || 1;
              const host = hosts.find((h) => h.ip === t.ip);
              const name = host?.alias || host?.hostname || t.ip;
              return (
                <div key={t.ip} className="flex items-center gap-3">
                  <div className="w-36 sm:w-44 shrink-0 min-w-0">
                    <div className="text-white text-sm truncate">{name}</div>
                    <div className="text-gray-600 text-xs font-mono truncate">{t.ip}</div>
                  </div>
                  <div className="flex-1 h-2 rounded-full bg-gray-800 overflow-hidden">
                    <div className="h-full bg-blue-500" style={{ width: `${(total / max) * 100}%` }} />
                  </div>
                  <div className="shrink-0 text-xs text-gray-400 flex items-center justify-end gap-3 w-32 sm:w-40">
                    <span className="inline-flex items-center gap-1" title="Download"><ArrowDown className="w-3 h-3 text-green-400" />{fmtBytes(t.rx_bytes)}</span>
                    <span className="inline-flex items-center gap-1" title="Upload"><ArrowUp className="w-3 h-3 text-orange-400" />{fmtBytes(t.tx_bytes)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      <Panel>
        {loading && hosts.length === 0 ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : error && hosts.length === 0 ? (
          <div className="text-center py-12 text-gray-500">Não foi possível carregar os hosts.</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            {hosts.length === 0 ? 'Nenhum host encontrado' : 'Nenhum host corresponde ao filtro'}
          </div>
        ) : (
          <>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {filtered.map((h) => (
                <div
                  key={h.mac || h.ip}
                  className={`rounded-lg border bg-gray-950/40 p-3 ${h.blocked ? 'border-l-2 border-l-red-500 border-gray-800 opacity-75' : 'border-gray-800'}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-white font-medium truncate">{h.alias || h.hostname || '—'}</div>
                      <span className={`inline-flex items-center gap-1.5 text-xs ${h.online ? 'text-green-400' : 'text-gray-600'}`}>
                        <Circle className={`w-2 h-2 ${h.online ? 'fill-green-400' : 'fill-gray-600'}`} />
                        {h.online ? h.state : 'offline'}
                      </span>
                    </div>
                    {canManage && (
                      <div className="flex shrink-0 gap-3">
                        <button
                          onClick={() => openAlias(h)}
                          aria-label="Apelido"
                          className="text-gray-400 hover:text-blue-400 transition-colors"
                        >
                          <Pencil className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => openConfirm(h)}
                          aria-label={h.blocked ? 'Desbloquear' : 'Bloquear'}
                          className={`transition-colors ${h.blocked ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                        >
                          {h.blocked ? <ShieldCheck className="w-5 h-5" /> : <Ban className="w-5 h-5" />}
                        </button>
                      </div>
                    )}
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">IP</dt>
                    <dd className="text-gray-400 font-mono">{h.ip || '—'}</dd>
                    <dt className="text-gray-500">MAC</dt>
                    <dd className="text-gray-500 font-mono">{h.mac}</dd>
                    <dt className="text-gray-500">Interface</dt>
                    <dd className="text-gray-400 font-mono">{h.interface || '—'}</dd>
                  </dl>
                  {h.blocked && (
                    <span className="mt-2 inline-flex items-center gap-1 text-xs text-red-400">
                      <Ban className="w-3 h-3" /> bloqueado
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block overflow-x-auto">
              <table className="hidden sm:table w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Host</th>
                    <th className="pb-3 pr-4 font-medium">IP</th>
                    <th className="pb-3 pr-4 font-medium">MAC</th>
                    <th className="pb-3 pr-4 font-medium">Interface</th>
                    <th className="pb-3 pr-4 font-medium">Estado</th>
                    {canManage && <th className="pb-3 font-medium">Ações</th>}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((h) => (
                    <tr key={h.mac || h.ip} className={`table-row ${h.blocked ? 'border-l-2 border-l-red-500 opacity-75' : ''}`}>
                      <td className="py-3 pr-4">
                        <div className="text-white font-medium">{h.alias || h.hostname || '—'}</div>
                        {h.blocked && (
                          <span className="inline-flex items-center gap-1 text-xs text-red-400">
                            <Ban className="w-3 h-3" /> bloqueado
                          </span>
                        )}
                      </td>
                      <td className="py-3 pr-4 text-gray-400 font-mono text-xs">{h.ip || '—'}</td>
                      <td className="py-3 pr-4 text-gray-500 font-mono text-xs">{h.mac}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono text-xs">{h.interface || '—'}</td>
                      <td className="py-3 pr-4">
                        <span className={`inline-flex items-center gap-1.5 text-xs ${h.online ? 'text-green-400' : 'text-gray-600'}`}>
                          <Circle className={`w-2 h-2 ${h.online ? 'fill-green-400' : 'fill-gray-600'}`} />
                          {h.online ? h.state : 'offline'}
                        </span>
                      </td>
                      {canManage && (
                        <td className="py-3">
                          <div className="flex gap-2">
                            <button
                              onClick={() => openAlias(h)}
                              title="Apelido"
                              aria-label="Apelido"
                              className="text-gray-400 hover:text-blue-400 transition-colors"
                            >
                              <Pencil className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => openConfirm(h)}
                              title={h.blocked ? 'Desbloquear' : 'Bloquear'}
                              aria-label={h.blocked ? 'Desbloquear' : 'Bloquear'}
                              className={`transition-colors ${h.blocked ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                            >
                              {h.blocked ? <ShieldCheck className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
                            </button>
                          </div>
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

      <Modal
        open={aliasFor !== null}
        onClose={() => setAliasFor(null)}
        title={<div><span className="text-white font-semibold">Apelido do host</span>{aliasFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{aliasFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {aliasFor && (
        <div className="p-6 space-y-4">
              <input
                className="input w-full"
                placeholder="Ex.: PC do João, TV da sala"
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                autoFocus
              />
              {aliasError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{aliasError}</div>
              )}
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
        </div>
        )}
      </Modal>

      <Modal
        open={confirmFor !== null}
        onClose={() => setConfirmFor(null)}
        title={<div><span className="text-white font-semibold">{confirmFor ? (confirmFor.blocked ? 'Desbloquear host' : 'Bloquear host') : ''}</span>{confirmFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{confirmFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {confirmFor && (
        <div className="p-6 space-y-4">
              <p className="text-sm text-gray-300">
                Deseja {confirmFor.blocked ? 'desbloquear' : 'bloquear'} o host{' '}
                <span className="text-white font-medium">{confirmFor.alias || confirmFor.ip || confirmFor.mac}</span>?
              </p>
              {confirmError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{confirmError}</div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={confirmToggleBlock}
                  disabled={confirming}
                  className={`flex-1 disabled:opacity-50 ${confirmFor.blocked ? 'btn-primary' : 'btn-primary bg-red-600 hover:bg-red-500'}`}
                >
                  {confirming ? 'Processando...' : confirmFor.blocked ? 'Desbloquear' : 'Bloquear'}
                </button>
                <button onClick={() => setConfirmFor(null)} disabled={confirming} className="btn-secondary flex-1 disabled:opacity-50">
                  Cancelar
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
