import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, Pencil, Ban, ShieldCheck, Circle, TrendingUp, ArrowDown, ArrowUp, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import { blockEnforcement, KIND_BLOCKED_HOSTS } from '../lib/blockGroups';
import type { NetHost, HostTraffic, FirewallGroup, FirewallGroupsData } from '../types';
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
  const { t } = useI18n();
  const canManage = can('hosts.block');
  const canReadFirewall = can('firewall.read');
  const [hosts, setHosts] = useState<NetHost[]>([]);
  // Os grupos do firewall, só para saber se o bloqueio de host está mesmo em
  // vigor. Desde que os bloqueios viraram grupos reordenáveis, marcar um host
  // como bloqueado deixou de bastar: o grupo "Hosts bloqueados" pode estar
  // desligado, ou arrastado para depois de um grupo do admin que faz accept —
  // e nos dois casos esta tela mostraria "bloqueado" enquanto o tráfego passa.
  // null = não consultado (sem permissão de firewall ou falha), que NÃO é o
  // mesmo que "está tudo certo": nesse caso a tela não afirma nada.
  const [fwGroups, setFwGroups] = useState<FirewallGroup[] | null>(null);
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
    await fetchBlockGroup();
  };

  // Estado do grupo de bloqueio — melhor esforço, exige firewall.read.
  const fetchBlockGroup = async () => {
    if (!canReadFirewall) { setFwGroups(null); return; }
    try {
      const g = await client.get<FirewallGroupsData>('/api/nftables/groups');
      setFwGroups(g.data?.groups ?? []);
    } catch {
      setFwGroups(null);
    }
  };

  useEffect(() => { fetchHosts(); }, []);
  // As permissões chegam depois da primeira renderização (/api/auth/me é
  // assíncrono): sem este efeito, a consulta acima seria pulada em toda
  // navegação direta para esta página e a tela nunca saberia se o bloqueio
  // está em vigor — calada, como se estivesse.
  useEffect(() => { fetchBlockGroup(); }, [canReadFirewall]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return hosts;
    return hosts.filter((h) =>
      [h.ip, h.mac, h.alias, h.hostname, h.interface].some((v) => v?.toLowerCase().includes(q)),
    );
  }, [hosts, filter]);

  const onlineCount = useMemo(() => hosts.filter((h) => h.online).length, [hosts]);
  const blockedCount = useMemo(() => hosts.filter((h) => h.blocked).length, [hosts]);

  // enforcement é a resposta a "bloquear aqui adianta alguma coisa?".
  //
  // O que as duas telas compartilham de verdade é o critério de "quem decide
  // antes deste bloqueio" (lib/blockGroups.adminGroupsAbove), usado aqui por
  // dentro do blockEnforcement e lá direto, no aviso de ordem da lista de
  // grupos — era isso que tinha duas implementações e já divergia. O resto
  // não é compartilhado nem deveria ser: a lista de grupos fala de UM item
  // que o admin está olhando, esta tela responde por um inventário inteiro e
  // por isso precisa também dos estados que a outra não tem o que dizer
  // (grupo ausente da lista, sem permissão para consultá-la).
  const enforcement = useMemo(() => blockEnforcement(fwGroups, KIND_BLOCKED_HOSTS), [fwGroups]);
  // `off_but_live` fica DE FORA daqui de propósito: nesse estado o kernel
  // está descartando o tráfego: dizer "podem não estar sendo bloqueados de
  // verdade" seria a mesma mentira ao contrário. Ele tem faixa própria.
  const notEnforced = enforcement.status === 'off' || enforcement.status === 'not_applied' || enforcement.status === 'shadowed';

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
      setAliasError(err.response?.data?.error || t('svc.hosts.alias.saveError'));
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
    const failMsg = h.blocked ? t('svc.hosts.err.unblock') : t('svc.hosts.err.block');
    setConfirming(true);
    setConfirmError('');
    try {
      await client.post('/api/hosts/block', { mac: h.mac, blocked: !h.blocked });
      setConfirmFor(null);
      await fetchHosts();
    } catch (err: any) {
      setConfirmError(err.response?.data?.error || failMsg);
    } finally {
      setConfirming(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('svc.hosts.title')}</h1>
          <p className="text-gray-500 text-sm">
            {t('svc.hosts.subtitle', { online: onlineCount, total: hosts.length })}
          </p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <input
            className="input flex-1 sm:w-64"
            placeholder={t('svc.hosts.filter.placeholder')}
            aria-label={t('svc.hosts.filter.aria')}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button onClick={fetchHosts} disabled={loading} className="btn-secondary flex items-center gap-2 whitespace-nowrap disabled:opacity-50">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> {t('svc.common.refresh')}
          </button>
        </div>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{t('svc.common.loadFailed')} <button onClick={fetchHosts} className="underline">{t('svc.common.tryAgain')}</button></div>}

      {/* "Bloqueado" no inventário não é mais garantia de bloqueio em vigor:
          o grupo do sistema que descarta esses hosts pode estar desligado,
          pode não estar aplicado, ou pode ter sido arrastado para depois de
          um grupo do admin que libera antes. Quando isso acontece, o painel
          diz — com o motivo e o caminho para resolver —, em vez de mostrar um
          selo vermelho de bloqueio que o tráfego desmente. */}
      {blockedCount > 0 && notEnforced && (
        <div className="card border border-orange-500/40 bg-orange-500/10 text-sm">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-orange-300">
                {blockedCount === 1 ? t('svc.hosts.notEnforced.one') : t('svc.hosts.notEnforced.many', { n: blockedCount })}
              </p>
              <p className="text-gray-300 text-xs mt-1">{enforcement.reason}</p>
              <p className="text-gray-400 text-xs mt-1">
                {enforcement.fix}{' '}
                <Link to="/firewall?tab=groups" className="text-blue-400 hover:text-blue-300 underline">{t('svc.hosts.openGroups')}</Link>
              </p>
            </div>
          </div>
        </div>
      )}
      {/* O inverso do aviso acima, e igualmente uma mentira se ficar calado:
          o grupo aparece desligado no painel e o firewall continua com as
          linhas de bloqueio. Quem desligou acha que liberou. */}
      {enforcement.status === 'off_but_live' && (
        <div className="card border border-yellow-500/40 bg-yellow-500/10 text-sm">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-yellow-300">{t('svc.hosts.offButLive')}</p>
              <p className="text-gray-300 text-xs mt-1">{enforcement.reason}</p>
              <p className="text-gray-400 text-xs mt-1">
                {enforcement.fix}{' '}
                <Link to="/firewall?tab=groups" className="text-blue-400 hover:text-blue-300 underline">{t('svc.hosts.openGroups')}</Link>
              </p>
            </div>
          </div>
        </div>
      )}
      {blockedCount > 0 && enforcement.status === 'unknown' && enforcement.reason && (
        <div className="card border border-gray-700 text-sm text-gray-400">
          <span className="text-gray-300">{enforcement.reason}</span>{' '}
          {t('svc.hosts.unknownEnforcement')} {enforcement.fix}
        </div>
      )}

      {talkers.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><TrendingUp className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('svc.hosts.talkers.title')}</span><span className="text-xs text-gray-600 font-normal">{t('svc.hosts.talkers.hint')}</span></span>}>
          <div className="space-y-2.5">
            {talkers.slice(0, 8).map((tk) => {
              const total = tk.rx_bytes + tk.tx_bytes;
              const max = (talkers[0].rx_bytes + talkers[0].tx_bytes) || 1;
              const host = hosts.find((h) => h.ip === tk.ip);
              const name = host?.alias || host?.hostname || tk.ip;
              return (
                <div key={tk.ip} className="flex items-center gap-3">
                  <div className="w-36 sm:w-44 shrink-0 min-w-0">
                    <div className="text-white text-sm truncate">{name}</div>
                    <div className="text-gray-600 text-xs font-mono truncate">{tk.ip}</div>
                  </div>
                  <div className="flex-1 h-2 rounded-full bg-gray-800 overflow-hidden">
                    <div className="h-full bg-blue-500" style={{ width: `${(total / max) * 100}%` }} />
                  </div>
                  <div className="shrink-0 text-xs text-gray-400 flex items-center justify-end gap-3 w-32 sm:w-40">
                    <span className="inline-flex items-center gap-1" title={t('svc.hosts.talkers.down')}><ArrowDown className="w-3 h-3 text-green-400" />{fmtBytes(tk.rx_bytes)}</span>
                    <span className="inline-flex items-center gap-1" title={t('svc.hosts.talkers.up')}><ArrowUp className="w-3 h-3 text-orange-400" />{fmtBytes(tk.tx_bytes)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      <Panel>
        {loading && hosts.length === 0 ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">{t('common.loading')}</div>
        ) : error && hosts.length === 0 ? (
          <div className="text-center py-12 text-gray-500">{t('svc.hosts.loadError')}</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            {hosts.length === 0 ? t('svc.hosts.empty') : t('svc.hosts.noMatch')}
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
                          aria-label={t('svc.hosts.alias')}
                          className="text-gray-400 hover:text-blue-400 transition-colors"
                        >
                          <Pencil className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => openConfirm(h)}
                          aria-label={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                          className={`transition-colors ${h.blocked ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                        >
                          {h.blocked ? <ShieldCheck className="w-5 h-5" /> : <Ban className="w-5 h-5" />}
                        </button>
                      </div>
                    )}
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('svc.hosts.col.ip')}</dt>
                    <dd className="text-gray-400 font-mono">{h.ip || '—'}</dd>
                    <dt className="text-gray-500">{t('svc.hosts.col.mac')}</dt>
                    <dd className="text-gray-500 font-mono">{h.mac}</dd>
                    <dt className="text-gray-500">{t('svc.hosts.col.interface')}</dt>
                    <dd className="text-gray-400 font-mono">{h.interface || '—'}</dd>
                  </dl>
                  {h.blocked && (
                    <span
                      className={`mt-2 inline-flex items-center gap-1 text-xs ${notEnforced ? 'text-orange-400' : 'text-red-400'}`}
                      title={notEnforced ? enforcement.reason : undefined}
                    >
                      <Ban className="w-3 h-3" /> {notEnforced ? t('svc.hosts.badge.notEnforced') : t('svc.hosts.badge.blocked')}
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
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.host')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.ip')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.mac')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.interface')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.state')}</th>
                    {canManage && <th className="pb-3 font-medium">{t('svc.hosts.col.actions')}</th>}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((h) => (
                    <tr key={h.mac || h.ip} className={`table-row ${h.blocked ? 'border-l-2 border-l-red-500 opacity-75' : ''}`}>
                      <td className="py-3 pr-4">
                        <div className="text-white font-medium">{h.alias || h.hostname || '—'}</div>
                        {h.blocked && (
                          <span
                            className={`inline-flex items-center gap-1 text-xs ${notEnforced ? 'text-orange-400' : 'text-red-400'}`}
                            title={notEnforced ? enforcement.reason : undefined}
                          >
                            <Ban className="w-3 h-3" /> {notEnforced ? t('svc.hosts.badge.notEnforced') : t('svc.hosts.badge.blocked')}
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
                              title={t('svc.hosts.alias')}
                              aria-label={t('svc.hosts.alias')}
                              className="text-gray-400 hover:text-blue-400 transition-colors"
                            >
                              <Pencil className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => openConfirm(h)}
                              title={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                              aria-label={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
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
        title={<div><span className="text-white font-semibold">{t('svc.hosts.aliasModal.title')}</span>{aliasFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{aliasFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {aliasFor && (
        <div className="p-6 space-y-4">
              <input
                className="input w-full"
                placeholder={t('svc.hosts.aliasModal.placeholder')}
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                autoFocus
              />
              {aliasError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{aliasError}</div>
              )}
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? t('common.saving') : t('common.save')}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">{t('common.cancel')}</button>
              </div>
        </div>
        )}
      </Modal>

      <Modal
        open={confirmFor !== null}
        onClose={() => setConfirmFor(null)}
        title={<div><span className="text-white font-semibold">{confirmFor ? (confirmFor.blocked ? t('svc.hosts.unblockModal.title') : t('svc.hosts.blockModal.title')) : ''}</span>{confirmFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{confirmFor.mac}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {confirmFor && (
        <div className="p-6 space-y-4">
              <p className="text-sm text-gray-300">
                {confirmFor.blocked ? t('svc.hosts.confirm.unblock') : t('svc.hosts.confirm.block')}{' '}
                <span className="text-white font-medium">{confirmFor.alias || confirmFor.ip || confirmFor.mac}</span>?
              </p>
              {/* Bloquear com o grupo desligado, não aplicado ou embaixo de um
                  grupo que libera devolveria "sucesso" e não bloquearia nada.
                  Dizer isso ANTES do clique é o ponto: depois, o host já
                  aparece bloqueado na lista. */}
              {!confirmFor.blocked && notEnforced && (
                <div className="rounded-lg border border-orange-500/40 bg-orange-500/10 px-3 py-2 text-xs">
                  <p className="text-orange-300 flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
                    <span>{t('svc.hosts.confirm.wontApply')}</span>
                  </p>
                  <p className="text-gray-300 mt-1">{enforcement.reason}</p>
                  <p className="text-gray-400 mt-1">
                    {enforcement.fix}{' '}
                    <Link to="/firewall?tab=groups" className="text-blue-400 hover:text-blue-300 underline">{t('svc.hosts.openGroups')}</Link>
                  </p>
                </div>
              )}
              {confirmError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{confirmError}</div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={confirmToggleBlock}
                  disabled={confirming}
                  className={`flex-1 disabled:opacity-50 ${confirmFor.blocked ? 'btn-primary' : 'btn-primary bg-red-600 hover:bg-red-500'}`}
                >
                  {confirming ? t('svc.hosts.processing') : confirmFor.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                </button>
                <button onClick={() => setConfirmFor(null)} disabled={confirming} className="btn-secondary flex-1 disabled:opacity-50">
                  {t('common.cancel')}
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
