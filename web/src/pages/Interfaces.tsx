import { useEffect, useState } from 'react';
import { Search, Pencil } from 'lucide-react';
import { Link } from 'react-router-dom';
import client from '../api/client';
import { useI18n } from '../i18n';
import InterfaceTraffic from '../components/InterfaceTraffic';
import Panel from '../components/ui/Panel';
import Tabs, { type TabItem } from '../components/ui/Tabs';
import Tag, { type TagVariant } from '../components/ui/Tag';
import IconButton from '../components/ui/IconButton';
import type { IfaceView, PendingChange, StableNameEntry } from '../types';

// Groups by the Role the backend already computed (spec §5.1: Role is a
// label, never re-derived on the frontend). The only extra step here is
// keeping a LAN bridge's members (e.g. eth2/eth3 under br10) out of
// "Não atribuídas" — they're rendered nested under their bridge instead of
// twice.
function groupByRole(ifaces: IfaceView[]) {
  const wan = ifaces.filter((i) => i.role === 'wan');
  const lan = ifaces.filter((i) => i.role === 'lan');
  const memberNames = new Set(lan.flatMap((i) => i.members ?? []));
  const unassigned = ifaces.filter((i) => i.role === 'unassigned' && !memberNames.has(i.name));
  return { wan, lan, unassigned, memberNames };
}

export default function Interfaces() {
  const { t } = useI18n();
  const TABS: TabItem[] = [
    { id: 'overview', label: t('net.if.tab.overview') },
    { id: 'list', label: t('net.if.tab.list') },
    { id: 'vlans', label: t('net.if.tab.vlans') },
    { id: 'bridges', label: t('net.if.tab.bridges') },
    { id: 'traffic', label: t('net.if.tab.traffic') },
  ];
  const kindLabel: Record<string, string> = { physical: t('net.if.kind.physical'), vlan: 'vlan', bridge: 'bridge' };
  const roleTag: Record<string, { label: string; variant: TagVariant }> = {
    wan: { label: 'WAN', variant: 'ok' },
    lan: { label: 'LAN', variant: 'neutral' },
    unassigned: { label: t('net.if.role.unassigned'), variant: 'idle' },
  };
  const [tab, setTab] = useState('overview');
  const [ifaces, setIfaces] = useState<IfaceView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState('');
  const [showSystem, setShowSystem] = useState(false);
  const [identifying, setIdentifying] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingChange[]>([]);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [actioning, setActioning] = useState<string | null>(null);
  const [stableNames, setStableNames] = useState<StableNameEntry[]>([]);
  const [applyingStable, setApplyingStable] = useState(false);
  const [stableApplied, setStableApplied] = useState(false);

  const handleIdentify = async (name: string) => {
    setIdentifying(name);
    try {
      await client.post(`/api/interfaces/${encodeURIComponent(name)}/identify`);
    } finally {
      setTimeout(() => setIdentifying((cur) => (cur === name ? null : cur)), 10000);
    }
  };

  useEffect(() => {
    let alive = true;
    const loadPending = async () => {
      try {
        const { data } = await client.get<PendingChange[]>('/api/interfaces/pending');
        if (alive) setPending(data ?? []);
      } catch {
        /* best-effort */
      }
    };
    loadPending();
    const t = setInterval(loadPending, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const { data } = await client.get<StableNameEntry[]>('/api/interfaces/stable-names');
        setStableNames(data);
      } catch {
        // silencioso — igual ao padrão já usado pro carregamento de `pending` acima:
        // uma falha aqui não deve travar o resto da tela.
      }
    })();
  }, []);

  const applyStableNames = async () => {
    setApplyingStable(true);
    try {
      await client.post('/api/interfaces/stable-names/apply');
      setStableApplied(true);
    } catch {
      // erro real de escrita em disco é raro (permissão, disco cheio) — o
      // handler já loga o detalhe real via writeInternalError; a UI só
      // precisa não travar.
    } finally {
      setApplyingStable(false);
    }
  };

  const handleConfirm = async (name: string) => {
    setActioning(name);
    try {
      await client.post('/api/interfaces/confirm', { name });
      setPending((prev) => prev.filter((p) => p.interface !== name));
    } finally {
      setActioning(null);
    }
  };

  const handleRollback = async (name: string) => {
    setActioning(name);
    try {
      await client.post('/api/interfaces/rollback', { name });
      setPending((prev) => prev.filter((p) => p.interface !== name));
    } finally {
      setActioning(null);
    }
  };

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const { data } = await client.get<IfaceView[]>('/api/interfaces');
        if (alive) {
          setIfaces(data ?? []);
          setError(false);
        }
      } catch {
        if (alive) setError(true);
      } finally {
        if (alive) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // System is only a naming heuristic (docker/veth/tun/wg/… prefixes — spec
  // §7.1); it says nothing about whether the interface is actually serving a
  // real, cross-referenced Role today. A LAN bridge or WAN link can
  // legitimately be named "wg0"/"tun0" (VPN-backed) or, as this dev machine's
  // docker bridges demonstrate, a "br-<hex>" name — hiding it behind the
  // system toggle would make the one interface an admin most needs to see
  // (their live WAN/LAN) silently vanish. A role-bearing interface is by
  // definition not decorative noise, so it's always visible.
  const visible = ifaces.filter((i) => showSystem || !i.live.system || i.role !== 'unassigned');
  const filtered = visible.filter((i) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      i.name.toLowerCase().includes(q) ||
      (i.alias ?? '').toLowerCase().includes(q) ||
      (i.description ?? '').toLowerCase().includes(q)
    );
  });
  const hiddenSystemCount = ifaces.length - visible.length;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">{t('net.if.title')}</h1>
        <p className="text-gray-500 text-sm mt-0.5">
          {t('net.if.subtitle')}
        </p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('net.if.loadFailed')}
        </div>
      )}

      {pending.map((p) => {
        const secondsLeft = Math.max(0, p.deadline_unix - now);
        return (
          <div key={p.interface} className="flex items-center gap-4 px-4 py-3 bg-amber-500/10 border border-amber-500/30 rounded-xl">
            <Tag variant="warn" dot>{secondsLeft}s</Tag>
            <div className="flex-1 text-sm text-amber-200">
              <span className="font-medium">{p.interface}</span>{' '}
              {t('net.if.pending.body')}
            </div>
            <button
              onClick={() => handleConfirm(p.interface)}
              disabled={actioning === p.interface}
              className="btn-primary text-xs"
            >
              {t('net.if.pending.confirm')}
            </button>
            <button
              onClick={() => handleRollback(p.interface)}
              disabled={actioning === p.interface}
              className="btn-secondary text-xs"
            >
              {t('net.if.pending.rollback')}
            </button>
          </div>
        );
      })}

      <Tabs items={TABS} active={tab} onChange={setTab} />

      {tab === 'overview' && (
        <Panel title={t('net.if.backPanel')}>
          {(() => {
            const { wan, lan, unassigned } = groupByRole(visible);
            // Only count interfaces actually still hidden — a role-bearing
            // system interface is already included in `visible` above, so it
            // must not inflate this "N hidden" count too.
            const systemIfaces = ifaces.filter((i) => i.live.system && i.role === 'unassigned');
            const byName = new Map(visible.map((i) => [i.name, i]));
            const renderRow = (i: IfaceView, indent = false) => {
              const physAbnormal = i.kind === 'physical' && (!i.live.carrier || i.live.rx_errors > 0);
              return (
                <div
                  key={i.name}
                  className={`flex items-center justify-between gap-3 py-2 border-b border-gray-800/50 last:border-0 ${indent ? 'pl-6' : ''}`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-white text-sm truncate">{i.alias || i.name}</span>
                    {i.alias && <span className="text-gray-600 text-xs font-mono">{i.name}</span>}
                    <span className="text-gray-500 text-xs font-mono">
                      {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                    </span>
                    {i.kind !== 'physical' && (
                      <span className="text-gray-600 text-xs">
                        {i.kind === 'vlan' ? `vlan · tag ${i.vlan_id}` : 'bridge'}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {i.kind === 'physical' && (
                      <Tag variant={physAbnormal ? 'warn' : 'ok'} dot>
                        {i.live.carrier ? t('net.if.link.up') : t('net.if.link.down')}
                      </Tag>
                    )}
                    {i.kind === 'physical' && (
                      <button
                        onClick={() => handleIdentify(i.name)}
                        disabled={identifying === i.name}
                        className="text-xs text-gray-500 hover:text-gray-300 disabled:text-blue-400"
                      >
                        {identifying === i.name ? t('net.if.blinking') : t('net.if.identify')}
                      </button>
                    )}
                    {i.kind === 'physical' && (
                      <Link to={`/interfaces/${encodeURIComponent(i.name)}/edit`} className="text-xs text-gray-500 hover:text-gray-300">
                        {t('net.if.edit')}
                      </Link>
                    )}
                  </div>
                </div>
              );
            };
            return (
              <div className="space-y-4">
                {wan.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">WAN</div>
                    {wan.map((i) => renderRow(i))}
                  </div>
                )}
                {lan.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">LAN</div>
                    {lan.map((i) => (
                      <div key={i.name}>
                        {renderRow(i)}
                        {(i.members ?? []).map((m) => {
                          const member = byName.get(m);
                          return member ? renderRow(member, true) : null;
                        })}
                      </div>
                    ))}
                  </div>
                )}
                {unassigned.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">{t('net.if.group.unassigned')}</div>
                    {unassigned.map((i) => renderRow(i))}
                  </div>
                )}
                {wan.length === 0 && lan.length === 0 && unassigned.length === 0 && (
                  <p className="text-gray-500 text-sm">{t('net.if.none')}</p>
                )}
                {systemIfaces.length > 0 && !showSystem && (
                  <button onClick={() => setShowSystem(true)} className="text-xs text-gray-600 hover:text-gray-400">
                    {t('net.if.systemHidden', { n: systemIfaces.length })}
                  </button>
                )}
              </div>
            );
          })()}
        </Panel>
      )}

      {tab === 'overview' && stableNames.length > 0 && (
        <Panel title={t('net.if.stable.title')}>
          <p className="text-gray-500 text-sm mb-3">
            {t('net.if.stable.body')}{' '}
            {t('net.if.stable.reboot')}<b>{t('net.if.stable.reboot.strong')}</b>{t('net.if.stable.reboot.tail')}
          </p>
          <div className="space-y-2 mb-3">
            {stableNames.map((e) => (
              <div key={e.interface} className="flex items-center justify-between text-sm border-b border-gray-800/50 last:border-0 py-1.5">
                <span className="text-gray-400">{e.link_name}</span>
                <span className="text-gray-600 font-mono text-xs">{e.mac}</span>
                <span className="text-white font-mono">{e.interface} → {e.stable_name}</span>
              </div>
            ))}
          </div>
          {stableApplied ? (
            <p className="text-green-400 text-sm">{t('net.if.stable.applied')}</p>
          ) : (
            <button onClick={applyStableNames} disabled={applyingStable} className="btn-primary text-sm disabled:opacity-50">
              {applyingStable ? t('net.if.stable.applying') : t('net.if.stable.apply')}
            </button>
          )}
        </Panel>
      )}

      {tab === 'list' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('net.if.search.ph')}
                className="input pl-9 w-full"
              />
            </div>
            {hiddenSystemCount > 0 && (
              <button
                onClick={() => setShowSystem((v) => !v)}
                className="text-xs text-gray-500 hover:text-gray-300"
              >
                {showSystem
                  ? t('net.if.toggle.hide', { n: hiddenSystemCount })
                  : t('net.if.toggle.show', { n: hiddenSystemCount })}
              </button>
            )}
          </div>

          {loading ? (
            <div className="text-gray-500 text-sm">{t('common.loading')}</div>
          ) : (
            <>
              {/* Mobile: stacked cards (< sm) */}
              <div className="sm:hidden space-y-2">
                {filtered.map((i) => {
                  const roleCfg = roleTag[i.role] ?? roleTag.unassigned;
                  const physAbnormal = !i.live.carrier || i.live.rx_errors > 0 || i.live.tx_errors > 0;
                  return (
                    <div key={i.name} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-white font-medium truncate">{i.alias || i.name}</div>
                          {i.alias && <div className="text-gray-500 text-xs font-mono truncate">{i.name}</div>}
                          <Tag variant={roleCfg.variant} className="mt-1">{roleCfg.label}</Tag>
                        </div>
                        {i.kind === 'physical' && (
                          <div className="flex shrink-0 gap-1">
                            <IconButton
                              icon={Pencil}
                              to={`/interfaces/${encodeURIComponent(i.name)}/edit`}
                              label={t('net.if.action.edit')}
                            />
                          </div>
                        )}
                      </div>
                      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                        <dt className="text-gray-500">{t('net.if.col.kind')}</dt>
                        <dd className="text-gray-400">{kindLabel[i.kind] ?? i.kind}</dd>
                        <dt className="text-gray-500">{t('net.if.col.address')}</dt>
                        <dd className="text-gray-400 font-mono">
                          {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                        </dd>
                        <dt className="text-gray-500">{t('net.if.col.physical')}</dt>
                        <dd>
                          {i.kind === 'physical' ? (
                            <Tag variant={physAbnormal ? 'warn' : 'ok'} dot>
                              {i.live.carrier ? t('net.if.link.up') : t('net.if.link.down')}
                            </Tag>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </dd>
                      </dl>
                    </div>
                  );
                })}
                {filtered.length === 0 && (
                  <div className="text-center text-gray-500 text-sm py-6">{t('net.if.noneFound')}</div>
                )}
              </div>

              {/* Desktop: table (>= sm) */}
              <div className="hidden sm:block card overflow-x-auto">
                <table className="hidden sm:table w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-gray-800">
                      <th className="pb-3 pr-4 font-medium">{t('net.if.col.interface')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.if.col.kind')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.if.col.address')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.if.col.physical')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.if.col.role')}</th>
                      <th className="pb-3 font-medium">{t('net.col.actions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((i) => {
                      const roleCfg = roleTag[i.role] ?? roleTag.unassigned;
                      const physAbnormal = !i.live.carrier || i.live.rx_errors > 0 || i.live.tx_errors > 0;
                      return (
                        <tr key={i.name} className="table-row">
                          <td className="py-3 pr-4">
                            <div className="text-white font-medium">{i.alias || i.name}</div>
                            {i.alias && <div className="text-gray-500 text-xs font-mono">{i.name}</div>}
                          </td>
                          <td className="py-3 pr-4 text-gray-400">{kindLabel[i.kind] ?? i.kind}</td>
                          <td className="py-3 pr-4 text-gray-400 font-mono">
                            {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                          </td>
                          <td className="py-3 pr-4">
                            {i.kind === 'physical' ? (
                              <Tag variant={physAbnormal ? 'warn' : 'ok'} dot>
                                {i.live.carrier ? t('net.if.link.up') : t('net.if.link.down')}
                              </Tag>
                            ) : (
                              <span className="text-gray-600">—</span>
                            )}
                          </td>
                          <td className="py-3 pr-4">
                            <Tag variant={roleCfg.variant}>{roleCfg.label}</Tag>
                          </td>
                          <td className="py-3">
                            {i.kind === 'physical' && (
                              <IconButton
                                icon={Pencil}
                                to={`/interfaces/${encodeURIComponent(i.name)}/edit`}
                                label={t('net.if.action.edit')}
                              />
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {filtered.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-6 text-center text-gray-500">
                          {t('net.if.noneFound')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {tab === 'vlans' && (() => {
        const vlans = visible.filter((i) => i.kind === 'vlan');
        return (
          <>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {vlans.map((i) => (
                <div key={i.name} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                  <div className="text-white font-medium truncate">{i.alias || i.name}</div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('net.if.col.parent')}</dt>
                    <dd className="text-gray-400 font-mono">{i.parent ?? '—'}</dd>
                    <dt className="text-gray-500">{t('net.if.col.tag')}</dt>
                    <dd className="text-gray-400 font-mono">{i.vlan_id ?? '—'}</dd>
                    <dt className="text-gray-500">{t('net.if.col.address')}</dt>
                    <dd className="text-gray-400 font-mono">
                      {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                    </dd>
                  </dl>
                </div>
              ))}
              {vlans.length === 0 && (
                <div className="text-center text-gray-500 text-sm py-6">{t('net.if.vlans.none')}</div>
              )}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block card overflow-x-auto">
              <table className="hidden sm:table w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">{t('net.if.col.name')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('net.if.col.parent')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('net.if.col.tag')}</th>
                    <th className="pb-3 font-medium">{t('net.if.col.address')}</th>
                  </tr>
                </thead>
                <tbody>
                  {vlans.map((i) => (
                    <tr key={i.name} className="table-row">
                      <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono">{i.parent ?? '—'}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono">{i.vlan_id ?? '—'}</td>
                      <td className="py-3 text-gray-400 font-mono">
                        {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                      </td>
                    </tr>
                  ))}
                  {vlans.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-6 text-center text-gray-500">{t('net.if.vlans.none')}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        );
      })()}

      {tab === 'bridges' && (() => {
        const bridges = visible.filter((i) => i.kind === 'bridge');
        return (
          <>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {bridges.map((i) => (
                <div key={i.name} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                  <div className="text-white font-medium truncate">{i.alias || i.name}</div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('net.if.col.members')}</dt>
                    <dd className="text-gray-400 font-mono">{(i.members ?? []).join(', ') || '—'}</dd>
                    <dt className="text-gray-500">{t('net.if.col.address')}</dt>
                    <dd className="text-gray-400 font-mono">
                      {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                    </dd>
                  </dl>
                </div>
              ))}
              {bridges.length === 0 && (
                <div className="text-center text-gray-500 text-sm py-6">{t('net.if.bridges.none')}</div>
              )}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block card overflow-x-auto">
              <table className="hidden sm:table w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">{t('net.if.col.name')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('net.if.col.members')}</th>
                    <th className="pb-3 font-medium">{t('net.if.col.address')}</th>
                  </tr>
                </thead>
                <tbody>
                  {bridges.map((i) => (
                    <tr key={i.name} className="table-row">
                      <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono">{(i.members ?? []).join(', ') || '—'}</td>
                      <td className="py-3 text-gray-400 font-mono">
                        {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                      </td>
                    </tr>
                  ))}
                  {bridges.length === 0 && (
                    <tr>
                      <td colSpan={3} className="py-6 text-center text-gray-500">{t('net.if.bridges.none')}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        );
      })()}

      {tab === 'traffic' && <InterfaceTraffic />}
    </div>
  );
}
