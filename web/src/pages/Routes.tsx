import { useEffect, useRef, useState } from 'react';
import { RefreshCw, Route as RouteIcon, Plus, Pencil, Trash2, ListTree } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import type { Route, IpRule } from '../types';
import IconButton from '../components/ui/IconButton';

type RouteForm = {
  destination: string;
  gateway: string;
  interface: string;
  table: string;
};

type RuleForm = {
  from: string;
  fwmark: string;
  table: string;
  priority: string;
};

const emptyRouteForm: RouteForm = { destination: 'default', gateway: '', interface: '', table: '' };
const emptyRuleForm: RuleForm = { from: 'all', fwmark: '', table: 'main', priority: '' };

export default function Routes() {
  const { t } = useI18n();
  const [routes, setRoutes] = useState<Route[]>([]);
  const [rules, setRules] = useState<IpRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'routes' | 'rules'>('routes');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  // Route modal state.
  const [showRouteModal, setShowRouteModal] = useState(false);
  const [routeEditing, setRouteEditing] = useState<Route | null>(null);
  const [routeForm, setRouteForm] = useState<RouteForm>(emptyRouteForm);
  const [routeError, setRouteError] = useState('');

  // Rule modal state.
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [ruleEditing, setRuleEditing] = useState<IpRule | null>(null);
  const [ruleForm, setRuleForm] = useState<RuleForm>(emptyRuleForm);
  const [ruleError, setRuleError] = useState('');

  const msgTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Auto-dismiss the status banner after ~4s.
  useEffect(() => {
    if (!msg) return;
    if (msgTimer.current) clearTimeout(msgTimer.current);
    msgTimer.current = setTimeout(() => setMsg(''), 4000);
    return () => {
      if (msgTimer.current) clearTimeout(msgTimer.current);
    };
  }, [msg]);

  // Clear the banner when switching tabs.
  useEffect(() => {
    setMsg('');
  }, [activeTab]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [routesRes, rulesRes] = await Promise.all([
        client.get<Route[]>('/api/routes'),
        client.get<IpRule[]>('/api/routes/rules'),
      ]);
      setRoutes(routesRes.data ?? []);
      setRules(rulesRes.data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const parseFromSelector = (selector: string) => {
    const trimmed = selector.trim();
    if (trimmed.startsWith('from ')) {
      return trimmed.slice(5).trim();
    }
    return '';
  };

  // The Route type carries no explicit table field; non-main routes come from
  // `ip route show table all`, which appends a `table <name>` token to the raw
  // line. Extract it so edit/delete can target the correct table.
  const parseRouteTable = (r: Route) => {
    const fields = (r.raw || '').trim().split(/\s+/);
    const idx = fields.indexOf('table');
    if (idx >= 0 && idx + 1 < fields.length) {
      const table = fields[idx + 1];
      if (table && table !== 'main') return table;
    }
    return '';
  };

  // ─── Route modal ──────────────────────────────────────────────────────────
  const openAddRoute = () => {
    setRouteEditing(null);
    setRouteForm({ ...emptyRouteForm });
    setRouteError('');
    setShowRouteModal(true);
  };

  const openEditRoute = (r: Route) => {
    setRouteEditing(r);
    setRouteForm({
      destination: r.destination,
      gateway: r.gateway || '',
      interface: r.interface || '',
      table: parseRouteTable(r),
    });
    setRouteError('');
    setShowRouteModal(true);
  };

  const submitRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!routeForm.destination.trim()) {
      setRouteError(t('net.routes.form.destRequired'));
      return;
    }

    setSaving(true);
    setRouteError('');
    setMsg('');
    try {
      if (routeEditing) {
        await client.put('/api/routes', {
          old_destination: routeEditing.destination,
          old_table: parseRouteTable(routeEditing),
          destination: routeForm.destination.trim(),
          gateway: routeForm.gateway.trim(),
          interface: routeForm.interface.trim(),
          table: routeForm.table.trim(),
        });
        setMsg(t('net.routes.toast.updated'));
      } else {
        await client.post('/api/routes', {
          destination: routeForm.destination.trim(),
          gateway: routeForm.gateway.trim(),
          interface: routeForm.interface.trim(),
          table: routeForm.table.trim(),
        });
        setMsg(t('net.routes.toast.added'));
      }
      setShowRouteModal(false);
      await fetchData();
    } catch (err: any) {
      setRouteError(err.response?.data?.error || err.message || t('net.routes.form.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRoute = async (r: Route) => {
    if (!confirm(t('net.routes.confirm.delete', { d: r.destination }))) return;
    setSaving(true);
    setMsg('');
    try {
      await client.delete('/api/routes', { data: { destination: r.destination, table: parseRouteTable(r) } });
      setMsg(t('net.routes.toast.removed'));
      await fetchData();
    } catch (e: any) {
      setMsg(t('net.msg.error', { e: e.response?.data?.error || e.message }));
    } finally {
      setSaving(false);
    }
  };

  // ─── Rule modal ───────────────────────────────────────────────────────────
  const openAddRule = () => {
    setRuleEditing(null);
    setRuleForm({ ...emptyRuleForm });
    setRuleError('');
    setShowRuleModal(true);
  };

  const openEditRule = (r: IpRule) => {
    setRuleEditing(r);
    setRuleForm({
      from: parseFromSelector(r.selector) || 'all',
      fwmark: r.fwmark || '',
      table: r.table || 'main',
      priority: r.priority || '',
    });
    setRuleError('');
    setShowRuleModal(true);
  };

  const submitRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleForm.table.trim()) {
      setRuleError(t('net.rules.form.tableRequired'));
      return;
    }
    const priorityNum = Number(ruleForm.priority || 0);
    const priority = Number.isNaN(priorityNum) ? 0 : priorityNum;

    setSaving(true);
    setRuleError('');
    setMsg('');
    try {
      if (ruleEditing) {
        await client.put('/api/routes/rules', {
          old_from: parseFromSelector(ruleEditing.selector),
          old_fwmark: ruleEditing.fwmark || '',
          old_table: ruleEditing.table,
          old_priority: Number(ruleEditing.priority || 0),
          from: ruleForm.from.trim(),
          fwmark: ruleForm.fwmark.trim(),
          table: ruleForm.table.trim(),
          priority,
        });
        setMsg(t('net.rules.toast.updated'));
      } else {
        await client.post('/api/routes/rules', {
          from: ruleForm.from.trim(),
          fwmark: ruleForm.fwmark.trim(),
          table: ruleForm.table.trim(),
          priority,
        });
        setMsg(t('net.rules.toast.added'));
      }
      setShowRuleModal(false);
      await fetchData();
    } catch (err: any) {
      setRuleError(err.response?.data?.error || err.message || t('net.rules.form.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRule = async (r: IpRule) => {
    if (!confirm(t('net.rules.confirm.delete', { p: r.priority, s: r.selector }))) return;
    setSaving(true);
    setMsg('');
    try {
      await client.delete('/api/routes/rules', {
        data: {
          from: parseFromSelector(r.selector),
          fwmark: r.fwmark || '',
          table: r.table,
          priority: Number(r.priority || 0),
        },
      });
      setMsg(t('net.rules.toast.removed'));
      await fetchData();
    } catch (e: any) {
      setMsg(t('net.msg.error', { e: e.response?.data?.error || e.message }));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('net.routes.title')}</h1>
          <p className="text-gray-500 text-sm">{t('net.routes.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          {activeTab === 'routes' ? (
            <button onClick={openAddRoute} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              <Plus className="w-4 h-4" />
              {t('net.routes.new')}
            </button>
          ) : (
            <button onClick={openAddRule} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              <Plus className="w-4 h-4" />
              {t('net.rules.new')}
            </button>
          )}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            {t('net.action.refresh')}
          </button>
        </div>
      </div>

      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith(t('net.msg.errorPrefix')) ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
          {msg}
        </div>
      )}

      <div className="flex gap-2 border-b border-gray-800">
        <button
          onClick={() => setActiveTab('routes')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            activeTab === 'routes' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          {t('net.routes.tab.routes', { n: routes.length })}
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            activeTab === 'rules' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          {t('net.routes.tab.rules', { n: rules.length })}
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">{t('common.loading')}</div>
        ) : activeTab === 'routes' ? (
          routes.length === 0 ? (
            <div className="text-center py-12">
              <RouteIcon className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">{t('net.routes.empty')}</p>
            </div>
          ) : (
            <>
              {/* Mobile: stacked cards (< sm) */}
              <div className="sm:hidden space-y-2">
                {routes.map((r) => (
                  <div key={`${r.destination}|${parseRouteTable(r) || 'main'}`} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-white font-medium font-mono truncate">{r.destination}</div>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <IconButton icon={Pencil} onClick={() => openEditRoute(r)} label={t('net.routes.action.edit')} disabled={saving} />
                        <IconButton icon={Trash2} onClick={() => handleDeleteRoute(r)} label={t('net.routes.action.delete')} variant="danger" disabled={saving} />
                      </div>
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">{t('net.routes.col.gateway')}</dt>
                      <dd className="text-gray-400 font-mono">{r.gateway || '—'}</dd>
                      <dt className="text-gray-500">{t('net.routes.col.interface')}</dt>
                      <dd className="text-gray-400 font-mono">{r.interface || '—'}</dd>
                      <dt className="text-gray-500">{t('net.routes.col.protocol')}</dt>
                      <dd className="text-gray-400">{r.protocol || '—'}</dd>
                      <dt className="text-gray-500">{t('net.routes.col.metric')}</dt>
                      <dd className="text-gray-400">{r.metric || '—'}</dd>
                      <dt className="text-gray-500">{t('net.routes.col.scope')}</dt>
                      <dd className="text-gray-400">{r.scope || '—'}</dd>
                    </dl>
                  </div>
                ))}
              </div>

              {/* Desktop: table (>= sm) */}
              <div className="hidden sm:block overflow-x-auto">
                <table className="hidden sm:table w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-gray-800">
                      <th className="pb-3 pr-4 font-medium">{t('net.routes.col.destination')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.routes.col.gateway')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.routes.col.interface')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.routes.col.protocol')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.routes.col.metric')}</th>
                      <th className="pb-3 font-medium">{t('net.routes.col.scope')}</th>
                      <th className="pb-3 font-medium">{t('net.col.actions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {routes.map((r) => (
                      <tr key={`${r.destination}|${parseRouteTable(r) || 'main'}`} className="table-row">
                        <td className="py-3 pr-4 text-white font-mono">{r.destination}</td>
                        <td className="py-3 pr-4 text-gray-400 font-mono">{r.gateway || '—'}</td>
                        <td className="py-3 pr-4 text-gray-400 font-mono">{r.interface || '—'}</td>
                        <td className="py-3 pr-4 text-gray-400">{r.protocol || '—'}</td>
                        <td className="py-3 pr-4 text-gray-400">{r.metric || '—'}</td>
                        <td className="py-3 text-gray-400">{r.scope || '—'}</td>
                        <td className="py-3">
                          <div className="flex gap-2">
                            <IconButton icon={Pencil} onClick={() => openEditRoute(r)} label={t('net.routes.action.edit')} disabled={saving} />
                            <IconButton icon={Trash2} onClick={() => handleDeleteRoute(r)} label={t('net.routes.action.delete')} variant="danger" disabled={saving} />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )
        ) : (
          rules.length === 0 ? (
            <div className="text-center py-12">
              <ListTree className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">{t('net.rules.empty')}</p>
            </div>
          ) : (
            <>
              {/* Mobile: stacked cards (< sm) */}
              <div className="sm:hidden space-y-2">
                {rules.map((r) => (
                  <div key={`${r.selector}|${r.priority}`} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-white font-medium font-mono truncate">{r.selector}</div>
                        <span className="text-xs text-gray-500 font-mono">{t('net.rules.priorityInline', { p: r.priority })}</span>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <IconButton icon={Pencil} onClick={() => openEditRule(r)} label={t('net.rules.action.edit')} disabled={saving} />
                        <IconButton icon={Trash2} onClick={() => handleDeleteRule(r)} label={t('net.rules.action.delete')} variant="danger" disabled={saving} />
                      </div>
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">{t('net.rules.col.priority')}</dt>
                      <dd className="text-gray-400 font-mono">{r.priority}</dd>
                      <dt className="text-gray-500">{t('net.rules.col.fwmark')}</dt>
                      <dd className="text-gray-400 font-mono">{r.fwmark || '—'}</dd>
                      <dt className="text-gray-500">{t('net.rules.col.action')}</dt>
                      <dd className="text-gray-400">{r.action || '—'}</dd>
                      <dt className="text-gray-500">{t('net.rules.col.table')}</dt>
                      <dd className="text-gray-400 font-mono">{r.table || '—'}</dd>
                    </dl>
                  </div>
                ))}
              </div>

              {/* Desktop: table (>= sm) */}
              <div className="hidden sm:block overflow-x-auto">
                <table className="hidden sm:table w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-gray-800">
                      <th className="pb-3 pr-4 font-medium">{t('net.rules.col.priority')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.rules.col.selector')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.rules.col.fwmark')}</th>
                      <th className="pb-3 pr-4 font-medium">{t('net.rules.col.action')}</th>
                      <th className="pb-3 font-medium">{t('net.rules.col.table')}</th>
                      <th className="pb-3 font-medium">{t('net.col.actions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((r) => (
                      <tr key={`${r.selector}|${r.priority}`} className="table-row">
                        <td className="py-3 pr-4 text-gray-400 font-mono">{r.priority}</td>
                        <td className="py-3 pr-4 text-white font-mono">{r.selector}</td>
                        <td className="py-3 pr-4 text-gray-400 font-mono">{r.fwmark || '—'}</td>
                        <td className="py-3 pr-4 text-gray-400">{r.action || '—'}</td>
                        <td className="py-3 text-gray-400 font-mono">{r.table || '—'}</td>
                        <td className="py-3">
                          <div className="flex gap-2">
                            <IconButton icon={Pencil} onClick={() => openEditRule(r)} label={t('net.rules.action.edit')} disabled={saving} />
                            <IconButton icon={Trash2} onClick={() => handleDeleteRule(r)} label={t('net.rules.action.delete')} variant="danger" disabled={saving} />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )
        )}
      </div>

      {/* Route modal */}
      {showRouteModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">
                {routeEditing ? t('net.routes.modal.edit') : t('net.routes.new')}
              </h2>
            </div>
            <form onSubmit={submitRoute} className="p-6 space-y-4">
              <div>
                <label className="label">{t('net.routes.field.destination')}</label>
                <input
                  className="input w-full"
                  placeholder={t('net.routes.ph.destination')}
                  value={routeForm.destination}
                  onChange={(e) => setRouteForm({ ...routeForm, destination: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">{t('net.routes.field.gateway')}</label>
                  <input
                    className="input w-full"
                    placeholder="192.168.1.254"
                    value={routeForm.gateway}
                    onChange={(e) => setRouteForm({ ...routeForm, gateway: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">{t('net.routes.field.interface')}</label>
                  <input
                    className="input w-full"
                    placeholder="eth0"
                    value={routeForm.interface}
                    onChange={(e) => setRouteForm({ ...routeForm, interface: e.target.value })}
                  />
                </div>
              </div>
              <div>
                <label className="label">{t('net.routes.field.table')}</label>
                <input
                  className="input w-full"
                  placeholder={t('net.routes.ph.table')}
                  value={routeForm.table}
                  onChange={(e) => setRouteForm({ ...routeForm, table: e.target.value })}
                />
                <p className="text-xs text-gray-500 mt-1">{t('net.routes.hint.table')}</p>
              </div>
              {routeError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{routeError}</div>
              )}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? t('common.saving') : t('common.save')}
                </button>
                <button type="button" onClick={() => setShowRouteModal(false)} className="btn-secondary flex-1">
                  {t('common.cancel')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rule modal */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">
                {ruleEditing ? t('net.rules.modal.edit') : t('net.rules.modal.new')}
              </h2>
            </div>
            <form onSubmit={submitRule} className="p-6 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">{t('net.rules.field.from')}</label>
                  <input
                    className="input w-full"
                    placeholder={t('net.rules.ph.from')}
                    value={ruleForm.from}
                    onChange={(e) => setRuleForm({ ...ruleForm, from: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">{t('net.rules.field.fwmark')}</label>
                  <input
                    className="input w-full"
                    placeholder="0x1"
                    value={ruleForm.fwmark}
                    onChange={(e) => setRuleForm({ ...ruleForm, fwmark: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">{t('net.rules.field.table')}</label>
                  <input
                    className="input w-full"
                    placeholder={t('net.routes.ph.table')}
                    value={ruleForm.table}
                    onChange={(e) => setRuleForm({ ...ruleForm, table: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">{t('net.rules.field.priority')}</label>
                  <input
                    type="number"
                    className="input w-full"
                    placeholder="100"
                    value={ruleForm.priority}
                    onChange={(e) => setRuleForm({ ...ruleForm, priority: e.target.value })}
                  />
                </div>
              </div>
              {ruleError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{ruleError}</div>
              )}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? t('common.saving') : t('common.save')}
                </button>
                <button type="button" onClick={() => setShowRuleModal(false)} className="btn-secondary flex-1">
                  {t('common.cancel')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
