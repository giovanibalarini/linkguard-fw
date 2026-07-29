import { useEffect, useRef, useState } from 'react';
import { RefreshCw, Route as RouteIcon, Plus, Pencil, Trash2, ListTree } from 'lucide-react';
import client from '../api/client';
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
      setRouteError('Informe o destino da rota.');
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
        setMsg('Rota atualizada com sucesso!');
      } else {
        await client.post('/api/routes', {
          destination: routeForm.destination.trim(),
          gateway: routeForm.gateway.trim(),
          interface: routeForm.interface.trim(),
          table: routeForm.table.trim(),
        });
        setMsg('Rota adicionada com sucesso!');
      }
      setShowRouteModal(false);
      await fetchData();
    } catch (err: any) {
      setRouteError(err.response?.data?.error || err.message || 'Erro ao salvar rota.');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRoute = async (r: Route) => {
    if (!confirm(`Remover rota ${r.destination}?`)) return;
    setSaving(true);
    setMsg('');
    try {
      await client.delete('/api/routes', { data: { destination: r.destination, table: parseRouteTable(r) } });
      setMsg('Rota removida com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
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
      setRuleError('Informe a tabela lookup (ex.: main ou 100).');
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
        setMsg('Regra atualizada com sucesso!');
      } else {
        await client.post('/api/routes/rules', {
          from: ruleForm.from.trim(),
          fwmark: ruleForm.fwmark.trim(),
          table: ruleForm.table.trim(),
          priority,
        });
        setMsg('Regra adicionada com sucesso!');
      }
      setShowRuleModal(false);
      await fetchData();
    } catch (err: any) {
      setRuleError(err.response?.data?.error || err.message || 'Erro ao salvar regra.');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRule = async (r: IpRule) => {
    if (!confirm(`Remover regra ${r.priority}: ${r.selector}?`)) return;
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
      setMsg('Regra removida com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Rotas</h1>
          <p className="text-gray-500 text-sm">Tabelas de roteamento e regras ip rule</p>
        </div>
        <div className="flex gap-2">
          {activeTab === 'routes' ? (
            <button onClick={openAddRoute} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              <Plus className="w-4 h-4" />
              Nova Rota
            </button>
          ) : (
            <button onClick={openAddRule} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              <Plus className="w-4 h-4" />
              Nova Regra
            </button>
          )}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Atualizar
          </button>
        </div>
      </div>

      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
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
          Rotas ({routes.length})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            activeTab === 'rules' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'
          }`}
        >
          Regras ip rule ({rules.length})
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : activeTab === 'routes' ? (
          routes.length === 0 ? (
            <div className="text-center py-12">
              <RouteIcon className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">Nenhuma rota disponível</p>
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
                        <IconButton icon={Pencil} onClick={() => openEditRoute(r)} label="Editar rota" disabled={saving} />
                        <IconButton icon={Trash2} onClick={() => handleDeleteRoute(r)} label="Remover rota" variant="danger" disabled={saving} />
                      </div>
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">Gateway</dt>
                      <dd className="text-gray-400 font-mono">{r.gateway || '—'}</dd>
                      <dt className="text-gray-500">Interface</dt>
                      <dd className="text-gray-400 font-mono">{r.interface || '—'}</dd>
                      <dt className="text-gray-500">Protocolo</dt>
                      <dd className="text-gray-400">{r.protocol || '—'}</dd>
                      <dt className="text-gray-500">Métrica</dt>
                      <dd className="text-gray-400">{r.metric || '—'}</dd>
                      <dt className="text-gray-500">Escopo</dt>
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
                      <th className="pb-3 pr-4 font-medium">Destino</th>
                      <th className="pb-3 pr-4 font-medium">Gateway</th>
                      <th className="pb-3 pr-4 font-medium">Interface</th>
                      <th className="pb-3 pr-4 font-medium">Protocolo</th>
                      <th className="pb-3 pr-4 font-medium">Métrica</th>
                      <th className="pb-3 font-medium">Escopo</th>
                      <th className="pb-3 font-medium">Ações</th>
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
                            <IconButton icon={Pencil} onClick={() => openEditRoute(r)} label="Editar rota" disabled={saving} />
                            <IconButton icon={Trash2} onClick={() => handleDeleteRoute(r)} label="Remover rota" variant="danger" disabled={saving} />
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
              <p className="text-gray-500">Nenhuma regra ip rule disponível</p>
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
                        <span className="text-xs text-gray-500 font-mono">prioridade {r.priority}</span>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <IconButton icon={Pencil} onClick={() => openEditRule(r)} label="Editar regra" disabled={saving} />
                        <IconButton icon={Trash2} onClick={() => handleDeleteRule(r)} label="Remover regra" variant="danger" disabled={saving} />
                      </div>
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">Prioridade</dt>
                      <dd className="text-gray-400 font-mono">{r.priority}</dd>
                      <dt className="text-gray-500">FWMark</dt>
                      <dd className="text-gray-400 font-mono">{r.fwmark || '—'}</dd>
                      <dt className="text-gray-500">Ação</dt>
                      <dd className="text-gray-400">{r.action || '—'}</dd>
                      <dt className="text-gray-500">Tabela</dt>
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
                      <th className="pb-3 pr-4 font-medium">Prioridade</th>
                      <th className="pb-3 pr-4 font-medium">Seletor</th>
                      <th className="pb-3 pr-4 font-medium">FWMark</th>
                      <th className="pb-3 pr-4 font-medium">Ação</th>
                      <th className="pb-3 font-medium">Tabela</th>
                      <th className="pb-3 font-medium">Ações</th>
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
                            <IconButton icon={Pencil} onClick={() => openEditRule(r)} label="Editar regra" disabled={saving} />
                            <IconButton icon={Trash2} onClick={() => handleDeleteRule(r)} label="Remover regra" variant="danger" disabled={saving} />
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
                {routeEditing ? 'Editar Rota' : 'Nova Rota'}
              </h2>
            </div>
            <form onSubmit={submitRoute} className="p-6 space-y-4">
              <div>
                <label className="label">Destino *</label>
                <input
                  className="input w-full"
                  placeholder="default ou 10.0.0.0/24"
                  value={routeForm.destination}
                  onChange={(e) => setRouteForm({ ...routeForm, destination: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">Gateway</label>
                  <input
                    className="input w-full"
                    placeholder="192.168.1.254"
                    value={routeForm.gateway}
                    onChange={(e) => setRouteForm({ ...routeForm, gateway: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">Interface</label>
                  <input
                    className="input w-full"
                    placeholder="eth0"
                    value={routeForm.interface}
                    onChange={(e) => setRouteForm({ ...routeForm, interface: e.target.value })}
                  />
                </div>
              </div>
              <div>
                <label className="label">Tabela</label>
                <input
                  className="input w-full"
                  placeholder="main ou 100"
                  value={routeForm.table}
                  onChange={(e) => setRouteForm({ ...routeForm, table: e.target.value })}
                />
                <p className="text-xs text-gray-500 mt-1">Deixe vazio para usar a tabela principal (main).</p>
              </div>
              {routeError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{routeError}</div>
              )}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button type="button" onClick={() => setShowRouteModal(false)} className="btn-secondary flex-1">
                  Cancelar
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
                {ruleEditing ? 'Editar Regra ip rule' : 'Nova Regra ip rule'}
              </h2>
            </div>
            <form onSubmit={submitRule} className="p-6 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">Origem (from)</label>
                  <input
                    className="input w-full"
                    placeholder="192.168.1.0/24 ou all"
                    value={ruleForm.from}
                    onChange={(e) => setRuleForm({ ...ruleForm, from: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">FWMark</label>
                  <input
                    className="input w-full"
                    placeholder="0x1"
                    value={ruleForm.fwmark}
                    onChange={(e) => setRuleForm({ ...ruleForm, fwmark: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">Tabela lookup *</label>
                  <input
                    className="input w-full"
                    placeholder="main ou 100"
                    value={ruleForm.table}
                    onChange={(e) => setRuleForm({ ...ruleForm, table: e.target.value })}
                  />
                </div>
                <div>
                  <label className="label">Prioridade</label>
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
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button type="button" onClick={() => setShowRuleModal(false)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
