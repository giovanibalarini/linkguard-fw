import { useEffect, useState } from 'react';
import { RefreshCw, Route as RouteIcon, Plus, Pencil, Trash2 } from 'lucide-react';
import client from '../api/client';
import type { Route, IpRule } from '../types';

export default function Routes() {
  const [routes, setRoutes] = useState<Route[]>([]);
  const [rules, setRules] = useState<IpRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'routes' | 'rules'>('routes');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

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

  const handleAddRoute = async () => {
    const destination = prompt('Destino da rota (ex.: default ou 10.0.0.0/24):', 'default');
    if (!destination) return;
    const gateway = prompt('Gateway (opcional):', '') ?? '';
    const iface = prompt('Interface (opcional):', '') ?? '';
    const table = prompt('Tabela (opcional, ex.: 100):', '') ?? '';

    setSaving(true);
    setMsg('');
    try {
      await client.post('/api/routes', { destination: destination.trim(), gateway: gateway.trim(), interface: iface.trim(), table: table.trim() });
      setMsg('Rota adicionada com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleEditRoute = async (r: Route) => {
    const destination = prompt('Novo destino da rota:', r.destination);
    if (!destination) return;
    const gateway = prompt('Gateway:', r.gateway || '') ?? '';
    const iface = prompt('Interface:', r.interface || '') ?? '';
    const table = prompt('Tabela (opcional):', '') ?? '';

    setSaving(true);
    setMsg('');
    try {
      await client.put('/api/routes', {
        old_destination: r.destination,
        old_table: '',
        destination: destination.trim(),
        gateway: gateway.trim(),
        interface: iface.trim(),
        table: table.trim(),
      });
      setMsg('Rota atualizada com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRoute = async (r: Route) => {
    if (!confirm(`Remover rota ${r.destination}?`)) return;
    setSaving(true);
    setMsg('');
    try {
      await client.delete('/api/routes', { data: { destination: r.destination, table: '' } });
      setMsg('Rota removida com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddRule = async () => {
    const from = prompt('Source (from), ex.: 192.168.1.0/24 ou all:', 'all');
    if (from === null) return;
    const table = prompt('Tabela lookup (obrigatória), ex.: main ou 100:', 'main');
    if (!table) return;
    const priorityRaw = prompt('Prioridade (opcional), ex.: 100:', '') ?? '';
    const priority = Number(priorityRaw || 0);

    setSaving(true);
    setMsg('');
    try {
      await client.post('/api/routes/rules', { from: from.trim(), table: table.trim(), priority: Number.isNaN(priority) ? 0 : priority });
      setMsg('Regra adicionada com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleEditRule = async (r: IpRule) => {
    const fromCurrent = parseFromSelector(r.selector);
    const from = prompt('Novo from (ex.: 192.168.1.0/24 ou all):', fromCurrent || 'all');
    if (from === null) return;
    const table = prompt('Nova tabela lookup:', r.table || 'main');
    if (!table) return;
    const priorityRaw = prompt('Nova prioridade (opcional):', r.priority || '') ?? '';
    const priority = Number(priorityRaw || 0);

    setSaving(true);
    setMsg('');
    try {
      await client.put('/api/routes/rules', {
        old_from: fromCurrent,
        old_table: r.table,
        old_priority: Number(r.priority || 0),
        from: from.trim(),
        table: table.trim(),
        priority: Number.isNaN(priority) ? 0 : priority,
      });
      setMsg('Regra atualizada com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Rotas</h1>
          <p className="text-gray-500 text-sm">Tabelas de roteamento e regras ip rule</p>
        </div>
        <div className="flex gap-2">
          {activeTab === 'routes' ? (
            <button onClick={handleAddRoute} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              <Plus className="w-4 h-4" />
              Nova Rota
            </button>
          ) : (
            <button onClick={handleAddRule} disabled={saving} className="btn-primary flex items-center gap-2 disabled:opacity-50">
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
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
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
                  {routes.map((r, i) => (
                    <tr key={i} className="table-row">
                      <td className="py-3 pr-4 text-white font-mono">{r.destination}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono">{r.gateway || '—'}</td>
                      <td className="py-3 pr-4 text-gray-400 font-mono">{r.interface || '—'}</td>
                      <td className="py-3 pr-4 text-gray-400">{r.protocol || '—'}</td>
                      <td className="py-3 pr-4 text-gray-400">{r.metric || '—'}</td>
                      <td className="py-3 text-gray-400">{r.scope || '—'}</td>
                      <td className="py-3">
                        <div className="flex gap-2">
                          <button onClick={() => handleEditRoute(r)} disabled={saving} className="text-gray-400 hover:text-blue-400 transition-colors disabled:opacity-50">
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button onClick={() => handleDeleteRoute(r)} disabled={saving} className="text-gray-400 hover:text-red-400 transition-colors disabled:opacity-50">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
          rules.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500">Nenhuma regra ip rule disponível</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Prioridade</th>
                    <th className="pb-3 pr-4 font-medium">Seletor</th>
                    <th className="pb-3 pr-4 font-medium">Ação</th>
                    <th className="pb-3 font-medium">Tabela</th>
                    <th className="pb-3 font-medium">Ações</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r, i) => (
                    <tr key={i} className="table-row">
                      <td className="py-3 pr-4 text-gray-400 font-mono">{r.priority}</td>
                      <td className="py-3 pr-4 text-white font-mono">{r.selector}</td>
                      <td className="py-3 pr-4 text-gray-400">{r.action || '—'}</td>
                      <td className="py-3 text-gray-400 font-mono">{r.table || '—'}</td>
                      <td className="py-3">
                        <div className="flex gap-2">
                          <button onClick={() => handleEditRule(r)} disabled={saving} className="text-gray-400 hover:text-blue-400 transition-colors disabled:opacity-50">
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button onClick={() => handleDeleteRule(r)} disabled={saving} className="text-gray-400 hover:text-red-400 transition-colors disabled:opacity-50">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </div>
    </div>
  );
}
