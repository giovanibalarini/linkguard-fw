import { useEffect, useState } from 'react';
import { RefreshCw, Route as RouteIcon } from 'lucide-react';
import client from '../api/client';
import type { Route, IpRule } from '../types';

export default function Routes() {
  const [routes, setRoutes] = useState<Route[]>([]);
  const [rules, setRules] = useState<IpRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'routes' | 'rules'>('routes');

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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Rotas</h1>
          <p className="text-gray-500 text-sm">Tabelas de roteamento e regras ip rule</p>
        </div>
        <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Atualizar
        </button>
      </div>

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
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r, i) => (
                    <tr key={i} className="table-row">
                      <td className="py-3 pr-4 text-gray-400 font-mono">{r.priority}</td>
                      <td className="py-3 pr-4 text-white font-mono">{r.selector}</td>
                      <td className="py-3 pr-4 text-gray-400">{r.action || '—'}</td>
                      <td className="py-3 text-gray-400 font-mono">{r.table || '—'}</td>
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
