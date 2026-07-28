import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import client from '../api/client';
import InterfaceTraffic from '../components/InterfaceTraffic';
import Tabs, { type TabItem } from '../components/ui/Tabs';
import Tag, { type TagVariant } from '../components/ui/Tag';
import type { IfaceView } from '../types';

const TABS: TabItem[] = [
  { id: 'overview', label: 'Visão geral' },
  { id: 'list', label: 'Interfaces' },
  { id: 'vlans', label: 'VLANs' },
  { id: 'bridges', label: 'Bridges' },
  { id: 'traffic', label: 'Tráfego' },
];

const kindLabel: Record<string, string> = { physical: 'física', vlan: 'vlan', bridge: 'bridge' };
const roleTag: Record<string, { label: string; variant: TagVariant }> = {
  wan: { label: 'WAN', variant: 'ok' },
  lan: { label: 'LAN', variant: 'neutral' },
  unassigned: { label: 'não atribuída', variant: 'idle' },
};

export default function Interfaces() {
  const [tab, setTab] = useState('overview');
  const [ifaces, setIfaces] = useState<IfaceView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState('');
  const [showSystem, setShowSystem] = useState(false);

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

  const visible = ifaces.filter((i) => showSystem || !i.live.system);
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
        <h1 className="text-xl font-bold text-white">Interfaces</h1>
        <p className="text-gray-500 text-sm mt-0.5">
          Estado físico e topologia da rede.
        </p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Falha ao carregar interfaces.
        </div>
      )}

      <Tabs items={TABS} active={tab} onChange={setTab} />

      {tab === 'overview' && (
        <div className="card text-gray-500 text-sm">
          {/* Implementado na próxima tarefa deste plano — árvore de topologia. */}
          Árvore de topologia — em construção nesta mesma fase (próxima tarefa).
        </div>
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
                placeholder="buscar por nome, apelido ou descrição"
                className="input pl-9 w-full"
              />
            </div>
            {hiddenSystemCount > 0 && (
              <button
                onClick={() => setShowSystem((v) => !v)}
                className="text-xs text-gray-500 hover:text-gray-300"
              >
                {showSystem ? 'ocultar' : 'mostrar'} {hiddenSystemCount} interfaces de sistema
              </button>
            )}
          </div>

          {loading ? (
            <div className="text-gray-500 text-sm">Carregando...</div>
          ) : (
            <div className="card overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Interface</th>
                    <th className="pb-3 pr-4 font-medium">Tipo</th>
                    <th className="pb-3 pr-4 font-medium">Endereço</th>
                    <th className="pb-3 pr-4 font-medium">Físico</th>
                    <th className="pb-3 font-medium">Papel</th>
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
                              {i.live.carrier ? 'link ativo' : 'sem link'}
                            </Tag>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                        <td className="py-3">
                          <Tag variant={roleCfg.variant}>{roleCfg.label}</Tag>
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-gray-500">
                        Nenhuma interface encontrada.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'vlans' && (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">Nome</th>
                <th className="pb-3 pr-4 font-medium">Pai</th>
                <th className="pb-3 pr-4 font-medium">Tag</th>
                <th className="pb-3 font-medium">Endereço</th>
              </tr>
            </thead>
            <tbody>
              {visible.filter((i) => i.kind === 'vlan').map((i) => (
                <tr key={i.name} className="table-row">
                  <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{i.parent ?? '—'}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{i.vlan_id ?? '—'}</td>
                  <td className="py-3 text-gray-400 font-mono">
                    {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                  </td>
                </tr>
              ))}
              {visible.filter((i) => i.kind === 'vlan').length === 0 && (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-gray-500">Nenhuma VLAN detectada.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'bridges' && (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">Nome</th>
                <th className="pb-3 pr-4 font-medium">Membros</th>
                <th className="pb-3 font-medium">Endereço</th>
              </tr>
            </thead>
            <tbody>
              {visible.filter((i) => i.kind === 'bridge').map((i) => (
                <tr key={i.name} className="table-row">
                  <td className="py-3 pr-4 text-white">{i.alias || i.name}</td>
                  <td className="py-3 pr-4 text-gray-400 font-mono">{(i.members ?? []).join(', ') || '—'}</td>
                  <td className="py-3 text-gray-400 font-mono">
                    {i.live.addresses?.find((a) => a.family === 'ipv4')?.cidr ?? '—'}
                  </td>
                </tr>
              ))}
              {visible.filter((i) => i.kind === 'bridge').length === 0 && (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-gray-500">Nenhuma bridge detectada.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'traffic' && <InterfaceTraffic />}
    </div>
  );
}
