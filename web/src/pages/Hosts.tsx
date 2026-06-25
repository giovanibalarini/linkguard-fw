import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Pencil, Ban, ShieldCheck, Circle } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { NetHost } from '../types';

export default function Hosts() {
  const { can } = useAuth();
  const canManage = can('hosts.block');
  const [hosts, setHosts] = useState<NetHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [aliasFor, setAliasFor] = useState<NetHost | null>(null);
  const [aliasValue, setAliasValue] = useState('');
  const [saving, setSaving] = useState(false);

  const fetchHosts = async () => {
    setLoading(true);
    try {
      const res = await client.get<NetHost[]>('/api/hosts');
      setHosts(res.data ?? []);
    } finally {
      setLoading(false);
    }
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
  };

  const saveAlias = async () => {
    if (!aliasFor) return;
    setSaving(true);
    try {
      await client.put('/api/hosts/alias', { mac: aliasFor.mac, alias: aliasValue.trim() });
      setAliasFor(null);
      await fetchHosts();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Erro ao salvar apelido');
    } finally {
      setSaving(false);
    }
  };

  const toggleBlock = async (h: NetHost) => {
    const verb = h.blocked ? 'desbloquear' : 'bloquear';
    if (!confirm(`Deseja ${verb} o host ${h.alias || h.ip} (${h.mac})?`)) return;
    try {
      await client.post('/api/hosts/block', { mac: h.mac, blocked: !h.blocked });
      await fetchHosts();
    } catch (err: any) {
      alert(err.response?.data?.error || `Erro ao ${verb} host`);
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
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button onClick={fetchHosts} className="btn-secondary flex items-center gap-2 whitespace-nowrap">
            <RefreshCw className="w-4 h-4" /> Atualizar
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500">Nenhum host encontrado</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
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
                  <tr key={h.mac || h.ip} className="table-row">
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
                          <button onClick={() => openAlias(h)} title="Apelido" className="text-gray-400 hover:text-blue-400 transition-colors">
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => toggleBlock(h)}
                            title={h.blocked ? 'Desbloquear' : 'Bloquear'}
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
        )}
      </div>

      {aliasFor && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-sm">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Apelido do host</h2>
              <p className="text-gray-500 text-xs mt-1 font-mono">{aliasFor.mac}</p>
            </div>
            <div className="p-6 space-y-4">
              <input
                className="input w-full"
                placeholder="Ex.: PC do João, TV da sala"
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                autoFocus
              />
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
