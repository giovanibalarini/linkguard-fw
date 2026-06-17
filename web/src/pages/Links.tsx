import { useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, RefreshCw, Wifi } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import client from '../api/client';
import type { WanLink } from '../types';

const emptyLink: Partial<WanLink> = {
  name: '',
  interface: '',
  ip_address: '',
  gateway: '',
  weight: 100,
  dns_test: '8.8.8.8',
  monitor_hosts: '1.1.1.1,8.8.8.8',
  enabled: true,
};

export default function Links() {
  const [links, setLinks] = useState<WanLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editLink, setEditLink] = useState<Partial<WanLink>>(emptyLink);
  const [isEditing, setIsEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const fetchLinks = async () => {
    setLoading(true);
    try {
      const res = await client.get<WanLink[]>('/api/links');
      setLinks(res.data ?? []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLinks(); }, []);

  const openCreate = () => {
    setEditLink({ ...emptyLink });
    setIsEditing(false);
    setError('');
    setShowModal(true);
  };

  const openEdit = (link: WanLink) => {
    setEditLink({ ...link });
    setIsEditing(true);
    setError('');
    setShowModal(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    try {
      if (isEditing && editLink.id) {
        await client.put(`/api/links/${editLink.id}`, editLink);
      } else {
        await client.post('/api/links', editLink);
      }
      setShowModal(false);
      await fetchLinks();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Erro ao salvar link');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Excluir link "${name}"?`)) return;
    try {
      await client.delete(`/api/links/${id}`);
      await fetchLinks();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Erro ao excluir link');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Links WAN</h1>
          <p className="text-gray-500 text-sm">Gerencie os links de internet</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchLinks} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Atualizar
          </button>
          <button onClick={openCreate} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Novo Link
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : links.length === 0 ? (
          <div className="text-center py-12">
            <Wifi className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">Nenhum link configurado</p>
            <p className="text-gray-600 text-sm mt-1">Clique em "Novo Link" para começar</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Nome</th>
                  <th className="pb-3 pr-4 font-medium">Interface</th>
                  <th className="pb-3 pr-4 font-medium">IP / Gateway</th>
                  <th className="pb-3 pr-4 font-medium">Peso</th>
                  <th className="pb-3 pr-4 font-medium">Latência</th>
                  <th className="pb-3 pr-4 font-medium">Perda</th>
                  <th className="pb-3 pr-4 font-medium">Status</th>
                  <th className="pb-3 font-medium">Ações</th>
                </tr>
              </thead>
              <tbody>
                {links.map(link => (
                  <tr key={link.id} className="table-row">
                    <td className="py-3 pr-4">
                      <div className="text-white font-medium">{link.name}</div>
                      {!link.enabled && <span className="text-gray-600 text-xs">desativado</span>}
                    </td>
                    <td className="py-3 pr-4 text-gray-400 font-mono">{link.interface}</td>
                    <td className="py-3 pr-4">
                      <div className="text-gray-400 font-mono text-xs">{link.ip_address || '—'}</div>
                      <div className="text-gray-600 font-mono text-xs">{link.gateway || '—'}</div>
                    </td>
                    <td className="py-3 pr-4 text-gray-400">{link.weight}</td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'}
                    </td>
                    <td className="py-3 pr-4 text-gray-400">
                      {link.packet_loss.toFixed(1)}%
                    </td>
                    <td className="py-3 pr-4"><StatusBadge status={link.status} /></td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        <button onClick={() => openEdit(link)} className="text-gray-400 hover:text-blue-400 transition-colors">
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button onClick={() => handleDelete(link.id, link.name)} className="text-gray-400 hover:text-red-400 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-lg">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">
                {isEditing ? 'Editar Link WAN' : 'Novo Link WAN'}
              </h2>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Nome *</label>
                  <input className="input w-full" value={editLink.name || ''} onChange={e => setEditLink({...editLink, name: e.target.value})} required />
                </div>
                <div>
                  <label className="label">Interface *</label>
                  <input className="input w-full" placeholder="eth0, ppp0..." value={editLink.interface || ''} onChange={e => setEditLink({...editLink, interface: e.target.value})} required />
                </div>
                <div>
                  <label className="label">Endereço IP</label>
                  <input className="input w-full" placeholder="192.168.1.1" value={editLink.ip_address || ''} onChange={e => setEditLink({...editLink, ip_address: e.target.value})} />
                </div>
                <div>
                  <label className="label">Gateway</label>
                  <input className="input w-full" placeholder="192.168.1.254" value={editLink.gateway || ''} onChange={e => setEditLink({...editLink, gateway: e.target.value})} />
                </div>
                <div>
                  <label className="label">Peso (prioridade)</label>
                  <input type="number" className="input w-full" min={1} max={1000} value={editLink.weight || 100} onChange={e => setEditLink({...editLink, weight: +e.target.value})} />
                </div>
                <div>
                  <label className="label">DNS de teste</label>
                  <input className="input w-full" placeholder="8.8.8.8" value={editLink.dns_test || ''} onChange={e => setEditLink({...editLink, dns_test: e.target.value})} />
                </div>
              </div>
              <div>
                <label className="label">Hosts de monitoramento (separados por vírgula)</label>
                <input className="input w-full" placeholder="1.1.1.1,8.8.8.8" value={editLink.monitor_hosts || ''} onChange={e => setEditLink({...editLink, monitor_hosts: e.target.value})} />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="enabled" checked={editLink.enabled ?? true} onChange={e => setEditLink({...editLink, enabled: e.target.checked})} className="w-4 h-4" />
                <label htmlFor="enabled" className="text-gray-400 text-sm">Link habilitado</label>
              </div>
              {error && <p className="text-red-400 text-sm">{error}</p>}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? 'Salvando...' : 'Salvar'}
                </button>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
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
