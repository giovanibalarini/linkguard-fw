import { useEffect, useMemo, useState } from 'react';
import {
  Edit2,
  FolderPlus,
  Loader2,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  Trash2,
  X,
} from 'lucide-react';
import client from '../../api/client';
import { useI18n } from '../../i18n';
import Panel from '../ui/Panel';
import type { HostGroup } from '../../types';

interface Props {
  canWrite: boolean;
  onMsg: (text: string, level?: 'ok' | 'warn' | 'error') => void;
}

export default function HostGroupsTab({ canWrite, onMsg }: Props) {
  const { t } = useI18n();
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<HostGroup | null>(null);

  // Form states
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [formHosts, setFormHosts] = useState('');
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchGroups = async () => {
    setLoading(true);
    try {
      const { data } = await client.get<HostGroup[]>('/api/hostgroups');
      setGroups(data ?? []);
    } catch (e: any) {
      onMsg(t('fwx.error', { msg: e.response?.data?.error || e.message }), 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, []);

  const openCreate = () => {
    setEditingGroup(null);
    setFormName('');
    setFormDesc('');
    setFormHosts('');
    setModalOpen(true);
  };

  const openEdit = (g: HostGroup) => {
    setEditingGroup(g);
    setFormName(g.name);
    setFormDesc(g.description || '');
    setFormHosts((g.hosts || []).join('\n'));
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = formName.trim();
    if (!name) {
      onMsg(t('fwx.hostgroups.name_required') || 'Nome é obrigatório', 'error');
      return;
    }
    const hosts = formHosts
      .split(/[\n,]+/)
      .map((h) => h.trim())
      .filter(Boolean);

    setSaving(true);
    try {
      if (editingGroup) {
        await client.put(`/api/hostgroups/${editingGroup.id}`, {
          name,
          description: formDesc.trim(),
          hosts,
        });
        onMsg(t('fwx.hostgroups.saved') || 'Grupo de hosts atualizado com sucesso');
      } else {
        await client.post('/api/hostgroups', {
          name,
          description: formDesc.trim(),
          hosts,
        });
        onMsg(t('fwx.hostgroups.created') || 'Grupo de hosts criado com sucesso');
      }
      setModalOpen(false);
      await fetchGroups();
    } catch (err: any) {
      onMsg(t('fwx.error', { msg: err.response?.data?.error || err.message }), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (g: HostGroup) => {
    if (!confirm(t('fwx.hostgroups.delete_confirm', { name: g.name }) || `Excluir o grupo "${g.name}"?`)) {
      return;
    }
    setDeletingId(g.id);
    try {
      await client.delete(`/api/hostgroups/${g.id}`);
      onMsg(t('fwx.hostgroups.deleted') || 'Grupo de hosts excluído com sucesso');
      await fetchGroups();
    } catch (err: any) {
      onMsg(t('fwx.error', { msg: err.response?.data?.error || err.message }), 'error');
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return groups;
    return groups.filter(
      (g) =>
        g.name.toLowerCase().includes(q) ||
        g.description.toLowerCase().includes(q) ||
        g.hosts.some((h) => h.toLowerCase().includes(q)),
    );
  }, [groups, search]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            {t('fwx.hostgroups.title') || 'Grupos de Hosts'}
          </h2>
          <p className="text-xs text-gray-500">
            {t('fwx.hostgroups.subtitle') ||
              'Coleções reutilizáveis de IPs e subredes para regras de firewall e perfis de acesso ZTNA da VPN.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('common.filter') || 'Filtrar...'}
              className="bg-gray-900 border border-gray-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 w-48 sm:w-64"
            />
          </div>
          <button
            onClick={fetchGroups}
            className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
            title={t('common.refresh') || 'Atualizar'}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          {canWrite && (
            <button
              onClick={openCreate}
              className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3"
            >
              <Plus className="w-3.5 h-3.5" />
              {t('fwx.hostgroups.btn_new') || 'Novo Grupo'}
            </button>
          )}
        </div>
      </div>

      {loading && groups.length === 0 ? (
        <div className="card text-center py-12 text-gray-500 animate-pulse">
          <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-gray-600" />
          {t('common.loading') || 'Carregando...'}
        </div>
      ) : filtered.length === 0 ? (
        <Panel className="p-8 text-center text-gray-500 text-sm">
          <Network className="w-8 h-8 mx-auto mb-2 text-gray-600" />
          <p className="font-medium text-gray-400">
            {search
              ? t('fwx.hostgroups.no_filter_matches') || 'Nenhum grupo corresponde ao filtro.'
              : t('fwx.hostgroups.empty') || 'Nenhum grupo de hosts cadastrado.'}
          </p>
          {!search && canWrite && (
            <button
              onClick={openCreate}
              className="btn-secondary text-xs inline-flex items-center gap-1.5 mt-3"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              {t('fwx.hostgroups.create_first') || 'Criar primeiro grupo de hosts'}
            </button>
          )}
        </Panel>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((g) => (
            <Panel key={g.id} className="p-4 flex flex-col justify-between hover:border-gray-700 transition-colors">
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-white truncate flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-blue-500 shrink-0" />
                      {g.name}
                    </h3>
                    {g.description && (
                      <p className="text-xs text-gray-400 mt-0.5 line-clamp-2">{g.description}</p>
                    )}
                  </div>
                  {canWrite && (
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => openEdit(g)}
                        className="p-1 text-gray-400 hover:text-white rounded hover:bg-gray-800 transition-colors"
                        title={t('common.edit') || 'Editar'}
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(g)}
                        disabled={deletingId === g.id}
                        className="p-1 text-gray-400 hover:text-red-400 rounded hover:bg-gray-800 transition-colors disabled:opacity-50"
                        title={t('common.delete') || 'Excluir'}
                      >
                        {deletingId === g.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-red-400" />
                        ) : (
                          <Trash2 className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  )}
                </div>

                <div className="mt-3">
                  <div className="text-[11px] font-medium text-gray-500 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                    <span>{t('fwx.hostgroups.hosts_label') || 'Hosts / IPs'}</span>
                    <span className="font-mono text-gray-400">({g.hosts?.length || 0})</span>
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-28 overflow-y-auto pr-1">
                    {g.hosts && g.hosts.length > 0 ? (
                      g.hosts.map((h) => (
                        <span
                          key={h}
                          className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-gray-900 border border-gray-800 text-gray-300"
                        >
                          {h}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-gray-600 italic">
                        {t('fwx.hostgroups.no_hosts') || 'Sem IPs cadastrados'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </Panel>
          ))}
        </div>
      )}

      {/* Modal Criar / Editar */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-gray-950 border border-gray-800 rounded-xl max-w-md w-full shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                {editingGroup
                  ? t('fwx.hostgroups.edit_title') || 'Editar Grupo de Hosts'
                  : t('fwx.hostgroups.new_title') || 'Novo Grupo de Hosts'}
              </h3>
              <button
                onClick={() => setModalOpen(false)}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSave} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">
                  {t('fwx.hostgroups.field_name') || 'Nome do Grupo'} *
                </label>
                <input
                  type="text"
                  required
                  maxLength={64}
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="ex: Cluster K3s OCI, Banco de Dados, Servidores Web"
                  className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1">
                  {t('fwx.hostgroups.field_desc') || 'Descrição'}
                </label>
                <input
                  type="text"
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                  placeholder="ex: Nós master e worker do ambiente de nuvem"
                  className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-300 mb-1 flex items-center justify-between">
                  <span>{t('fwx.hostgroups.field_hosts') || 'Endereços IPv4 ou Subredes CIDR'}</span>
                  <span className="text-[10px] text-gray-500">1 por linha ou separado por vírgula</span>
                </label>
                <textarea
                  rows={4}
                  value={formHosts}
                  onChange={(e) => setFormHosts(e.target.value)}
                  placeholder={`10.0.1.20\n10.0.1.21\n10.0.2.0/24`}
                  className="w-full bg-gray-900 border border-gray-800 rounded-lg p-3 text-xs font-mono text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
                <p className="text-[11px] text-gray-500 mt-1">
                  Aceita IPs individuais (ex: 10.0.1.20) ou prefixos de rede (ex: 10.0.0.0/16).
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-gray-800">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  disabled={saving}
                  className="btn-secondary text-xs px-3 py-1.5"
                >
                  {t('common.cancel') || 'Cancelar'}
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5"
                >
                  {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  {t('common.save') || 'Salvar'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

