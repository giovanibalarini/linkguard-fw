import { useEffect, useMemo, useState } from 'react';
import { Plus, Pencil, Trash2, RefreshCw, Users, ShieldCheck, Lock } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import type { AppUser, AppRole, PermissionCatalogEntry } from '../types';

type Tab = 'users' | 'roles';

export default function Admin() {
  const { can } = useAuth();
  const canUsers = can('users.manage');
  const canRoles = can('roles.manage');
  const [tab, setTab] = useState<Tab>(canUsers ? 'users' : 'roles');

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Administração</h1>
        <p className="text-gray-500 text-sm">Usuários, papéis e permissões de acesso</p>
      </div>

      <div className="flex gap-2 border-b border-gray-800">
        {canUsers && (
          <TabButton active={tab === 'users'} onClick={() => setTab('users')} icon={Users} label="Usuários" />
        )}
        {canRoles && (
          <TabButton active={tab === 'roles'} onClick={() => setTab('roles')} icon={ShieldCheck} label="Papéis" />
        )}
      </div>

      {!canUsers && !canRoles && (
        <div className="card flex flex-col items-center text-center py-12 gap-3">
          <Lock className="w-8 h-8 text-gray-600" />
          <p className="text-gray-400 text-sm">Você não tem permissão para administrar usuários ou papéis.</p>
        </div>
      )}

      {tab === 'users' && canUsers && <UsersTab />}
      {tab === 'roles' && canRoles && <RolesTab />}
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label }: {
  active: boolean; onClick: () => void; icon: typeof Users; label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
        active ? 'border-blue-500 text-blue-400 font-medium' : 'border-transparent text-gray-400 hover:text-gray-200'
      }`}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}

// ─── Users tab ───────────────────────────────────────────────────────────────

const emptyUser = { username: '', password: '', role_ids: [] as string[] };

function UsersTab() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<AppUser[]>([]);
  const [roles, setRoles] = useState<AppRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState(emptyUser);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [fetchError, setFetchError] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<AppUser | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  const fetchAll = async () => {
    setLoading(true);
    setFetchError('');
    try {
      const [u, r] = await Promise.all([
        client.get<AppUser[]>('/api/users'),
        client.get<AppRole[]>('/api/roles'),
      ]);
      setUsers(u.data ?? []);
      setRoles(r.data ?? []);
    } catch (err: any) {
      setFetchError(err.response?.data?.error || 'Erro ao carregar usuários e papéis');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const roleName = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of roles) m.set(r.id, r.name);
    return m;
  }, [roles]);

  const openCreate = () => {
    setForm({ ...emptyUser, role_ids: [] });
    setIsEditing(false);
    setEditId(null);
    setError('');
    setShowModal(true);
  };

  const openEdit = (u: AppUser) => {
    setForm({ username: u.username, password: '', role_ids: [...u.role_ids] });
    setIsEditing(true);
    setEditId(u.id);
    setError('');
    setShowModal(true);
  };

  const toggleRole = (id: string) => {
    setForm((f) => ({
      ...f,
      role_ids: f.role_ids.includes(id) ? f.role_ids.filter((x) => x !== id) : [...f.role_ids, id],
    }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    try {
      if (isEditing && editId) {
        const payload: { role_ids: string[]; password?: string } = { role_ids: form.role_ids };
        if (form.password) payload.password = form.password;
        await client.put(`/api/users/${editId}`, payload);
      } else {
        await client.post('/api/users', form);
      }
      setShowModal(false);
      await fetchAll();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Erro ao salvar usuário');
    } finally {
      setSaving(false);
    }
  };

  const openDelete = (u: AppUser) => {
    setDeleteTarget(u);
    setDeleteError('');
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError('');
    try {
      await client.delete(`/api/users/${deleteTarget.id}`);
      setDeleteTarget(null);
      await fetchAll();
    } catch (err: any) {
      setDeleteError(err.response?.data?.error || 'Erro ao excluir usuário');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:justify-end gap-2">
        <button onClick={fetchAll} className="btn-secondary flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4" /> Atualizar
        </button>
        <button onClick={openCreate} className="btn-primary flex items-center justify-center gap-2">
          <Plus className="w-4 h-4" /> Novo Usuário
        </button>
      </div>

      {fetchError && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{fetchError}</div>}

      <Panel>
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : fetchError ? (
          <div className="text-center py-12 text-gray-600 text-sm">Não foi possível carregar os dados.</div>
        ) : users.length === 0 ? (
          <div className="text-center py-12 text-gray-500">Nenhum usuário</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Usuário</th>
                  <th className="pb-3 pr-4 font-medium">Papéis</th>
                  <th className="pb-3 pr-4 font-medium">Criado em</th>
                  <th className="pb-3 font-medium">Ações</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="table-row">
                    <td className="py-3 pr-4">
                      <span className="text-white font-medium">{u.username}</span>
                      {currentUser?.id === u.id && <span className="text-gray-600 text-xs ml-2">(você)</span>}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {u.role_ids.length === 0 && <span className="text-gray-600 text-xs">sem papel</span>}
                        {u.role_ids.map((rid) => (
                          <span key={rid} className="px-2 py-0.5 rounded bg-blue-600/20 text-blue-300 text-xs">
                            {roleName.get(rid) ?? rid}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 pr-4 text-gray-500 text-xs">{new Date(u.created_at).toLocaleString()}</td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => openEdit(u)}
                          title="Editar usuário"
                          aria-label={`Editar usuário ${u.username}`}
                          className="text-gray-400 hover:text-blue-400 transition-colors"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openDelete(u)}
                          title="Excluir usuário"
                          aria-label={`Excluir usuário ${u.username}`}
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
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
      </Panel>

      <Modal open={showModal} onClose={() => setShowModal(false)} title={isEditing ? 'Editar Usuário' : 'Novo Usuário'} size="md">
        <form onSubmit={handleSave} className="p-6 space-y-4">
          <div>
            <label className="label">Nome de usuário *</label>
            <input
              className="input w-full disabled:opacity-50"
              value={form.username}
              disabled={isEditing}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="label">{isEditing ? 'Nova senha (deixe vazio para manter)' : 'Senha *'}</label>
            <input
              type="password"
              className="input w-full"
              value={form.password}
              placeholder={isEditing ? '••••••••' : 'mínimo 8 caracteres'}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required={!isEditing}
              minLength={!isEditing || form.password ? 8 : undefined}
            />
          </div>
          <div>
            <label className="label">Papéis</label>
            <div className="space-y-2 mt-1 max-h-48 overflow-y-auto">
              {roles.map((r) => (
                <label key={r.id} className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="w-4 h-4 mt-0.5"
                    checked={form.role_ids.includes(r.id)}
                    onChange={() => toggleRole(r.id)}
                  />
                  <span>
                    <span className="text-gray-200 text-sm">{r.name}</span>
                    {r.description && <span className="text-gray-600 text-xs block">{r.description}</span>}
                  </span>
                </label>
              ))}
            </div>
          </div>
          {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
          <div className="flex gap-3 pt-2">
            <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
              {saving ? 'Salvando...' : 'Salvar'}
            </button>
            <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </form>
      </Modal>

      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Excluir usuário" size="sm">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            Tem certeza que deseja excluir o usuário <span className="font-medium text-white">"{deleteTarget?.username}"</span>? Esta ação não pode ser desfeita.
          </p>
          {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              disabled={deleting}
              onClick={handleDelete}
              className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
            >
              {deleting ? 'Excluindo...' : 'Excluir'}
            </button>
            <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
              Cancelar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── Roles tab ───────────────────────────────────────────────────────────────

const emptyRole = { name: '', description: '', permissions: [] as string[] };

function RolesTab() {
  const [roles, setRoles] = useState<AppRole[]>([]);
  const [catalog, setCatalog] = useState<PermissionCatalogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState(emptyRole);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [fetchError, setFetchError] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<AppRole | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  const fetchAll = async () => {
    setLoading(true);
    setFetchError('');
    try {
      const [r, c] = await Promise.all([
        client.get<AppRole[]>('/api/roles'),
        client.get<PermissionCatalogEntry[]>('/api/permissions'),
      ]);
      setRoles(r.data ?? []);
      setCatalog(c.data ?? []);
    } catch (err: any) {
      setFetchError(err.response?.data?.error || 'Erro ao carregar papéis e permissões');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  // Catalog grouped by area, preserving the backend order.
  const areas = useMemo(() => {
    const order: string[] = [];
    const byArea = new Map<string, PermissionCatalogEntry[]>();
    for (const e of catalog) {
      if (!byArea.has(e.area)) { byArea.set(e.area, []); order.push(e.area); }
      byArea.get(e.area)!.push(e);
    }
    return order.map((a) => ({ area: a, entries: byArea.get(a)! }));
  }, [catalog]);

  const openCreate = () => {
    setForm({ ...emptyRole, permissions: [] });
    setIsEditing(false);
    setEditId(null);
    setError('');
    setShowModal(true);
  };

  const openEdit = (r: AppRole) => {
    setForm({ name: r.name, description: r.description, permissions: [...r.permissions] });
    setIsEditing(true);
    setEditId(r.id);
    setError('');
    setShowModal(true);
  };

  const togglePerm = (key: string) => {
    setForm((f) => ({
      ...f,
      permissions: f.permissions.includes(key) ? f.permissions.filter((x) => x !== key) : [...f.permissions, key],
    }));
  };

  const toggleArea = (keys: string[], selectAll: boolean) => {
    setForm((f) => {
      const set = new Set(f.permissions);
      if (selectAll) {
        for (const k of keys) set.add(k);
      } else {
        for (const k of keys) set.delete(k);
      }
      return { ...f, permissions: Array.from(set) };
    });
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError('');
    try {
      if (isEditing && editId) {
        await client.put(`/api/roles/${editId}`, form);
      } else {
        await client.post('/api/roles', form);
      }
      setShowModal(false);
      await fetchAll();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Erro ao salvar papel');
    } finally {
      setSaving(false);
    }
  };

  const openDelete = (r: AppRole) => {
    setDeleteTarget(r);
    setDeleteError('');
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError('');
    try {
      await client.delete(`/api/roles/${deleteTarget.id}`);
      setDeleteTarget(null);
      await fetchAll();
    } catch (err: any) {
      setDeleteError(err.response?.data?.error || 'Erro ao excluir papel');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:justify-end gap-2">
        <button onClick={fetchAll} className="btn-secondary flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4" /> Atualizar
        </button>
        <button onClick={openCreate} className="btn-primary flex items-center justify-center gap-2">
          <Plus className="w-4 h-4" /> Novo Papel
        </button>
      </div>

      {fetchError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{fetchError}</div>}

      <div className="card">
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">Carregando...</div>
        ) : fetchError ? (
          <div className="text-center py-12 text-gray-600 text-sm">Não foi possível carregar os dados.</div>
        ) : roles.length === 0 ? (
          <div className="text-center py-12 text-gray-500">Nenhum papel</div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {roles.map((r) => (
              <div key={r.id} className="rounded-lg border border-gray-800 bg-gray-900/60 p-4 flex flex-col">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-white font-medium flex items-center gap-2">
                      {r.name}
                      {r.builtin && (
                        <span className="inline-flex items-center gap-1 text-xs text-gray-500" title="Papel embutido">
                          <Lock className="w-3 h-3" />
                        </span>
                      )}
                    </p>
                    <p className="text-gray-500 text-xs mt-0.5">{r.description || '—'}</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => openEdit(r)}
                      title="Editar papel"
                      aria-label={`Editar papel ${r.name}`}
                      className="text-gray-400 hover:text-blue-400 transition-colors"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {!r.builtin && (
                      <button
                        onClick={() => openDelete(r)}
                        title="Excluir papel"
                        aria-label={`Excluir papel ${r.name}`}
                        className="text-gray-400 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
                <p className="text-gray-600 text-xs mt-3">{r.permissions.length} permissões</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">{isEditing ? 'Editar Papel' : 'Novo Papel'}</h2>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4 overflow-y-auto">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">Nome *</label>
                  <input
                    className="input w-full"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="label">Descrição</label>
                  <input
                    className="input w-full"
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                  />
                </div>
              </div>

              <div>
                <label className="label">Permissões por funcionalidade</label>
                <div className="space-y-4 mt-2">
                  {areas.map(({ area, entries }) => {
                    const keys = entries.map((e) => e.key);
                    const selectedCount = keys.filter((k) => form.permissions.includes(k)).length;
                    const allSelected = selectedCount === keys.length && keys.length > 0;
                    return (
                      <div key={area}>
                        <div className="flex items-center justify-between mb-2 gap-2">
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              className="w-4 h-4"
                              checked={allSelected}
                              ref={(el) => {
                                if (el) el.indeterminate = selectedCount > 0 && !allSelected;
                              }}
                              onChange={() => toggleArea(keys, !allSelected)}
                              aria-label={`${allSelected ? 'Limpar' : 'Marcar tudo'} em ${area}`}
                              title={allSelected ? 'Limpar' : 'Marcar tudo'}
                            />
                            <span className="text-gray-400 text-xs font-semibold uppercase tracking-wide">{area}</span>
                          </label>
                          <span className="text-gray-600 text-xs whitespace-nowrap">{selectedCount}/{keys.length} selecionadas</span>
                        </div>
                        <div className="grid sm:grid-cols-2 gap-2">
                          {entries.map((e) => (
                            <label key={e.key} className="flex items-start gap-2 cursor-pointer" title={e.description}>
                              <input
                                type="checkbox"
                                className="w-4 h-4 mt-0.5"
                                checked={form.permissions.includes(e.key)}
                                onChange={() => togglePerm(e.key)}
                              />
                              <span className="text-gray-200 text-sm">{e.label}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
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

      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-white font-semibold">Excluir papel</h2>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-gray-300 text-sm">
                Tem certeza que deseja excluir o papel <span className="font-medium text-white">"{deleteTarget.name}"</span>? Esta ação não pode ser desfeita.
              </p>
              {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  disabled={deleting}
                  onClick={handleDelete}
                  className="btn-primary flex-1 bg-red-600 hover:bg-red-500 border-red-600 disabled:opacity-50"
                >
                  {deleting ? 'Excluindo...' : 'Excluir'}
                </button>
                <button type="button" onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
