import { useEffect, useMemo, useState } from 'react';
import { Plus, Pencil, Trash2, RefreshCw, Wifi, Wand2, Network } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import client from '../api/client';
import type { WanLink, SystemMetrics, InterfaceMetrics } from '../types';

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
  const [interfaces, setInterfaces] = useState<InterfaceMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [editLink, setEditLink] = useState<Partial<WanLink>>(emptyLink);
  const [isEditing, setIsEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [wizardLoading, setWizardLoading] = useState(false);
  const [wizardError, setWizardError] = useState('');
  const [wizardMode, setWizardMode] = useState<'failover' | 'balance'>('failover');
  const [wizardPrimary, setWizardPrimary] = useState('');
  const [wizardSecondary, setWizardSecondary] = useState('');
  const [wizardLan, setWizardLan] = useState('');
  const [wizardPrimaryWeight, setWizardPrimaryWeight] = useState(70);
  const [wizardSecondaryWeight, setWizardSecondaryWeight] = useState(30);

  const fetchLinks = async () => {
    setLoading(true);
    try {
      const [res, sysRes] = await Promise.all([
        client.get<WanLink[]>('/api/links'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setLinks(res.data ?? []);
      const discovered = (sysRes.data?.interfaces ?? [])
        .filter((iface) => iface.name && iface.name !== 'lo');
      setInterfaces(discovered);
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

  const openWizard = () => {
    const preferred = links.map((l) => l.interface);
    setWizardPrimary(preferred[0] || interfaces[0]?.name || '');
    setWizardSecondary(preferred[1] || interfaces[1]?.name || '');
    setWizardLan('');
    setWizardMode('failover');
    setWizardPrimaryWeight(70);
    setWizardSecondaryWeight(30);
    setWizardError('');
    setShowWizard(true);
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

  const linkMap = useMemo(() => {
    const map = new Map<string, WanLink>();
    for (const l of links) {
      map.set(l.interface, l);
    }
    return map;
  }, [links]);

  const ensureLink = async (iface: string, defaults: Partial<WanLink>) => {
    const existing = linkMap.get(iface);
    if (existing) {
      await client.put(`/api/links/${existing.id}`, {
        ...existing,
        ...defaults,
        interface: iface,
        enabled: true,
      });
      return existing;
    }

    const payload: Partial<WanLink> = {
      name: defaults.name || `WAN ${iface}`,
      interface: iface,
      ip_address: defaults.ip_address || '',
      gateway: defaults.gateway || '',
      weight: defaults.weight || 100,
      dns_test: defaults.dns_test || '8.8.8.8',
      monitor_hosts: defaults.monitor_hosts || '1.1.1.1,8.8.8.8',
      enabled: true,
    };
    const created = await client.post<WanLink>('/api/links', payload);
    return created.data;
  };

  const applyDualWanWizard = async () => {
    if (!wizardPrimary || !wizardSecondary || wizardPrimary === wizardSecondary) {
      setWizardError('Selecione duas interfaces WAN diferentes.');
      return;
    }
    if (wizardMode === 'balance' && !wizardLan.trim()) {
      setWizardError('Informe a sub-rede LAN para balanceamento (ex.: 192.168.0.0/24).');
      return;
    }

    setWizardLoading(true);
    setWizardError('');
    setError('');
    try {
      // Sync auto-detect first to fill gateway/ip from default routes when available.
      await client.post('/api/links/auto-detect');
      await fetchLinks();

      const primary = await ensureLink(wizardPrimary, {
        name: `WAN Primaria (${wizardPrimary})`,
        weight: wizardMode === 'balance' ? wizardPrimaryWeight : 100,
      });
      const secondary = await ensureLink(wizardSecondary, {
        name: `WAN Secundaria (${wizardSecondary})`,
        weight: wizardMode === 'balance' ? wizardSecondaryWeight : 10,
      });

      const primaryTable = String(primary.table_id || 100);
      const secondaryTable = String(secondary.table_id || 101);

      if (primary.gateway && primary.interface) {
        await client.post('/api/routes', {
          destination: 'default',
          gateway: primary.gateway,
          interface: primary.interface,
          table: primaryTable,
        });
      }
      if (secondary.gateway && secondary.interface) {
        await client.post('/api/routes', {
          destination: 'default',
          gateway: secondary.gateway,
          interface: secondary.interface,
          table: secondaryTable,
        });
      }

      if (wizardMode === 'failover') {
        await client.post('/api/routes/rules', {
          from: 'all',
          table: primaryTable,
          priority: 100,
        });
        await client.post('/api/routes/rules', {
          from: 'all',
          table: secondaryTable,
          priority: 200,
        });
        setError('Assistente aplicado: failover configurado (primario > secundario).');
      } else {
        await client.post('/api/firewall/rules', {
          table: 'mangle',
          chain: 'PREROUTING',
          rule_spec: `-s ${wizardLan.trim()} -m conntrack --ctstate NEW -m statistic --mode random --probability ${(wizardPrimaryWeight / 100).toFixed(2)} -j MARK --set-mark 0x1`,
        });
        await client.post('/api/firewall/rules', {
          table: 'mangle',
          chain: 'PREROUTING',
          rule_spec: `-s ${wizardLan.trim()} -m conntrack --ctstate NEW -j MARK --set-mark 0x2`,
        });
        await client.post('/api/routes/rules', {
          fwmark: '0x1',
          table: primaryTable,
          priority: 110,
        });
        await client.post('/api/routes/rules', {
          fwmark: '0x2',
          table: secondaryTable,
          priority: 120,
        });
        setError('Assistente aplicado: balanceamento por marca (mangle + ip rule fwmark).');
      }

      await fetchLinks();
      setShowWizard(false);
    } catch (err: any) {
      setWizardError(err.response?.data?.error || 'Falha ao aplicar assistente de 2 WAN.');
    } finally {
      setWizardLoading(false);
    }
  };

  const interfaceOptions = useMemo(() => {
    const merged = new Set<string>([...interfaces.map((iface) => iface.name), ...links.map((l) => l.interface)]);
    return Array.from(merged).filter(Boolean).sort();
  }, [interfaces, links]);

  const interfaceAliasByName = useMemo(() => {
    const map = new Map<string, string>();
    for (const iface of interfaces) {
      const alias = iface.alias?.trim();
      if (alias) {
        map.set(iface.name, alias);
      }
    }
    return map;
  }, [interfaces]);

  const formatInterfaceLabel = (name: string) => {
    const alias = interfaceAliasByName.get(name);
    return alias ? `${alias} (${name})` : name;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Links WAN</h1>
          <p className="text-gray-500 text-sm">Gerencie os links de internet</p>
        </div>
        <div className="flex gap-2">
          <button onClick={openWizard} className="btn-secondary flex items-center gap-2">
            <Wand2 className="w-4 h-4" />
            Assistente 2 WAN
          </button>
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
                    <td className="py-3 pr-4 text-gray-400 font-mono">{formatInterfaceLabel(link.interface)}</td>
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
                  <select
                    className="input w-full"
                    value={editLink.interface || ''}
                    onChange={e => setEditLink({...editLink, interface: e.target.value})}
                    required
                  >
                    <option value="">Selecione interface</option>
                    {interfaceOptions.map((name) => (
                      <option key={name} value={name}>{formatInterfaceLabel(name)}</option>
                    ))}
                  </select>
                  {interfaceOptions.length === 0 && (
                    <p className="text-xs text-gray-500 mt-1">Nenhuma interface detectada. Verifique permissões do host e atualize.</p>
                  )}
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

      {showWizard && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-blue-500/30 bg-gradient-to-b from-gray-900 to-gray-950 shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h2 className="text-white font-semibold flex items-center gap-2">
                  <Network className="w-5 h-5 text-blue-400" />
                  Assistente Magico de 2 WAN
                </h2>
                <p className="text-xs text-gray-400 mt-1">Configura failover rapido ou balanceamento por marcacao de pacotes.</p>
              </div>
            </div>

            <div className="p-6 space-y-5">
              <div className="grid sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setWizardMode('failover')}
                  className={`rounded-xl border p-4 text-left transition ${wizardMode === 'failover' ? 'border-blue-400 bg-blue-500/10' : 'border-gray-700 bg-gray-900/60 hover:border-gray-500'}`}
                >
                  <p className="text-white font-medium">Failover inteligente</p>
                  <p className="text-xs text-gray-400 mt-1">Todo trafego usa WAN principal e troca para secundaria em falha.</p>
                </button>
                <button
                  onClick={() => setWizardMode('balance')}
                  className={`rounded-xl border p-4 text-left transition ${wizardMode === 'balance' ? 'border-blue-400 bg-blue-500/10' : 'border-gray-700 bg-gray-900/60 hover:border-gray-500'}`}
                >
                  <p className="text-white font-medium">Balanceamento por marca</p>
                  <p className="text-xs text-gray-400 mt-1">Mangle + fwmark + ip rule para dividir clientes entre 2 links.</p>
                </button>
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">WAN primaria *</label>
                  <select className="input w-full" value={wizardPrimary} onChange={(e) => setWizardPrimary(e.target.value)}>
                    <option value="">Selecione</option>
                    {interfaceOptions.map((name) => <option key={`p-${name}`} value={name}>{formatInterfaceLabel(name)}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">WAN secundaria *</label>
                  <select className="input w-full" value={wizardSecondary} onChange={(e) => setWizardSecondary(e.target.value)}>
                    <option value="">Selecione</option>
                    {interfaceOptions.map((name) => <option key={`s-${name}`} value={name}>{formatInterfaceLabel(name)}</option>)}
                  </select>
                </div>
              </div>

              {wizardMode === 'balance' && (
                <>
                  <div>
                    <label className="label">Sub-rede LAN dos clientes *</label>
                    <input
                      className="input w-full"
                      placeholder="192.168.0.0/24"
                      value={wizardLan}
                      onChange={(e) => setWizardLan(e.target.value)}
                    />
                  </div>
                  <div className="grid sm:grid-cols-2 gap-4">
                    <div>
                      <label className="label">Peso WAN primaria (%)</label>
                      <input type="number" min={1} max={99} className="input w-full" value={wizardPrimaryWeight} onChange={(e) => setWizardPrimaryWeight(Number(e.target.value || 70))} />
                    </div>
                    <div>
                      <label className="label">Peso WAN secundaria (%)</label>
                      <input type="number" min={1} max={99} className="input w-full" value={wizardSecondaryWeight} onChange={(e) => setWizardSecondaryWeight(Number(e.target.value || 30))} />
                    </div>
                  </div>
                </>
              )}

              {wizardError && <p className="text-red-400 text-sm">{wizardError}</p>}

              <div className="flex gap-3 pt-2">
                <button onClick={applyDualWanWizard} disabled={wizardLoading} className="btn-primary flex-1 disabled:opacity-50">
                  {wizardLoading ? 'Aplicando...' : 'Aplicar Assistente'}
                </button>
                <button onClick={() => setShowWizard(false)} type="button" className="btn-secondary flex-1">
                  Fechar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
