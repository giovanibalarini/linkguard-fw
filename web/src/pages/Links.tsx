import { useEffect, useMemo, useState } from 'react';
import WanBalancing from '../components/WanBalancing';
import LinkStressTest from '../components/LinkStressTest';
import { useAuth } from '../context/AuthContext';
import { Plus, Pencil, Trash2, RefreshCw, Wifi, Wand2, Network } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
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
  const { can } = useAuth();
  const [links, setLinks] = useState<WanLink[]>([]);
  const [interfaces, setInterfaces] = useState<InterfaceMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [editLink, setEditLink] = useState<Partial<WanLink>>(emptyLink);
  const [isEditing, setIsEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [wizardLoading, setWizardLoading] = useState(false);
  const [wizardError, setWizardError] = useState('');
  const [wizardConfirm, setWizardConfirm] = useState(false);
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

  // Auto-dismiss the page-level success banner after ~4s.
  useEffect(() => {
    if (!success) return;
    const t = setTimeout(() => setSuccess(''), 4000);
    return () => clearTimeout(t);
  }, [success]);

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
    setWizardConfirm(false);
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

  const requestDelete = (id: string, name: string) => {
    setDeleteError('');
    setDeleteTarget({ id, name });
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError('');
    try {
      await client.delete(`/api/links/${deleteTarget.id}`);
      setDeleteTarget(null);
      setSuccess(`Link "${deleteTarget.name}" excluído com sucesso.`);
      await fetchLinks();
    } catch (err: any) {
      setDeleteError(err.response?.data?.error || 'Erro ao excluir link');
    } finally {
      setDeleting(false);
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

  const validateWizard = () => {
    if (!wizardPrimary || !wizardSecondary || wizardPrimary === wizardSecondary) {
      setWizardError('Selecione duas interfaces WAN diferentes.');
      return false;
    }
    if (wizardMode === 'balance') {
      if (!wizardLan.trim()) {
        setWizardError('Informe a sub-rede LAN para balanceamento (ex.: 192.168.0.0/24).');
        return false;
      }
      if (wizardPrimaryWeight + wizardSecondaryWeight !== 100) {
        setWizardError('A soma dos pesos das WANs deve ser 100%.');
        return false;
      }
    }
    return true;
  };

  // First step: validate and move to the confirmation/preview screen.
  const reviewWizard = () => {
    if (!validateWizard()) return;
    setWizardError('');
    setWizardConfirm(true);
  };

  const applyDualWanWizard = async () => {
    if (!validateWizard()) {
      setWizardConfirm(false);
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
        name: `WAN Primária (${wizardPrimary})`,
        weight: wizardMode === 'balance' ? wizardPrimaryWeight : 100,
      });
      const secondary = await ensureLink(wizardSecondary, {
        name: `WAN Secundária (${wizardSecondary})`,
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
        setSuccess('Assistente aplicado: failover configurado (primária > secundária).');
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
        setSuccess('Assistente aplicado: balanceamento por marca (mangle + ip rule fwmark).');
      }

      await fetchLinks();
      setWizardConfirm(false);
      setShowWizard(false);
    } catch (err: any) {
      setWizardError(err.response?.data?.error || 'Falha ao aplicar assistente de 2 WAN.');
      setWizardConfirm(false);
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
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
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

      {success && (
        <div className="card border border-green-500/30 bg-green-500/10 text-green-400 text-sm">{success}</div>
      )}

      {!loading && links.length >= 2 && <WanBalancing links={links} onChanged={fetchLinks} />}

      {!loading && links.length >= 2 && <LinkStressTest links={links} canRun={can('routes.write')} />}

      <Panel title="Links WAN">
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
                        <button onClick={() => requestDelete(link.id, link.name)} className="text-gray-400 hover:text-red-400 transition-colors">
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

      {/* Modal */}
      <Modal
        open={showModal}
        onClose={() => setShowModal(false)}
        title={isEditing ? 'Editar Link WAN' : 'Novo Link WAN'}
        size="md"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        <form onSubmit={handleSave} className="p-6 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
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

      <Modal
        open={showWizard}
        onClose={() => setShowWizard(false)}
        size="lg"
        className="rounded-2xl border border-blue-500/30 bg-gradient-to-b from-gray-900 to-gray-950 shadow-2xl"
        title={
          <div>
            <span className="text-white font-semibold flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-400" />
              Assistente Mágico de 2 WAN
            </span>
            <p className="text-xs text-gray-400 mt-1">Configura failover rápido ou balanceamento por marcação de pacotes.</p>
          </div>
        }
      >
        <div className="p-6 space-y-5">
              {!wizardConfirm && (
              <div className="space-y-5">
              <div className="grid sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setWizardMode('failover')}
                  className={`rounded-xl border p-4 text-left transition ${wizardMode === 'failover' ? 'border-blue-400 bg-blue-500/10' : 'border-gray-700 bg-gray-900/60 hover:border-gray-500'}`}
                >
                  <p className="text-white font-medium">Failover inteligente</p>
                  <p className="text-xs text-gray-400 mt-1">Todo tráfego usa a WAN principal e troca para a secundária em falha.</p>
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
                  <label className="label">WAN primária *</label>
                  <select className="input w-full" value={wizardPrimary} onChange={(e) => setWizardPrimary(e.target.value)}>
                    <option value="">Selecione</option>
                    {interfaceOptions.map((name) => <option key={`p-${name}`} value={name}>{formatInterfaceLabel(name)}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">WAN secundária *</label>
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
                      <label className="label">Peso WAN primária (%)</label>
                      <input
                        type="number"
                        min={1}
                        max={99}
                        className="input w-full"
                        value={wizardPrimaryWeight}
                        onChange={(e) => {
                          const primaryW = Number(e.target.value || 70);
                          setWizardPrimaryWeight(primaryW);
                          setWizardSecondaryWeight(100 - primaryW);
                        }}
                      />
                    </div>
                    <div>
                      <label className="label">Peso WAN secundária (%)</label>
                      <input
                        type="number"
                        min={1}
                        max={99}
                        className="input w-full"
                        value={wizardSecondaryWeight}
                        onChange={(e) => {
                          const secondaryW = Number(e.target.value || 30);
                          setWizardSecondaryWeight(secondaryW);
                          setWizardPrimaryWeight(100 - secondaryW);
                        }}
                      />
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 -mt-1">Os pesos são complementares e devem somar 100%.</p>
                </>
              )}
              </div>
              )}

              {wizardConfirm && (
                <div className="space-y-4">
                  <div className="px-4 py-3 rounded-lg text-sm bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    <p className="font-medium">Revise antes de aplicar</p>
                    <p className="mt-1 text-amber-300/90">
                      As alterações abaixo serão aplicadas ao roteamento e firewall do host. A conectividade pode cair por alguns instantes durante a aplicação.
                    </p>
                  </div>

                  <div className="rounded-xl border border-gray-700 bg-gray-900/60 p-4 space-y-3 text-sm">
                    <p className="text-gray-400">
                      Modo: <span className="text-white font-medium">{wizardMode === 'failover' ? 'Failover inteligente' : 'Balanceamento por marca'}</span>
                    </p>
                    <div>
                      <p className="text-gray-500 mb-1 font-medium">Links WAN que serão criados/atualizados:</p>
                      <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                        <li>WAN Primária em <span className="font-mono text-white">{formatInterfaceLabel(wizardPrimary)}</span>{wizardMode === 'balance' && ` (peso ${wizardPrimaryWeight}%)`}</li>
                        <li>WAN Secundária em <span className="font-mono text-white">{formatInterfaceLabel(wizardSecondary)}</span>{wizardMode === 'balance' && ` (peso ${wizardSecondaryWeight}%)`}</li>
                      </ul>
                    </div>
                    <div>
                      <p className="text-gray-500 mb-1 font-medium">Rotas padrão por tabela:</p>
                      <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                        <li>Rota <span className="font-mono">default</span> via gateway da primária na tabela própria do link.</li>
                        <li>Rota <span className="font-mono">default</span> via gateway da secundária na tabela própria do link.</li>
                      </ul>
                    </div>
                    {wizardMode === 'failover' ? (
                      <div>
                        <p className="text-gray-500 mb-1 font-medium">Regras ip rule:</p>
                        <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                          <li><span className="font-mono">from all</span> → tabela da primária (prioridade 100).</li>
                          <li><span className="font-mono">from all</span> → tabela da secundária (prioridade 200).</li>
                        </ul>
                      </div>
                    ) : (
                      <>
                        <div>
                          <p className="text-gray-500 mb-1 font-medium">Regras mangle MARK (PREROUTING) para a LAN <span className="font-mono">{wizardLan.trim()}</span>:</p>
                          <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                            <li>MARK <span className="font-mono">0x1</span> aleatório com probabilidade {(wizardPrimaryWeight / 100).toFixed(2)}.</li>
                            <li>MARK <span className="font-mono">0x2</span> para o tráfego restante.</li>
                          </ul>
                        </div>
                        <div>
                          <p className="text-gray-500 mb-1 font-medium">Regras ip rule por fwmark:</p>
                          <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                            <li><span className="font-mono">fwmark 0x1</span> → tabela da primária (prioridade 110).</li>
                            <li><span className="font-mono">fwmark 0x2</span> → tabela da secundária (prioridade 120).</li>
                          </ul>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              )}

              {wizardError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{wizardError}</div>}

              <div className="flex gap-3 pt-2">
                {!wizardConfirm ? (
                  <>
                    <button onClick={reviewWizard} disabled={wizardLoading} className="btn-primary flex-1 disabled:opacity-50">
                      Revisar alterações
                    </button>
                    <button onClick={() => setShowWizard(false)} type="button" className="btn-secondary flex-1">
                      Fechar
                    </button>
                  </>
                ) : (
                  <>
                    <button onClick={applyDualWanWizard} disabled={wizardLoading} className="btn-primary flex-1 disabled:opacity-50">
                      {wizardLoading ? 'Aplicando...' : 'Confirmar e aplicar'}
                    </button>
                    <button onClick={() => setWizardConfirm(false)} disabled={wizardLoading} type="button" className="btn-secondary flex-1 disabled:opacity-50">
                      Voltar
                    </button>
                  </>
                )}
              </div>
        </div>
      </Modal>

      {/* Delete confirmation modal */}
      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Excluir Link WAN"
        size="sm"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {deleteTarget && (
        <div className="p-6 space-y-4">
              <p className="text-gray-400 text-sm">
                Tem certeza que deseja excluir o link <span className="text-white font-medium">"{deleteTarget.name}"</span>? Esta ação não pode ser desfeita.
              </p>
              {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
              <div className="flex gap-3 pt-2">
                <button onClick={confirmDelete} disabled={deleting} className="btn-primary flex-1 disabled:opacity-50 bg-red-600 hover:bg-red-500">
                  {deleting ? 'Excluindo...' : 'Excluir'}
                </button>
                <button onClick={() => setDeleteTarget(null)} disabled={deleting} type="button" className="btn-secondary flex-1 disabled:opacity-50">
                  Cancelar
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
