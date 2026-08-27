import { useEffect, useMemo, useState } from 'react';
import WanBalancing from '../components/WanBalancing';
import DomainTargets from '../components/DomainTargets';
import LinkDdns from '../components/LinkDdns';
import LinkQuota from '../components/LinkQuota';
import LinkStressTest from '../components/LinkStressTest';
import LinkQosPanel from '../components/LinkQosPanel';
import { useAuth } from '../context/AuthContext';
import { Plus, Pencil, Trash2, RefreshCw, Wifi, Wand2, Network } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import client from '../api/client';
import { useI18n } from '../i18n';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import IconButton from '../components/ui/IconButton';
import type { WanLink, SystemMetrics, InterfaceMetrics, QosUpdateRequest } from '../types';

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
  const { t } = useI18n();
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
      setError(err.response?.data?.error || t('links.error.save'));
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
      setSuccess(t('links.success.deleted', { name: deleteTarget.name }));
      await fetchLinks();
    } catch (err: any) {
      setDeleteError(err.response?.data?.error || t('links.error.delete'));
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
      setWizardError(t('links.wizard.err.twoIfaces'));
      return false;
    }
    if (wizardMode === 'balance') {
      if (!wizardLan.trim()) {
        setWizardError(t('links.wizard.err.lanRequired'));
        return false;
      }
      if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(wizardLan.trim())) {
        setWizardError(t('links.wizard.err.lanInvalid'));
        return false;
      }
      if (wizardPrimaryWeight + wizardSecondaryWeight !== 100) {
        setWizardError(t('links.wizard.err.weightSum'));
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
        name: t('links.wizard.primaryLinkName', { iface: wizardPrimary }),
        weight: wizardMode === 'balance' ? wizardPrimaryWeight : 100,
      });
      const secondary = await ensureLink(wizardSecondary, {
        name: t('links.wizard.secondaryLinkName', { iface: wizardSecondary }),
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
        setSuccess(t('links.wizard.success.failover'));
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
        setSuccess(t('links.wizard.success.balance'));
      }

      await fetchLinks();
      setWizardConfirm(false);
      setShowWizard(false);
    } catch (err: any) {
      setWizardError(err.response?.data?.error || t('links.wizard.err.apply'));
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

  const handleQosUpdated = (linkID: string, value: QosUpdateRequest) => {
    setLinks((current) => current.map((link) => link.id === linkID ? {
      ...link,
      qos_enabled: value.enabled,
      qos_upload_mbps: value.upload_mbps,
      qos_download_mbps: value.download_mbps,
      qos_interactive: value.interactive,
    } : link));
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('links.title')}</h1>
          <p className="text-gray-500 text-sm">{t('links.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={openWizard} className="btn-secondary flex items-center gap-2">
            <Wand2 className="w-4 h-4" />
            {t('links.btn.wizard')}
          </button>
          <button onClick={fetchLinks} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            {t('links.btn.refresh')}
          </button>
          <button onClick={openCreate} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            {t('links.btn.new')}
          </button>
        </div>
      </div>

      {success && (
        <div className="card border border-green-500/30 bg-green-500/10 text-green-400 text-sm">{success}</div>
      )}

      {!loading && <DomainTargets links={links} canEdit={can('links.write')} />}

      {!loading && links.length >= 2 && <WanBalancing links={links} onChanged={fetchLinks} />}

      {!loading && links.length > 0 && <LinkQuota canEdit={can('links.write')} />}

      {!loading && links.length > 0 && <LinkDdns canEdit={can('links.write')} />}

      {!loading && links.map((link) => (
        <LinkQosPanel
          key={link.id}
          link={link}
          canEdit={can('links.write')}
          onUpdated={handleQosUpdated}
        />
      ))}

      {!loading && links.length >= 2 && <LinkStressTest links={links} canRun={can('routes.write')} />}

      <Panel title={t('links.title')}>
        {loading ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">{t('links.loading')}</div>
        ) : links.length === 0 ? (
          <div className="text-center py-12">
            <Wifi className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">{t('links.empty.title')}</p>
            <p className="text-gray-600 text-sm mt-1">{t('links.empty.hint')}</p>
          </div>
        ) : (
          <>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {links.map(link => (
                <div key={link.id} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-white font-medium truncate">{link.name}</div>
                      {!link.enabled && <span className="text-gray-600 text-xs">{t('links.disabled')}</span>}
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <StatusBadge status={link.status} />
                      <IconButton icon={Pencil} onClick={() => openEdit(link)} label={t('links.action.edit')} />
                      <IconButton icon={Trash2} onClick={() => requestDelete(link.id, link.name)} label={t('links.action.delete')} variant="danger" />
                    </div>
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('links.field.interface')}</dt>
                    <dd className="text-gray-400 font-mono">{formatInterfaceLabel(link.interface)}</dd>
                    <dt className="text-gray-500">{t('links.field.ip')}</dt>
                    <dd className="text-gray-400 font-mono">{link.ip_address || '—'}</dd>
                    <dt className="text-gray-500">{t('links.field.gateway')}</dt>
                    <dd className="text-gray-400 font-mono">{link.gateway || '—'}</dd>
                    <dt className="text-gray-500">{t('links.field.weight')}</dt>
                    <dd className="text-gray-400">{link.weight}</dd>
                    <dt className="text-gray-500">{t('links.field.latency')}</dt>
                    <dd className="text-gray-400">{link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'}</dd>
                    <dt className="text-gray-500">{t('links.field.loss')}</dt>
                    <dd className="text-gray-400">{link.packet_loss.toFixed(1)}%</dd>
                  </dl>
                </div>
              ))}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">{t('links.field.name')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.interface')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.ipGateway')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.weight')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.latency')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.loss')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('links.field.status')}</th>
                    <th className="pb-3 font-medium">{t('links.field.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {links.map(link => (
                    <tr key={link.id} className="table-row">
                      <td className="py-3 pr-4">
                        <div className="text-white font-medium">{link.name}</div>
                        {!link.enabled && <span className="text-gray-600 text-xs">{t('links.disabled')}</span>}
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
                          <IconButton icon={Pencil} onClick={() => openEdit(link)} label={t('links.action.edit')} />
                          <IconButton icon={Trash2} onClick={() => requestDelete(link.id, link.name)} label={t('links.action.delete')} variant="danger" />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      {/* Modal */}
      <Modal
        open={showModal}
        onClose={() => setShowModal(false)}
        title={isEditing ? t('links.modal.edit') : t('links.modal.new')}
        size="md"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        <form onSubmit={handleSave} className="p-6 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">{t('links.form.name')}</label>
                  <input className="input w-full" value={editLink.name || ''} onChange={e => setEditLink({...editLink, name: e.target.value})} required />
                </div>
                <div>
                  <label className="label">{t('links.form.interface')}</label>
                  <select
                    className="input w-full"
                    value={editLink.interface || ''}
                    onChange={e => setEditLink({...editLink, interface: e.target.value})}
                    required
                  >
                    <option value="">{t('links.form.selectInterface')}</option>
                    {interfaceOptions.map((name) => (
                      <option key={name} value={name}>{formatInterfaceLabel(name)}</option>
                    ))}
                  </select>
                  {interfaceOptions.length === 0 && (
                    <p className="text-xs text-gray-500 mt-1">{t('links.form.noInterfaces')}</p>
                  )}
                </div>
                <div>
                  <label className="label">{t('links.form.ip')}</label>
                  <input className="input w-full" placeholder="192.168.1.1" value={editLink.ip_address || ''} onChange={e => setEditLink({...editLink, ip_address: e.target.value})} />
                </div>
                <div>
                  <label className="label">{t('links.form.gateway')}</label>
                  <input className="input w-full" placeholder="192.168.1.254" value={editLink.gateway || ''} onChange={e => setEditLink({...editLink, gateway: e.target.value})} />
                </div>
                <div>
                  <label className="label">{t('links.form.weight')}</label>
                  <input type="number" className="input w-full" min={1} max={1000} value={editLink.weight || 100} onChange={e => setEditLink({...editLink, weight: +e.target.value})} />
                </div>
                <div>
                  <label className="label">{t('links.form.dnsTest')}</label>
                  <input className="input w-full" placeholder="8.8.8.8" value={editLink.dns_test || ''} onChange={e => setEditLink({...editLink, dns_test: e.target.value})} />
                </div>
              </div>
              <div>
                <label className="label">{t('links.form.monitorHosts')}</label>
                <input className="input w-full" placeholder="1.1.1.1,8.8.8.8" value={editLink.monitor_hosts || ''} onChange={e => setEditLink({...editLink, monitor_hosts: e.target.value})} />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="enabled" checked={editLink.enabled ?? true} onChange={e => setEditLink({...editLink, enabled: e.target.checked})} className="w-4 h-4" />
                <label htmlFor="enabled" className="text-gray-400 text-sm">{t('links.form.enabled')}</label>
              </div>
              {error && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{error}</div>}
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? t('links.btn.saving') : t('links.btn.save')}
                </button>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary flex-1">
                  {t('links.btn.cancel')}
                </button>
              </div>
        </form>
      </Modal>

      <Modal
        open={showWizard}
        onClose={() => setShowWizard(false)}
        size="lg"
        className="rounded-2xl border border-blue-500/30 bg-linear-to-b from-gray-900 to-gray-950 shadow-2xl"
        title={
          <div>
            <span className="text-white font-semibold flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-400" />
              {t('links.wizard.title')}
            </span>
            <p className="text-xs text-gray-400 mt-1">{t('links.wizard.subtitle')}</p>
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
                  <p className="text-white font-medium">{t('links.wizard.mode.failover')}</p>
                  <p className="text-xs text-gray-400 mt-1">{t('links.wizard.mode.failoverDesc')}</p>
                </button>
                <button
                  onClick={() => setWizardMode('balance')}
                  className={`rounded-xl border p-4 text-left transition ${wizardMode === 'balance' ? 'border-blue-400 bg-blue-500/10' : 'border-gray-700 bg-gray-900/60 hover:border-gray-500'}`}
                >
                  <p className="text-white font-medium">{t('links.wizard.mode.balance')}</p>
                  <p className="text-xs text-gray-400 mt-1">{t('links.wizard.mode.balanceDesc')}</p>
                </button>
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div>
                  <label className="label">{t('links.wizard.primary')}</label>
                  <select className="input w-full" value={wizardPrimary} onChange={(e) => setWizardPrimary(e.target.value)}>
                    <option value="">{t('links.wizard.select')}</option>
                    {interfaceOptions.map((name) => <option key={`p-${name}`} value={name}>{formatInterfaceLabel(name)}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">{t('links.wizard.secondary')}</label>
                  <select className="input w-full" value={wizardSecondary} onChange={(e) => setWizardSecondary(e.target.value)}>
                    <option value="">{t('links.wizard.select')}</option>
                    {interfaceOptions.map((name) => <option key={`s-${name}`} value={name}>{formatInterfaceLabel(name)}</option>)}
                  </select>
                </div>
              </div>

              {wizardMode === 'balance' && (
                <>
                  <div>
                    <label className="label">{t('links.wizard.lan')}</label>
                    <input
                      className="input w-full"
                      placeholder="192.168.0.0/24"
                      value={wizardLan}
                      onChange={(e) => setWizardLan(e.target.value)}
                    />
                  </div>
                  <div className="grid sm:grid-cols-2 gap-4">
                    <div>
                      <label className="label">{t('links.wizard.primaryWeight')}</label>
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
                      <label className="label">{t('links.wizard.secondaryWeight')}</label>
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
                  <p className="text-xs text-gray-500 -mt-1">{t('links.wizard.weightsNote')}</p>
                </>
              )}
              </div>
              )}

              {wizardConfirm && (
                <div className="space-y-4">
                  <div className="px-4 py-3 rounded-lg text-sm bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    <p className="font-medium">{t('links.wizard.review.title')}</p>
                    <p className="mt-1 text-amber-300/90">
                      {t('links.wizard.review.warn')}
                    </p>
                  </div>

                  <div className="rounded-xl border border-gray-700 bg-gray-900/60 p-4 space-y-3 text-sm">
                    <p className="text-gray-400">
                      {t('links.wizard.review.mode')} <span className="text-white font-medium">{wizardMode === 'failover' ? t('links.wizard.mode.failover') : t('links.wizard.mode.balance')}</span>
                    </p>
                    <div>
                      <p className="text-gray-500 mb-1 font-medium">{t('links.wizard.review.linksTitle')}</p>
                      <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                        <li>{t('links.wizard.review.primaryOn')} <span className="font-mono text-white">{formatInterfaceLabel(wizardPrimary)}</span>{wizardMode === 'balance' && t('links.wizard.review.weightSuffix', { w: wizardPrimaryWeight })}</li>
                        <li>{t('links.wizard.review.secondaryOn')} <span className="font-mono text-white">{formatInterfaceLabel(wizardSecondary)}</span>{wizardMode === 'balance' && t('links.wizard.review.weightSuffix', { w: wizardSecondaryWeight })}</li>
                      </ul>
                    </div>
                    <div>
                      <p className="text-gray-500 mb-1 font-medium">{t('links.wizard.review.routesTitle')}</p>
                      <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                        <li>{t('links.wizard.review.routePre')} <span className="font-mono">default</span> {t('links.wizard.review.routePrimaryPost')}</li>
                        <li>{t('links.wizard.review.routePre')} <span className="font-mono">default</span> {t('links.wizard.review.routeSecondaryPost')}</li>
                      </ul>
                    </div>
                    {wizardMode === 'failover' ? (
                      <div>
                        <p className="text-gray-500 mb-1 font-medium">{t('links.wizard.review.ipRuleTitle')}</p>
                        <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                          <li><span className="font-mono">from all</span> {t('links.wizard.review.fromAllPrimary')}</li>
                          <li><span className="font-mono">from all</span> {t('links.wizard.review.fromAllSecondary')}</li>
                        </ul>
                      </div>
                    ) : (
                      <>
                        <div>
                          <p className="text-gray-500 mb-1 font-medium">{t('links.wizard.review.mangleTitle')} <span className="font-mono">{wizardLan.trim()}</span>:</p>
                          <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                            <li>MARK <span className="font-mono">0x1</span> {t('links.wizard.review.markRandom', { p: (wizardPrimaryWeight / 100).toFixed(2) })}</li>
                            <li>MARK <span className="font-mono">0x2</span> {t('links.wizard.review.markRest')}</li>
                          </ul>
                        </div>
                        <div>
                          <p className="text-gray-500 mb-1 font-medium">{t('links.wizard.review.fwmarkTitle')}</p>
                          <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                            <li><span className="font-mono">fwmark 0x1</span> {t('links.wizard.review.fwmarkPrimary')}</li>
                            <li><span className="font-mono">fwmark 0x2</span> {t('links.wizard.review.fwmarkSecondary')}</li>
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
                      {t('links.wizard.btn.review')}
                    </button>
                    <button onClick={() => setShowWizard(false)} type="button" className="btn-secondary flex-1">
                      {t('links.wizard.btn.close')}
                    </button>
                  </>
                ) : (
                  <>
                    <button onClick={applyDualWanWizard} disabled={wizardLoading} className="btn-primary flex-1 disabled:opacity-50">
                      {wizardLoading ? t('links.wizard.btn.applying') : t('links.wizard.btn.apply')}
                    </button>
                    <button onClick={() => setWizardConfirm(false)} disabled={wizardLoading} type="button" className="btn-secondary flex-1 disabled:opacity-50">
                      {t('links.wizard.btn.back')}
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
        title={t('links.delete.title')}
        size="sm"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {deleteTarget && (
        <div className="p-6 space-y-4">
              <p className="text-gray-400 text-sm">
                {t('links.delete.confirmPre')} <span className="text-white font-medium">"{deleteTarget.name}"</span>{t('links.delete.confirmPost')}
              </p>
              {deleteError && <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{deleteError}</div>}
              <div className="flex gap-3 pt-2">
                <button onClick={confirmDelete} disabled={deleting} className="btn-primary flex-1 disabled:opacity-50 bg-red-600 hover:bg-red-500">
                  {deleting ? t('links.delete.deleting') : t('links.delete.confirm')}
                </button>
                <button onClick={() => setDeleteTarget(null)} disabled={deleting} type="button" className="btn-secondary flex-1 disabled:opacity-50">
                  {t('links.btn.cancel')}
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}
