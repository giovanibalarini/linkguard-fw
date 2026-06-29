import { useEffect, useState } from 'react';
import {
  RefreshCw, Database, Download, RotateCcw, Terminal, Plus, X, Network, Ban,
  ShieldOff, ArrowUp, ArrowDown, Pencil, Trash2, Check, Slash, ListChecks,
} from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import PortForwarding from '../components/PortForwarding';
import type { IptablesBackup, NftManaged, NftUserRule, SystemMetrics } from '../types';

type Tab = 'rules' | 'portforward' | 'ruleset' | 'backups';
type Action = 'accept' | 'drop' | 'reject';

const ACTIONS: Record<Action, { label: string; color: string; ring: string; Icon: typeof Check }> = {
  accept: { label: 'Permitir', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10', Icon: Check },
  drop: { label: 'Bloquear', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10', Icon: Ban },
  reject: { label: 'Rejeitar', color: 'text-orange-400', ring: 'border-orange-500 bg-orange-500/10', Icon: Slash },
};

const emptyModal = {
  open: false, handle: 0, action: 'drop' as Action,
  iif: '', oif: '', saddr: '', daddr: '', proto: '', dport: '',
};

function describe(r: NftUserRule): string {
  const parts: string[] = [];
  if (r.iif) parts.push(`entrada ${r.iif}`);
  if (r.oif) parts.push(`saída ${r.oif}`);
  if (r.saddr) parts.push(`origem ${r.saddr}`);
  if (r.daddr) parts.push(`destino ${r.daddr}`);
  if (r.proto) parts.push(r.proto.toUpperCase() + (r.dport ? `:${r.dport}` : ''));
  return parts.length ? parts.join(' · ') : 'qualquer tráfego';
}

function previewNft(m: typeof emptyModal): string {
  const t: string[] = [];
  if (m.iif) t.push('iifname', m.iif);
  if (m.oif) t.push('oifname', m.oif);
  if (m.saddr) t.push('ip saddr', m.saddr);
  if (m.daddr) t.push('ip daddr', m.daddr);
  if (m.proto === 'tcp' || m.proto === 'udp') {
    if (m.dport) t.push(m.proto, 'dport', m.dport);
    else t.push('ip protocol', m.proto);
  } else if (m.proto === 'icmp') t.push('ip protocol', 'icmp');
  t.push('counter', m.action);
  return t.join(' ');
}

export default function Firewall() {
  const { can } = useAuth();
  const canWrite = can('firewall.write');
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  const [rules, setRules] = useState<NftUserRule[]>([]);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState('');
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('rules');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [newWan, setNewWan] = useState('');
  const [newBlock, setNewBlock] = useState('');
  const [modal, setModal] = useState(emptyModal);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [mg, rl, rs, bk, sys] = await Promise.all([
        client.get<NftManaged>('/api/nftables/managed'),
        client.get<NftUserRule[]>('/api/nftables/rules'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
        client.get<IptablesBackup[]>('/api/nftables/backups'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setManaged(mg.data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
      setRules(rl.data ?? []);
      setRuleset(rs.data?.ruleset ?? '');
      setBackups(bk.data ?? []);
      setIfaces((sys.data?.interfaces ?? []).map((i) => i.name).filter((n) => n && n !== 'lo'));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true);
    setMsg('');
    try {
      await fn();
      if (ok) setMsg(ok);
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  // Managed sets/map
  const addWan = () => newWan.trim() && run(() => client.post('/api/nftables/wan-host', { ip: newWan.trim() }), 'Host direcionado para a WAN2.').then(() => setNewWan(''));
  const delWan = (ip: string) => run(() => client.delete('/api/nftables/wan-host', { data: { ip } }), 'Host revertido para a WAN1.');
  const addBlock = () => newBlock.trim() && run(() => client.post('/api/nftables/blocklist', { cidr: newBlock.trim() }), 'Destino bloqueado.').then(() => setNewBlock(''));
  const delBlock = (cidr: string) => run(() => client.delete('/api/nftables/blocklist', { data: { cidr } }), 'Destino desbloqueado.');

  // Custom rules
  const openCreate = () => setModal({ ...emptyModal, open: true });
  const openEdit = (r: NftUserRule) => setModal({ open: true, handle: r.handle, action: (r.action as Action) || 'drop', iif: r.iif, oif: r.oif, saddr: r.saddr, daddr: r.daddr, proto: r.proto, dport: r.dport });
  const closeModal = () => setModal((m) => ({ ...m, open: false }));
  const saveRule = () => {
    const payload = { action: modal.action, iif: modal.iif, oif: modal.oif, saddr: modal.saddr, daddr: modal.daddr, proto: modal.proto, dport: modal.dport };
    const req = modal.handle > 0 ? client.put('/api/nftables/rules', { handle: modal.handle, ...payload }) : client.post('/api/nftables/rules', payload);
    run(() => req, modal.handle > 0 ? 'Regra atualizada.' : 'Regra criada.').then(closeModal);
  };
  const delRule = (r: NftUserRule) => confirm(`Remover esta regra? (${ACTIONS[r.action as Action]?.label || r.action}: ${describe(r)})`) && run(() => client.delete('/api/nftables/rules', { data: { handle: r.handle } }), 'Regra removida.');
  const moveRule = (handle: number, dir: 'up' | 'down') => run(() => client.post('/api/nftables/rules/move', { handle, dir }), '');

  const handleBackup = () => run(() => client.post('/api/nftables/backup', { label: '' }), 'Snapshot criado.');
  const handleRollback = (b: IptablesBackup) => confirm(`Restaurar o ruleset do snapshot "${b.label}"?`) && run(() => client.post('/api/nftables/rollback', { backup_id: b.id }), 'Ruleset restaurado.');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Firewall</h1>
          <p className="text-gray-500 text-sm">Gestão nativa via nftables (table inet linkguard)</p>
        </div>
        <div className="flex gap-2">
          {canWrite && (
            <button onClick={handleBackup} disabled={busy} className="btn-secondary flex items-center gap-2 disabled:opacity-50">
              <Database className="w-4 h-4" /> Snapshot
            </button>
          )}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Atualizar
          </button>
        </div>
      </div>

      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>
      )}

      <div className="flex gap-2 border-b border-gray-800">
        {([['rules', 'Regras'], ['portforward', 'Encaminhamento'], ['ruleset', 'Ruleset'], ['backups', `Snapshots (${backups.length})`]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === id ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>{label}</button>
        ))}
      </div>

      {loading ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : activeTab === 'rules' ? (
        <div className="space-y-4">
          {/* Custom rules (ordered) */}
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <ListChecks className="w-4 h-4 text-blue-400" />
                <h3 className="text-white font-semibold">Regras personalizadas</h3>
              </div>
              {canWrite && <button onClick={openCreate} className="btn-primary flex items-center gap-2 w-full sm:w-auto justify-center"><Plus className="w-4 h-4" /> Nova regra</button>}
            </div>
            <p className="text-gray-500 text-xs mb-3">Avaliadas de cima para baixo, antes dos bloqueios. A primeira que casar decide.</p>
            {rules.length === 0 ? (
              <p className="text-gray-600 text-sm py-2">Nenhuma regra personalizada. Clique em "Nova regra".</p>
            ) : (
              <div className="space-y-2">
                {rules.map((r, i) => {
                  const a = ACTIONS[r.action as Action] || ACTIONS.drop;
                  return (
                    <div key={r.handle} className="flex items-center gap-3 bg-gray-800/60 rounded-lg px-3 py-2">
                      <span className="text-gray-600 text-xs w-5 text-right select-none">{i + 1}</span>
                      {canWrite && (
                        <div className="flex flex-col">
                          <button onClick={() => moveRule(r.handle, 'up')} disabled={i === 0 || busy} className="text-gray-500 hover:text-gray-200 disabled:opacity-20"><ArrowUp className="w-3.5 h-3.5" /></button>
                          <button onClick={() => moveRule(r.handle, 'down')} disabled={i === rules.length - 1 || busy} className="text-gray-500 hover:text-gray-200 disabled:opacity-20"><ArrowDown className="w-3.5 h-3.5" /></button>
                        </div>
                      )}
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${a.ring} ${a.color}`}><a.Icon className="w-3 h-3" />{a.label}</span>
                      <span className="text-gray-300 text-sm flex-1 min-w-0 truncate">{describe(r)}</span>
                      {canWrite && (
                        <div className="flex items-center gap-2 shrink-0">
                          <button onClick={() => openEdit(r)} className="text-gray-400 hover:text-blue-400"><Pencil className="w-4 h-4" /></button>
                          <button onClick={() => delRule(r)} className="text-gray-400 hover:text-red-400"><Trash2 className="w-4 h-4" /></button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* WAN steering */}
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><Network className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Direcionamento por WAN</h3></div>
            <p className="text-gray-500 text-xs mb-3">Hosts nesta lista saem pela <span className="text-blue-300">WAN2 (sumicity)</span>; os demais pela WAN1 (padrão).</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder="IP do host (ex.: 192.168.3.50)" value={newWan} onChange={(e) => setNewWan(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addWan()} />
                <button onClick={addWan} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> Adicionar</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {managed.wan_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host direcionado.</span>}
              {managed.wan_hosts.map((h) => (
                <span key={h.ip} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{h.ip}<span className="text-blue-400 text-xs font-sans">WAN2</span>{canWrite && <button onClick={() => delWan(h.ip)} className="text-gray-500 hover:text-red-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </div>

          {/* Blocklist */}
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><Ban className="w-4 h-4 text-red-400" /><h3 className="text-white font-semibold">Destinos bloqueados</h3></div>
            <p className="text-gray-500 text-xs mb-3">IPs/CIDRs cujo tráfego forward é descartado (origem e destino).</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder="CIDR ou IP (ex.: 163.116.128.0/17)" value={newBlock} onChange={(e) => setNewBlock(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addBlock()} />
                <button onClick={addBlock} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> Bloquear</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {managed.blocklist.length === 0 && <span className="text-gray-600 text-sm">Nenhum destino bloqueado.</span>}
              {managed.blocklist.map((c) => (
                <span key={c} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{c}{canWrite && <button onClick={() => delBlock(c)} className="text-gray-500 hover:text-green-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </div>

          {/* Blocked hosts (read-only) */}
          <div className="card">
            <div className="flex items-center gap-2 mb-1"><ShieldOff className="w-4 h-4 text-orange-400" /><h3 className="text-white font-semibold">Hosts bloqueados</h3></div>
            <p className="text-gray-500 text-xs mb-3">Bloqueie/desbloqueie na página <span className="text-gray-300">Hosts</span> (mantém o inventário em sincronia).</p>
            <div className="flex flex-wrap gap-2">
              {managed.blocked_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host bloqueado.</span>}
              {managed.blocked_hosts.map((ip) => (<span key={ip} className="px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{ip}</span>))}
            </div>
          </div>
        </div>
      ) : activeTab === 'portforward' ? (
        <PortForwarding ifaces={ifaces} canWrite={canWrite} onMsg={setMsg} />
      ) : activeTab === 'ruleset' ? (
        <div className="card p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500"><Terminal className="w-3.5 h-3.5" /><span className="font-mono">nft list ruleset</span></div>
          {ruleset.trim() ? <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre> : <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>}
        </div>
      ) : (
        <div className="card">
          {backups.length === 0 ? (
            <div className="text-center py-12"><Download className="w-12 h-12 text-gray-700 mx-auto mb-3" /><p className="text-gray-400">Nenhum snapshot disponível</p></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-gray-500 border-b border-gray-800"><th className="pb-3 pr-4 font-medium">Label</th><th className="pb-3 pr-4 font-medium">Tamanho</th><th className="pb-3 pr-4 font-medium">Data</th>{canWrite && <th className="pb-3 font-medium">Ações</th>}</tr></thead>
                <tbody>
                  {backups.map((b) => (
                    <tr key={b.id} className="table-row">
                      <td className="py-3 pr-4 text-white">{b.label}</td>
                      <td className="py-3 pr-4 text-gray-400">{(b.rules.length / 1024).toFixed(1)} KB</td>
                      <td className="py-3 pr-4 text-gray-400">{new Date(b.created_at).toLocaleString()}</td>
                      {canWrite && <td className="py-3"><button onClick={() => handleRollback(b)} disabled={busy} className="text-gray-400 hover:text-blue-400 flex items-center gap-1 disabled:opacity-50"><RotateCcw className="w-4 h-4" /> Restaurar</button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Rule modal */}
      {modal.open && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-lg rounded-xl border border-gray-700 bg-gray-900 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="px-6 py-4 border-b border-gray-800">
              <h3 className="text-white font-semibold">{modal.handle > 0 ? 'Editar regra' : 'Nova regra'}</h3>
            </div>
            <div className="p-6 space-y-4 overflow-y-auto">
              <div>
                <label className="label mb-2 block">Ação</label>
                <div className="grid grid-cols-3 gap-2">
                  {(Object.keys(ACTIONS) as Action[]).map((act) => {
                    const a = ACTIONS[act];
                    const active = modal.action === act;
                    return (
                      <button key={act} onClick={() => setModal({ ...modal, action: act })} className={`flex flex-col items-center gap-1 rounded-lg border p-3 transition ${active ? a.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}>
                        <a.Icon className={`w-5 h-5 ${active ? a.color : 'text-gray-400'}`} />
                        <span className={`text-xs ${active ? a.color : 'text-gray-400'}`}>{a.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Interface de entrada</label>
                  <select className="input w-full" value={modal.iif} onChange={(e) => setModal({ ...modal, iif: e.target.value })}>
                    <option value="">Qualquer</option>
                    {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">Interface de saída</label>
                  <select className="input w-full" value={modal.oif} onChange={(e) => setModal({ ...modal, oif: e.target.value })}>
                    <option value="">Qualquer</option>
                    {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <div>
                  <label className="label">Origem (IP/CIDR)</label>
                  <input className="input w-full" placeholder="qualquer" value={modal.saddr} onChange={(e) => setModal({ ...modal, saddr: e.target.value })} />
                </div>
                <div>
                  <label className="label">Destino (IP/CIDR)</label>
                  <input className="input w-full" placeholder="qualquer" value={modal.daddr} onChange={(e) => setModal({ ...modal, daddr: e.target.value })} />
                </div>
                <div>
                  <label className="label">Protocolo</label>
                  <select className="input w-full" value={modal.proto} onChange={(e) => setModal({ ...modal, proto: e.target.value })}>
                    <option value="">Qualquer</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                  </select>
                </div>
                {(modal.proto === 'tcp' || modal.proto === 'udp') && (
                  <div>
                    <label className="label">Porta de destino</label>
                    <input className="input w-full" placeholder="ex.: 443 ou 1000-2000" value={modal.dport} onChange={(e) => setModal({ ...modal, dport: e.target.value })} />
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
                <p className="text-xs text-gray-400 mb-1">
                  <span className={ACTIONS[modal.action].color}>{ACTIONS[modal.action].label}</span>{' '}
                  {describe({ ...modal, handle: 0, raw: '' } as NftUserRule)}
                </p>
                <p className="font-mono text-[11px] text-gray-500 break-all">{previewNft(modal)}</p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
              <button onClick={saveRule} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
              <button onClick={closeModal} className="btn-secondary flex-1">Cancelar</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
