import { useEffect, useState } from 'react';
import type { DragEvent } from 'react';
import {
  RefreshCw, Database, Download, RotateCcw, Terminal, Plus, X, Network, Ban,
  ShieldOff, ArrowUp, ArrowDown, Pencil, Trash2, Check, Slash, ListChecks,
  GripVertical, Power, PowerOff,
} from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import IconButton from '../components/ui/IconButton';
import { useAuth } from '../context/AuthContext';
import PortForwarding from '../components/PortForwarding';
import FirewallOverview from '../components/FirewallOverview';
import type { FirewallRule, FirewallRulesData, IptablesBackup, LastApply, NftChainInfo, NftManaged, SystemMetrics } from '../types';

type Tab = 'overview' | 'rules' | 'portforward' | 'ruleset' | 'backups';
type Action = 'accept' | 'drop' | 'reject';

const ACTIONS: Record<Action, { label: string; color: string; ring: string; Icon: typeof Check }> = {
  accept: { label: 'Permitir', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10', Icon: Check },
  drop: { label: 'Bloquear', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10', Icon: Ban },
  reject: { label: 'Rejeitar', color: 'text-orange-400', ring: 'border-orange-500 bg-orange-500/10', Icon: Slash },
};

const emptyModal = {
  open: false, id: '', action: 'drop' as Action,
  iif: '', oif: '', saddr: '', daddr: '', proto: '', dport: '', description: '',
};

// RuleLike is only the fields that decide the plain-language description —
// a Pick, not the full FirewallRule/modal shape, so both a stored rule and
// the in-progress modal state (which carries extra fields like id/open) can
// be passed straight through without a throwaway cast at every call site.
type RuleLike = Pick<FirewallRule, 'iif' | 'oif' | 'saddr' | 'daddr' | 'proto' | 'dport'>;

function describe(r: RuleLike): string {
  const parts: string[] = [];
  if (r.iif) parts.push(`entrada ${r.iif}`);
  if (r.oif) parts.push(`saída ${r.oif}`);
  if (r.saddr) parts.push(`origem ${r.saddr}`);
  if (r.daddr) parts.push(`destino ${r.daddr}`);
  if (r.proto) parts.push(r.proto.toUpperCase() + (r.dport ? `:${r.dport}` : ''));
  return parts.length ? parts.join(' · ') : 'qualquer tráfego';
}

// moveItem returns a copy of arr with the element at `from` relocated to
// `to` — shared by drag-and-drop and the up/down button fallback so both
// paths compute the exact same new order before sending it to the reorder
// endpoint.
function moveItem<T>(arr: T[], from: number, to: number): T[] {
  const next = arr.slice();
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
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
  const [rules, setRules] = useState<FirewallRule[]>([]);
  // rulesApplyStatus (C-3): the outcome of the last user_rules reconcile —
  // handler-triggered or boot-time, both persisted server-side under the
  // same key — so a DB write that failed to actually apply into nft shows
  // up here instead of only in a 200 the admin already dismissed.
  const [rulesApplyStatus, setRulesApplyStatus] = useState<LastApply | undefined>(undefined);
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [overview, setOverview] = useState<NftChainInfo[]>([]);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState('');
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [newWan, setNewWan] = useState('');
  const [newBlock, setNewBlock] = useState('');
  const [modal, setModal] = useState(emptyModal);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [mg, rl, ov, rs, bk, sys] = await Promise.all([
        client.get<NftManaged>('/api/nftables/managed'),
        client.get<FirewallRulesData>('/api/nftables/rules'),
        client.get<NftChainInfo[]>('/api/nftables/overview'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
        client.get<IptablesBackup[]>('/api/nftables/backups'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setManaged(mg.data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
      setRules(rl.data?.rules ?? []);
      setRulesApplyStatus(rl.data?.apply_status);
      setOverview(ov.data ?? []);
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
  const openEdit = (r: FirewallRule) => setModal({ open: true, id: r.id, action: (r.action as Action) || 'drop', iif: r.iif, oif: r.oif, saddr: r.saddr, daddr: r.daddr, proto: r.proto, dport: r.dport, description: r.description });
  const closeModal = () => setModal((m) => ({ ...m, open: false }));
  const saveRule = () => {
    const payload = {
      action: modal.action, iif: modal.iif, oif: modal.oif, saddr: modal.saddr, daddr: modal.daddr,
      proto: modal.proto, dport: modal.dport, description: modal.description,
    };
    const req = modal.id ? client.put('/api/nftables/rules', { id: modal.id, ...payload }) : client.post('/api/nftables/rules', payload);
    run(() => req, modal.id ? 'Regra atualizada.' : 'Regra criada.').then(closeModal);
  };
  const delRule = (r: FirewallRule) => confirm(`Remover esta regra? (${ACTIONS[r.action as Action]?.label || r.action}: ${describe(r)})`) && run(() => client.delete('/api/nftables/rules', { data: { id: r.id } }), 'Regra removida.');
  const toggleRule = (r: FirewallRule) => run(() => client.post('/api/nftables/rules/toggle', { id: r.id, enabled: !r.enabled }), r.enabled ? 'Regra desativada.' : 'Regra ativada.');

  // Reordering: drag-and-drop (native HTML5 DnD — no library) with an
  // up/down button fallback for keyboard/accessibility, both funnelling
  // into the same reorder call so they can never disagree about the result.
  //
  // I-3: the optimistic setRules(newOrder) below used to have no rollback —
  // `run`'s error path never calls fetchData, so a rejected reorder (a bad
  // id, a race with another client) left the screen showing an order the
  // server never accepted, on a screen where order decides which rule wins.
  // This keeps the previous array and restores it explicitly on failure,
  // rather than reusing `run` (which would need every other caller's error
  // path changed just for this one case).
  const reorderTo = (newOrder: FirewallRule[]) => {
    const previous = rules;
    setRules(newOrder); // optimistic: the drag/click feels instant
    setBusy(true);
    setMsg('');
    client.post('/api/nftables/rules/reorder', { ids: newOrder.map((r) => r.id) })
      .then(() => fetchData())
      .catch((e: any) => {
        setRules(previous); // roll back — the server never accepted this order
        setMsg(`Erro: ${e.response?.data?.error || e.message}`);
      })
      .finally(() => setBusy(false));
  };
  const moveRule = (index: number, dir: 'up' | 'down') => {
    const to = dir === 'up' ? index - 1 : index + 1;
    if (to < 0 || to >= rules.length) return;
    reorderTo(moveItem(rules, index, to));
  };
  // I-6: Firefox requires dataTransfer to actually carry data for an HTML5
  // drag to start at all — without this call, `dragstart` fires but the
  // browser never enters a drag session, so `drop` (and therefore the whole
  // reorder) silently never fires in Firefox. The value itself isn't read
  // back (dragIndex, in closure state, is what onDrop uses); only setting
  // it is what Firefox needs.
  const onDragStart = (e: DragEvent, index: number) => {
    if (!canWrite) return;
    e.dataTransfer.setData('text/plain', String(index));
    e.dataTransfer.effectAllowed = 'move';
    setDragIndex(index);
  };
  const onDragOver = (e: DragEvent) => { if (dragIndex !== null) e.preventDefault(); };
  const onDrop = (index: number) => {
    if (dragIndex === null || dragIndex === index) { setDragIndex(null); return; }
    reorderTo(moveItem(rules, dragIndex, index));
    setDragIndex(null);
  };
  const onDragEnd = () => setDragIndex(null);

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

      {/* rulesApplyStatus (C-3): the last DB->nft reconcile can fail on its
          own — a boot-time reconcile in particular has no HTTP response for
          anyone to see — so this is a standing banner, not tied to `msg`
          (which only ever reflects the admin's own last action in this
          session), mirroring the NTP page's firewall_apply banner. */}
      {rulesApplyStatus && !rulesApplyStatus.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          A última tentativa de aplicar suas regras personalizadas ao nftables falhou: {rulesApplyStatus.error || 'erro desconhecido'}. O que está em vigor pode não refletir o que está configurado aqui — confira a aba "Visão geral" antes de confiar nas regras abaixo.
        </div>
      )}

      {msg && (
        <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>
      )}

      <div className="flex gap-2 border-b border-gray-800 overflow-x-auto">
        {([['overview', 'Visão geral'], ['rules', 'Regras'], ['portforward', 'Encaminhamento'], ['ruleset', 'Ruleset'], ['backups', `Snapshots (${backups.length})`]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap shrink-0 ${activeTab === id ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>{label}</button>
        ))}
      </div>

      {loading ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : activeTab === 'overview' ? (
        <FirewallOverview
          chains={overview}
          onOpenRulesTab={() => setActiveTab('rules')}
          onOpenPortForwardTab={() => setActiveTab('portforward')}
        />
      ) : activeTab === 'rules' ? (
        <div className="space-y-4">
          {/* Custom rules (ordered) */}
          <Panel
            title={<span className="flex items-center gap-2"><ListChecks className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Regras personalizadas</span></span>}
            action={canWrite ? <button onClick={openCreate} className="btn-primary flex items-center gap-2 justify-center"><Plus className="w-4 h-4" /> Nova regra</button> : undefined}
          >
            <p className="text-gray-500 text-xs mb-3">
              Avaliadas de cima para baixo, antes dos bloqueios. A primeira que casar decide.
              {canWrite && rules.length > 1 && <> Arraste pelo <GripVertical className="w-3 h-3 inline -mt-0.5" /> para reordenar.</>}
            </p>
            {rules.length === 0 ? (
              <p className="text-gray-600 text-sm py-2">Nenhuma regra personalizada. Clique em "Nova regra".</p>
            ) : (
              <div className="space-y-2">
                {rules.map((r, i) => {
                  const a = ACTIONS[r.action as Action] || ACTIONS.drop;
                  const disabled = !r.enabled;
                  return (
                    <div
                      key={r.id}
                      draggable={canWrite && !busy}
                      onDragStart={(e) => onDragStart(e, i)}
                      onDragOver={onDragOver}
                      onDrop={() => onDrop(i)}
                      onDragEnd={onDragEnd}
                      className={`flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3 flex-wrap bg-gray-800/60 rounded-lg px-3 py-2 transition-opacity ${disabled ? 'opacity-50' : ''} ${dragIndex === i ? 'opacity-30' : ''} ${canWrite ? 'cursor-grab active:cursor-grabbing' : ''}`}
                    >
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        {canWrite && <GripVertical className="w-4 h-4 text-gray-600 shrink-0" aria-hidden="true" />}
                        <span className="text-gray-600 text-xs w-5 text-right select-none shrink-0">{i + 1}</span>
                        {canWrite && (
                          <div className="flex flex-col shrink-0">
                            <IconButton
                              icon={ArrowUp}
                              onClick={() => moveRule(i, 'up')}
                              disabled={i === 0 || busy}
                              label="Mover regra para cima"
                              variant="custom"
                              className="text-gray-500 hover:text-gray-200 disabled:opacity-20"
                            />
                            <IconButton
                              icon={ArrowDown}
                              onClick={() => moveRule(i, 'down')}
                              disabled={i === rules.length - 1 || busy}
                              label="Mover regra para baixo"
                              variant="custom"
                              className="text-gray-500 hover:text-gray-200 disabled:opacity-20"
                            />
                          </div>
                        )}
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border shrink-0 ${a.ring} ${a.color}`}><a.Icon className="w-3 h-3" />{a.label}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-gray-300 text-sm truncate">{describe(r)}</span>
                            {disabled && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border border-gray-600 bg-gray-700/40 text-gray-400 shrink-0">
                                Desativada
                              </span>
                            )}
                          </div>
                          {r.description && <p className="text-gray-500 text-xs truncate">{r.description}</p>}
                        </div>
                      </div>
                      {canWrite && (
                        <div className="flex justify-end gap-1 sm:justify-start shrink-0">
                          <IconButton
                            icon={r.enabled ? Power : PowerOff}
                            onClick={() => toggleRule(r)}
                            label={r.enabled ? 'Desativar regra' : 'Ativar regra'}
                            variant={r.enabled ? 'default' : 'custom'}
                            className={r.enabled ? '' : 'text-yellow-500 hover:text-yellow-400'}
                          />
                          <IconButton icon={Pencil} onClick={() => openEdit(r)} label="Editar regra" />
                          <IconButton icon={Trash2} onClick={() => delRule(r)} label="Excluir regra" variant="danger" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>

          {/* WAN steering */}
          <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Direcionamento por WAN</span></span>}>
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
          </Panel>

          {/* Blocklist */}
          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">Destinos bloqueados</span></span>}>
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
          </Panel>

          {/* Blocked hosts (read-only) */}
          <Panel title={<span className="flex items-center gap-2"><ShieldOff className="w-4 h-4 text-orange-400" /><span className="text-white font-semibold">Hosts bloqueados</span></span>}>
            <p className="text-gray-500 text-xs mb-3">Bloqueie/desbloqueie na página <span className="text-gray-300">Hosts</span> (mantém o inventário em sincronia).</p>
            <div className="flex flex-wrap gap-2">
              {managed.blocked_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host bloqueado.</span>}
              {managed.blocked_hosts.map((ip) => (<span key={ip} className="px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{ip}</span>))}
            </div>
          </Panel>
        </div>
      ) : activeTab === 'portforward' ? (
        <PortForwarding ifaces={ifaces} canWrite={canWrite} onMsg={setMsg} />
      ) : activeTab === 'ruleset' ? (
        <Panel className="p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500"><Terminal className="w-3.5 h-3.5" /><span className="font-mono">nft list ruleset</span></div>
          {ruleset.trim() ? <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre> : <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>}
        </Panel>
      ) : (
        <>
          {/* I-1: Restore (`nft -f`) reloads everything the snapshot
              captured — WAN steering, bloqueios, encaminhamentos de porta,
              as chains estruturais — but suas regras personalizadas (aba
              "Regras") continuam vindo do banco de dados, não do snapshot:
              logo após restaurar, elas são reaplicadas por cima de qualquer
              coisa que o snapshot tinha em user_rules. Um "Restaurar" não
              desfaz uma alteração feita nas suas regras desde o snapshot —
              só nos outros elementos do firewall. */}
          <p className="text-gray-500 text-xs">
            Restaurar um snapshot recarrega direcionamento por WAN, destinos bloqueados, encaminhamentos de porta e as chains internas exatamente como estavam.
            As suas regras personalizadas (aba "Regras") não fazem parte do snapshot — elas continuam vindo do banco de dados e são reaplicadas por cima logo em seguida.
          </p>
          <Panel>
          {backups.length === 0 ? (
            <div className="text-center py-12"><Download className="w-12 h-12 text-gray-700 mx-auto mb-3" /><p className="text-gray-400">Nenhum snapshot disponível</p></div>
          ) : (
            <>
              {/* Mobile: stacked cards (< sm) */}
              <div className="sm:hidden space-y-2">
                {backups.map((b) => (
                  <div key={b.id} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-white font-medium truncate">{b.label}</div>
                      </div>
                      {canWrite && (
                        <IconButton
                          icon={RotateCcw}
                          onClick={() => handleRollback(b)}
                          disabled={busy}
                          label="Restaurar"
                          className="shrink-0"
                        />
                      )}
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">Tamanho</dt>
                      <dd className="text-gray-400 font-mono">{(b.rules.length / 1024).toFixed(1)} KB</dd>
                      <dt className="text-gray-500">Data</dt>
                      <dd className="text-gray-400 font-mono">{new Date(b.created_at).toLocaleString()}</dd>
                    </dl>
                  </div>
                ))}
              </div>

              {/* Desktop: table (>= sm) */}
              <div className="hidden sm:block overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="text-left text-gray-500 border-b border-gray-800"><th className="pb-3 pr-4 font-medium">Label</th><th className="pb-3 pr-4 font-medium">Tamanho</th><th className="pb-3 pr-4 font-medium">Data</th>{canWrite && <th className="pb-3 font-medium">Ações</th>}</tr></thead>
                  <tbody>
                    {backups.map((b) => (
                      <tr key={b.id} className="table-row">
                        <td className="py-3 pr-4 text-white">{b.label}</td>
                        <td className="py-3 pr-4 text-gray-400">{(b.rules.length / 1024).toFixed(1)} KB</td>
                        <td className="py-3 pr-4 text-gray-400">{new Date(b.created_at).toLocaleString()}</td>
                        {canWrite && (
                          <td className="py-3">
                            <IconButton
                              icon={RotateCcw}
                              onClick={() => handleRollback(b)}
                              disabled={busy}
                              label="Restaurar"
                            />
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          </Panel>
        </>
      )}

      {/* Rule modal */}
      <Modal
        open={modal.open}
        onClose={closeModal}
        title={modal.id ? 'Editar regra' : 'Nova regra'}
        size="md"
        className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
      >
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

              <div>
                <label className="label">Descrição (por que essa regra existe)</label>
                <input
                  className="input w-full"
                  placeholder="ex.: libera VPN do parceiro X"
                  maxLength={500}
                  value={modal.description}
                  onChange={(e) => setModal({ ...modal, description: e.target.value })}
                />
              </div>

              <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
                <p className="text-xs text-gray-400 mb-1">
                  <span className={ACTIONS[modal.action].color}>{ACTIONS[modal.action].label}</span>{' '}
                  {describe(modal)}
                </p>
                <p className="font-mono text-[11px] text-gray-500 break-all">{previewNft(modal)}</p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
              <button onClick={saveRule} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
              <button onClick={closeModal} className="btn-secondary flex-1">Cancelar</button>
            </div>
      </Modal>
    </div>
  );
}
