import { useEffect, useState } from 'react';
import type { DragEvent } from 'react';
import {
  Plus, Pencil, Trash2, Check, Ban, Slash, GripVertical, Power, PowerOff,
  Layers, CornerDownRight, ShieldAlert, RefreshCw, Lock, X, AlertTriangle,
} from 'lucide-react';
import client from '../api/client';
import Modal from './ui/Modal';
import IconButton from './ui/IconButton';
import { useAuth } from '../context/AuthContext';
import { isSystemGroup, KIND_BLOCKED_HOSTS, KIND_BLOCKLIST } from '../lib/blockGroups';
import type {
  FirewallGroup, FirewallGroupsData, FirewallRule, FirewallRulesData,
  GroupFallthrough, LastApply, NetHost, NftChainRule, NftManaged,
} from '../types';

interface Props {
  ifaces: string[];
  canWrite: boolean;
  onMsg: (m: string) => void;
}

export type Action = 'accept' | 'drop' | 'reject';

// The labels are the nftables keywords themselves, never translated: what
// the admin reads here is what they will find in `nft list ruleset`, with no
// panel-only vocabulary in between. `hint` carries the meaning in plain
// Portuguese for the rule form, where someone is choosing rather than
// reading. Same reasoning as rendering rule conditions in raw nft syntax
// (design spec §7.2.1).
export const ACTIONS: Record<Action, { label: string; hint: string; color: string; ring: string; Icon: typeof Check }> = {
  accept: { label: 'accept', hint: 'deixa passar', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10', Icon: Check },
  drop: { label: 'drop', hint: 'descarta em silêncio', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10', Icon: Ban },
  reject: { label: 'reject', hint: 'recusa e avisa a origem', color: 'text-orange-400', ring: 'border-orange-500 bg-orange-500/10', Icon: Slash },
};

// "E o que sobrar?" is the group's own verdict for traffic that entered it
// and that none of its rules decided. The three values are nft keywords too
// (`continue` really is one), so they are not translated either — the short
// Portuguese sentence beside each one carries the meaning.
const FALLTHROUGH: Record<GroupFallthrough, { hint: string; color: string; ring: string }> = {
  continue: { hint: 'não decide nada; a avaliação segue adiante', color: 'text-gray-300', ring: 'border-gray-600 bg-gray-700/30' },
  accept: { hint: 'deixa passar tudo o que sobrou', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10' },
  drop: { hint: 'descarta em silêncio tudo o que sobrou', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10' },
};

/**
 * SYSTEM_KINDS descreve os dois grupos que o LinkGuard mantém (spec §2.1).
 *
 * `lines` são as linhas que o kind põe na chain forward, na mesma ordem em
 * que o backend as emite (systemGroupForwardRules, internal/nftables/
 * groups.go): o que se lê aqui é o que se acha no `nft list chain inet
 * linkguard forward`, sem um segundo dicionário no meio — mesma disciplina
 * das expressões das regras.
 *
 * `members` é o rótulo do conteúdo: um grupo do sistema não tem regras, tem
 * membros de um named set.
 */
const SYSTEM_KINDS: Record<string, {
  what: string;
  lines: string[];
  member: [string, string];
  empty: string;
}> = {
  [KIND_BLOCKED_HOSTS]: {
    what: 'Qualquer tráfego de ou para estes hosts é descartado. Este grupo não tem condição de entrada nem regras: a lista de membros é o próprio conteúdo.',
    lines: ['ip saddr @blocked_hosts counter drop', 'ip daddr @blocked_hosts counter drop'],
    member: ['host', 'hosts'],
    empty: 'Nenhum host bloqueado.',
  },
  [KIND_BLOCKLIST]: {
    what: 'Qualquer tráfego de ou para estes destinos é descartado — a faixa vale como origem e como destino. Este grupo não tem condição de entrada nem regras: a lista de membros é o próprio conteúdo.',
    lines: ['ip daddr @blocklist counter drop', 'ip saddr @blocklist counter drop'],
    member: ['faixa', 'faixas'],
    empty: 'Nenhum destino bloqueado.',
  },
};

type Unit = 'bytes' | 'bits';

const emptyRuleModal = {
  open: false, id: '', groupId: '', groupName: '', action: 'drop' as Action,
  iif: '', oif: '', saddr: '', daddr: '', proto: '', dport: '', description: '',
};

const emptyGroupModal = {
  open: false, id: '', name: '', cond_saddr: '', cond_daddr: '', cond_iif: '',
  fallthrough: 'continue' as GroupFallthrough, chain_name: '',
};

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

// previewNft renders exactly the tokens the backend will build for this
// rule, so the form shows the line that will land in the chain — same
// vocabulary as the "quando a regra casa" column.
function previewNft(m: typeof emptyRuleModal): string {
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

// jumpLine is the line the group puts in the forward chain — the entry
// condition followed by `counter jump <chain>`. Field order matches the
// backend's groupJumpTokens so the preview is the real line, not a
// paraphrase of it.
function jumpLine(g: { cond_iif: string; cond_saddr: string; cond_daddr: string; chain_name: string }): string {
  const t: string[] = [];
  if (g.cond_iif) t.push('iifname', g.cond_iif);
  if (g.cond_saddr) t.push('ip saddr', g.cond_saddr);
  if (g.cond_daddr) t.push('ip daddr', g.cond_daddr);
  t.push('counter', 'jump', g.chain_name || 'grp_…');
  return t.join(' ');
}

function describeCondition(g: { cond_iif: string; cond_saddr: string; cond_daddr: string }): string {
  const parts: string[] = [];
  if (g.cond_iif) parts.push(`entrada ${g.cond_iif}`);
  if (g.cond_saddr) parts.push(`origem ${g.cond_saddr}`);
  if (g.cond_daddr) parts.push(`destino ${g.cond_daddr}`);
  return parts.length ? parts.join(' · ') : 'todo o tráfego que atravessa o firewall';
}

function moveItem<T>(arr: T[], from: number, to: number): T[] {
  const next = arr.slice();
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
}

function formatCount(bytes: number, unit: Unit): string {
  const value = unit === 'bits' ? bytes * 8 : bytes;
  const suffixes = unit === 'bits' ? ['b', 'Kb', 'Mb', 'Gb', 'Tb'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = value;
  let i = 0;
  while (v >= 1000 && i < suffixes.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${suffixes[i]}`;
}

// ruleAction derives the badge from the raw nft expression for a line the
// panel has no DB row for (the group's own verdict). Same palette as
// ACTIONS, same untranslated keywords.
function ruleAction(expr: string): Action {
  if (/\baccept$/.test(expr)) return 'accept';
  if (/\breject/.test(expr)) return 'reject';
  return 'drop';
}

/**
 * splitGroupRules separates what the merged chain carries.
 *
 * The admin's rules each have a stable DB `id`. The lines at the END with
 * no id are live-only: chiefly the group's own "e o que sobrar" verdict,
 * which is the group's `fallthrough` field and NOT a row in firewall_rules
 * — it must never grow an edit or delete button. Anything else without an
 * id is a divergence between the DB and the live chain, and is shown (never
 * hidden) but likewise not editable.
 *
 * This is why editability is decided by the presence of `id` and never by
 * `managed === false`: the verdict line comes back with managed=false, just
 * like a real rule of the admin's.
 */
function splitGroupRules(g: FirewallGroup): { rules: NftChainRule[]; extras: NftChainRule[]; fall?: NftChainRule } {
  const all = g.rules?.rules ?? [];
  let end = all.length;
  while (end > 0 && !all[end - 1].id) end--;
  const rules = all.slice(0, end);
  const tail = all.slice(end);
  const fall = g.fallthrough !== 'continue' && tail.length > 0 ? tail[tail.length - 1] : undefined;
  const extras = fall ? tail.slice(0, -1) : tail;
  return { rules, extras, fall };
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } }; message?: string };
  return ax?.response?.data?.error || ax?.message || 'falha na operação';
}

/**
 * FirewallGroups is the "grupos de regras" screen (design spec §7): an
 * INDEX on the left and the DETAIL of the selected group on the right.
 * Nothing expands or collapses — the screen never changes height under the
 * cursor, which was the origin of the "confuso" verdict on the accordion
 * proposal that got rejected.
 *
 * Two things the code below is deliberate about:
 *
 *  - Counters. has_counter=false renders "—", never "0": not measured and
 *    measured-zero are different states, for the group's jump and for every
 *    rule alike (§7.3).
 *  - Rule position is GLOBAL, not per group. /rules/reorder wants every
 *    rule of every group and refuses a partial list, so reordering inside a
 *    group rebuilds the whole list, keeping every other group's rules in
 *    the exact slots they already occupied.
 */
export default function FirewallGroups({ ifaces, canWrite, onMsg }: Props) {
  const { can } = useAuth();
  // Bloquear/desbloquear host é permissão da tela de Hosts (hosts.block), não
  // de firewall.write: o bloqueio por MAC mora no inventário, e é de lá que a
  // API o aplica ao set. Quem pode mexer no firewall mas não nos hosts vê a
  // lista de membros e nenhum botão que fingiria funcionar.
  const canBlockHosts = can('hosts.block');
  const canReadHosts = can('hosts.read');
  const [groups, setGroups] = useState<FirewallGroup[]>([]);
  // allRules is the flat, globally ordered list behind /rules/reorder. The
  // groups payload alone cannot stand in for it: its rules carry no
  // position, so there is no way to know where a group's rules sit among
  // the others.
  const [allRules, setAllRules] = useState<FirewallRule[]>([]);
  // managed traz os membros dos named sets — o conteúdo dos grupos do
  // sistema. Eles não vêm em `rules` (um grupo do sistema não tem chain):
  // /api/nftables/managed é a leitura do set vivo, os mesmos endpoints que a
  // aba antiga usava.
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  // hosts é o inventário, só para dar nome e MAC ao IP que está no set — e
  // porque desbloquear exige o MAC. null = não consultado ou sem permissão,
  // que é diferente de "inventário vazio".
  const [hosts, setHosts] = useState<NetHost[] | null>(null);
  const [applyStatus, setApplyStatus] = useState<LastApply | undefined>(undefined);
  const [selectedId, setSelectedId] = useState<string>('');
  const [unit, setUnit] = useState<Unit>('bytes');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [dragGroup, setDragGroup] = useState<number | null>(null);
  const [dragRule, setDragRule] = useState<number | null>(null);
  const [ruleModal, setRuleModal] = useState(emptyRuleModal);
  const [groupModal, setGroupModal] = useState(emptyGroupModal);
  const [newCidr, setNewCidr] = useState('');
  const [hostPicker, setHostPicker] = useState({ open: false, filter: '' });

  const load = async () => {
    try {
      const [gr, rl, mg] = await Promise.all([
        client.get<FirewallGroupsData>('/api/nftables/groups'),
        client.get<FirewallRulesData>('/api/nftables/rules'),
        client.get<NftManaged>('/api/nftables/managed'),
      ]);
      setGroups(gr.data?.groups ?? []);
      setApplyStatus(gr.data?.apply_status ?? undefined);
      setAllRules(rl.data?.rules ?? []);
      setManaged(mg.data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
    } catch (e) {
      onMsg('Erro: ' + errMsg(e));
    } finally {
      setLoading(false);
    }
    await loadHosts();
  };

  // Inventário: melhor esforço e à parte, porque exige outra permissão
  // (hosts.read). Falhar aqui não pode derrubar a tela de grupos.
  const loadHosts = async () => {
    if (!canReadHosts) { setHosts(null); return; }
    try {
      const hs = await client.get<NetHost[]>('/api/hosts');
      setHosts(hs.data ?? []);
    } catch {
      setHosts(null);
    }
  };

  useEffect(() => { load(); }, []);
  // As permissões chegam depois da primeira renderização (/api/auth/me é
  // assíncrono). Sem este efeito, numa navegação direta para esta aba o
  // inventário nunca seria lido e a lista de hosts bloqueados apareceria sem
  // nome, sem MAC e sem como desbloquear.
  useEffect(() => { loadHosts(); }, [canReadHosts]);

  const selected = groups.find((g) => g.id === selectedId) ?? groups[0];

  // ruleById lets a merged chain line find the DB row behind it — the action
  // keyword comes from there when it exists, instead of being guessed off
  // the expression (a disabled rule whose fields the backend could not
  // render falls back to its description as "expression", and guessing on
  // that would print an action the rule does not have).
  const ruleById = new Map(allRules.map((r) => [r.id, r]));
  // noteOf devolve o que o ADMIN escreveu na regra, não a frase que o
  // backend gera a partir da expressão. MergeUserRules preenche
  // ChainRule.Description com describeUserRuleExpression() — útil na Visão
  // geral, onde não há colunas —, mas aqui isso só repetiria "Ação" e "Quando
  // a regra casa" ao lado delas, e enterraria a anotação que dá o PORQUÊ da
  // regra ("libera VPN do parceiro X"), que é justamente o que falta quando
  // se lê um firewall meses depois (spec §4.1). A linha de "e o que sobrar"
  // não tem id e continua caindo na descrição gerada, que ali é a certa.
  const noteOf = (r: NftChainRule): string => {
    const db = r.id ? ruleById.get(r.id) : undefined;
    return db ? db.description : r.description;
  };

  const actionOf = (r: NftChainRule): Action => {
    const db = r.id ? ruleById.get(r.id)?.action : undefined;
    if (db === 'accept' || db === 'drop' || db === 'reject') return db;
    return ruleAction(r.expression);
  };

  // run reports whether the call actually succeeded, so a form only closes
  // when the server took it: the backend refuses IPv6, bad CIDRs and
  // anything `nft -c` rejects, and closing on failure would throw away what
  // the admin typed along with the chance to fix it.
  const run = async (fn: () => Promise<unknown>, ok: string): Promise<boolean> => {
    setBusy(true);
    onMsg('');
    try {
      await fn();
      onMsg(ok);
      await load();
      return true;
    } catch (e) {
      onMsg('Erro: ' + errMsg(e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  // ─── Grupos ────────────────────────────────────────────────────────────
  const openNewGroup = () => setGroupModal({ ...emptyGroupModal, open: true });
  const openEditGroup = (g: FirewallGroup) => setGroupModal({
    open: true, id: g.id, name: g.name, cond_saddr: g.cond_saddr, cond_daddr: g.cond_daddr,
    cond_iif: g.cond_iif, fallthrough: g.fallthrough || 'continue', chain_name: g.chain_name,
  });
  const closeGroupModal = () => setGroupModal((m) => ({ ...m, open: false }));
  const saveGroup = () => {
    const payload = {
      name: groupModal.name.trim(), cond_saddr: groupModal.cond_saddr.trim(),
      cond_daddr: groupModal.cond_daddr.trim(), cond_iif: groupModal.cond_iif.trim(),
      fallthrough: groupModal.fallthrough,
    };
    const req = groupModal.id
      ? client.put('/api/nftables/groups', { id: groupModal.id, ...payload })
      : client.post<FirewallGroup>('/api/nftables/groups', payload);
    run(async () => {
      const res = await req;
      // Selecting the brand-new group is the natural next move: the admin
      // created it to put rules in it.
      const created = (res.data as FirewallGroup | undefined)?.id;
      if (!groupModal.id && created) setSelectedId(created);
    }, groupModal.id ? 'Grupo atualizado.' : 'Grupo criado.').then((ok) => { if (ok) closeGroupModal(); });
  };
  // A mensagem diz o que continua guardado, e um grupo do sistema não guarda
  // regras: guarda os membros do set (é literalmente o que o nft mostra —
  // as linhas somem da forward, o set fica intacto).
  const toggleGroup = (g: FirewallGroup) => run(
    () => client.post('/api/nftables/groups/toggle', { id: g.id, enabled: !g.enabled }),
    g.enabled
      ? (isSystemGroup(g.kind) ? 'Bloqueio desligado — os membros continuam guardados.' : 'Grupo desligado — as regras continuam guardadas.')
      : (isSystemGroup(g.kind) ? 'Bloqueio ligado.' : 'Grupo ligado.'),
  );
  const removeGroup = (g: FirewallGroup) => {
    const n = splitGroupRules(g).rules.length;
    const detail = n === 0 ? '' : ` As ${n} regra${n === 1 ? '' : 's'} dentro dele ${n === 1 ? 'será apagada' : 'serão apagadas'} junto.`;
    if (!confirm(`Remover o grupo "${g.name}"?${detail}`)) return;
    run(() => client.delete('/api/nftables/groups', { data: { id: g.id } }), 'Grupo removido.');
  };

  // ─── Membros dos grupos do sistema ─────────────────────────────────────
  // O conteúdo de um grupo do sistema é a lista de membros do named set, não
  // regras: adicionar e remover continuam nos endpoints que já existiam.
  const membersOf = (g: FirewallGroup): string[] => {
    if (g.kind === KIND_BLOCKED_HOSTS) return managed.blocked_hosts;
    if (g.kind === KIND_BLOCKLIST) return managed.blocklist;
    return [];
  };
  const hostByIP = new Map((hosts ?? []).map((h) => [h.ip, h]));

  // adminGroupsAbove devolve os grupos do admin LIGADOS que estão antes da
  // posição `i` na lista — a condição do aviso da spec §2.2. `groups` já vem
  // ordenado por position, e é essa mesma ordem que a forward tem.
  const adminGroupsAbove = (i: number): string[] =>
    groups.slice(0, i).filter((g) => !isSystemGroup(g.kind) && g.enabled).map((g) => g.name);

  const addCidr = () => {
    const cidr = newCidr.trim();
    if (!cidr) return;
    run(() => client.post('/api/nftables/blocklist', { cidr }), 'Destino bloqueado.')
      .then((ok) => { if (ok) setNewCidr(''); });
  };
  const delCidr = (cidr: string) => {
    if (!confirm(`Desbloquear o destino ${cidr}?`)) return;
    run(() => client.delete('/api/nftables/blocklist', { data: { cidr } }), 'Destino desbloqueado.');
  };
  // Host bloqueado é identificado pelo MAC (o inventário é a fonte de
  // verdade; o IP é o que vai para o set) — daí a ida ao endpoint de hosts em
  // vez de mexer no set direto, que deixaria o inventário mentindo.
  const blockHost = (h: NetHost) => {
    run(() => client.post('/api/hosts/block', { mac: h.mac, blocked: true }), 'Host bloqueado.')
      .then((ok) => { if (ok) setHostPicker({ open: false, filter: '' }); });
  };
  const unblockHost = (h: NetHost) => {
    if (!confirm(`Desbloquear o host ${h.alias || h.hostname || h.ip}?`)) return;
    run(() => client.post('/api/hosts/block', { mac: h.mac, blocked: false }), 'Host desbloqueado.');
  };

  // Reordering, both here and in the rules table, is optimistic with an
  // explicit rollback: the server is the only authority on order, and a
  // screen left showing an order it refused would be a screen lying about
  // which rule wins.
  const reorderGroups = (next: FirewallGroup[]) => {
    const previous = groups;
    setGroups(next);
    setBusy(true);
    onMsg('');
    client.post('/api/nftables/groups/reorder', { ids: next.map((g) => g.id) })
      .then(() => load())
      .catch((e) => { setGroups(previous); onMsg('Erro: ' + errMsg(e)); })
      .finally(() => setBusy(false));
  };

  // I-6 (Fase B): Firefox will not start an HTML5 drag session unless
  // dataTransfer actually carries data — without setData, `dragstart` fires
  // but `drop` never does, so the whole reorder silently dies in Firefox.
  // The value is not read back; setting it is what matters.
  const onGroupDragStart = (e: DragEvent, i: number) => {
    if (!canWrite) return;
    e.dataTransfer.setData('text/plain', String(i));
    e.dataTransfer.effectAllowed = 'move';
    setDragGroup(i);
  };
  const onGroupDrop = (i: number) => {
    if (dragGroup === null || dragGroup === i) { setDragGroup(null); return; }
    reorderGroups(moveItem(groups, dragGroup, i));
    setDragGroup(null);
  };

  // ─── Regras ────────────────────────────────────────────────────────────
  const openNewRule = (g: FirewallGroup) => setRuleModal({ ...emptyRuleModal, open: true, groupId: g.id, groupName: g.name });
  const openEditRule = (g: FirewallGroup, r: NftChainRule) => {
    const row = allRules.find((x) => x.id === r.id);
    if (!row) { onMsg('Erro: essa regra não está mais no banco. Atualize a tela.'); return; }
    setRuleModal({
      open: true, id: row.id, groupId: g.id, groupName: g.name,
      action: (row.action as Action) || 'drop', iif: row.iif, oif: row.oif,
      saddr: row.saddr, daddr: row.daddr, proto: row.proto, dport: row.dport,
      description: row.description,
    });
  };
  const closeRuleModal = () => setRuleModal((m) => ({ ...m, open: false }));
  const saveRule = () => {
    const payload = {
      group_id: ruleModal.groupId, action: ruleModal.action, iif: ruleModal.iif, oif: ruleModal.oif,
      saddr: ruleModal.saddr, daddr: ruleModal.daddr, proto: ruleModal.proto,
      dport: ruleModal.dport, description: ruleModal.description,
    };
    const req = ruleModal.id
      ? client.put('/api/nftables/rules', { id: ruleModal.id, ...payload })
      : client.post('/api/nftables/rules', payload);
    run(() => req, ruleModal.id ? 'Regra atualizada.' : 'Regra criada.').then((ok) => { if (ok) closeRuleModal(); });
  };
  const removeRule = (r: NftChainRule) => {
    if (!r.id) return;
    if (!confirm(`Remover esta regra?\n\n${r.expression}`)) return;
    run(() => client.delete('/api/nftables/rules', { data: { id: r.id } }), 'Regra removida.');
  };
  const toggleRule = (r: NftChainRule) => {
    if (!r.id) return;
    run(() => client.post('/api/nftables/rules/toggle', { id: r.id, enabled: r.enabled === false }),
      r.enabled === false ? 'Regra ativada.' : 'Regra desativada.');
  };

  // reorderRules rebuilds the COMPLETE global list: it walks every rule in
  // its current global order and, at each slot that belongs to this group,
  // drops in the next id of the group's new order. Every other group's
  // rules keep the exact slots they already had, which is what makes a
  // per-group drag expressible in a global endpoint that refuses partial
  // lists.
  const reorderRules = (g: FirewallGroup, nextRows: NftChainRule[]) => {
    const ids = nextRows.map((r) => r.id).filter((id): id is string => !!id);
    const mine = allRules.filter((r) => r.group_id === g.id);
    if (mine.length !== ids.length) {
      onMsg('Erro: a tela está fora de sincronia com o banco. Atualize e tente de novo.');
      load();
      return;
    }
    let k = 0;
    const globalOrder = allRules.map((r) => (r.group_id === g.id ? ids[k++] : r.id));

    const previous = groups;
    const { extras, fall } = splitGroupRules(g);
    const merged = [...nextRows, ...extras, ...(fall ? [fall] : [])];
    setGroups(groups.map((x) => (x.id === g.id ? { ...x, rules: { ...x.rules, rules: merged } } : x)));
    setBusy(true);
    onMsg('');
    client.post('/api/nftables/rules/reorder', { ids: globalOrder })
      .then(() => load())
      .catch((e) => { setGroups(previous); onMsg('Erro: ' + errMsg(e)); })
      .finally(() => setBusy(false));
  };
  const onRuleDragStart = (e: DragEvent, i: number) => {
    if (!canWrite) return;
    e.dataTransfer.setData('text/plain', String(i));
    e.dataTransfer.effectAllowed = 'move';
    setDragRule(i);
  };
  const onRuleDrop = (g: FirewallGroup, rows: NftChainRule[], i: number) => {
    if (dragRule === null || dragRule === i) { setDragRule(null); return; }
    reorderRules(g, moveItem(rows, dragRule, i));
    setDragRule(null);
  };

  if (loading) {
    return <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando grupos...</div>;
  }

  const detail = selected ? splitGroupRules(selected) : undefined;
  // Grupo do sistema: outro detalhe inteiro. Não tem condição de entrada,
  // não tem tabela de regras e não tem "e o que sobrar" — mostrar esses
  // blocos vazios sugeriria que ele os tem e que estão neutros, o que é
  // diferente de não existirem (spec §2.1).
  const selectedSys = selected ? SYSTEM_KINDS[selected.kind] : undefined;
  const selectedIdx = selected ? groups.findIndex((g) => g.id === selected.id) : -1;
  const aboveSelected = selectedSys && selectedIdx > 0 ? adminGroupsAbove(selectedIdx) : [];
  const selectedMembers = selected && selectedSys ? membersOf(selected) : [];

  return (
    <div className="space-y-4">
      {/* apply_status: the last DB→nft reconcile can fail on its own — a
          boot-time one has no HTTP response for anyone to see — so this is a
          standing banner, not a transient message. */}
      {applyStatus && !applyStatus.ok && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          A última tentativa de aplicar seus grupos ao nftables falhou: {applyStatus.error || 'erro desconhecido'}. O que está em vigor pode não refletir o que está configurado aqui — confira a aba "Visão geral" antes de confiar nas regras abaixo.
        </div>
      )}

      {/* Ordem de avaliação: a faixa antiga dizia que os bloqueios eram
          avaliados antes dos grupos e "sempre venciam". Desde que eles
          viraram grupos reordenáveis (spec §2.2) isso deixou de ser verdade
          universal — e a ordem real agora está na lista abaixo, numerada. */}
      <div className="card flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-gray-400 text-xs flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
          <span>
            <span className="text-gray-300">A lista abaixo é a ordem real de avaliação, de cima para baixo.</span>{' '}
            O que a condição de entrada de um grupo não casar é pulado inteiro; os bloqueios do sistema nascem no topo e podem ser arrastados como qualquer outro item.
          </span>
        </p>
        <div className="flex items-center gap-2 text-xs shrink-0">
          <span className="text-gray-500">Contadores em:</span>
          <div className="inline-flex rounded-lg border border-gray-700 overflow-hidden">
            <button onClick={() => setUnit('bytes')} className={`px-3 py-1.5 ${unit === 'bytes' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}>bytes</button>
            <button onClick={() => setUnit('bits')} className={`px-3 py-1.5 border-l border-gray-700 ${unit === 'bits' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}>bits</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[17rem_minmax(0,1fr)] gap-4 items-start">
        {/* ─── Índice ─────────────────────────────────────────────────── */}
        <div className="card p-0 overflow-hidden">
          <div className="flex items-center justify-between gap-2 px-3 py-2.5 border-b border-gray-800">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">
              {groups.length} grupo{groups.length === 1 ? '' : 's'}
            </span>
            <div className="flex items-center gap-1">
              <IconButton icon={RefreshCw} onClick={load} label="Atualizar grupos" className="min-w-[32px] min-h-[32px]" />
              {canWrite && (
                <button onClick={openNewGroup} className="btn-primary flex items-center gap-1.5 text-xs px-2.5 py-1.5">
                  <Plus className="w-3.5 h-3.5" /> Novo
                </button>
              )}
            </div>
          </div>

          {groups.length === 0 ? (
            <p className="text-gray-600 text-sm px-3 py-6 text-center">
              Nenhum grupo ainda.{canWrite && ' Clique em "Novo".'}
            </p>
          ) : (
            <ul className="divide-y divide-gray-800/70">
              {groups.map((g, i) => {
                const { rules } = splitGroupRules(g);
                const active = selected?.id === g.id;
                const notApplied = g.enabled && !g.applied;
                // O outro lado do par Enabled × Applied, que nenhum dos dois
                // rótulos cobria: desligado no banco e ainda vivo no
                // firewall. "desligado" sozinho afirmaria que o grupo não
                // vale nada enquanto o kernel ainda o avalia.
                const staleOff = !g.enabled && g.applied;
                const sys = SYSTEM_KINDS[g.kind];
                const n = sys ? membersOf(g).length : rules.length;
                const noun = sys
                  ? (n === 1 ? sys.member[0] : sys.member[1])
                  : `regra${n === 1 ? '' : 's'}`;
                // Aviso de ordem (spec §2.2): um bloqueio arrastado para
                // depois de um grupo LIGADO do admin pode nunca ver o pacote,
                // porque aquele grupo pode decidir antes. Grupo desligado não
                // põe linha na forward, então não entra na conta — seria
                // alarme falso.
                const above = sys ? adminGroupsAbove(i) : [];
                return (
                  <li
                    key={g.id}
                    draggable={canWrite && !busy}
                    onDragStart={(e) => onGroupDragStart(e, i)}
                    onDragOver={(e) => { if (dragGroup !== null) e.preventDefault(); }}
                    onDrop={() => onGroupDrop(i)}
                    onDragEnd={() => setDragGroup(null)}
                    className={`group relative ${dragGroup === i ? 'opacity-30' : ''}`}
                  >
                    <button
                      onClick={() => setSelectedId(g.id)}
                      className={`w-full text-left flex items-start gap-2 px-3 py-2.5 transition-colors ${active ? 'bg-blue-500/10' : 'hover:bg-gray-800/50'}`}
                    >
                      {/* O ⠿ só aparece no hover, para a lista ficar limpa
                          em repouso (spec §7.1). */}
                      <GripVertical
                        className={`w-3.5 h-3.5 mt-0.5 shrink-0 text-gray-600 transition-opacity ${canWrite ? 'opacity-0 group-hover:opacity-100 cursor-grab active:cursor-grabbing' : 'opacity-0'}`}
                        aria-hidden="true"
                      />
                      <span className="text-[11px] font-mono text-gray-600 mt-0.5 w-3 text-right shrink-0">{i + 1}</span>
                      <span
                        className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${staleOff || notApplied ? 'bg-yellow-400' : !g.enabled ? 'bg-gray-600' : 'bg-green-400'}`}
                        aria-hidden="true"
                      />
                      <span className="min-w-0 flex-1">
                        <span className={`flex items-center gap-1.5 text-sm ${active ? 'text-white font-medium' : 'text-gray-200'}`}>
                          <span className="truncate">{g.name}</span>
                          {sys && (
                            <Lock
                              className="w-3 h-3 shrink-0 text-gray-500"
                              aria-label="grupo do sistema"
                            />
                          )}
                        </span>
                        <span className="block text-[11px] text-gray-500 font-mono truncate">
                          {n} {noun} · {g.has_counter ? formatCount(g.bytes, unit) : '—'}
                        </span>
                        {!g.enabled && !staleOff && <span className="block text-[11px] text-gray-500">desligado</span>}
                        {staleOff && <span className="block text-[11px] text-yellow-500">desligado, ainda no firewall</span>}
                        {notApplied && <span className="block text-[11px] text-yellow-500">configurado, não aplicado</span>}
                        {above.length > 0 && g.enabled && (
                          <span className="mt-0.5 flex items-start gap-1 text-[11px] text-orange-400">
                            <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
                            <span>regras acima deste bloqueio podem liberar tráfego que ele descartaria</span>
                          </span>
                        )}
                      </span>
                    </button>
                    {active && <span className="absolute inset-y-0 left-0 w-0.5 bg-blue-500" aria-hidden="true" />}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* ─── Detalhe ────────────────────────────────────────────────── */}
        {!selected || !detail ? (
          <div className="card text-center py-16">
            <Layers className="w-10 h-10 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">Nenhum grupo para mostrar.</p>
            <p className="text-gray-600 text-xs mt-1">Um grupo junta regras sob uma condição de entrada e liga ou desliga todas de uma vez.</p>
          </div>
        ) : selectedSys ? (
          /* ─── Detalhe de um grupo do sistema (spec §4) ───────────────── */
          <div className="card space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-white font-semibold truncate">{selected.name}</h3>
                <p className="text-[11px] text-gray-600">Mantido pelo LinkGuard: não pode ser apagado nem renomeado. Pode ser ligado, desligado e reordenado.</p>
              </div>
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-300">
                  <Lock className="w-3 h-3" aria-hidden="true" /> do sistema
                </span>
                {!selected.enabled && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-400">
                    Desligado
                  </span>
                )}
                {selected.enabled && !selected.applied && (
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                    title="O bloqueio está ligado aqui, mas o firewall não confirma as linhas dele na chain forward — pode ser um erro ao aplicar; confira o aviso no topo."
                  >
                    Configurado, não aplicado
                  </span>
                )}
                {canWrite && (
                  <button
                    onClick={() => toggleGroup(selected)}
                    disabled={busy}
                    className="btn-secondary flex items-center gap-1.5 text-xs px-2.5 py-1.5 disabled:opacity-50"
                  >
                    {selected.enabled ? <><PowerOff className="w-3.5 h-3.5" /> Desligar</> : <><Power className="w-3.5 h-3.5" /> Ligar</>}
                  </button>
                )}
              </div>
            </div>

            {/* O que ele faz, as linhas exatas que ele põe na forward e
                quanto elas descartaram. */}
            <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2.5 space-y-1.5">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                <p className="text-sm text-gray-300 min-w-0">{selectedSys.what}</p>
                <div className="text-xs font-mono text-gray-400 shrink-0">
                  {selected.has_counter
                    ? <>descartou {selected.packets.toLocaleString('pt-BR')} pct · {formatCount(selected.bytes, unit)}</>
                    : <span className="text-gray-600">sem contador · —</span>}
                </div>
              </div>
              <div>
                {selectedSys.lines.map((line) => (
                  <p key={line} className="font-mono text-[11px] text-gray-600 break-words">{line}</p>
                ))}
              </div>
              {!selected.applied && (
                <p className={`text-[11px] ${selected.enabled ? 'text-yellow-500' : 'text-gray-500'}`}>
                  {selected.enabled
                    ? 'O firewall não confirma estas linhas na chain forward: neste momento nenhum membro abaixo está sendo bloqueado.'
                    : 'Grupo desligado: nenhum membro abaixo está sendo bloqueado. Eles continuam guardados para quando ele voltar.'}
                </p>
              )}
              {/* Aviso de ordem (spec §2.2): a flexibilidade de arrastar um
                  bloqueio para baixo não pode virar armadilha silenciosa. */}
              {selected.enabled && aboveSelected.length > 0 && (
                <p className="text-[11px] text-orange-400 flex items-start gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
                  <span>
                    Regras acima deste bloqueio podem liberar tráfego que ele descartaria:{' '}
                    <span className="text-orange-300">{aboveSelected.join(', ')}</span>{' '}
                    {aboveSelected.length === 1 ? 'é avaliado' : 'são avaliados'} antes dele.
                    {canWrite && ' Arraste-o para o topo da lista para voltar ao padrão.'}
                  </span>
                </p>
              )}
            </div>

            {/* Membros do named set — o conteúdo do grupo. Não há contador
                por membro: o nft conta as linhas de drop do grupo (acima),
                não cada elemento do set, e inventar um número por membro
                seria dado falso. */}
            <div>
              <h4 className="text-[11px] uppercase tracking-wide text-gray-500 mb-2">
                {selectedMembers.length} {selectedMembers.length === 1 ? selectedSys.member[0] : selectedSys.member[1]}
              </h4>
              {selectedMembers.length === 0 ? (
                <p className="text-gray-600 text-sm py-2">{selectedSys.empty}</p>
              ) : (
                <ul className="rounded-lg border border-gray-800 divide-y divide-gray-800/70">
                  {selectedMembers.map((m) => {
                    const h = selected.kind === KIND_BLOCKED_HOSTS ? hostByIP.get(m) : undefined;
                    return (
                      <li key={m} className="flex items-center gap-3 px-3 py-2">
                        <span className="font-mono text-sm text-gray-200 shrink-0">{m}</span>
                        {selected.kind === KIND_BLOCKED_HOSTS && (
                          <span className="text-xs text-gray-500 truncate min-w-0 flex-1">
                            {h ? (
                              <>
                                {(h.alias || h.hostname) && <span className="text-gray-400">{h.alias || h.hostname} </span>}
                                <span className="font-mono text-gray-600">{h.mac}</span>
                              </>
                            ) : hosts === null ? '' : (
                              <span className="text-gray-600">sem host correspondente no inventário</span>
                            )}
                          </span>
                        )}
                        <span className="flex-1" />
                        {selected.kind === KIND_BLOCKLIST && canWrite && (
                          <IconButton icon={X} onClick={() => delCidr(m)} disabled={busy} label="Desbloquear destino" variant="danger" className="min-w-[32px] min-h-[32px]" />
                        )}
                        {selected.kind === KIND_BLOCKED_HOSTS && canBlockHosts && (
                          h ? (
                            <IconButton icon={X} onClick={() => unblockHost(h)} disabled={busy} label="Desbloquear host" variant="danger" className="min-w-[32px] min-h-[32px]" />
                          ) : (
                            <span className="text-[10px] text-gray-600 text-right" title="O bloqueio de host é feito pelo MAC, no inventário. Este IP está no set sem host correspondente — desbloqueie pela página Hosts quando ele reaparecer.">
                              só pela página Hosts
                            </span>
                          )
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}

              {/* Adicionar membro: os mesmos endpoints de sempre. */}
              {selected.kind === KIND_BLOCKLIST && canWrite && (
                <div className="flex flex-col sm:flex-row gap-2 mt-3">
                  <input
                    className="input flex-1"
                    placeholder="CIDR ou IP (ex.: 163.116.128.0/17)"
                    value={newCidr}
                    onChange={(e) => setNewCidr(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addCidr()}
                  />
                  <button onClick={addCidr} disabled={busy || !newCidr.trim()} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50">
                    <Plus className="w-4 h-4" /> Bloquear destino
                  </button>
                </div>
              )}
              {selected.kind === KIND_BLOCKED_HOSTS && (
                canBlockHosts && hosts !== null ? (
                  <button onClick={() => setHostPicker({ open: true, filter: '' })} disabled={busy} className="btn-secondary flex items-center gap-2 text-sm mt-3 disabled:opacity-50">
                    <Plus className="w-4 h-4" /> Bloquear host
                  </button>
                ) : (
                  <p className="text-[11px] text-gray-600 mt-3">
                    O bloqueio de host é feito pelo MAC, na página <span className="text-gray-400">Hosts</span> — é lá que a máquina é reconhecida pelo nome.
                  </p>
                )
              )}
            </div>
          </div>
        ) : (
          <div className="card space-y-4">
            {/* Cabeçalho: nome e ações do grupo */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-white font-semibold truncate">{selected.name}</h3>
                <p className="text-[11px] text-gray-600 font-mono truncate">chain {selected.chain_name}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                {!selected.enabled && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-400">
                    Desligado
                  </span>
                )}
                {selected.enabled && !selected.applied && (
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                    title="O grupo está ligado aqui, mas o firewall não confirma que o jump para a chain dele está em vigor — pode ser um erro ao aplicar; confira o aviso no topo."
                  >
                    Configurada, não aplicada
                  </span>
                )}
                {canWrite && (
                  <>
                    <button
                      onClick={() => toggleGroup(selected)}
                      disabled={busy}
                      className="btn-secondary flex items-center gap-1.5 text-xs px-2.5 py-1.5 disabled:opacity-50"
                    >
                      {selected.enabled ? <><PowerOff className="w-3.5 h-3.5" /> Desligar</> : <><Power className="w-3.5 h-3.5" /> Ligar</>}
                    </button>
                    <IconButton icon={Pencil} onClick={() => openEditGroup(selected)} disabled={busy} label="Editar grupo" />
                    <IconButton icon={Trash2} onClick={() => removeGroup(selected)} disabled={busy} label="Remover grupo" variant="danger" />
                  </>
                )}
              </div>
            </div>

            {/* Faixa da condição de entrada, com o contador do próprio jump:
                quanto tráfego de fato ENTROU no grupo — não a soma das
                regras (spec §7.3). */}
            <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="min-w-0 text-sm">
                  <span className="text-gray-500 text-xs uppercase tracking-wide mr-2">Quando</span>
                  <span className="text-gray-200">{describeCondition(selected)}</span>
                  <span className="text-gray-600 mx-2">·</span>
                  <span className="text-gray-500 text-xs uppercase tracking-wide mr-2">Onde</span>
                  <span className="text-gray-200">atravessando</span>
                </div>
                <div className="text-xs font-mono text-gray-400 shrink-0">
                  {selected.has_counter
                    ? <>entraram {selected.packets.toLocaleString('pt-BR')} pct · {formatCount(selected.bytes, unit)}</>
                    : <span className="text-gray-600">sem contador · —</span>}
                </div>
              </div>
              <p className="mt-1.5 text-[11px] font-mono text-gray-600 break-all">{jumpLine(selected)}</p>
              {/* Alcançabilidade é transitiva: se nada pula para a chain,
                  nada dentro dela está em vigor. Dizer isso uma vez aqui é
                  mais honesto — e muito menos ruidoso — do que carimbar
                  "Configurada, não aplicada" em cada regra de dentro, que
                  faria uma escolha deliberada do admin (desligar o grupo)
                  parecer uma falha. */}
              {!selected.applied && (
                <p className={`mt-1.5 text-[11px] ${selected.enabled ? 'text-yellow-500' : 'text-gray-500'}`}>
                  {selected.enabled
                    ? 'O firewall não confirma o jump para este grupo: nenhuma regra abaixo está em vigor.'
                    : 'Grupo desligado: nenhuma regra abaixo está em vigor. Elas continuam guardadas para quando ele voltar.'}
                </p>
              )}
            </div>

            {/* Tabela de regras: colunas alinhadas, e a coluna "quando a
                regra casa" em sintaxe nft crua — o que se lê aqui é o que
                se acha no `nft list` (spec §7.2). */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[46rem]">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800 text-[11px] uppercase tracking-wide">
                    <th className="pb-2 pr-2 font-medium w-10">#</th>
                    <th className="pb-2 pr-3 font-medium w-28">Ação</th>
                    <th className="pb-2 pr-3 font-medium">Quando a regra casa</th>
                    <th className="pb-2 pr-3 font-medium">Descrição</th>
                    <th className="pb-2 pr-3 font-medium text-right w-20">Pacotes</th>
                    <th className="pb-2 pr-3 font-medium text-right w-20">Tráfego</th>
                    {canWrite && <th className="pb-2 font-medium w-28 text-right">Ações</th>}
                  </tr>
                </thead>
                <tbody>
                  {detail.rules.length === 0 && detail.extras.length === 0 && (
                    <tr>
                      <td colSpan={canWrite ? 7 : 6} className="py-4 text-gray-600 text-sm">
                        Nenhuma regra neste grupo{selected.fallthrough === 'continue' ? ' — todo tráfego que entrar aqui segue adiante sem decisão.' : '.'}
                      </td>
                    </tr>
                  )}

                  {detail.rules.map((r, i) => {
                    const a = ACTIONS[actionOf(r)];
                    const disabled = r.enabled === false;
                    // Só é anomalia DA REGRA quando o grupo em volta está de
                    // fato em vigor; num grupo desligado (ou cujo jump o
                    // firewall não confirma) applied=false é a consequência
                    // esperada, já dita uma vez na faixa acima.
                    const notApplied = selected.applied && r.enabled === true && r.applied === false;
                    return (
                      <tr
                        key={r.id || `x-${i}`}
                        draggable={canWrite && !busy && !!r.id}
                        onDragStart={(e) => onRuleDragStart(e, i)}
                        onDragOver={(e) => { if (dragRule !== null) e.preventDefault(); }}
                        onDrop={() => onRuleDrop(selected, detail.rules, i)}
                        onDragEnd={() => setDragRule(null)}
                        className={`border-b border-gray-800/60 ${disabled ? 'opacity-50' : ''} ${dragRule === i ? 'opacity-30' : ''} ${notApplied ? 'bg-yellow-500/5' : ''}`}
                      >
                        <td className="py-2 pr-2 align-top">
                          <span className="flex items-center gap-1 text-gray-600 text-xs font-mono">
                            {canWrite && r.id && <GripVertical className="w-3.5 h-3.5 shrink-0 cursor-grab active:cursor-grabbing" aria-hidden="true" />}
                            {i + 1}
                          </span>
                        </td>
                        <td className="py-2 pr-3 align-top">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${a.ring} ${a.color}`}>
                            <a.Icon className="w-3 h-3" /><span className="font-mono">{a.label}</span>
                          </span>
                        </td>
                        <td className="py-2 pr-3 align-top font-mono text-[12px] text-gray-300 break-words">{r.expression}</td>
                        <td className="py-2 pr-3 align-top text-gray-400 text-xs">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className={noteOf(r) ? '' : 'text-gray-700'}>{noteOf(r) || '—'}</span>
                            {disabled && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border border-gray-600 bg-gray-700/40 text-gray-400">
                                Desativada
                              </span>
                            )}
                            {notApplied && (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                                title="Está ativada aqui, mas o firewall não confirma que ela está em vigor — pode ser um erro ao aplicar; confira o aviso no topo."
                              >
                                Configurada, não aplicada
                              </span>
                            )}
                          </span>
                        </td>
                        <td className="py-2 pr-3 align-top text-right font-mono text-xs text-gray-500">
                          {r.has_counter ? r.packets.toLocaleString('pt-BR') : '—'}
                        </td>
                        <td className="py-2 pr-3 align-top text-right font-mono text-xs text-gray-500">
                          {r.has_counter ? formatCount(r.bytes, unit) : '—'}
                        </td>
                        {canWrite && (
                          <td className="py-1 align-top">
                            {/* Editar e apagar dependem do ID, nunca de
                                managed=false: a linha do "e o que sobrar"
                                também chega com managed=false. */}
                            {r.id ? (
                              <div className="flex justify-end">
                                <IconButton
                                  icon={disabled ? PowerOff : Power}
                                  onClick={() => toggleRule(r)}
                                  disabled={busy}
                                  label={disabled ? 'Ativar regra' : 'Desativar regra'}
                                  variant={disabled ? 'custom' : 'default'}
                                  className={`min-w-[32px] min-h-[32px] ${disabled ? 'text-yellow-500 hover:text-yellow-400' : ''}`}
                                />
                                <IconButton icon={Pencil} onClick={() => openEditRule(selected, r)} disabled={busy} label="Editar regra" className="min-w-[32px] min-h-[32px]" />
                                <IconButton icon={Trash2} onClick={() => removeRule(r)} disabled={busy} label="Excluir regra" variant="danger" className="min-w-[32px] min-h-[32px]" />
                              </div>
                            ) : (
                              <span className="block text-right text-[10px] text-gray-600">não é sua regra</span>
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}

                  {/* Linhas vivas sem regra correspondente no banco — nunca
                      escondidas, mas também nunca editáveis daqui. */}
                  {detail.extras.map((r, i) => (
                    <tr key={`extra-${i}`} className="border-b border-gray-800/60">
                      <td className="py-2 pr-2 align-top text-gray-700 text-xs font-mono">·</td>
                      <td className="py-2 pr-3 align-top">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border border-yellow-500/30 bg-yellow-500/5 text-yellow-500">
                          fora do painel
                        </span>
                      </td>
                      <td className="py-2 pr-3 align-top font-mono text-[12px] text-gray-400 break-words">{r.expression}</td>
                      <td className="py-2 pr-3 align-top text-gray-500 text-xs">Está no firewall, mas não corresponde a nenhuma regra sua.</td>
                      <td className="py-2 pr-3 align-top text-right font-mono text-xs text-gray-500">{r.has_counter ? r.packets.toLocaleString('pt-BR') : '—'}</td>
                      <td className="py-2 pr-3 align-top text-right font-mono text-xs text-gray-500">{r.has_counter ? formatCount(r.bytes, unit) : '—'}</td>
                      {canWrite && <td />}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* "E o que sobrar": fecho do grupo, não uma regra. Vem do campo
                `fallthrough`; a linha viva (quando existe) só empresta os
                contadores. */}
            <div className={`rounded-lg border px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${FALLTHROUGH[selected.fallthrough]?.ring ?? FALLTHROUGH.continue.ring}`}>
              <div className="flex items-center gap-2 text-sm min-w-0">
                <CornerDownRight className="w-3.5 h-3.5 text-gray-500 shrink-0" aria-hidden="true" />
                <span className="text-gray-400 text-xs">E o que sobrar?</span>
                <span className={`font-mono text-xs font-medium ${FALLTHROUGH[selected.fallthrough]?.color ?? 'text-gray-300'}`}>
                  {selected.fallthrough || 'continue'}
                </span>
                <span className="text-gray-500 text-xs truncate">
                  {FALLTHROUGH[selected.fallthrough]?.hint ?? FALLTHROUGH.continue.hint}
                </span>
              </div>
              <div className="text-xs font-mono text-gray-500 shrink-0">
                {detail.fall?.has_counter
                  ? <>{detail.fall.packets.toLocaleString('pt-BR')} pct · {formatCount(detail.fall.bytes, unit)}</>
                  : '—'}
              </div>
            </div>

            {canWrite && (
              <button onClick={() => openNewRule(selected)} disabled={busy} className="btn-secondary flex items-center gap-2 text-sm disabled:opacity-50">
                <Plus className="w-4 h-4" /> Nova regra neste grupo
              </button>
            )}
          </div>
        )}
      </div>

      {/* ─── Modal do grupo ─────────────────────────────────────────────── */}
      <Modal
        open={groupModal.open}
        onClose={closeGroupModal}
        title={groupModal.id ? 'Editar grupo' : 'Novo grupo'}
        size="md"
        className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
      >
        <div className="p-6 space-y-4 overflow-y-auto">
          <div>
            <label className="label">Nome do grupo</label>
            <input
              className="input w-full"
              placeholder="ex.: Wi-Fi visitantes"
              maxLength={80}
              value={groupModal.name}
              onChange={(e) => setGroupModal({ ...groupModal, name: e.target.value })}
            />
          </div>

          <div>
            <p className="label mb-2">Quando entrar neste grupo (condição de entrada)</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="label">Interface de entrada</label>
                <select className="input w-full" value={groupModal.cond_iif} onChange={(e) => setGroupModal({ ...groupModal, cond_iif: e.target.value })}>
                  <option value="">Qualquer</option>
                  {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Origem (IP/CIDR)</label>
                <input className="input w-full" placeholder="qualquer" value={groupModal.cond_saddr} onChange={(e) => setGroupModal({ ...groupModal, cond_saddr: e.target.value })} />
              </div>
              <div>
                <label className="label">Destino (IP/CIDR)</label>
                <input className="input w-full" placeholder="qualquer" value={groupModal.cond_daddr} onChange={(e) => setGroupModal({ ...groupModal, cond_daddr: e.target.value })} />
              </div>
            </div>
            <p className="text-[11px] text-gray-600 mt-1.5">Sem condição, todo o tráfego que atravessa o firewall entra no grupo. Só IPv4 por enquanto.</p>
          </div>

          <div>
            <p className="label mb-2">E o que sobrar?</p>
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(FALLTHROUGH) as GroupFallthrough[]).map((f) => {
                const meta = FALLTHROUGH[f];
                const active = groupModal.fallthrough === f;
                return (
                  <button
                    key={f}
                    onClick={() => setGroupModal({ ...groupModal, fallthrough: f })}
                    className={`flex flex-col items-center gap-1 rounded-lg border p-3 transition ${active ? meta.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}
                  >
                    <span className={`text-xs font-mono ${active ? meta.color : 'text-gray-400'}`}>{f}</span>
                    <span className="text-[10px] text-gray-500 leading-tight text-center">{meta.hint}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
            <p className="text-xs text-gray-400 mb-1">Linha que este grupo põe na chain forward:</p>
            <p className="font-mono text-[11px] text-gray-500 break-all">{jumpLine(groupModal)}</p>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
          <button onClick={saveGroup} disabled={busy || !groupModal.name.trim()} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
          <button onClick={closeGroupModal} className="btn-secondary flex-1">Cancelar</button>
        </div>
      </Modal>

      {/* ─── Modal da regra ─────────────────────────────────────────────── */}
      <Modal
        open={ruleModal.open}
        onClose={closeRuleModal}
        title={ruleModal.id ? 'Editar regra' : `Nova regra em "${ruleModal.groupName}"`}
        size="md"
        className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
      >
        <div className="p-6 space-y-4 overflow-y-auto">
          <div>
            <label className="label mb-2 block">Ação</label>
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(ACTIONS) as Action[]).map((act) => {
                const a = ACTIONS[act];
                const active = ruleModal.action === act;
                return (
                  <button key={act} onClick={() => setRuleModal({ ...ruleModal, action: act })} className={`flex flex-col items-center gap-1 rounded-lg border p-3 transition ${active ? a.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}>
                    <a.Icon className={`w-5 h-5 ${active ? a.color : 'text-gray-400'}`} />
                    <span className={`text-xs font-mono ${active ? a.color : 'text-gray-400'}`}>{a.label}</span>
                    <span className="text-[10px] text-gray-500 leading-tight text-center">{a.hint}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">Interface de entrada</label>
              <select className="input w-full" value={ruleModal.iif} onChange={(e) => setRuleModal({ ...ruleModal, iif: e.target.value })}>
                <option value="">Qualquer</option>
                {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Interface de saída</label>
              <select className="input w-full" value={ruleModal.oif} onChange={(e) => setRuleModal({ ...ruleModal, oif: e.target.value })}>
                <option value="">Qualquer</option>
                {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Origem (IP/CIDR)</label>
              <input className="input w-full" placeholder="qualquer" value={ruleModal.saddr} onChange={(e) => setRuleModal({ ...ruleModal, saddr: e.target.value })} />
            </div>
            <div>
              <label className="label">Destino (IP/CIDR)</label>
              <input className="input w-full" placeholder="qualquer" value={ruleModal.daddr} onChange={(e) => setRuleModal({ ...ruleModal, daddr: e.target.value })} />
            </div>
            <div>
              <label className="label">Protocolo</label>
              <select className="input w-full" value={ruleModal.proto} onChange={(e) => setRuleModal({ ...ruleModal, proto: e.target.value })}>
                <option value="">Qualquer</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
              </select>
            </div>
            {(ruleModal.proto === 'tcp' || ruleModal.proto === 'udp') && (
              <div>
                <label className="label">Porta de destino</label>
                <input className="input w-full" placeholder="ex.: 443 ou 1000-2000" value={ruleModal.dport} onChange={(e) => setRuleModal({ ...ruleModal, dport: e.target.value })} />
              </div>
            )}
          </div>

          <div>
            <label className="label">Descrição (por que essa regra existe)</label>
            <input
              className="input w-full"
              placeholder="ex.: libera VPN do parceiro X"
              maxLength={500}
              value={ruleModal.description}
              onChange={(e) => setRuleModal({ ...ruleModal, description: e.target.value })}
            />
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
            <p className="text-xs text-gray-400 mb-1">
              <span className={`font-mono ${ACTIONS[ruleModal.action].color}`}>{ACTIONS[ruleModal.action].label}</span>{' '}
              {describe(ruleModal)}
            </p>
            <p className="font-mono text-[11px] text-gray-500 break-all">{previewNft(ruleModal)}</p>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
          <button onClick={saveRule} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
          <button onClick={closeRuleModal} className="btn-secondary flex-1">Cancelar</button>
        </div>
      </Modal>

      {/* ─── Escolher host para bloquear ────────────────────────────────── */}
      {/* O bloqueio é por MAC, e quem sabe o MAC é o inventário — por isso a
          escolha é uma lista de hosts conhecidos, e não um campo de IP livre
          que gravaria um bloqueio que o inventário não reconheceria. */}
      <Modal
        open={hostPicker.open}
        onClose={() => setHostPicker({ open: false, filter: '' })}
        title="Bloquear host"
        size="md"
        className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
      >
        <div className="p-6 space-y-3 overflow-y-auto">
          <input
            className="input w-full"
            placeholder="Filtrar por IP, MAC, apelido..."
            value={hostPicker.filter}
            onChange={(e) => setHostPicker({ ...hostPicker, filter: e.target.value })}
          />
          {(() => {
            const q = hostPicker.filter.trim().toLowerCase();
            const list = (hosts ?? [])
              .filter((h) => !h.blocked)
              .filter((h) => !q || [h.ip, h.mac, h.alias, h.hostname].some((v) => v?.toLowerCase().includes(q)));
            if (list.length === 0) {
              return <p className="text-gray-600 text-sm py-4 text-center">Nenhum host disponível{q ? ' para este filtro' : ''}.</p>;
            }
            return (
              <ul className="rounded-lg border border-gray-800 divide-y divide-gray-800/70 max-h-72 overflow-y-auto">
                {list.map((h) => (
                  <li key={h.mac || h.ip}>
                    <button
                      onClick={() => blockHost(h)}
                      disabled={busy}
                      className="w-full text-left px-3 py-2 hover:bg-gray-800/60 disabled:opacity-50 flex items-center gap-3"
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm text-gray-200 truncate">{h.alias || h.hostname || h.ip || h.mac}</span>
                        <span className="block text-[11px] text-gray-600 font-mono truncate">{h.ip || 'sem IP'} · {h.mac}</span>
                      </span>
                      <Ban className="w-4 h-4 text-gray-500 shrink-0" aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            );
          })()}
          <p className="text-[11px] text-gray-600">
            O host entra no set <span className="font-mono">@blocked_hosts</span> e fica marcado como bloqueado no inventário. Um host sem IP conhecido só passa a ser descartado quando aparecer na rede.
          </p>
        </div>
        <div className="px-6 py-4 border-t border-gray-800">
          <button onClick={() => setHostPicker({ open: false, filter: '' })} className="btn-secondary w-full">Fechar</button>
        </div>
      </Modal>
    </div>
  );
}
