import { useEffect, useState } from 'react';
import type { DragEvent } from 'react';
import {
  Plus, Pencil, Trash2, GripVertical, Power, PowerOff, Layers, CornerDownRight,
  ShieldAlert, Lock, AlertTriangle, DoorOpen,
} from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import IconButton from './ui/IconButton';
import { useAuth } from '../context/AuthContext';
import { adminGroupsAbove, isSystemGroup } from '../lib/blockGroups';
// As duas contas que erram em silêncio (o corte da chain e a tradução de ordem
// local → global) moram em lib/groupRules desde que ganharam asserção própria:
// aqui dentro nada as alcançava sem montar a tela inteira, e é a ordem de
// avaliação do firewall que elas decidem. Ver groupRules.check.ts.
import { globalReorder, mergeGroupRules, moveItem, splitGroupRules } from '../lib/groupRules';
// A contagem regressiva mora em lib/pendingWindow desde que ela passou a ser
// desenhada também pela faixa global do Layout (M-5): duas cópias divergiriam
// justamente no número que decide se ainda dá tempo de testar o SSH.
import { claimFullBanner } from '../lib/pendingWindow';
import { errMsg } from '../lib/apiError';
// A máquina do confirmar-ou-reverte inteira — o pendente, a âncora do relógio,
// a trava do backend refletida na tela e o `run` por onde passa TODA mutação.
// Ela saiu daqui ANTES de a tela ser fatiada, e nessa ordem de propósito: as
// peças visuais dependem de `busy`, de `locked` e de `run`, e cortá-las com a
// máquina ainda espalhada pelo meio significaria seis a oito props por peça.
// Agora é um objeto só, `cor`, que cada peça recebe inteiro.
import { useConfirmOrRevert } from '../lib/useConfirmOrRevert';
import ConfirmOrRevertBanner from './firewall/ConfirmOrRevertBanner';
import GroupList from './firewall/GroupList';
import GroupModal from './firewall/GroupModal';
import RuleModal from './firewall/RuleModal';
import SystemGroupMembers from './firewall/SystemGroupMembers';
import NftPreview, { groupPreviewBody } from './firewall/NftPreview';
import {
  ACTIONS, CONN_STATES, FALLTHROUGH, SCOPES, SYSTEM_KINDS,
  describeCondition, emptyGroupModal, emptyRuleModal, formatCount,
  groupConnState, groupScope, ruleAction,
} from './firewall/groupMeta';
import type { Action, Unit } from './firewall/groupMeta';
import type {
  FirewallApplyStatus, FirewallGroup, FirewallGroupsData, FirewallRule,
  FirewallRulesData, MsgLevel, NetHost, NftChainRule, NftManaged,
} from '../types';

interface Props {
  ifaces: string[];
  canWrite: boolean;
  // O tom é OPCIONAL: sem ele a faixa do pai continua decidindo como sempre
  // decidiu (vermelho quando o texto começa com "Erro", verde no resto). Ele
  // existe para a única mensagem daqui que não é nem uma coisa nem outra — a
  // reversão por prazo esgotado, que em verde diria ao operador que deu tudo
  // certo com uma mudança que acabou de ser desfeita.
  onMsg: (m: string, level?: MsgLevel) => void;
}

/**
 * FirewallGroups is the "grupos de regras" screen (design spec §7): an
 * INDEX on the left and the DETAIL of the selected group on the right.
 * Nothing expands or collapses — the screen never changes height under the
 * cursor, which was the origin of the "confuso" verdict on the accordion
 * proposal that got rejected.
 *
 * O que ficou AQUI depois do fatiamento: os dados da tela (grupos, regras,
 * membros dos sets, inventário), a ordem — que é a ordem de avaliação do
 * firewall — e o detalhe do grupo do admin, que é a tabela de regras. O
 * vocabulário está em firewall/groupMeta, a máquina dos 90 segundos em
 * lib/useConfirmOrRevert, e as quatro peças visuais em firewall/.
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
  const { t } = useI18n();
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
  const [applyStatus, setApplyStatus] = useState<FirewallApplyStatus | undefined>(undefined);
  const [selectedId, setSelectedId] = useState<string>('');
  const [unit, setUnit] = useState<Unit>('bytes');
  const [loading, setLoading] = useState(true);
  const [dragRule, setDragRule] = useState<number | null>(null);
  const [ruleModal, setRuleModal] = useState(emptyRuleModal);
  const [groupModal, setGroupModal] = useState(emptyGroupModal);

  // `quiet` existe para um caso só: o recarregar que acontece DEPOIS de uma
  // operação que já falhou. Ali a falha desta leitura é secundária, e deixá-la
  // escrever na mesma faixa trocaria a mensagem específica do backend ("não
  // foi possível concluir a reversão; o LinkGuard vai tentar de novo sozinho")
  // pelo genérico "erro interno do servidor" — perdendo justamente o que o
  // operador precisa saber.
  const load = async (quiet = false) => {
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
      if (!quiet) onMsg(t('fwx.error', { msg: errMsg(e) }), 'error');
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

  // A máquina do confirmar-ou-reverte. Ela só sabe QUANDO recarregar; o que
  // recarregar é `load`, que mora aqui porque é aqui que os dados moram.
  const cor = useConfirmOrRevert(load, onMsg);
  const { busy, locked, lockReason, editDisabled, refreshPending, adoptPending, run } = cor;

  useEffect(() => { load(); refreshPending(); }, []);
  // Enquanto esta tela está montada, a faixa COMPLETA daqui é a que o operador
  // vê; a faixa compacta do Layout se esconde sozinha (ver lib/pendingWindow).
  // A declaração é por componente montado, e não pela rota, porque esta tela é
  // uma ABA: nas outras abas do firewall quem tem de aparecer é a do Layout.
  useEffect(() => claimFullBanner(), []);
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

  // ─── Grupos ────────────────────────────────────────────────────────────
  const openNewGroup = () => setGroupModal({ ...emptyGroupModal, open: true });
  const openEditGroup = (g: FirewallGroup) => setGroupModal({
    open: true, id: g.id, name: g.name, cond_saddr: g.cond_saddr, cond_daddr: g.cond_daddr,
    cond_iif: g.cond_iif, fallthrough: g.fallthrough || 'continue', chain_name: g.chain_name,
    scope: groupScope(g),
    conn_state: groupConnState(g),
  });
  const closeGroupModal = () => setGroupModal((m) => ({ ...m, open: false }));
  // A mensagem diz o que continua guardado, e um grupo do sistema não guarda
  // regras: guarda os membros do set (é literalmente o que o nft mostra —
  // as linhas somem da forward, o set fica intacto).
  const toggleGroup = (g: FirewallGroup) => run(
    () => client.post('/api/nftables/groups/toggle', { id: g.id, enabled: !g.enabled }),
    g.enabled
      ? (isSystemGroup(g.kind) ? t('fw.toast.group.blockOff') : t('fw.toast.group.off'))
      : (isSystemGroup(g.kind) ? t('fw.toast.group.blockOn') : t('fw.toast.group.on')),
  );
  const removeGroup = (g: FirewallGroup) => {
    const n = splitGroupRules(g).rules.length;
    const detail = n === 0 ? '' : (n === 1 ? t('fwx.group.remove.detail.one') : t('fwx.group.remove.detail.many', { n }));
    if (!confirm(t('fwx.group.remove.confirm', { name: g.name, detail }))) return;
    run(() => client.delete('/api/nftables/groups', { data: { id: g.id } }), t('fw.toast.group.removed'));
  };

  // Reordering, both here and in the rules table, is optimistic with an
  // explicit rollback: the server is the only authority on order, and a
  // screen left showing an order it refused would be a screen lying about
  // which rule wins.
  const reorderGroups = (next: FirewallGroup[]) => {
    const previous = groups;
    setGroups(next);
    cor.setBusy(true);
    onMsg('');
    client.post('/api/nftables/groups/reorder', { ids: next.map((g) => g.id) })
      .then((res) => { adoptPending(res); return load(); })
      // Reordenar também pode armar a janela (mover um grupo de escopo input
      // muda a ordem da chain input) e também pode levar 409 da trava: as duas
      // pontas passam por uma releitura do pendente, senão a tela mostraria a
      // ordem nova sem a faixa, ou o 409 sem o motivo.
      .catch((e) => { setGroups(previous); onMsg(t('fwx.error', { msg: errMsg(e) }), 'error'); })
      .finally(() => { cor.setBusy(false); refreshPending(); });
  };

  // ─── Regras ────────────────────────────────────────────────────────────
  const openNewRule = (g: FirewallGroup) => setRuleModal({ ...emptyRuleModal, open: true, groupId: g.id, groupName: g.name });
  const openEditRule = (g: FirewallGroup, r: NftChainRule) => {
    const row = allRules.find((x) => x.id === r.id);
    if (!row) { onMsg(t('fwx.err.ruleGone'), 'error'); return; }
    setRuleModal({
      open: true, id: row.id, groupId: g.id, groupName: g.name,
      action: (row.action as Action) || 'drop', iif: row.iif, oif: row.oif,
      saddr: row.saddr, daddr: row.daddr, proto: row.proto, dport: row.dport,
      description: row.description,
    });
  };
  const closeRuleModal = () => setRuleModal((m) => ({ ...m, open: false }));
  const removeRule = (r: NftChainRule) => {
    if (!r.id) return;
    if (!confirm(t('fwx.rule.remove.confirm', { expr: r.expression }))) return;
    run(() => client.delete('/api/nftables/rules', { data: { id: r.id } }), t('fwx.toast.rule.removed'));
  };
  const toggleRule = (r: NftChainRule) => {
    if (!r.id) return;
    run(() => client.post('/api/nftables/rules/toggle', { id: r.id, enabled: r.enabled === false }),
      r.enabled === false ? t('fwx.toast.rule.enabled') : t('fwx.toast.rule.disabled'));
  };

  // reorderRules rebuilds the COMPLETE global list: it walks every rule in
  // its current global order and, at each slot that belongs to this group,
  // drops in the next id of the group's new order. Every other group's
  // rules keep the exact slots they already had, which is what makes a
  // per-group drag expressible in a global endpoint that refuses partial
  // lists.
  const reorderRules = (g: FirewallGroup, nextRows: NftChainRule[]) => {
    const translated = globalReorder(allRules, g.id, nextRows);
    if (!translated.ok) {
      onMsg(t('fwx.err.outOfSync'), 'error');
      load();
      return;
    }
    const globalOrder = translated.ids;

    const previous = groups;
    const merged = mergeGroupRules(nextRows, splitGroupRules(g));
    setGroups(groups.map((x) => (x.id === g.id ? { ...x, rules: { ...x.rules, rules: merged } } : x)));
    cor.setBusy(true);
    onMsg('');
    client.post('/api/nftables/rules/reorder', { ids: globalOrder })
      .then((res) => { adoptPending(res); return load(); })
      .catch((e) => { setGroups(previous); onMsg(t('fwx.error', { msg: errMsg(e) }), 'error'); })
      .finally(() => { cor.setBusy(false); refreshPending(); });
  };
  // I-6 (Fase B): Firefox will not start an HTML5 drag session unless
  // dataTransfer actually carries data — without setData, `dragstart` fires
  // but `drop` never does, so the whole reorder silently dies in Firefox.
  // The value is not read back; setting it is what matters.
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
    return <div className="card text-center py-8 text-gray-500 animate-pulse">{t('fw.groups.loading')}</div>;
  }

  const detail = selected ? splitGroupRules(selected) : undefined;
  // Grupo do sistema: outro detalhe inteiro. Não tem condição de entrada,
  // não tem tabela de regras e não tem "e o que sobrar" — mostrar esses
  // blocos vazios sugeriria que ele os tem e que estão neutros, o que é
  // diferente de não existirem (spec §2.1).
  const selectedSys = selected ? SYSTEM_KINDS[selected.kind] : undefined;
  const selectedIdx = selected ? groups.findIndex((g) => g.id === selected.id) : -1;
  // adminGroupsAbove devolve os grupos do admin LIGADOS que estão antes da
  // posição na lista — a condição do aviso da spec §2.2. `groups` já vem
  // ordenado por position, e é essa mesma ordem que a forward tem. O critério
  // em si mora em lib/blockGroups: a tela de Hosts faz a MESMA pergunta sobre o
  // MESMO bloqueio (via blockEnforcement) e as duas não podem discordar.
  const aboveSelected = selectedSys && selectedIdx > 0 ? adminGroupsAbove(groups, selectedIdx) : [];

  return (
    <div className="space-y-4">
      {/* ─── Faixa do confirmar-ou-reverte (spec §5) ──────────────────────── */}
      <ConfirmOrRevertBanner cor={cor} canWrite={canWrite} />

      {/* apply_status: the last DB→nft reconcile can fail on its own — a
          boot-time one has no HTTP response for anyone to see — so this is a
          standing banner, not a transient message. */}
      {/* `ok: false` passou a ter DUAS causas possíveis, e elas pedem ações
          opostas do operador — daí a condição não ser mais só `!ok`.

          Se a única coisa que aconteceu foi o arquivo de boot não ter sido
          gravado (`boot_persist_error` sem `error`), esta faixa NÃO aparece:
          as regras entraram no kernel e estão valendo, e chamar isso de "o
          apply falhou" faria o operador desfazer um trabalho que funcionou.
          Quem fala desse caso é a faixa âmbar logo abaixo.

          O `|| !boot_persist_error` mantém o comportamento antigo para um
          `ok: false` sem mensagem nenhuma: continua sendo uma falha de apply
          sem detalhe, não um silêncio. */}
      {applyStatus && !applyStatus.ok && (applyStatus.error || !applyStatus.boot_persist_error) && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('fwx.apply.failed', { err: applyStatus.error || t('fwx.apply.unknownError') })}
        </div>
      )}

      {/* Âmbar, e não vermelho: as regras ESTÃO valendo agora — o que não está
          é o próximo boot. As duas faixas podem aparecer juntas na mesma
          passada (o nft recusou algo E o arquivo de boot ficou para trás):
          são dois problemas diferentes, com duas ações diferentes. */}
      {applyStatus?.boot_persist_error && (
        <div className="card border border-amber-500/30 bg-amber-500/10 text-amber-300 text-sm">
          <p className="font-medium">{t('fw.groups.notPersisted')}</p>
          <p className="mt-1 text-amber-200/80">
            {t('fwx.boot.persist.body', { err: applyStatus.boot_persist_error })}
          </p>
          {/* A instrução de saída, e não só o diagnóstico. Medido em VM
              (cenário 5 da validação de 2026-08-13): depois de devolver a
              permissão de escrita, APLICAR OUTRA REGRA NÃO RESOLVE — a unidade
              tem ProtectSystem=strict com ReadWritePaths=-/etc/nftables.conf, e
              um caminho ausente no start do serviço não entra gravável no
              namespace do processo já rodando. Sem esta frase o operador tenta
              exatamente isso primeiro, vê que não muda nada e conclui que o
              produto está quebrado. */}
          <p className="mt-2 text-amber-200/80">
            <span className="font-medium text-amber-300">{t('fw.groups.howToFix')}</span> {t('fw.groups.restorePermission')} <code className="font-mono text-xs">/etc/nftables.conf</code> {t('fw.groups.andThen')} <span className="font-medium text-amber-300">{t('fw.groups.restartService')}</span> — <code className="font-mono text-xs break-all">systemctl restart linkguard-fw</code>. {t('fwx.boot.restartNote')}
          </p>
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
            <span className="text-gray-300">{t('fw.groups.evalOrder')}</span>{' '}
            {t('fwx.evalOrder.tail')}
          </span>
        </p>
        <div className="flex items-center gap-2 text-xs shrink-0">
          <span className="text-gray-500">{t('fw.groups.countersIn')}</span>
          <div className="inline-flex rounded-lg border border-gray-700 overflow-hidden">
            <button onClick={() => setUnit('bytes')} className={`px-3 py-1.5 ${unit === 'bytes' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}>bytes</button>
            <button onClick={() => setUnit('bits')} className={`px-3 py-1.5 border-l border-gray-700 ${unit === 'bits' ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'}`}>bits</button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[17rem_minmax(0,1fr)] gap-4 items-start">
        {/* ─── Índice ─────────────────────────────────────────────────── */}
        <GroupList
          groups={groups}
          managed={managed}
          selectedId={selected?.id ?? ''}
          unit={unit}
          canWrite={canWrite}
          cor={cor}
          onSelect={setSelectedId}
          onNewGroup={openNewGroup}
          onRefresh={() => { load(); refreshPending(); }}
          onReorder={reorderGroups}
        />

        {/* ─── Detalhe ────────────────────────────────────────────────── */}
        {!selected || !detail ? (
          <div className="card text-center py-16">
            <Layers className="w-10 h-10 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">{t('fw.groups.empty')}</p>
            <p className="text-gray-600 text-xs mt-1">{t('fwx.groups.emptyHint')}</p>
          </div>
        ) : selectedSys ? (
          /* ─── Detalhe de um grupo do sistema (spec §4) ───────────────── */
          <SystemGroupMembers
            group={selected}
            sys={selectedSys}
            managed={managed}
            hosts={hosts}
            above={aboveSelected}
            unit={unit}
            canWrite={canWrite}
            canBlockHosts={canBlockHosts}
            cor={cor}
            onToggle={() => toggleGroup(selected)}
          />
        ) : (
          <div className="card space-y-4">
            {/* Cabeçalho: nome e ações do grupo */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-white font-semibold truncate">{selected.name}</h3>
                <p className="text-[11px] text-gray-600 font-mono truncate">chain {selected.chain_name}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                {groupScope(selected) === 'input' && (
                  <span
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-orange-500/40 bg-orange-500/10 text-orange-300"
                    title={t('fwx.badge.input.title')}
                  >
                    <AlertTriangle className="w-3 h-3" aria-hidden="true" /> {t('fwx.badge.input.label')}
                  </span>
                )}
                {groupConnState(selected) === 'new' && (
                  <span
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-sky-500/40 bg-sky-500/10 text-sky-300"
                    title={t('fwx.badge.new.title')}
                  >
                    <DoorOpen className="w-3 h-3" aria-hidden="true" /> {t('fwx.label.newOnly')}
                  </span>
                )}
                {!selected.enabled && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-400">
                    {t('fwx.badge.off')}
                  </span>
                )}
                {selected.enabled && !selected.applied && (
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                    title={t('fwx.badge.notApplied.group.title')}
                  >
                    {t('fwx.badge.notApplied.group')}
                  </span>
                )}
                {canWrite && (
                  <>
                    <button
                      onClick={() => toggleGroup(selected)}
                      disabled={editDisabled}
                      title={locked ? lockReason : undefined}
                      className="btn-secondary flex items-center gap-1.5 text-xs px-2.5 py-1.5 disabled:opacity-50"
                    >
                      {selected.enabled ? <><PowerOff className="w-3.5 h-3.5" />{t('fw.groups.disable')}</> : <><Power className="w-3.5 h-3.5" />{t('fw.groups.enable')}</>}
                    </button>
                    <IconButton icon={Pencil} onClick={() => openEditGroup(selected)} disabled={editDisabled} label={t('fwx.action.editGroup')} title={locked ? lockReason : undefined} />
                    <IconButton icon={Trash2} onClick={() => removeGroup(selected)} disabled={editDisabled} label={t('fwx.action.removeGroup')} title={locked ? lockReason : undefined} variant="danger" />
                  </>
                )}
              </div>
            </div>

            {canWrite && locked && (
              <p className="text-[11px] text-amber-300/80 flex items-start gap-1.5">
                <Lock className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{lockReason}</span>
              </p>
            )}

            {/* Faixa da condição de entrada, com o contador do próprio jump:
                quanto tráfego de fato ENTROU no grupo — não a soma das
                regras (spec §7.3). */}
            <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="min-w-0 text-sm">
                  <span className="text-gray-500 text-xs uppercase tracking-wide mr-2">{t('fw.groups.when')}</span>
                  <span className="text-gray-200">{describeCondition(selected)}</span>
                  <span className="text-gray-600 mx-2">·</span>
                  <span className="text-gray-500 text-xs uppercase tracking-wide mr-2">{t('fw.groups.where')}</span>
                  {/* "Onde" era um texto fixo dizendo "atravessando" — com o
                      escopo da Fase C2 isso vira mentira na tela justamente no
                      grupo que pode cortar o acesso do operador. */}
                  <span className={groupScope(selected) === 'input' ? 'text-orange-300' : 'text-gray-200'}>
                    {SCOPES[groupScope(selected)].title}
                  </span>
                  <span className="text-gray-600 mx-1.5 font-mono text-xs">chain {SCOPES[groupScope(selected)].chain}</span>
                  {/* "Para quais conexões" só aparece quando há o que dizer:
                      em "toda conexão" ele repetiria, em toda tela, o
                      comportamento que o produto sempre teve. */}
                  {groupConnState(selected) === 'new' && (
                    <>
                      <span className="text-gray-600 mx-2">·</span>
                      <span className="text-gray-500 text-xs uppercase tracking-wide mr-2">{t('fw.groups.whichConnections')}</span>
                      <span className="text-sky-300">{CONN_STATES.new.title}</span>
                    </>
                  )}
                </div>
                <div className="text-xs font-mono text-gray-400 shrink-0">
                  {selected.has_counter
                    ? t('fwx.group.jumpCounter', { pkts: selected.packets.toLocaleString('pt-BR'), bytes: formatCount(selected.bytes, unit) })
                    : <span className="text-gray-600">{t('fw.groups.noCounter')}</span>}
                </div>
              </div>
              {/* A linha de verdade, com o `ct state new` no meio quando ele
                  existe: a tela não esconde o que vai para o firewall. */}
              <NftPreview endpoint="/api/nftables/groups/preview" body={groupPreviewBody(selected)} className="mt-1.5 text-gray-600" />
              {groupConnState(selected) === 'new' && (
                <p className="mt-1.5 text-[11px] text-sky-300/90">
                  {t('fw.groups.newOnly', { hint: t(CONN_STATES.new.hint) })}
                </p>
              )}
              {/* Alcançabilidade é transitiva: se nada pula para a chain,
                  nada dentro dela está em vigor. Dizer isso uma vez aqui é
                  mais honesto — e muito menos ruidoso — do que carimbar
                  "Configurada, não aplicada" em cada regra de dentro, que
                  faria uma escolha deliberada do admin (desligar o grupo)
                  parecer uma falha. */}
              {!selected.applied && (
                <p className={`mt-1.5 text-[11px] ${selected.enabled ? 'text-yellow-500' : 'text-gray-500'}`}>
                  {selected.enabled
                    ? t('fwx.group.jumpUnconfirmed')
                    : t('fwx.group.offNoRules')}
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
                    <th className="pb-2 pr-3 font-medium w-28">{t('fw.groups.col.action')}</th>
                    <th className="pb-2 pr-3 font-medium">{t('fw.groups.col.match')}</th>
                    <th className="pb-2 pr-3 font-medium">{t('fw.groups.col.description')}</th>
                    <th className="pb-2 pr-3 font-medium text-right w-20">{t('fw.groups.col.packets')}</th>
                    <th className="pb-2 pr-3 font-medium text-right w-20">{t('fw.groups.col.traffic')}</th>
                    {canWrite && <th className="pb-2 font-medium w-28 text-right">{t('fw.groups.col.actions')}</th>}
                  </tr>
                </thead>
                <tbody>
                  {detail.rules.length === 0 && detail.extras.length === 0 && (
                    <tr>
                      <td colSpan={canWrite ? 7 : 6} className="py-4 text-gray-600 text-sm">
                        {t(selected.fallthrough === 'continue' ? 'fwx.rules.empty.continue' : 'fwx.rules.empty')}
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
                        draggable={canWrite && !busy && !locked && !!r.id}
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
                                {t('fwx.badge.ruleDisabled')}
                              </span>
                            )}
                            {notApplied && (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                                title={t('fwx.badge.notApplied.rule.title')}
                              >
                                {t('fwx.badge.notApplied.rule')}
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
                                  disabled={editDisabled}
                                  title={locked ? lockReason : undefined}
                                  label={disabled ? t('fwx.action.enableRule') : t('fwx.action.disableRule')}
                                  variant={disabled ? 'custom' : 'default'}
                                  className={`min-w-[32px] min-h-[32px] ${disabled ? 'text-yellow-500 hover:text-yellow-400' : ''}`}
                                />
                                <IconButton icon={Pencil} onClick={() => openEditRule(selected, r)} disabled={editDisabled} title={locked ? lockReason : undefined} label={t('fwx.action.editRule')} className="min-w-[32px] min-h-[32px]" />
                                <IconButton icon={Trash2} onClick={() => removeRule(r)} disabled={editDisabled} title={locked ? lockReason : undefined} label={t('fwx.action.deleteRule')} variant="danger" className="min-w-[32px] min-h-[32px]" />
                              </div>
                            ) : (
                              <span className="block text-right text-[10px] text-gray-600">{t('fw.groups.notYourRule')}</span>
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
                          {t('fwx.badge.outsidePanel')}
                        </span>
                      </td>
                      <td className="py-2 pr-3 align-top font-mono text-[12px] text-gray-400 break-words">{r.expression}</td>
                      <td className="py-2 pr-3 align-top text-gray-500 text-xs">{t('fw.groups.notYourRule.hint')}</td>
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
                <span className="text-gray-400 text-xs">{t('fw.group.leftover')}</span>
                <span className={`font-mono text-xs font-medium ${FALLTHROUGH[selected.fallthrough]?.color ?? 'text-gray-300'}`}>
                  {selected.fallthrough || 'continue'}
                </span>
                <span className="text-gray-500 text-xs truncate">
                  {t(FALLTHROUGH[selected.fallthrough]?.hint ?? FALLTHROUGH.continue.hint)}
                </span>
              </div>
              <div className="text-xs font-mono text-gray-500 shrink-0">
                {detail.fall?.has_counter
                  ? t('fwx.counter.pkts', { pkts: detail.fall.packets.toLocaleString('pt-BR'), bytes: formatCount(detail.fall.bytes, unit) })
                  : '—'}
              </div>
            </div>

            {canWrite && (
              <button
                onClick={() => openNewRule(selected)}
                disabled={editDisabled}
                title={locked ? lockReason : undefined}
                className="btn-secondary flex items-center gap-2 text-sm disabled:opacity-50"
              >
                <Plus className="w-4 h-4" /> {t('fw.groups.newRuleHere')}
              </button>
            )}
          </div>
        )}
      </div>

      {/* ─── Modal do grupo ─────────────────────────────────────────────── */}
      <GroupModal
        state={groupModal}
        setState={setGroupModal}
        ifaces={ifaces}
        cor={cor}
        onClose={closeGroupModal}
        onCreated={setSelectedId}
      />

      {/* ─── Modal da regra ─────────────────────────────────────────────── */}
      <RuleModal
        state={ruleModal}
        setState={setRuleModal}
        ifaces={ifaces}
        cor={cor}
        onClose={closeRuleModal}
      />
    </div>
  );
}
