/**
 * O ÍNDICE da tela de grupos: a lista da esquerda, que é a ordem real de
 * avaliação do firewall de cima para baixo — e por isso é arrastável.
 *
 * O estado do arraste (`dragGroup`) mora aqui dentro e em nenhum outro lugar:
 * ele não sobrevive ao drop e nada fora desta lista o lê. O que sai daqui é uma
 * ordem nova inteira, via `onReorder`; quem manda ao servidor e desfaz quando
 * ele recusa é a tela, porque é ela que é dona de `groups`.
 */

import type { DragEvent } from 'react';
import { Plus, RefreshCw, GripVertical, Lock, AlertTriangle, DoorOpen } from 'lucide-react';
import IconButton from '../ui/IconButton';
import { adminGroupsAbove } from '../../lib/blockGroups';
import { useI18n } from '../../i18n';
import { moveItem, splitGroupRules } from '../../lib/groupRules';
import { SYSTEM_KINDS, formatCount, groupConnState, groupScope, membersOf } from './groupMeta';
import type { Unit } from './groupMeta';
import type { ConfirmOrRevert } from '../../lib/useConfirmOrRevert';
import type { FirewallGroup, NftManaged } from '../../types';
import { useState } from 'react';

interface Props {
  groups: FirewallGroup[];
  managed: NftManaged;
  selectedId: string;
  unit: Unit;
  canWrite: boolean;
  cor: ConfirmOrRevert;
  onSelect: (id: string) => void;
  onNewGroup: () => void;
  onRefresh: () => void;
  onReorder: (next: FirewallGroup[]) => void;
}

export default function GroupList({
  groups, managed, selectedId, unit, canWrite, cor, onSelect, onNewGroup, onRefresh, onReorder,
}: Props) {
  const { t } = useI18n();
  const [dragGroup, setDragGroup] = useState<number | null>(null);
  const { busy, locked, lockReason, editDisabled } = cor;

  // I-6 (Fase B): Firefox will not start an HTML5 drag session unless
  // dataTransfer actually carries data — without setData, `dragstart` fires
  // but `drop` never does, so the whole reorder silently dies in Firefox.
  // The value is not read back; setting it is what matters.
  const onDragStart = (e: DragEvent, i: number) => {
    if (!canWrite) return;
    e.dataTransfer.setData('text/plain', String(i));
    e.dataTransfer.effectAllowed = 'move';
    setDragGroup(i);
  };
  const onDrop = (i: number) => {
    if (dragGroup === null || dragGroup === i) { setDragGroup(null); return; }
    onReorder(moveItem(groups, dragGroup, i));
    setDragGroup(null);
  };

  return (
    <div className="card p-0 overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-3 py-2.5 border-b border-gray-800">
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">
          {groups.length} grupo{groups.length === 1 ? '' : 's'}
        </span>
        <div className="flex items-center gap-1">
          <IconButton icon={RefreshCw} onClick={onRefresh} label="Atualizar grupos" className="min-w-[32px] min-h-[32px]" />
          {canWrite && (
            <button
              onClick={onNewGroup}
              disabled={editDisabled}
              title={locked ? lockReason : undefined}
              className="btn-primary flex items-center gap-1.5 text-xs px-2.5 py-1.5 disabled:opacity-50"
            >
              <Plus className="w-3.5 h-3.5" /> {t('fw.groups.new')}
            </button>
          )}
        </div>
      </div>

      {/* A razão de os controles estarem desabilitados, escrita onde eles
          estão — um botão apagado sem explicação é só um painel quebrado. */}
      {canWrite && locked && (
        <p className="px-3 py-2 text-[11px] text-amber-300/80 bg-amber-500/5 border-b border-gray-800 flex items-start gap-1.5">
          <Lock className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{lockReason}</span>
        </p>
      )}

      {groups.length === 0 ? (
        <p className="text-gray-600 text-sm px-3 py-6 text-center">
          Nenhum grupo ainda.{canWrite && ' Clique em "Novo".'}
        </p>
      ) : (
        <ul className="divide-y divide-gray-800/70">
          {groups.map((g, i) => {
            const { rules } = splitGroupRules(g);
            const active = selectedId === g.id;
            const notApplied = g.enabled && !g.applied;
            // O outro lado do par Enabled × Applied, que nenhum dos dois
            // rótulos cobria: desligado no banco e ainda vivo no
            // firewall. "desligado" sozinho afirmaria que o grupo não
            // vale nada enquanto o kernel ainda o avalia.
            const staleOff = !g.enabled && g.applied;
            const sys = SYSTEM_KINDS[g.kind];
            const n = sys ? membersOf(g, managed).length : rules.length;
            const noun = sys
              ? (n === 1 ? t(sys.member[0]) : t(sys.member[1]))
              : `regra${n === 1 ? '' : 's'}`;
            // Aviso de ordem (spec §2.2): um bloqueio arrastado para
            // depois de um grupo LIGADO do admin pode nunca ver o pacote,
            // porque aquele grupo pode decidir antes. Grupo desligado não
            // põe linha na forward, então não entra na conta — seria
            // alarme falso.
            //
            // O critério em si mora em lib/blockGroups: a tela de Hosts faz a
            // MESMA pergunta sobre o MESMO bloqueio (via blockEnforcement) e as
            // duas não podem discordar.
            const above = sys ? adminGroupsAbove(groups, i) : [];
            // Marca do escopo input: quem arrasta, liga/desliga ou edita
            // este item dispara a janela de 90 segundos, e precisa saber
            // disso ANTES de encostar nele. Daí a borda (ring, que
            // sobrevive à barra azul do item selecionado) e o ⚠ ao lado do
            // nome — os dois, porque só a cor não diz o que significa.
            const inputScope = groupScope(g) === 'input';
            // Marca da escolha de conexões: dois grupos com o MESMO nome,
            // a mesma condição e as mesmas regras se comportam de formas
            // diferentes conforme este campo — um derruba a transferência
            // em curso, o outro não. Sem a marca na lista, a diferença só
            // existe dentro do modal, e é assim que o operador começa a
            // desconfiar do software.
            const newOnly = groupConnState(g) === 'new';
            return (
              <li
                key={g.id}
                draggable={canWrite && !busy && !locked}
                onDragStart={(e) => onDragStart(e, i)}
                onDragOver={(e) => { if (dragGroup !== null) e.preventDefault(); }}
                onDrop={() => onDrop(i)}
                onDragEnd={() => setDragGroup(null)}
                className={`group relative ${dragGroup === i ? 'opacity-30' : ''} ${inputScope ? 'ring-1 ring-inset ring-orange-500/40 bg-orange-500/[0.03]' : ''}`}
              >
                <button
                  onClick={() => onSelect(g.id)}
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
                      {inputScope && (
                        <AlertTriangle
                          className="w-3 h-3 shrink-0 text-orange-400"
                          aria-label="grupo de tráfego destinado ao firewall"
                        />
                      )}
                      {newOnly && (
                        <DoorOpen
                          className="w-3 h-3 shrink-0 text-sky-300"
                          aria-label="grupo que vale só para conexões novas"
                        />
                      )}
                    </span>
                    <span className="block text-[11px] text-gray-500 font-mono truncate">
                      {n} {noun} · {g.has_counter ? formatCount(g.bytes, unit) : '—'}
                    </span>
                    {inputScope && (
                      <span className="block text-[11px] text-orange-400/90">{t('fw.groups.inputBadge')}</span>
                    )}
                    {newOnly && (
                      <span className="block text-[11px] text-sky-300/90">
                        só conexões novas · <span className="font-mono">ct state new</span>
                      </span>
                    )}
                    {!g.enabled && !staleOff && <span className="block text-[11px] text-gray-500">{t('fw.groups.off')}</span>}
                    {staleOff && <span className="block text-[11px] text-yellow-500">{t('fw.groups.offStillInFirewall')}</span>}
                    {notApplied && <span className="block text-[11px] text-yellow-500">{t('fw.groups.configuredNotApplied')}</span>}
                    {above.length > 0 && g.enabled && (
                      <span className="mt-0.5 flex items-start gap-1 text-[11px] text-orange-400">
                        <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
                        <span>{t('fw.group.dropAbove')}</span>
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
  );
}
