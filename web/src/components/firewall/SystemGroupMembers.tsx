/**
 * O DETALHE de um grupo do sistema (spec §4) — outro detalhe inteiro, e não uma
 * variação do detalhe comum: ele não tem condição de entrada, não tem tabela de
 * regras e não tem "e o que sobrar". Mostrar esses blocos vazios sugeriria que
 * ele os tem e que estão neutros, o que é diferente de não existirem (spec
 * §2.1).
 *
 * O conteúdo dele é a lista de MEMBROS de um named set. Por isso `newCidr` e o
 * seletor de hosts moram aqui: são os dois jeitos de acrescentar um membro, e
 * nenhuma outra parte da tela os lê. `managed` e `hosts` chegam de fora porque
 * é a tela que os carrega — o inventário é melhor esforço e depende de outra
 * permissão (hosts.read).
 */

import { useState } from 'react';
import { Plus, Power, PowerOff, Lock, X, AlertTriangle, Ban } from 'lucide-react';
import client from '../../api/client';
import Modal from '../ui/Modal';
import IconButton from '../ui/IconButton';
import { KIND_BLOCKED_HOSTS, KIND_BLOCKLIST } from '../../lib/blockGroups';
import { formatCount, membersOf } from './groupMeta';
import type { SystemKind, Unit } from './groupMeta';
import type { ConfirmOrRevert } from '../../lib/useConfirmOrRevert';
import type { FirewallGroup, NetHost, NftManaged } from '../../types';

interface Props {
  group: FirewallGroup;
  sys: SystemKind;
  managed: NftManaged;
  /** null = inventário não consultado ou sem permissão — diferente de vazio. */
  hosts: NetHost[] | null;
  /** Os grupos do admin LIGADOS acima deste bloqueio (aviso da spec §2.2). */
  above: string[];
  unit: Unit;
  canWrite: boolean;
  canBlockHosts: boolean;
  cor: ConfirmOrRevert;
  onToggle: () => void;
}

export default function SystemGroupMembers({
  group, sys, managed, hosts, above, unit, canWrite, canBlockHosts, cor, onToggle,
}: Props) {
  const [newCidr, setNewCidr] = useState('');
  const [hostPicker, setHostPicker] = useState({ open: false, filter: '' });
  const { busy, locked, lockReason, editDisabled, run } = cor;

  const members = membersOf(group, managed);
  const hostByIP = new Map((hosts ?? []).map((h) => [h.ip, h]));

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

  return (
    <div className="card space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-white font-semibold truncate">{group.name}</h3>
          <p className="text-[11px] text-gray-600">Mantido pelo LinkGuard: não pode ser apagado nem renomeado. Pode ser ligado, desligado e reordenado.</p>
        </div>
        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-300">
            <Lock className="w-3 h-3" aria-hidden="true" /> do sistema
          </span>
          {!group.enabled && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-gray-600 bg-gray-700/40 text-gray-400">
              Desligado
            </span>
          )}
          {group.enabled && !group.applied && (
            <span
              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
              title="O bloqueio está ligado aqui, mas o firewall não confirma as linhas dele na chain forward — pode ser um erro ao aplicar; confira o aviso no topo."
            >
              Configurado, não aplicado
            </span>
          )}
          {canWrite && (
            <button
              onClick={onToggle}
              disabled={editDisabled}
              title={locked ? lockReason : undefined}
              className="btn-secondary flex items-center gap-1.5 text-xs px-2.5 py-1.5 disabled:opacity-50"
            >
              {group.enabled ? <><PowerOff className="w-3.5 h-3.5" /> Desligar</> : <><Power className="w-3.5 h-3.5" /> Ligar</>}
            </button>
          )}
        </div>
      </div>

      {canWrite && locked && (
        <p className="text-[11px] text-amber-300/80 flex items-start gap-1.5">
          <Lock className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{lockReason}</span>
        </p>
      )}

      {/* O que ele faz, as linhas exatas que ele põe na forward e
          quanto elas descartaram. */}
      <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2.5 space-y-1.5">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
          <p className="text-sm text-gray-300 min-w-0">{sys.what}</p>
          <div className="text-xs font-mono text-gray-400 shrink-0">
            {group.has_counter
              ? <>descartou {group.packets.toLocaleString('pt-BR')} pct · {formatCount(group.bytes, unit)}</>
              : <span className="text-gray-600">sem contador · —</span>}
          </div>
        </div>
        <div>
          {sys.lines.map((line) => (
            <p key={line} className="font-mono text-[11px] text-gray-600 break-words">{line}</p>
          ))}
        </div>
        {!group.applied && (
          <p className={`text-[11px] ${group.enabled ? 'text-yellow-500' : 'text-gray-500'}`}>
            {group.enabled
              ? 'O firewall não confirma estas linhas na chain forward: neste momento nenhum membro abaixo está sendo bloqueado.'
              : 'Grupo desligado: nenhum membro abaixo está sendo bloqueado. Eles continuam guardados para quando ele voltar.'}
          </p>
        )}
        {/* Aviso de ordem (spec §2.2): a flexibilidade de arrastar um
            bloqueio para baixo não pode virar armadilha silenciosa. */}
        {group.enabled && above.length > 0 && (
          <p className="text-[11px] text-orange-400 flex items-start gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
            <span>
              Regras acima deste bloqueio podem liberar tráfego que ele descartaria:{' '}
              <span className="text-orange-300">{above.join(', ')}</span>{' '}
              {above.length === 1 ? 'é avaliado' : 'são avaliados'} antes dele.
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
          {members.length} {members.length === 1 ? sys.member[0] : sys.member[1]}
        </h4>
        {members.length === 0 ? (
          <p className="text-gray-600 text-sm py-2">{sys.empty}</p>
        ) : (
          <ul className="rounded-lg border border-gray-800 divide-y divide-gray-800/70">
            {members.map((m) => {
              const h = group.kind === KIND_BLOCKED_HOSTS ? hostByIP.get(m) : undefined;
              return (
                <li key={m} className="flex items-center gap-3 px-3 py-2">
                  <span className="font-mono text-sm text-gray-200 shrink-0">{m}</span>
                  {group.kind === KIND_BLOCKED_HOSTS && (
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
                  {group.kind === KIND_BLOCKLIST && canWrite && (
                    <IconButton icon={X} onClick={() => delCidr(m)} disabled={busy} label="Desbloquear destino" variant="danger" className="min-w-[32px] min-h-[32px]" />
                  )}
                  {group.kind === KIND_BLOCKED_HOSTS && canBlockHosts && (
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
        {group.kind === KIND_BLOCKLIST && canWrite && (
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
        {group.kind === KIND_BLOCKED_HOSTS && (
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
