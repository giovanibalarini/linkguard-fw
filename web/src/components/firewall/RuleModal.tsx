/**
 * O formulário da regra. Criar e editar são o mesmo formulário; o `id` no
 * estado é a diferença, e o `group_id` diz em qual grupo ela entra.
 *
 * A pré-visualização é a linha nft de verdade, vinda do backend: o corpo que
 * ela manda é o estado do formulário inteiro, como sempre foi — quem decide o
 * que importa é o servidor, que é o mesmo código que monta a linha para o
 * kernel.
 */

import client from '../../api/client';
import Modal from '../ui/Modal';
import NftPreview from './NftPreview';
import { ACTIONS } from './groupMeta';
import type { Action, RuleModalState } from './groupMeta';
import type { ConfirmOrRevert } from '../../lib/useConfirmOrRevert';
import type { FirewallRule } from '../../types';

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

interface Props {
  state: RuleModalState;
  setState: (s: RuleModalState) => void;
  ifaces: string[];
  cor: ConfirmOrRevert;
  onClose: () => void;
}

export default function RuleModal({ state, setState, ifaces, cor, onClose }: Props) {
  const { busy, locked, lockReason, editDisabled, run } = cor;

  const saveRule = () => {
    const payload = {
      group_id: state.groupId, action: state.action, iif: state.iif, oif: state.oif,
      saddr: state.saddr, daddr: state.daddr, proto: state.proto,
      dport: state.dport, description: state.description,
    };
    const req = state.id
      ? client.put('/api/nftables/rules', { id: state.id, ...payload })
      : client.post('/api/nftables/rules', payload);
    run(() => req, state.id ? 'Regra atualizada.' : 'Regra criada.').then((ok) => { if (ok) onClose(); });
  };

  return (
    <Modal
      open={state.open}
      onClose={onClose}
      title={state.id ? 'Editar regra' : `Nova regra em "${state.groupName}"`}
      size="md"
      className="rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col"
    >
      <div className="p-6 space-y-4 overflow-y-auto">
        <div>
          <label className="label mb-2 block">Ação</label>
          <div className="grid grid-cols-3 gap-2">
            {(Object.keys(ACTIONS) as Action[]).map((act) => {
              const a = ACTIONS[act];
              const active = state.action === act;
              return (
                <button key={act} onClick={() => setState({ ...state, action: act })} className={`flex flex-col items-center gap-1 rounded-lg border p-3 transition ${active ? a.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}>
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
            <select className="input w-full" value={state.iif} onChange={(e) => setState({ ...state, iif: e.target.value })}>
              <option value="">Qualquer</option>
              {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Interface de saída</label>
            <select className="input w-full" value={state.oif} onChange={(e) => setState({ ...state, oif: e.target.value })}>
              <option value="">Qualquer</option>
              {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Origem (IP/CIDR)</label>
            <input className="input w-full" placeholder="qualquer" value={state.saddr} onChange={(e) => setState({ ...state, saddr: e.target.value })} />
          </div>
          <div>
            <label className="label">Destino (IP/CIDR)</label>
            <input className="input w-full" placeholder="qualquer" value={state.daddr} onChange={(e) => setState({ ...state, daddr: e.target.value })} />
          </div>
          <div>
            <label className="label">Protocolo</label>
            <select className="input w-full" value={state.proto} onChange={(e) => setState({ ...state, proto: e.target.value })}>
              <option value="">Qualquer</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
          {(state.proto === 'tcp' || state.proto === 'udp') && (
            <div>
              <label className="label">Porta de destino</label>
              <input className="input w-full" placeholder="ex.: 443 ou 1000-2000" value={state.dport} onChange={(e) => setState({ ...state, dport: e.target.value })} />
            </div>
          )}
        </div>

        <div>
          <label className="label">Descrição (por que essa regra existe)</label>
          <input
            className="input w-full"
            placeholder="ex.: libera VPN do parceiro X"
            maxLength={500}
            value={state.description}
            onChange={(e) => setState({ ...state, description: e.target.value })}
          />
        </div>

        <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
          <p className="text-xs text-gray-400 mb-1">
            <span className={`font-mono ${ACTIONS[state.action].color}`}>{ACTIONS[state.action].label}</span>{' '}
            {describe(state)}
          </p>
          <NftPreview endpoint="/api/nftables/rules/preview" body={state} />
        </div>
      </div>
      <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
        <button
          onClick={saveRule}
          disabled={editDisabled}
          title={locked ? lockReason : undefined}
          className="btn-primary flex-1 disabled:opacity-50"
        >
          {busy ? 'Salvando...' : 'Salvar'}
        </button>
        <button onClick={onClose} className="btn-secondary flex-1">Cancelar</button>
      </div>
    </Modal>
  );
}
