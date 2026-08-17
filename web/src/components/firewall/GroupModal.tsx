/**
 * O formulário do grupo — criar e editar são o mesmo, e a diferença é só o
 * `id` no estado.
 *
 * A ORDEM dos blocos é conteúdo, não estética: "onde o grupo age" vem antes da
 * condição de entrada porque é ele que muda o significado do que vem depois, e
 * "para quais conexões" vem logo depois dela porque é ela que ele qualifica.
 * Mexer nessa ordem muda o que o operador entende antes de salvar.
 *
 * O estado do formulário fica na tela (`state`/`setState`) e não aqui dentro:
 * é ele que o `NftPreview` manda ao backend, byte a byte, e é a tela que decide
 * quando abrir com um grupo já gravado. O que É deste componente: o desenho e a
 * gravação — `saveGroup` mora aqui porque só aqui se sabe o que os campos
 * significam.
 */

import { AlertTriangle } from 'lucide-react';
import client from '../../api/client';
import Modal from '../ui/Modal';
import NftPreview, { groupPreviewBody } from './NftPreview';
import { CONN_STATES, FALLTHROUGH, SCOPES } from './groupMeta';
import type { GroupModalState } from './groupMeta';
import type { ConfirmOrRevert } from '../../lib/useConfirmOrRevert';
import type { FirewallGroup, GroupFallthrough } from '../../types';

interface Props {
  state: GroupModalState;
  setState: (s: GroupModalState) => void;
  ifaces: string[];
  cor: ConfirmOrRevert;
  onClose: () => void;
  /** Selecionar o grupo recém-criado é o próximo passo natural: o admin o
   *  criou para pôr regras dentro dele. */
  onCreated: (id: string) => void;
}

export default function GroupModal({ state, setState, ifaces, cor, onClose, onCreated }: Props) {
  const { busy, locked, lockReason, editDisabled, run } = cor;

  const saveGroup = () => {
    const payload = {
      name: state.name.trim(), cond_saddr: state.cond_saddr.trim(),
      cond_daddr: state.cond_daddr.trim(), cond_iif: state.cond_iif.trim(),
      fallthrough: state.fallthrough,
      // O escopo vai SEMPRE, inclusive quando é forward. O backend trata
      // `scope` ausente como "mantenha o gravado" (proteção contra cliente
      // antigo que rebaixaria um grupo de input em silêncio), então omiti-lo
      // aqui faria trocar o escopo na tela não fazer nada — com HTTP 200 e o
      // operador achando que trocou.
      scope: state.scope,
      // E a escolha de conexões vai SEMPRE pelo mesmo motivo, com o sinal
      // trocado: `conn_state` ausente também é "mantenha o gravado" (a
      // proteção contra o cliente antigo que AFROUXARIA um grupo restrito de
      // propósito). Omiti-lo aqui faria a troca na tela não acontecer, com
      // HTTP 200 — o defeito exato que o campo `scope` já teve neste projeto.
      conn_state: state.conn_state,
    };
    const req = state.id
      ? client.put('/api/nftables/groups', { id: state.id, ...payload })
      : client.post<FirewallGroup>('/api/nftables/groups', payload);
    run(async () => {
      const res = await req;
      const created = (res.data as FirewallGroup | undefined)?.id;
      if (!state.id && created) onCreated(created);
      // A resposta volta para o `run`, que tira dela o pendente que ESTA
      // mutação armou (adoptPending): é o que faz a faixa da contagem
      // regressiva aparecer no mesmo instante em que o grupo de escopo input
      // é salvo, sem esperar o poll.
      return res;
    }, state.id ? 'Grupo atualizado.' : 'Grupo criado.').then((ok) => { if (ok) onClose(); });
  };

  return (
    <Modal
      open={state.open}
      onClose={onClose}
      title={state.id ? 'Editar grupo' : 'Novo grupo'}
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
            value={state.name}
            onChange={(e) => setState({ ...state, name: e.target.value })}
          />
        </div>

        {/* Onde o grupo age — o campo `scope`. Vem ANTES da condição de
            entrada de propósito: é ele que muda o significado de tudo o que
            vem depois (a mesma condição "origem 10.0.0.0/8" quer dizer
            coisas diferentes na forward e na input). */}
        <div>
          <p className="label mb-2">Onde este grupo age</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {(['forward', 'input'] as const).map((s) => {
              const meta = SCOPES[s];
              const active = state.scope === s;
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => setState({ ...state, scope: s })}
                  className={`flex items-start gap-2 rounded-lg border p-3 text-left transition ${active ? meta.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}
                >
                  <meta.Icon className={`w-4 h-4 shrink-0 mt-0.5 ${active ? meta.color : 'text-gray-400'}`} aria-hidden="true" />
                  <span className="min-w-0">
                    <span className={`block text-xs font-medium ${active ? meta.color : 'text-gray-300'}`}>{meta.title}</span>
                    <span className="block text-[10px] text-gray-500 leading-tight mt-0.5">{meta.hint}</span>
                    {/* O nome da chain é do nftables e não se traduz: é o
                        que o admin vai achar no `nft list ruleset`. */}
                    <span className="block text-[10px] font-mono text-gray-600 mt-1">chain {meta.chain}</span>
                  </span>
                </button>
              );
            })}
          </div>
          {/* O aviso da janela de 90 segundos aparece AQUI, no instante em
              que o escopo input é escolhido, e não depois de salvar: quem
              está prestes a mexer no acesso à própria máquina tem que saber
              disso antes de clicar. */}
          {state.scope === 'input' && (
            <div className="mt-2 rounded-lg border border-orange-500/40 bg-orange-500/10 p-3 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div className="text-[11px] text-orange-200/90 space-y-1">
                <p className="font-medium text-orange-200">Salvar vai abrir uma janela de 90 segundos.</p>
                <p>
                  Este grupo passa a filtrar o que chega no próprio firewall — SSH, este painel, DNS. A alteração é aplicada na hora e, se ninguém confirmar em 90 segundos, o LinkGuard desfaz os grupos e as regras sozinho.
                </p>
                <p className="text-orange-200/70">
                  Enquanto ela estiver aguardando confirmação, a edição de grupos e regras fica bloqueada. Tenha um segundo acesso à máquina à mão se puder.
                </p>
              </div>
            </div>
          )}
        </div>

        <div>
          <p className="label mb-2">Quando entrar neste grupo (condição de entrada)</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="label">Interface de entrada</label>
              <select className="input w-full" value={state.cond_iif} onChange={(e) => setState({ ...state, cond_iif: e.target.value })}>
                <option value="">Qualquer</option>
                {ifaces.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Origem (IP/CIDR)</label>
              <input className="input w-full" placeholder="qualquer" value={state.cond_saddr} onChange={(e) => setState({ ...state, cond_saddr: e.target.value })} />
            </div>
            <div>
              <label className="label">Destino (IP/CIDR)</label>
              <input className="input w-full" placeholder="qualquer" value={state.cond_daddr} onChange={(e) => setState({ ...state, cond_daddr: e.target.value })} />
            </div>
          </div>
          <p className="text-[11px] text-gray-600 mt-1.5">
            Sem condição, {state.scope === 'input' ? 'todo o tráfego destinado ao firewall' : 'todo o tráfego que atravessa o firewall'} entra no grupo. Só IPv4 por enquanto.
          </p>
        </div>

        {/* Para quais conexões — o campo `conn_state`. Vem logo depois da
            condição de entrada porque é ela que ele qualifica: o mesmo
            "origem 192.168.50.0/24" vale para tudo o que casar, ou só para o
            que estiver começando agora. */}
        <div>
          <p className="label mb-2">Para quais conexões este grupo vale</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {(['any', 'new'] as const).map((c) => {
              const meta = CONN_STATES[c];
              const active = state.conn_state === c;
              return (
                <button
                  key={c}
                  type="button"
                  onClick={() => setState({ ...state, conn_state: c })}
                  className={`flex items-start gap-2 rounded-lg border p-3 text-left transition ${active ? meta.ring : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'}`}
                >
                  <meta.Icon className={`w-4 h-4 shrink-0 mt-0.5 ${active ? meta.color : 'text-gray-400'}`} aria-hidden="true" />
                  <span className="min-w-0">
                    <span className={`block text-xs font-medium ${active ? meta.color : 'text-gray-300'}`}>{meta.title}</span>
                    <span className="block text-[10px] text-gray-500 leading-tight mt-0.5">{meta.hint}</span>
                    {/* O token do nftables, quando existe. "toda conexão" não
                        acrescenta nada à linha — e dizer isso é mais honesto
                        do que inventar uma expressão para ela. */}
                    <span className="block text-[10px] font-mono text-gray-600 mt-1">
                      {meta.expr || 'sem `ct state` na linha'}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
          {/* O aviso que a escolha obriga, e que é a razão de a Fase C2 e
              esta feature conviverem: num grupo de escopo input, "só
              conexões novas" desarma o teste dos 90 segundos — a sessão do
              operador NÃO cai, então ela não prova nada. Dito aqui, antes de
              salvar, e repetido na faixa depois. */}
          {state.conn_state === 'new' && state.scope === 'input' && (
            <div className="mt-2 rounded-lg border border-sky-500/40 bg-sky-500/10 p-3 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-sky-300 shrink-0 mt-0.5" aria-hidden="true" />
              <div className="text-[11px] text-sky-100/90 space-y-1">
                <p className="font-medium text-sky-100">A sua sessão atual não vai cair — nem se este grupo bloquear você.</p>
                <p>
                  Nos 90 segundos de confirmação, testar o acesso na aba que já está aberta (ou no SSH já conectado) vai funcionar de qualquer jeito. Para testar de verdade, abra uma conexão nova: outro terminal SSH, uma aba anônima.
                </p>
              </div>
            </div>
          )}
        </div>

        <div>
          <p className="label mb-2">E o que sobrar?</p>
          <div className="grid grid-cols-3 gap-2">
            {(Object.keys(FALLTHROUGH) as GroupFallthrough[]).map((f) => {
              const meta = FALLTHROUGH[f];
              const active = state.fallthrough === f;
              return (
                <button
                  key={f}
                  onClick={() => setState({ ...state, fallthrough: f })}
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
          {/* A chain nomeada aqui é a de verdade: a linha é a mesma nos dois
              escopos, o que muda é ONDE ela é escrita. Dizer "forward" num
              grupo de input mandaria o admin procurar a linha na chain
              errada. */}
          <p className="text-xs text-gray-400 mb-1">
            Linha que este grupo põe na chain <span className="font-mono">{SCOPES[state.scope].chain}</span>:
          </p>
          <NftPreview endpoint="/api/nftables/groups/preview" body={groupPreviewBody(state)} />
        </div>
      </div>
      <div className="px-6 py-4 border-t border-gray-800 flex gap-3">
        <button
          onClick={saveGroup}
          disabled={editDisabled || !state.name.trim()}
          title={locked ? lockReason : undefined}
          className="btn-primary flex-1 disabled:opacity-50"
        >
          {busy ? 'Salvando...' : state.scope === 'input' ? 'Salvar e iniciar os 90 s' : 'Salvar'}
        </button>
        <button onClick={onClose} className="btn-secondary flex-1">Cancelar</button>
      </div>
    </Modal>
  );
}
