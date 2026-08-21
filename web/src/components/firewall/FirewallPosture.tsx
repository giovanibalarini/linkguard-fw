/**
 * A tela da postura padrão do firewall (issue #94).
 *
 * O que ela entrega: a capacidade que a #78 e a #92 puseram na API — bloquear
 * por padrão e liberar só o que foi autorizado — para quem entra pelo painel e
 * nunca vai chamar um PUT à mão.
 *
 * DUAS DECISÕES QUE NÃO SÃO ESTILO.
 *
 * A lista de "o que continua passando" vem do SERVIDOR, não daqui. A porta do
 * painel não é fixa (8080 no binário, 9997 no .deb, outra atrás de um proxy),
 * as redes da LAN vêm da configuração, e a linha do cliente DHCP só existe em
 * quem tem WAN por DHCP. Uma tela que adivinhasse estaria mentindo exatamente
 * na frase que o operador lê para decidir se continua entrando na máquina
 * depois de apertar o botão.
 *
 * E as duas chains NÃO são apresentadas com o mesmo peso. Bloquear o que
 * atravessa é a operação comum, que não toca no painel; bloquear o que chega ao
 * próprio LinkGuard é a que tranca o administrador do lado de fora. A segunda
 * fica atrás de um "mostrar", com o risco escrito antes dos botões.
 */

import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldOff, ChevronDown, ChevronRight, AlertTriangle, Check } from 'lucide-react';
import client from '../../api/client';
import Panel from '../ui/Panel';
import ConfirmOrRevertBanner from './ConfirmOrRevertBanner';
import { useConfirmOrRevert } from '../../lib/useConfirmOrRevert';
import { claimFullBanner } from '../../lib/pendingWindow';
import { useUIMode } from '../../context/UIModeContext';
import { POSTURE_ORDER, policyLine, postureRequest, survivalLines } from '../../lib/posture';
import type { Policy, PostureChain } from '../../lib/posture';
import { useI18n } from '../../i18n';
import type { MsgLevel } from '../../types';

interface Exposure {
  management_open_on_wan: boolean;
  management_ports?: number[] | null;
  wan_interfaces?: string[] | null;
  ipv6_forwarding: 'on' | 'off' | 'unknown';
  address_rules_ipv4_only: boolean;
  host_block_covers_ipv6: boolean;
  error?: string;
}

interface PolicyResponse {
  policy: Policy;
  forward: Policy;
  survival?: { input: string[] | null; forward: string[] | null; error?: string };
  exposure?: Exposure;
}

interface Props {
  canWrite: boolean;
  onMsg: (m: string, level?: MsgLevel) => void;
}

export default function FirewallPosture({ canWrite, onMsg }: Props) {
  const { mode } = useUIMode();
  const { t } = useI18n();
  const [data, setData] = useState<PolicyResponse | null>(null);
  const [erro, setErro] = useState('');
  // A input começa recolhida. Ela é a decisão rara e perigosa, e não pode ser a
  // primeira que a mão alcança.
  const [aberta, setAberta] = useState<Record<PostureChain, boolean>>({ forward: true, input: false });

  const load = async () => {
    try {
      const res = await client.get<PolicyResponse>('/api/nftables/policy');
      setData(res.data);
      setErro('');
    } catch {
      // A postura desconhecida NÃO vira "liberado" na tela: desenhar accept
      // porque o GET falhou seria a tela afirmando que o firewall está aberto
      // no minuto em que ele talvez esteja bloqueando tudo.
      setData(null);
      setErro(t('fw.posture.readError'));
    }
  };

  const cor = useConfirmOrRevert(load, onMsg);
  const { busy, locked, lockReason, run } = cor;

  useEffect(() => { load(); cor.refreshPending(); }, []);
  useEffect(() => claimFullBanner(), []);

  const trocar = (chain: PostureChain, policy: Policy) => {
    // A frase da confirmação é montada por interpolação: o ALVO ("o tráfego que
    // atravessa" / "o acesso ao próprio LinkGuard") é uma chave à parte porque
    // ele aparece nas duas frases, e porque a ordem das palavras muda entre os
    // idiomas — concatenar pedaços no JSX é onde isso quebraria.
    const alvo = t(`fw.posture.target.${chain}`);
    if (!window.confirm(t(`fw.posture.confirm.${policy}`, { alvo }))) return;
    run(
      () => client.put('/api/nftables/policy', postureRequest(chain, policy)),
      t(policy === 'drop' ? 'fw.posture.applied.drop' : 'fw.posture.applied.accept'),
    );
  };

  const atual = (chain: PostureChain): Policy | null => {
    if (!data) return null;
    return chain === 'forward' ? data.forward : data.policy;
  };

  const linhas = (chain: PostureChain) =>
    survivalLines(chain === 'forward' ? data?.survival?.forward : data?.survival?.input);

  return (
    <div className="space-y-4">
      <ConfirmOrRevertBanner cor={cor} canWrite={canWrite} />

      {erro && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {erro} {t('fw.posture.readError.tail')}
        </div>
      )}

      {POSTURE_ORDER.map((chain) => {
        const p = atual(chain);
        const perigosa = chain === 'input';
        const expandida = aberta[chain];
        return (
          <Panel key={chain}>
            <button
              type="button"
              className="w-full flex items-start gap-3 text-left"
              onClick={() => setAberta((a) => ({ ...a, [chain]: !a[chain] }))}
              aria-expanded={expandida}
            >
              {expandida
                ? <ChevronDown className="w-5 h-5 text-gray-400 mt-0.5 shrink-0" aria-hidden="true" />
                : <ChevronRight className="w-5 h-5 text-gray-400 mt-0.5 shrink-0" aria-hidden="true" />}
              <div className="min-w-0 flex-1">
                <h2 className="text-white font-semibold">{t(`fw.posture.${chain}.title`)}</h2>
                <p className="text-sm text-gray-400 mt-0.5">{t(`fw.posture.${chain}.subtitle`)}</p>
              </div>
              {/* O selo da postura atual fica visível mesmo com o cartão
                  recolhido: "está bloqueando?" é a pergunta que se responde de
                  relance, e abrir um cartão para descobri-la seria esconder o
                  estado do firewall atrás de um clique. */}
              <span
                className={`shrink-0 text-xs px-2.5 py-1 rounded-full border font-medium ${
                  p === null ? 'border-gray-600 text-gray-400'
                    : p === 'drop' ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                      : 'border-green-500/30 bg-green-500/10 text-green-400'
                }`}
              >
                {t(p === null ? 'fw.posture.badge.unknown' : p === 'drop' ? 'fw.posture.badge.drop' : 'fw.posture.badge.accept')}
              </span>
            </button>

            {expandida && (
              <div className="mt-4 space-y-4">
                {perigosa && (
                  <div className="flex gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100">
                    <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" aria-hidden="true" />
                    <p>{t(`fw.posture.${chain}.risk`)}</p>
                  </div>
                )}

                <div className="grid gap-3 sm:grid-cols-2">
                  {(['accept', 'drop'] as Policy[]).map((op) => {
                    const escolhida = p === op;
                    const Icone = op === 'drop' ? ShieldOff : ShieldCheck;
                    return (
                      <button
                        key={op}
                        type="button"
                        disabled={!canWrite || busy || locked || escolhida || p === null}
                        title={locked ? lockReason : undefined}
                        onClick={() => trocar(chain, op)}
                        className={`text-left rounded-xl border p-4 transition ${
                          escolhida
                            ? op === 'drop'
                              ? 'border-amber-500/50 bg-amber-500/10'
                              : 'border-green-500/40 bg-green-500/10'
                            : 'border-gray-700 bg-gray-800/40 hover:border-gray-500 disabled:hover:border-gray-700'
                        } disabled:opacity-60 disabled:cursor-not-allowed`}
                      >
                        <span className="flex items-center gap-2">
                          <Icone
                            className={`w-4 h-4 ${op === 'drop' ? 'text-amber-400' : 'text-green-400'}`}
                            aria-hidden="true"
                          />
                          <strong className="text-white text-sm">
                            {t(op === 'drop' ? 'fw.posture.choice.drop' : 'fw.posture.choice.accept')}
                          </strong>
                          {escolhida && <Check className="w-4 h-4 text-gray-400 ml-auto" aria-hidden="true" />}
                        </span>
                        <p className="text-sm text-gray-400 mt-2">
                          {t(`fw.posture.${chain}.${op}`)}
                        </p>
                        {mode === 'advanced' && (
                          <code className="block mt-2 text-[11px] font-mono text-gray-500 break-all">
                            {policyLine(chain, op)}
                          </code>
                        )}
                      </button>
                    );
                  })}
                </div>

                {!perigosa && (
                  <p className="text-sm text-gray-400">{t(`fw.posture.${chain}.risk`)}</p>
                )}

                <div>
                  <h3 className="text-sm font-medium text-white">{t('fw.posture.survival.title')}</h3>
                  <p className="text-xs text-gray-500 mt-0.5">{t('fw.posture.survival.subtitle')}</p>
                  {data?.survival?.error && (
                    <p className="text-xs text-amber-300 mt-2">
                      {t('fw.posture.survival.error', { erro: data.survival.error })}
                    </p>
                  )}
                  <ul className="mt-3 space-y-2">
                    {linhas(chain).map((l) => (
                      <li key={l.nft} className="flex gap-2.5 text-sm">
                        <Check className="w-4 h-4 text-green-400 mt-0.5 shrink-0" aria-hidden="true" />
                        <div className="min-w-0 flex-1">
                          {/* Linha que a tabela de explicações não conhece
                              aparece assim mesmo, crua. Escondê-la faria a tela
                              afirmar que o firewall preserva MENOS do que
                              preserva — o erro na direção que assusta à toa. */}
                          <span className="text-gray-200">
                            {l.key ? t(`fw.posture.survival.${l.key}.what`) : l.nft}
                          </span>
                          {l.key && (
                            <p className="text-xs text-gray-500 mt-0.5">
                              {t(`fw.posture.survival.${l.key}.why`)}
                            </p>
                          )}
                          {mode === 'advanced' && l.key && (
                            <code className="block text-[11px] font-mono text-gray-600 mt-1 break-all">{l.nft}</code>
                          )}
                        </div>
                      </li>
                    ))}
                    {linhas(chain).length === 0 && !data?.survival?.error && (
                      <li className="text-sm text-gray-500">—</li>
                    )}
                  </ul>
                </div>
              </div>
            )}
          </Panel>
        );
      })}

      {data?.exposure && <CartaoExposicao e={data.exposure} />}
    </div>
  );
}

/**
 * CartaoExposicao conta o que o firewall deixa passar (issue #119, fase 3).
 *
 * As duas primeiras fases mexeram em regra; esta mexe em AFIRMAÇÃO. O ruleset
 * passou a proteger mais e a tela continuou descrevendo um firewall que não é o
 * que está rodando — e num produto cujo valor é o operador confiar no que lê,
 * omissão e mentira custam igual.
 *
 * Fica DEPOIS dos cartões de postura de propósito: quem chega aqui já leu
 * "bloquear" ou "aceitar" e formou uma impressão. Este cartão é onde ela é
 * corrigida.
 */
function CartaoExposicao({ e }: { e: Exposure }) {
  const { t } = useI18n();
  const itens: { texto: string; detalhe?: string; nivel: 'aviso' | 'neutro' }[] = [];

  if (e.error) {
    itens.push({ texto: t('fw.exposure.unknown', { erro: e.error }), nivel: 'aviso' });
  } else if (e.management_open_on_wan) {
    itens.push({
      texto: t('fw.exposure.mgmtOpen', {
        portas: (e.management_ports ?? []).join(', '),
        wans: (e.wan_interfaces ?? []).join(', '),
      }),
      detalhe: t('fw.exposure.mgmtOpen.why'),
      nivel: 'aviso',
    });
  }

  if (e.ipv6_forwarding === 'off') {
    itens.push({ texto: t('fw.exposure.ipv6Off'), detalhe: t('fw.exposure.ipv6Off.why'), nivel: 'neutro' });
  } else if (e.ipv6_forwarding === 'on') {
    // Roteando IPv6 com as regras por endereço valendo só IPv4, o que o admin
    // acha que bloqueou está metade aberto. Aqui o aviso é forte de propósito.
    itens.push({ texto: t('fw.exposure.ipv6On'), detalhe: t('fw.exposure.ipv6On.why'), nivel: 'aviso' });
  } else {
    itens.push({ texto: t('fw.exposure.ipv6Unknown'), nivel: 'neutro' });
  }

  if (e.address_rules_ipv4_only) {
    itens.push({
      texto: t('fw.exposure.addrIPv4Only'),
      detalhe: e.host_block_covers_ipv6 ? t('fw.exposure.addrIPv4Only.exception') : undefined,
      nivel: 'neutro',
    });
  }

  return (
    <Panel title={<span className="text-white font-semibold">{t('fw.exposure.title')}</span>}>
      <p className="text-gray-500 text-xs mb-4">{t('fw.exposure.subtitle')}</p>
      <ul className="space-y-3">
        {itens.map((i, n) => (
          <li key={n} className="flex gap-2.5 text-sm">
            <AlertTriangle
              className={`w-4 h-4 mt-0.5 shrink-0 ${i.nivel === 'aviso' ? 'text-amber-400' : 'text-gray-500'}`}
              aria-hidden="true"
            />
            <div className="min-w-0 flex-1">
              <span className="text-gray-200">{i.texto}</span>
              {i.detalhe && <p className="text-xs text-gray-500 mt-0.5">{i.detalhe}</p>}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
