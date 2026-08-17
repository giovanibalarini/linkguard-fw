import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, ChevronRight, GraduationCap, X, PartyPopper } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import HelpTip from './HelpTip';
import type { SystemMetrics, WanLink, DHCPData } from '../types';

interface Step {
  key: string;
  title: string;
  to: string;
  cta: string;
  done: boolean;
  help: { title: string; body: React.ReactNode };
  body: string;
}

export const DISMISS_KEY = 'lg_hide_getting_started';

export interface OnboardingProgress {
  /** `null` enquanto o estado da máquina ainda não voltou. */
  steps: Step[] | null;
  /** false enquanto ainda não se sabe nada — nem "pronto", nem "faltando". */
  ready: boolean;
  done: number;
  total: number;
  allDone: boolean;
}

/**
 * O estado dos seis passos, medido na própria máquina.
 *
 * Virou hook porque o painel precisa da MESMA resposta que este cartão:
 * "Primeiros passos" sai do painel quando os 6 passos terminam (spec §4.5), e
 * quem decide isso é o Dashboard, que não desenha os passos. Duas cópias da
 * regra divergiriam no primeiro passo novo que alguém acrescentasse — e o
 * sintoma seria um cartão de onboarding que reaparece sozinho numa máquina que
 * roda há meses, que é exatamente a queixa que originou esta entrega.
 */
export function useOnboardingSteps(): OnboardingProgress {
  const { user } = useAuth();
  const [steps, setSteps] = useState<Step[] | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      const [sys, links, dhcp, ruleset] = await Promise.allSettled([
        client.get<SystemMetrics>('/api/system/status'),
        client.get<WanLink[]>('/api/links'),
        client.get<DHCPData>('/api/dhcp'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
      ]);
      const ifaces = sys.status === 'fulfilled' ? (sys.value.data.interfaces ?? []).filter((i) => i.name && i.name !== 'lo') : [];
      const wan = links.status === 'fulfilled' ? (links.value.data ?? []) : [];
      const leases = dhcp.status === 'fulfilled' ? (dhcp.value.data.leases ?? []) : [];
      const rs = ruleset.status === 'fulfilled' ? (ruleset.value.data.ruleset ?? '') : '';

      if (!alive) return;
      setSteps([
        {
          key: 'iface', title: 'Identifique suas conexões', to: '/interfaces', cta: 'Ver interfaces',
          done: ifaces.length >= 2, body: 'Toda máquina-firewall tem pelo menos duas conexões de rede.',
          help: { title: 'WAN e LAN', body: <>A <b>WAN</b> é a sua conexão com a <b>internet</b> (o cabo do provedor/modem). A <b>LAN</b> é a sua <b>rede local</b> (os aparelhos de casa). O firewall fica no meio, protegendo a LAN e compartilhando a internet.</> },
        },
        {
          key: 'wan', title: 'Configure sua internet (WAN)', to: '/links', cta: 'Configurar WAN',
          done: wan.length >= 1, body: 'Diga qual interface é a sua internet. Pode ter mais de uma (multi-WAN).',
          help: { title: 'Link WAN', body: <>É a porta por onde a internet entra. Com <b>duas WANs</b>, o LinkGuard pode equilibrar o uso e trocar automaticamente se uma cair (<b>failover</b>).</> },
        },
        {
          key: 'nat', title: 'Transforme em firewall (NAT)', to: '/firewall', cta: 'Ver firewall',
          done: rs.includes('masquerade'), body: 'Compartilha a internet com a sua rede local com segurança.',
          help: { title: 'NAT / roteamento', body: <>O <b>NAT</b> deixa vários aparelhos da sua casa usarem uma única internet, escondidos atrás do firewall. É o que transforma a máquina num <b>roteador</b>.</> },
        },
        {
          key: 'dhcp', title: 'Distribua IPs (DHCP)', to: '/dhcp', cta: 'Configurar DHCP',
          done: leases.length > 0, body: 'Dá um endereço automático para cada aparelho que conecta na sua rede.',
          help: { title: 'DHCP', body: <>Sem DHCP você teria que configurar o IP de cada celular, TV e PC na mão. O <b>DHCP</b> faz isso sozinho. Você ainda pode <b>reservar</b> um IP fixo para um aparelho específico.</> },
        },
        {
          key: 'dns', title: 'Resolva nomes (DNS)', to: '/dns', cta: 'Configurar DNS',
          done: leases.length > 0, body: 'Traduz "google.com" no endereço real — e pode filtrar sites.',
          help: { title: 'DNS', body: <>O <b>DNS</b> é a "lista telefônica" da internet: transforma nomes (<i>google.com</i>) em números (IPs). Pelo LinkGuard você vê o que cada aparelho acessa e pode <b>bloquear</b> domínios.</> },
        },
        {
          key: 'sec', title: 'Proteja o acesso ao painel', to: '/admin', cta: 'Criar meu usuário',
          done: !!user && user.username !== 'admin', body: 'Crie seu usuário e troque a senha padrão antes de usar pra valer.',
          help: { title: 'Segurança do painel', body: <>O usuário padrão é <b>admin/admin</b> — qualquer um na rede entraria. Crie um <b>usuário seu</b> e troque a senha. Você pode dar permissões diferentes para cada pessoa.</> },
        },
      ]);
    })();
    return () => { alive = false; };
  }, [user]);

  const done = steps ? steps.filter((s) => s.done).length : 0;
  const total = steps ? steps.length : 0;
  return { steps, ready: steps !== null, done, total, allDone: steps !== null && done === total };
}

/**
 * `onDismiss` existe porque este cartão virou widget do painel: quando ele vem,
 * o X é o mesmo gesto que remover o widget, e quem grava a remoção é o painel.
 * Sem ele, o comportamento antigo continua valendo.
 */
export default function GettingStarted({ onDismiss }: { onDismiss?: () => void } = {}) {
  const { steps, done: doneCount, allDone } = useOnboardingSteps();
  const [hidden, setHidden] = useState(localStorage.getItem(DISMISS_KEY) === '1');

  if ((hidden && !onDismiss) || !steps) return null;
  const next = steps.find((s) => !s.done);

  const dismiss = () => {
    if (onDismiss) {
      onDismiss();
      return;
    }
    localStorage.setItem(DISMISS_KEY, '1');
    setHidden(true);
  };

  return (
    <div className="card h-full overflow-y-auto border border-blue-500/30 bg-linear-to-b from-blue-500/5 to-transparent">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          {allDone ? <PartyPopper className="w-5 h-5 text-green-400" /> : <GraduationCap className="w-5 h-5 text-blue-400" />}
          <div>
            <h2 className="text-white font-semibold">{allDone ? 'Tudo pronto! 🎉' : 'Primeiros passos'}</h2>
            <p className="text-gray-500 text-xs">
              {allDone ? 'Seu firewall está configurado. Você pode ocultar este guia.' : 'Vamos transformar esta máquina num firewall — a gente explica cada passo.'}
            </p>
          </div>
        </div>
        <button onClick={dismiss} className="text-gray-500 hover:text-gray-300" title="Ocultar guia" aria-label="Ocultar guia"><X className="w-4 h-4" /></button>
      </div>

      {/* progress */}
      <div className="mt-3 mb-4">
        <div className="flex justify-between text-xs text-gray-500 mb-1"><span>{doneCount} de {steps.length}</span></div>
        <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
          <div className="h-full bg-blue-500 transition-all" style={{ width: `${(doneCount / steps.length) * 100}%` }} />
        </div>
      </div>

      <ul className="space-y-2">
        {steps.map((s) => {
          const isNext = !s.done && s === next;
          return (
            <li key={s.key} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 ${isNext ? 'bg-blue-500/10 border border-blue-500/30' : 'bg-gray-800/40'}`}>
              <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs ${s.done ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'}`}>
                {s.done ? <Check className="w-3.5 h-3.5" /> : steps.indexOf(s) + 1}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <span className={`text-sm font-medium ${s.done ? 'text-gray-400 line-through' : 'text-white'}`}>{s.title}</span>
                  <HelpTip title={s.help.title}>{s.help.body}</HelpTip>
                </div>
                {!s.done && <p className="text-gray-500 text-xs mt-0.5">{s.body}</p>}
              </div>
              {!s.done && (
                <Link to={s.to} className="btn-secondary flex items-center gap-1 shrink-0 text-xs whitespace-nowrap">
                  {s.cta} <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
