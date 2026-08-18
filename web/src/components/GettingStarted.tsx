import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, ChevronRight, GraduationCap, X, PartyPopper } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import HelpTip from './HelpTip';
import { useI18n } from '../i18n';
import type { SystemMetrics, WanLink, DHCPData } from '../types';

/**
 * Só o esqueleto do passo. O texto (título, explicação, chamada e a ajuda) vem
 * do YAML pela chave `recipes.start.<key>.*` na hora de desenhar, e não daqui:
 * assim trocar de idioma não obriga a refazer as quatro consultas que medem o
 * progresso — elas medem a máquina, que não muda de idioma.
 */
interface Step {
  key: string;
  to: string;
  done: boolean;
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
 * Devolve o texto com a ênfase que ele sempre teve: `*assim*` vira negrito e
 * `_assim_` vira itálico.
 *
 * O negrito carrega o sentido da explicação ("a *WAN* é a sua conexão com a
 * *internet*"), e o YAML só guarda string. Partir a frase em pedaços colados no
 * JSX prenderia a ordem das palavras à do português, então cada frase é UMA
 * chave e os marcadores viajam dentro dela.
 */
function comEnfase(texto: string): React.ReactNode[] {
  return texto.split(/(\*[^*]+\*|_[^_]+_)/g).map((pedaco, i) => {
    if (pedaco.length > 2 && pedaco.startsWith('*') && pedaco.endsWith('*')) {
      return <b key={i}>{pedaco.slice(1, -1)}</b>;
    }
    if (pedaco.length > 2 && pedaco.startsWith('_') && pedaco.endsWith('_')) {
      return <i key={i}>{pedaco.slice(1, -1)}</i>;
    }
    return pedaco;
  });
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
        { key: 'iface', to: '/interfaces', done: ifaces.length >= 2 },
        { key: 'wan', to: '/links', done: wan.length >= 1 },
        { key: 'nat', to: '/firewall', done: rs.includes('masquerade') },
        { key: 'dhcp', to: '/dhcp', done: leases.length > 0 },
        { key: 'dns', to: '/dns', done: leases.length > 0 },
        { key: 'sec', to: '/admin', done: !!user && user.username !== 'admin' },
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
  const { t } = useI18n();
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
            <h2 className="text-white font-semibold">{allDone ? t('recipes.start.heading.done') : t('recipes.start.heading')}</h2>
            <p className="text-gray-500 text-xs">
              {allDone ? t('recipes.start.subtitle.done') : t('recipes.start.subtitle')}
            </p>
          </div>
        </div>
        <button onClick={dismiss} className="text-gray-500 hover:text-gray-300" title={t('recipes.start.hide')} aria-label={t('recipes.start.hide')}><X className="w-4 h-4" /></button>
      </div>

      {/* progress */}
      <div className="mt-3 mb-4">
        <div className="flex justify-between text-xs text-gray-500 mb-1"><span>{t('recipes.start.progress', { feitos: doneCount, total: steps.length })}</span></div>
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
                  <span className={`text-sm font-medium ${s.done ? 'text-gray-400 line-through' : 'text-white'}`}>{t(`recipes.start.${s.key}.title`)}</span>
                  <HelpTip title={t(`recipes.start.${s.key}.help.title`)}>{comEnfase(t(`recipes.start.${s.key}.help.body`))}</HelpTip>
                </div>
                {!s.done && <p className="text-gray-500 text-xs mt-0.5">{t(`recipes.start.${s.key}.body`)}</p>}
              </div>
              {!s.done && (
                <Link to={s.to} className="btn-secondary flex items-center gap-1 shrink-0 text-xs whitespace-nowrap">
                  {t(`recipes.start.${s.key}.cta`)} <ChevronRight className="w-3.5 h-3.5" />
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
