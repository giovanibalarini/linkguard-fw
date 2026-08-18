import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Wand2, ChevronRight, ChevronDown, Ban, Gauge, Pin, ShieldOff, Network, Lock, ArrowRightLeft,
} from 'lucide-react';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';

/**
 * Recipes is the task-oriented entry point for beginners: instead of asking
 * "which menu does this live in?", the user picks what they want to DO and gets
 * numbered, plain-language steps plus a shortcut to the right screen. Power users
 * can collapse the whole card. Pairs with GettingStarted (one-time setup) — this
 * one is for recurring everyday tasks.
 */
interface Recipe {
  id: string;
  icon: typeof Ban;
  to: string;
  /** Quantos passos a receita tem; o texto de cada um vem do YAML. */
  passos: number;
}

/**
 * Só o esqueleto de cada receita mora aqui. Título, resumo, chamada e o texto
 * dos passos vêm do YAML pela chave `recipes.<id>.*`, porque este cartão é lido
 * nos dois idiomas e texto cravado no JSX foi exatamente o que fez a tradução
 * parar em 3 de 70 telas (issue #105).
 */
const recipes: Recipe[] = [
  { id: 'block-site', icon: Ban, to: '/dns', passos: 4 },
  { id: 'top-talkers', icon: Gauge, to: '/hosts', passos: 3 },
  { id: 'reserve-ip', icon: Pin, to: '/dhcp', passos: 4 },
  { id: 'port-forward', icon: ArrowRightLeft, to: '/firewall', passos: 4 },
  { id: 'block-device', icon: ShieldOff, to: '/hosts', passos: 4 },
  { id: 'balance-wan', icon: Network, to: '/links', passos: 3 },
  { id: 'secure-panel', icon: Lock, to: '/admin', passos: 4 },
];

/**
 * Devolve o passo com a ênfase que ele sempre teve: `*assim*` vira negrito e
 * `` `assim` `` vira literal monoespaçado.
 *
 * O negrito marca o ALVO do clique ("Abra a tela DNS", "Clique em Aplicar") —
 * é o que faz um passo ser lido de relance, então não dava para perdê-lo ao
 * mover o texto para o YAML, que só guarda string. A alternativa era quebrar
 * cada frase em três chaves coladas no JSX, e aí a ordem das palavras ficaria
 * presa à do português: "Open the *DNS* screen" põe o alvo no meio, "Abra a
 * tela *DNS*" põe no fim. Uma chave por frase deixa cada idioma se virar.
 */
function comEnfase(texto: string): React.ReactNode[] {
  return texto.split(/(\*[^*]+\*|`[^`]+`)/g).map((pedaco, i) => {
    if (pedaco.length > 2 && pedaco.startsWith('*') && pedaco.endsWith('*')) {
      return <b key={i}>{pedaco.slice(1, -1)}</b>;
    }
    if (pedaco.length > 2 && pedaco.startsWith('`') && pedaco.endsWith('`')) {
      return <code key={i} className="text-blue-300">{pedaco.slice(1, -1)}</code>;
    }
    return pedaco;
  });
}

const DISMISS_KEY = 'lg_hide_recipes';

/**
 * `onDismiss` existe porque este cartão virou widget do painel (spec §4.5).
 * Quando ele vem, "Ocultar" é o mesmo gesto que remover o widget: quem tira o
 * widget da grade é o painel, que também o grava. Sem ele, o comportamento
 * antigo continua valendo (esconder por localStorage).
 */
export default function Recipes({ onDismiss }: { onDismiss?: () => void } = {}) {
  const { t } = useI18n();
  const [hidden, setHidden] = useState(localStorage.getItem(DISMISS_KEY) === '1');
  const [open, setOpen] = useState<string | null>(null);

  if (hidden && !onDismiss) return null;

  const dismiss = () => {
    if (onDismiss) {
      onDismiss();
      return;
    }
    localStorage.setItem(DISMISS_KEY, '1');
    setHidden(true);
  };

  return (
    <Panel title={t('recipes.panel.title')} className="h-full overflow-y-auto">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Wand2 className="w-5 h-5 text-blue-400" />
          <div>
            <p className="text-gray-500 text-xs">{t('recipes.panel.subtitle')}</p>
          </div>
        </div>
        <button onClick={dismiss} className="text-gray-500 hover:text-gray-300 text-xs whitespace-nowrap" title={t('recipes.hide.title')}>{t('recipes.hide')}</button>
      </div>

      <ul className="mt-4 space-y-2">
        {recipes.map((r) => {
          const Icon = r.icon;
          const isOpen = open === r.id;
          return (
            <li key={r.id} className={`rounded-lg border ${isOpen ? 'border-blue-500/30 bg-blue-500/5' : 'border-gray-800 bg-gray-800/30'}`}>
              <button
                onClick={() => setOpen(isOpen ? null : r.id)}
                className="flex w-full items-center gap-3 px-3 py-2.5 text-left"
                aria-expanded={isOpen}
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gray-800 text-blue-400">
                  <Icon className="w-4 h-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-white">{t(`recipes.${r.id}.title`)}</span>
                  <span className="block text-xs text-gray-500 truncate">{t(`recipes.${r.id}.summary`)}</span>
                </span>
                <ChevronDown className={`w-4 h-4 shrink-0 text-gray-500 transition-transform ${isOpen ? '' : '-rotate-90'}`} />
              </button>
              {isOpen && (
                <div className="px-3 pb-3 pl-14">
                  <ol className="space-y-1.5">
                    {Array.from({ length: r.passos }, (_, i) => (
                      <li key={i} className="flex gap-2 text-sm text-gray-300">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-gray-800 text-[11px] text-gray-400">{i + 1}</span>
                        <span className="leading-relaxed">{comEnfase(t(`recipes.${r.id}.step${i + 1}`))}</span>
                      </li>
                    ))}
                  </ol>
                  <Link to={r.to} className="btn-secondary mt-3 inline-flex items-center gap-1 text-xs">
                    {t(`recipes.${r.id}.cta`)} <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
