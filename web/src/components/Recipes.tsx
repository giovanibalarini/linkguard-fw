import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Wand2, ChevronRight, ChevronDown, Ban, Gauge, Pin, ShieldOff, Network, Lock, ArrowRightLeft,
} from 'lucide-react';

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
  title: string;
  summary: string;
  steps: React.ReactNode[];
  to: string;
  cta: string;
}

const recipes: Recipe[] = [
  {
    id: 'block-site',
    icon: Ban,
    title: 'Bloquear um site ou aplicativo',
    summary: 'Impedir o acesso a um domínio (ex.: redes sociais) em toda a rede.',
    to: '/dns',
    cta: 'Ir para DNS',
    steps: [
      <>Abra a tela <b>DNS</b>.</>,
      <>Na <b>lista de bloqueio</b>, digite o domínio (ex.: <code className="text-blue-300">facebook.com</code>) e adicione.</>,
      <>Clique em <b>Aplicar</b>. O bloqueio vale para todos os aparelhos que usam este firewall como DNS.</>,
      <>Para liberar de novo, é só remover o domínio da lista.</>,
    ],
  },
  {
    id: 'top-talkers',
    icon: Gauge,
    title: 'Ver quem está consumindo a internet',
    summary: 'Descobrir qual aparelho está usando mais banda agora.',
    to: '/hosts',
    cta: 'Ir para Hosts',
    steps: [
      <>Abra a tela <b>Hosts</b>.</>,
      <>No topo, veja o card <b>Top consumidores</b> — lista os aparelhos por uso de banda em tempo real.</>,
      <>A barra azul mostra o consumo relativo; à direita, o <b>download</b> e o <b>upload</b> de cada um.</>,
    ],
  },
  {
    id: 'reserve-ip',
    icon: Pin,
    title: 'Dar um IP fixo a um aparelho',
    summary: 'Garantir que um aparelho receba sempre o mesmo endereço.',
    to: '/dhcp',
    cta: 'Ir para DHCP',
    steps: [
      <>Em <b>Hosts</b>, encontre o aparelho e copie o <b>MAC</b> (o "RG" da placa de rede).</>,
      <>Abra a tela <b>DHCP</b> e vá em <b>Reservas</b>.</>,
      <>Informe o <b>MAC</b>, o <b>IP fixo</b> desejado e um nome, e salve.</>,
      <>Clique em <b>Aplicar</b>. Na próxima conexão o aparelho receberá esse IP.</>,
    ],
  },
  {
    id: 'port-forward',
    icon: ArrowRightLeft,
    title: 'Liberar / encaminhar uma porta',
    summary: 'Deixar algo de fora acessar um serviço seu (servidor, câmera, jogo).',
    to: '/firewall',
    cta: 'Ir para Firewall',
    steps: [
      <>Reserve um <b>IP fixo</b> para o aparelho no <b>DHCP</b> (assim o encaminhamento não muda de dono).</>,
      <>Abra <b>Firewall → Encaminhamento</b>.</>,
      <>Informe a <b>porta externa</b>, o <b>protocolo</b> (TCP/UDP) e o <b>IP:porta interna</b> do aparelho, e salve.</>,
      <>Abra só o necessário — cada porta aberta é uma porta de entrada na sua rede.</>,
    ],
  },
  {
    id: 'block-device',
    icon: ShieldOff,
    title: 'Bloquear um aparelho da rede',
    summary: 'Cortar o acesso à internet de um dispositivo específico.',
    to: '/hosts',
    cta: 'Ir para Hosts',
    steps: [
      <>Abra a tela <b>Hosts</b>.</>,
      <>Localize o aparelho pelo nome, IP ou MAC.</>,
      <>Clique em <b>Bloquear</b>. Ele perde o acesso à internet imediatamente.</>,
      <>Para liberar, clique em <b>Desbloquear</b> no mesmo aparelho.</>,
    ],
  },
  {
    id: 'balance-wan',
    icon: Network,
    title: 'Escolher / equilibrar a internet (WAN)',
    summary: 'Definir prioridade entre links ou dividir o tráfego (multi-WAN).',
    to: '/links',
    cta: 'Ir para Links WAN',
    steps: [
      <>Abra a tela <b>Links WAN</b>.</>,
      <>Ajuste o <b>peso</b> de cada link: maior peso recebe mais tráfego.</>,
      <>Com dois links, o LinkGuard equilibra o uso e troca sozinho se um cair (<b>failover</b>).</>,
    ],
  },
  {
    id: 'secure-panel',
    icon: Lock,
    title: 'Proteger o acesso ao painel',
    summary: 'Trocar a senha padrão e criar usuários nominais.',
    to: '/admin',
    cta: 'Ir para Administração',
    steps: [
      <>Abra a tela <b>Administração</b>.</>,
      <>Crie um <b>usuário só seu</b> e defina uma senha forte.</>,
      <>Para cada pessoa, você pode dar <b>permissões diferentes</b> (papéis).</>,
      <>Deixe de usar a conta padrão <b>admin/admin</b>.</>,
    ],
  },
];

const DISMISS_KEY = 'lg_hide_recipes';

export default function Recipes() {
  const [hidden, setHidden] = useState(localStorage.getItem(DISMISS_KEY) === '1');
  const [open, setOpen] = useState<string | null>(null);

  if (hidden) return null;

  const dismiss = () => { localStorage.setItem(DISMISS_KEY, '1'); setHidden(true); };

  return (
    <div className="card">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Wand2 className="w-5 h-5 text-blue-400" />
          <div>
            <h2 className="text-white font-semibold">O que você quer fazer?</h2>
            <p className="text-gray-500 text-xs">Tarefas comuns, passo a passo — escolha uma e a gente te leva até lá.</p>
          </div>
        </div>
        <button onClick={dismiss} className="text-gray-500 hover:text-gray-300 text-xs whitespace-nowrap" title="Ocultar este card">Ocultar</button>
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
                  <span className="block text-sm font-medium text-white">{r.title}</span>
                  <span className="block text-xs text-gray-500 truncate">{r.summary}</span>
                </span>
                <ChevronDown className={`w-4 h-4 shrink-0 text-gray-500 transition-transform ${isOpen ? '' : '-rotate-90'}`} />
              </button>
              {isOpen && (
                <div className="px-3 pb-3 pl-14">
                  <ol className="space-y-1.5">
                    {r.steps.map((s, i) => (
                      <li key={i} className="flex gap-2 text-sm text-gray-300">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-gray-800 text-[11px] text-gray-400">{i + 1}</span>
                        <span className="leading-relaxed">{s}</span>
                      </li>
                    ))}
                  </ol>
                  <Link to={r.to} className="btn-secondary mt-3 inline-flex items-center gap-1 text-xs">
                    {r.cta} <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
