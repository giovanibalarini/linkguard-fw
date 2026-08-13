import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { NavLink } from 'react-router-dom';
import { Timer, Check, RotateCcw, HelpCircle, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import { anchorFrom, countdownNow, formatCountdown, fullBannerShown, subscribeFullBanner } from '../lib/pendingWindow';
import type { CountdownAnchor } from '../lib/pendingWindow';
import type { FirewallPendingChange, FirewallPendingResponse } from '../types';

/**
 * A faixa do confirmar-ou-reverte em QUALQUER tela do painel (M-5 da revisão
 * final da Fase C2).
 *
 * Por que ela existe fora da tela de firewall: os 90 segundos correm onde o
 * operador estiver. Ele aplica uma regra de escopo input, vai para o Painel ou
 * para Hosts conferir se a rede continua de pé — que é exatamente o que se pede
 * a ele que faça — e, até aqui, não via relógio nenhum: a contagem e os dois
 * botões só existiam na aba "Grupos de regras". Perder o prazo sem ver a
 * contagem significa a alteração legítima dele sendo desfeita sozinha, e a
 * edição do firewall travada por 90 segundos sem explicação na tela.
 *
 * Ela é compacta de propósito. A faixa completa — o que a reversão desfaz e o
 * que ela não desfaz, a explicação da trava, o estado "revertendo" — continua na
 * tela de grupos, que é onde cabe ler tudo isso; esta aqui responde às três
 * perguntas que não podem esperar: quanto tempo falta, o que está pendente e
 * como resolver. Por isso ela some enquanto a completa está montada — duas
 * faixas empilhadas dizendo a mesma coisa é ruído no minuto em que ruído é caro
 * —, e é a completa que declara isso (claimFullBanner), não a rota: ela mora na
 * ABA "Grupos de regras", e nas outras abas da tela de firewall é esta aqui que
 * tem de aparecer.
 *
 * Ela não recarrega nada de outras telas quando a janela fecha: cada tela cuida
 * dos dados dela. O que ela garante é que o operador vê o relógio e alcança os
 * dois botões de onde estiver.
 */
export default function PendingWindowBanner() {
  const { can, permsLoaded } = useAuth();
  const canRead = can('firewall.read');
  const canWrite = can('firewall.write');
  // Enquanto a faixa COMPLETA estiver montada (aba "Grupos de regras"), quem
  // manda é ela.
  const hidden = useSyncExternalStore(subscribeFullBanner, fullBannerShown, fullBannerShown);

  const [pending, setPending] = useState<FirewallPendingChange | null>(null);
  // O terceiro estado: o GET falhou. Nunca vira "não há nada pendente" — essa
  // afirmação, errada, é o operador concluindo que já confirmou.
  const [unknown, setUnknown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [now, setNow] = useState(() => Date.now());
  const [anchor, setAnchor] = useState<CountdownAnchor>({ at: Date.now(), left: null });
  const pendingRef = useRef<FirewallPendingChange | null>(null);

  const take = (next: FirewallPendingChange | null) => {
    pendingRef.current = next;
    setPending(next);
    setUnknown(false);
    if (next) {
      setAnchor(anchorFrom(next));
      setNow(Date.now());
    }
  };

  const refresh = async () => {
    if (!canRead) return;
    try {
      const { data } = await client.get<FirewallPendingResponse>('/api/nftables/pending');
      take(data?.pending ?? null);
    } catch {
      // Sem `setPending(null)`: o último pendente conhecido continua na tela.
      setUnknown(true);
    }
  };

  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  // O poll é o mesmo de 3 s da faixa da tela de grupos — é ele que faz a faixa
  // aparecer quando OUTRO admin aplicou a mudança. A condição é só a permissão
  // de leitura: ele continua rodando com a faixa escondida (`hidden` apenas não
  // desenha), porque um GET a cada 3 s é barato e assim sair da aba de grupos
  // para qualquer outra tela já mostra o relógio no primeiro quadro, em vez de
  // até três segundos depois.
  useEffect(() => {
    if (!canRead) return;
    refreshRef.current();
    let alive = true;
    const t = setInterval(() => { if (alive) refreshRef.current(); }, 3000);
    return () => { alive = false; clearInterval(t); };
  }, [canRead]);

  const hasPending = !!pending;
  useEffect(() => {
    if (!hasPending) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [hasPending]);

  const seconds = pending ? countdownNow(anchor, now) : null;

  const resolve = async (path: string) => {
    const p = pending;
    if (!p) return;
    setBusy(true);
    setErr('');
    try {
      await client.post(path, { id: p.id });
      await refresh();
    } catch (e) {
      const ax = e as { response?: { data?: { error?: string } }; message?: string };
      setErr(ax?.response?.data?.error || ax?.message || 'falha na operação');
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  if (!permsLoaded || !canRead || hidden) return null;
  if (!pending && !unknown) return null;

  // Sem pendente conhecido e com o GET falhando: dizer que não se sabe é o
  // mínimo honesto — pode haver um relógio correndo agora.
  if (!pending) {
    return (
      <div className="flex items-start gap-3 px-4 py-2.5 bg-yellow-500/10 border-b border-yellow-500/30 text-yellow-200 text-sm flex-shrink-0">
        <HelpCircle className="w-4 h-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
        <p className="flex-1">
          Não foi possível saber se há uma alteração de firewall aguardando confirmação. Se você acabou de aplicar uma, ela pode estar contando os 90 segundos agora —{' '}
          <NavLink to="/firewall" className="underline font-medium hover:text-yellow-100">abra os grupos de regras</NavLink>.
        </p>
      </div>
    );
  }

  // Revertendo: não cabe confirmar nem reverter (o backend recusa os dois), e a
  // edição está LIBERADA — o texto não pode prometer trava.
  if (pending.reverting) {
    return (
      <div className="flex items-start gap-3 px-4 py-2.5 bg-blue-500/10 border-b border-blue-500/30 text-blue-100 text-sm flex-shrink-0">
        <RotateCcw className="w-4 h-4 mt-0.5 flex-shrink-0 animate-spin" aria-hidden="true" />
        <p className="flex-1">
          Uma alteração de firewall está sendo revertida ({pending.summary}). Os grupos e as regras já voltaram ao estado anterior; falta o firewall aceitar, e o LinkGuard repete até conseguir.{' '}
          <NavLink to="/firewall" className="underline font-medium hover:text-blue-50">Ver na tela de firewall</NavLink>.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2 px-4 py-2.5 bg-amber-500/10 border-b border-amber-500/30 text-amber-100 text-sm flex-shrink-0">
      <div className="flex items-center gap-2 shrink-0">
        <Timer className="w-4 h-4 text-amber-400" aria-hidden="true" />
        {/* "reverte em", nunca "expira em": o relógio diz o que vai acontecer. */}
        <span className="text-xs text-amber-300/80">reverte em</span>
        <span className="font-mono text-lg font-semibold text-amber-300 tabular-nums">
          {seconds === null ? '—' : formatCountdown(seconds)}
        </span>
      </div>
      <div className="min-w-0 flex-1">
        <p>
          Uma alteração no tráfego destinado ao próprio firewall aguarda confirmação —{' '}
          <span className="text-amber-200/80 break-words">{pending.summary}</span>. Teste o acesso que importa (SSH, este painel) antes de confirmar.
        </p>
        {/* O aviso que torna esta janela honesta (spec §5). Um grupo restrito a
            `ct state new` não derruba a conexão que já está de pé: testar o
            acesso na aba aberta, ou no SSH já conectado, passa mesmo com o
            bloqueio valendo — e ele morde na próxima reconexão, quando não há
            mais reversão automática nenhuma. Ele só aparece quando o servidor
            diz que é esse o caso: numa janela comum a sessão cai de verdade, o
            teste vale sozinho, e um aviso em toda faixa é um aviso que o
            operador aprende a pular. */}
        {pending.new_connections_only && (
          <p className="mt-1 flex items-start gap-1.5 text-amber-50">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-300" aria-hidden="true" />
            <span>
              Este grupo vale só para conexões novas. <strong className="font-semibold">A sua sessão atual não é afetada</strong> — abra uma conexão nova (outro terminal SSH, uma aba anônima) para testar de verdade antes de confirmar.
            </span>
          </p>
        )}
        {err && <p className="text-xs text-red-300 mt-1">Erro: {err}</p>}
        {unknown && (
          <p className="text-xs text-amber-200/70 mt-1">
            O painel não conseguiu reler o estado desta janela agora — o que está acima é a última leitura boa. Continua tentando.
          </p>
        )}
      </div>
      {canWrite ? (
        <div className="flex gap-2 shrink-0">
          <button
            onClick={() => resolve('/api/nftables/pending/confirm')}
            disabled={busy}
            className="btn-primary text-xs flex items-center justify-center gap-1.5 disabled:opacity-50"
          >
            <Check className="w-3.5 h-3.5" aria-hidden="true" /> Confirmar acesso
          </button>
          <button
            onClick={() => resolve('/api/nftables/pending/revert')}
            disabled={busy}
            className="btn-secondary text-xs flex items-center justify-center gap-1.5 disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" /> Reverter agora
          </button>
        </div>
      ) : (
        <NavLink to="/firewall" className="underline font-medium hover:text-amber-50 shrink-0">Ver na tela de firewall</NavLink>
      )}
    </div>
  );
}
