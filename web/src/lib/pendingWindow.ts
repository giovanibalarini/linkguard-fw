import type { FirewallPendingChange } from '../types';

/**
 * A contagem regressiva da janela de confirmação (Fase C2, spec §5), num lugar
 * só porque ela é desenhada em DOIS: a faixa completa da tela de grupos de
 * regras e a faixa compacta que segue o operador por qualquer tela do painel
 * (M-5 da revisão final). Duas cópias divergiriam justamente no número que o
 * operador usa para decidir se ainda dá tempo de testar o SSH.
 *
 * countdownAnchor é o ponto de partida: quantos segundos o SERVIDOR disse que
 * faltavam, e o instante local em que essa resposta chegou.
 *
 * A âncora existe porque quem conta é o servidor e quem desenha é o navegador.
 * O relógio local só mede o INTERVALO desde a resposta (uma duração, que não
 * depende de os dois relógios concordarem); o valor absoluto vem sempre de
 * `seconds_left`, e cada resposta do poll re-ancora. Um relógio de estação
 * adiantado em 40 segundos deixou de errar o número.
 *
 * `left` null é "não sei" — a faixa mostra como não sabido, nunca como zero,
 * que afirmaria que o prazo acabou.
 */
export interface CountdownAnchor {
  at: number;
  left: number | null;
}

/**
 * anchorFrom lê a contagem que o servidor mandou. `expires_at` é a reserva para
 * um corpo sem `seconds_left` (servidor mais velho que este painel): pior que a
 * contagem do servidor, melhor que nenhuma contagem.
 */
export function anchorFrom(p: FirewallPendingChange): CountdownAnchor {
  const now = Date.now();
  if (Number.isFinite(p.seconds_left)) {
    return { at: now, left: Math.max(0, Math.trunc(p.seconds_left)) };
  }
  const t = Date.parse(p.expires_at);
  return { at: now, left: Number.isNaN(t) ? null : Math.max(0, Math.round((t - now) / 1000)) };
}

// countdownNow desconta localmente o tempo passado desde a âncora — é o que dá
// a suavidade de segundo a segundo entre dois polls. O servidor corrige o ponto
// de partida; daqui até a próxima resposta, quem anda é o relógio local.
export function countdownNow(a: CountdownAnchor, now: number): number | null {
  if (a.left === null) return null;
  return Math.max(0, a.left - Math.max(0, Math.round((now - a.at) / 1000)));
}

// formatCountdown escreve o prazo do jeito que se lê de relance: segundos
// enquanto cabem em segundos, m:ss depois disso.
export function formatCountdown(s: number): string {
  if (s < 60) return `${s} s`;
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/**
 * Quem está desenhando a faixa completa neste instante.
 *
 * As duas faixas do confirmar-ou-reverte não podem aparecer juntas: a completa
 * (tela de grupos de regras, com o que a reversão desfaz e o que ela não desfaz)
 * e a compacta do Layout, que segue o operador por qualquer tela. Duas
 * empilhadas dizendo a mesma coisa é ruído no minuto em que ruído é caro.
 *
 * A condição NÃO pode ser a rota `/firewall`: a faixa completa mora dentro de
 * FirewallGroups, que só existe na ABA "Grupos de regras" — nas outras abas
 * (Visão geral, Steering, Encaminhamentos, Ruleset, Backups) a tela ficaria sem
 * faixa nenhuma, que é exatamente o buraco que a faixa global existe para
 * fechar. Quem sabe a resposta é o componente que está montado, e é ele que a
 * declara aqui.
 *
 * Um contador, e não um booleano: durante a troca de aba o React pode montar o
 * novo antes de desmontar o velho, e um booleano deixaria a faixa global sumida
 * para sempre.
 */
let fullBannerOwners = 0;
const fullBannerListeners = new Set<() => void>();

// claimFullBanner declara "a faixa completa está na tela". Devolve a função que
// desfaz a declaração — a forma que um useEffect() consome direto.
export function claimFullBanner(): () => void {
  fullBannerOwners++;
  fullBannerListeners.forEach((fn) => fn());
  return () => {
    fullBannerOwners = Math.max(0, fullBannerOwners - 1);
    fullBannerListeners.forEach((fn) => fn());
  };
}

export function subscribeFullBanner(fn: () => void): () => void {
  fullBannerListeners.add(fn);
  return () => { fullBannerListeners.delete(fn); };
}

export function fullBannerShown(): boolean {
  return fullBannerOwners > 0;
}
