/**
 * A máquina do confirmar-ou-reverte da tela de grupos — e não uma parte da
 * tela, apesar de ter nascido dentro dela.
 *
 * O que ela guarda: a janela de 90 segundos em aberto, a âncora da contagem
 * regressiva, o terceiro estado (o GET falhou), a trava que o backend impõe
 * enquanto a janela corre, e as duas marcas de ref que decidem se uma janela
 * que sumiu foi resolvida por nós ou pelo relógio. O que ela faz: o poll de 3 s,
 * o relógio de 1 s, a releitura imediata no vencimento, e o `run` por onde passa
 * TODA mutação de grupo e de regra.
 *
 * Ela saiu de `components/FirewallGroups.tsx` antes de a tela ser fatiada, e
 * nessa ordem de propósito: as quatro peças visuais dependem de `busy`, de
 * `locked` e de `run`, e cortá-las com a máquina ainda espalhada pelo meio
 * significaria seis a oito props por peça — que é onde uma delas se perde em
 * silêncio, e o silêncio aqui é uma tela dizendo que dá para editar enquanto o
 * backend responde 409, ou um relógio que não conta.
 *
 * O que ela NÃO faz: recarregar grupos, regras e membros. Isso é `load`, que
 * mora na tela e chega por parâmetro — a máquina só sabe QUANDO recarregar.
 */

import { useEffect, useRef, useState } from 'react';
import client from '../api/client';
import { errMsg } from './apiError';
import { anchorFrom, countdownNow } from './pendingWindow';
import type { CountdownAnchor } from './pendingWindow';
// Quem fechou a janela — a conta que decide se o aviso da reversão por prazo
// sai ou é engolido. Ela mora fora daqui porque ganhou asserção própria
// (resolutionMark.check.ts): dentro do hook, nada a alcançava sem montar a tela
// inteira e esperar noventa segundos.
import { claim, consume, release } from './resolutionMark';
import type { FirewallPendingChange, FirewallPendingResponse, MsgLevel } from '../types';

// locked é a trava do backend refletida na tela — nada mais e nada menos.
// Aguardando confirmação, TODA mutação de grupo e de regra responde 409, e um
// 409 cru numa tela sem explicação é pior que um botão desabilitado que diz
// por quê: daí lockReason, no `title` de cada controle e no texto ao lado.
export const LOCK_REASON = 'Há uma alteração aguardando confirmação. Confirme o acesso ou reverta agora, na faixa no topo, para voltar a editar.';

export interface ConfirmOrRevert {
  /** A janela em aberto, ou null quando não há nenhuma. */
  pending: FirewallPendingChange | null;
  /** O terceiro estado: a leitura falhou. Nunca vira "não há nada pendente". */
  pendingUnknown: boolean;
  /** Segundos que faltam, do relógio do SERVIDOR; null quando não há janela. */
  pendingSeconds: number | null;
  busy: boolean;
  setBusy: (b: boolean) => void;
  locked: boolean;
  lockReason: string;
  editDisabled: boolean;
  refreshPending: () => Promise<void>;
  adoptPending: (res: unknown) => void;
  run: (fn: () => Promise<unknown>, ok: string) => Promise<boolean>;
  confirmPending: () => void;
  revertPending: () => void;
}

export function useConfirmOrRevert(
  load: (quiet?: boolean) => Promise<void>,
  onMsg: (m: string, level?: MsgLevel) => void,
): ConfirmOrRevert {
  // pending é a janela de confirmação em aberto (null = não há nenhuma).
  // pendingUnknown é o terceiro estado, e ele existe porque os outros dois não
  // cobrem "o GET falhou": a faixa sumindo por causa de um GET que não
  // respondeu seria a tela AFIRMANDO que não há nada aguardando, no minuto em
  // que confirmar é a única coisa que devolve o acesso do operador. Estado
  // desconhecido se mostra como desconhecido.
  const [pending, setPending] = useState<FirewallPendingChange | null>(null);
  const [pendingUnknown, setPendingUnknown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  // A âncora da contagem regressiva, recolocada a cada resposta do servidor
  // (ver CountdownAnchor). Sem pendente ela não é lida.
  const [anchor, setAnchor] = useState<CountdownAnchor>({ at: Date.now(), left: null });
  // pendingRef acompanha o último pendente visto para que o poll saiba
  // distinguir "continua igual" de "sumiu" sem depender do estado do React.
  const pendingRef = useRef<FirewallPendingChange | null>(null);
  // resolvedRef guarda o id da janela que NÓS acabamos de confirmar ou
  // reverter: sem ele, o poll seguinte veria o pendente sumir e anunciaria uma
  // reversão automática que não houve. Quem mexe nele são claim/release/consume
  // — ver resolutionMark.
  const resolvedRef = useRef('');
  // expiredRef marca a janela cujo vencimento já disparou uma releitura, para
  // que o relógio chegando a zero peça o estado ao servidor uma vez, e não a
  // cada segundo.
  const expiredRef = useRef('');

  // `load` e `onMsg` são recriados a cada renderização da tela; os refs
  // garantem que o poll — montado uma vez, com deps [] — chame sempre a versão
  // atual. Sem isso ele fecharia sobre o `load` da PRIMEIRA renderização, que
  // ainda achava que não havia permissão para ler o inventário (/api/auth/me é
  // assíncrono), e a lista de hosts bloqueados perderia nome e MAC toda vez que
  // uma janela se fechasse.
  const loadRef = useRef(load);
  loadRef.current = load;
  const msgRef = useRef(onMsg);
  msgRef.current = onMsg;

  // takePending é o único lugar que adota um pendente vindo do servidor — do
  // GET ou do corpo da própria mutação. Junto com ele vem sempre a âncora da
  // contagem: toda resposta re-ancora, e é isso que mantém o relógio da tela
  // preso ao do firewall em vez de ao da estação do operador.
  const takePending = (next: FirewallPendingChange | null) => {
    pendingRef.current = next;
    setPending(next);
    setPendingUnknown(false);
    if (next) {
      setAnchor(anchorFrom(next));
      setNow(Date.now());
    }
  };

  /**
   * refreshPending lê a janela de confirmação — a fonte do id que confirmar e
   * reverter exigem, e da contagem regressiva.
   *
   * Três coisas que ela faz de propósito:
   *
   *  - falha NÃO vira `null`. Vira pendingUnknown, com o último pendente
   *    conhecido ainda na tela (regra do projeto: nada de dado falso, e "não
   *    há nada aguardando" é um dado);
   *  - o pendente que SUMIU sem que a gente tenha confirmado ou revertido só
   *    pode ter sido o prazo vencendo — o operador precisa saber que a
   *    alteração foi desfeita, e a tela precisa recarregar para mostrar os
   *    grupos como voltaram a ser;
   *  - ela nunca chama a si mesma via load(): load() recarrega grupos, regras
   *    e membros, e só o poll e as ações chamam as duas.
   */
  const refreshPending = async () => {
    try {
      const { data } = await client.get<FirewallPendingResponse>('/api/nftables/pending');
      const next = data?.pending ?? null;
      const prev = pendingRef.current;
      takePending(next);
      if (prev && !next) {
        // A janela fechou. Só a MENSAGEM depende de quem a fechou; o recarregar
        // é incondicional, e a diferença é visível: uma reversão que a gente
        // pediu mas que só terminou depois (o firewall vivo demorou a aceitar,
        // ou o watchdog concluiu por nós) deixava na tela um grupo que já não
        // existia mais no banco — a tela afirmando uma regra de firewall que
        // não está lá.
        if (!consume(resolvedRef, prev.id)) {
          // Em ÂMBAR, não em verde: uma alteração desfeita pelo relógio não é
          // uma boa notícia, e a cor é a primeira coisa que o operador lê.
          msgRef.current('O prazo acabou sem confirmação: a alteração foi revertida e os grupos e as regras voltaram ao estado anterior.', 'warn');
        }
        await loadRef.current();
      }
    } catch {
      // Sem `setPending(null)` aqui, e é o ponto inteiro deste ramo.
      setPendingUnknown(true);
    }
  };

  // O poll roda com deps [] (um intervalo só, montado uma vez), então ele
  // fecharia sobre o refreshPending da PRIMEIRA renderização. O ref aponta
  // sempre para a versão atual.
  const refreshRef = useRef(refreshPending);
  refreshRef.current = refreshPending;

  // O pendente é lido a cada 3 s — o mesmo intervalo da faixa de confirmação
  // das Interfaces, que resolve o mesmo problema. Ele é o que faz a faixa
  // aparecer quando OUTRO admin aplicou a mudança, e o que faz ela sumir
  // quando a janela se fecha por qualquer caminho.
  useEffect(() => {
    let alive = true;
    const t = setInterval(() => { if (alive) refreshRef.current(); }, 3000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // O relógio da tela só corre quando há o que contar. `hasPending` (e não o
  // objeto `pending`) é a dependência de propósito: o poll devolve um objeto
  // novo a cada 3 s, e depender dele reiniciaria o intervalo a cada volta.
  const hasPending = !!pending;
  useEffect(() => {
    if (!hasPending) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [hasPending]);

  const pendingSeconds = pending ? countdownNow(anchor, now) : null;

  // Prazo vencido com a página aberta: pede o estado ao servidor na hora, em
  // vez de esperar o próximo poll de 3 s olhando uma faixa que já morreu. Uma
  // vez por janela (expiredRef) — a reversão do watchdog leva o tempo que
  // levar, e o relógio continua em zero enquanto ela não termina.
  useEffect(() => {
    if (!pending || pending.reverting || pendingSeconds === null || pendingSeconds > 0) return;
    if (expiredRef.current === pending.id) return;
    expiredRef.current = pending.id;
    refreshRef.current();
  }, [pending, pendingSeconds]);

  // adoptPending pega a janela que a PRÓPRIA mutação armou: toda mutação de
  // grupo ou regra que abre uma janela devolve o pendente no corpo do 200. Sem
  // isto, a faixa só apareceria no próximo poll — até 3 segundos em que o
  // operador acabou de aplicar uma mudança que pode cortar o acesso dele e a
  // tela não mostra nem o relógio nem o botão de confirmar.
  const adoptPending = (res: unknown) => {
    const p = (res as { data?: { pending?: FirewallPendingChange | null } } | undefined)?.data?.pending;
    if (!p) return;
    takePending(p);
  };

  // run reports whether the call actually succeeded, so a form only closes
  // when the server took it: the backend refuses IPv6, bad CIDRs and
  // anything `nft -c` rejects, and closing on failure would throw away what
  // the admin typed along with the chance to fix it.
  const run = async (fn: () => Promise<unknown>, ok: string): Promise<boolean> => {
    setBusy(true);
    msgRef.current('');
    try {
      const res = await fn();
      adoptPending(res);
      msgRef.current(ok);
      await loadRef.current();
      await refreshPending();
      return true;
    } catch (e) {
      msgRef.current('Erro: ' + errMsg(e));
      // Uma mutação que falhou não deixa a tela como estava: a reversão que
      // não conclui, por exemplo, já restaurou o BANCO e devolve 500 — sem
      // este load a lista continuaria mostrando o grupo que acabou de deixar
      // de existir. E o pendente é relido porque a recusa pode ter sido
      // justamente a trava (409): é o que troca o "Erro: ..." solto pela faixa
      // com o relógio e os dois botões.
      await loadRef.current(true);
      await refreshPending();
      return false;
    } finally {
      setBusy(false);
    }
  };

  // ─── Confirmar-ou-reverte ──────────────────────────────────────────────
  // E o estado "revertendo" NÃO tranca, porque o backend não tranca nele — e
  // essa liberação foi deliberada e cara. Neste produto o banco é a verdade e o
  // nftables é o resultado renderizado: com a reversão já concluída no banco, o
  // que resta é uma reconciliação que qualquer mutação seguinte também faz.
  //
  // Travar aqui refazia, pela tela, o beco sem saída que o backend acabou de
  // fechar: numa máquina onde o `nft` recusa persistentemente (a regra passa no
  // `nft -c` e é rejeitada no apply), o painel virava somente-leitura por tempo
  // indefinido — sem apagar a regra que causa a falha, sem confirmar, sem
  // reverter, e com reboot não ajudando. A saída era `sqlite3` na máquina.
  const locked = !!pending && !pending.reverting;
  const editDisabled = busy || locked;

  /**
   * resolve fecha a janela pelo caminho que o operador escolheu.
   *
   * A marca vai ANTES da chamada porque o `run` relê o pendente dentro dele:
   * quando a chamada dá certo, é ela que impede o poll seguinte de anunciar uma
   * reversão automática que não houve.
   *
   * E ela é DESFEITA no ramo de erro, dentro do próprio `fn`, antes de o `run`
   * chegar à releitura dele. Uma chamada que falhou não resolveu janela
   * nenhuma: deixar a marca presa aí fazia a janela — a mesma, que continua
   * correndo — sumir em silêncio quando o prazo vencesse, engolindo a única
   * mensagem que o painel tem para dizer ao operador que a alteração dele foi
   * desfeita. O lado seguro é este: na dúvida, avisar. Ver resolutionMark.
   */
  const resolve = (path: string, ok: string) => {
    const p = pending;
    if (!p) return;
    claim(resolvedRef, p.id);
    run(async () => {
      try {
        // O id vai no corpo porque a janela tem dono: sem ele, confirmar agiria
        // sobre a janela que estiver aberta no instante da chamada — que pode
        // ser a de outro admin, com uma mudança que este operador nunca viu.
        return await client.post(path, { id: p.id });
      } catch (e) {
        release(resolvedRef, p.id);
        throw e;
      }
    }, ok);
  };

  const confirmPending = () => resolve(
    '/api/nftables/pending/confirm',
    'Acesso confirmado: a alteração passa a valer e não será mais revertida.',
  );
  const revertPending = () => resolve(
    '/api/nftables/pending/revert',
    'Alteração revertida: os grupos e as regras voltaram ao estado anterior.',
  );

  return {
    pending, pendingUnknown, pendingSeconds, busy, setBusy,
    locked, lockReason: LOCK_REASON, editDisabled,
    refreshPending, adoptPending, run, confirmPending, revertPending,
  };
}
