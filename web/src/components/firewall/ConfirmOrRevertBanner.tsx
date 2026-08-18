/**
 * A cara da máquina do confirmar-ou-reverte (spec §5) — os três estados que a
 * janela de 90 segundos pode ter, e nenhum deles é "a faixa some".
 *
 * Ela recebe a máquina inteira num objeto só (`cor`) em vez de sete escalares
 * soltos. Não é economia de digitação: `pending`, `pendingUnknown`,
 * `pendingSeconds`, `busy`, `confirmPending` e `revertPending` são um estado
 * só, e passá-los separados é como uma delas se perde em silêncio — uma faixa
 * que conta errado, ou dois botões que não fazem nada.
 *
 * Não confundir com `components/PendingWindowBanner.tsx`: aquela é a faixa
 * COMPACTA do Layout, a que aparece nas outras telas. Esta é a completa, a que
 * tem o id da janela e os dois botões.
 */

import { Timer, AlertTriangle, Check, RotateCcw, HelpCircle, RefreshCw } from 'lucide-react';
import { formatCountdown } from '../../lib/pendingWindow';
import { useI18n } from '../../i18n';
import type { ConfirmOrRevert } from '../../lib/useConfirmOrRevert';

export default function ConfirmOrRevertBanner({ cor, canWrite }: { cor: ConfirmOrRevert; canWrite: boolean }) {
  const { pending, pendingUnknown, pendingSeconds, busy } = cor;
  const { t } = useI18n();
  return (
    <>
      {/* A mudança de escopo input já está APLICADA quando esta faixa
          aparece: em 90 segundos o LinkGuard a desfaz sozinho, a menos que
          alguém confirme aqui. É a única parte da tela que sabe o id da
          janela, e confirmar e reverter o exigem — sem ela, a única saída
          seria uma chamada direta à API. */}
      {pending && !pending.reverting && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-start gap-3">
            <div className="flex items-center gap-2 shrink-0">
              {/* O relógio diz "reverte em", nunca "expira em": ele informa o
                  que vai acontecer, não que um prazo terminou. E o número sai
                  do seconds_left do SERVIDOR, recalculado a cada resposta —
                  recarregar a página não reinicia nada, e o relógio da estação
                  do operador não tem como deslocá-lo. */}
              <Timer className="w-5 h-5 text-amber-400" aria-hidden="true" />
              <span className="text-xs text-amber-300/80">{t('fw.confirm.countdown')}</span>
              <span className="font-mono text-2xl font-semibold text-amber-300 tabular-nums" aria-live="off">
                {pendingSeconds === null ? '—' : formatCountdown(pendingSeconds)}
              </span>
            </div>
            <div className="min-w-0 flex-1 text-sm text-amber-100">
              <p className="font-medium">{t('fw.confirm.title')}</p>
              <p className="text-amber-200/80 mt-0.5 break-words">
                {pending.summary}
                <span className="text-amber-200/50">{t('fw.confirm.appliedBy')}</span>
                <span className="font-mono">{pending.applied_by || t('fw.confirm.unknownUser')}</span>
              </p>
              <p className="text-amber-200/70 text-xs mt-1.5">
                {t('fw.confirm.testAccess')}{' '}
                {t(pendingSeconds === 0 ? 'fw.confirm.deadlinePassed' : 'fw.confirm.deadlineRunning')}
              </p>
              {/* O aviso da spec §5, e a razão de esta feature poder existir.
                  Um grupo restrito a `ct state new` NÃO derruba a sessão do
                  operador: ele testaria na aba que já estava aberta, veria
                  tudo funcionando, confirmaria — e descobriria o bloqueio na
                  próxima reconexão, quando já não há rede de proteção
                  nenhuma. Aqui ele ganha caixa própria, e não mais uma linha
                  na mesma parede de texto âmbar, porque é a única frase desta
                  faixa que contradiz o que o operador acabou de testar.

                  E ele NÃO aparece numa janela comum (o servidor decide, em
                  new_connections_only): ali a sessão cai de verdade e o teste
                  vale sozinho — um aviso em toda janela vira ruído e ninguém
                  lê. */}
              {pending.new_connections_only && (
                <div className="mt-2 rounded-lg border border-amber-400/60 bg-amber-400/10 px-3 py-2 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" aria-hidden="true" />
                  <p className="text-xs text-amber-50">
                    {t('fw.confirm.newConnectionsOnly')}{' '}
                    <strong className="font-semibold">{t('fw.confirm.newConnectionsOnly.strong')}</strong>{' '}
                    {t('fw.confirm.newConnectionsOnly.tail')}
                  </p>
                </div>
              )}
              {/* O que a reversão desfaz, dito antes de alguém apertar
                  qualquer botão: o snapshot cobre `groups` e `rules` e mais
                  nada. Acreditar numa volta completa que não aconteceu é o
                  pior resultado possível aqui. */}
              <p className="text-amber-200/60 text-xs mt-1.5">
                A reversão desfaz apenas <span className="text-amber-200">grupos e regras</span>. Bloqueios por host, encaminhamentos de porta e o NTP não voltam atrás — o que você mudou neles durante a janela continua valendo.
              </p>
            </div>
          </div>
          {canWrite ? (
            <div className="flex flex-col sm:flex-row gap-2">
              <button
                onClick={cor.confirmPending}
                disabled={busy}
                className="btn-primary text-sm flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <Check className="w-4 h-4" aria-hidden="true" /> Confirmar acesso
              </button>
              <button
                onClick={cor.revertPending}
                disabled={busy}
                className="btn-secondary text-sm flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <RotateCcw className="w-4 h-4" aria-hidden="true" /> Reverter agora
              </button>
            </div>
          ) : (
            <p className="text-xs text-amber-200/70">
              {t('fw.confirm.needWrite')}
            </p>
          )}
          {pendingUnknown && (
            <p className="text-xs text-amber-200/70 flex items-start gap-1.5">
              <HelpCircle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
              <span>{t('fw.confirm.staleRead')}</span>
            </p>
          )}
        </div>
      )}

      {/* Revertendo: o estado anterior JÁ voltou ao banco e o que falta é o
          firewall vivo aceitar — o LinkGuard repete até conseguir. Aqui não
          cabe nenhum dos dois botões (o backend recusa confirmar e reverter), e
          o texto tem que dizer que a reversão está em curso, não perguntar.
          E não pode prometer trava: a edição está LIBERADA neste estado, do
          mesmo jeito que no backend — é assim que o operador consegue apagar a
          regra que está fazendo o `nft` recusar. */}
      {pending?.reverting && (
        <div className="rounded-xl border border-blue-500/40 bg-blue-500/10 p-4 flex flex-col sm:flex-row sm:items-start gap-3">
          <RotateCcw className="w-5 h-5 text-blue-400 shrink-0 animate-spin" aria-hidden="true" />
          <div className="min-w-0 flex-1 text-sm text-blue-100">
            <p className="font-medium">{t('fw.confirm.reverting.title')}</p>
            <p className="text-blue-200/80 mt-0.5 break-words">{pending.summary}</p>
            <p className="text-blue-200/70 text-xs mt-1.5">
              {t('fw.confirm.reverting.body')}
            </p>
            <p className="text-blue-200/70 text-xs mt-1.5">
              {t('fw.confirm.reverting.editable')}
            </p>
            <p className="text-blue-200/60 text-xs mt-1.5">
              {t('fw.confirm.reverting.scope')}
            </p>
          </div>
        </div>
      )}

      {/* Desconhecido: a leitura falhou e NÃO há última leitura para mostrar.
          Sumir seria a tela afirmando "não há nada aguardando" — e o operador
          concluindo que já confirmou, quando o relógio pode estar correndo. */}
      {!pending && pendingUnknown && (
        <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/5 p-4 flex flex-col sm:flex-row sm:items-start gap-3">
          <HelpCircle className="w-5 h-5 text-yellow-400 shrink-0" aria-hidden="true" />
          <div className="min-w-0 flex-1 text-sm text-yellow-100">
            <p className="font-medium">{t('fw.confirm.unknown.title')}</p>
            <p className="text-yellow-200/70 text-xs mt-1">
              {t('fw.confirm.unknown.body')}
            </p>
          </div>
          <button onClick={() => cor.refreshPending()} className="btn-secondary text-xs shrink-0 flex items-center justify-center gap-2">
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> {t('fw.confirm.retry')}
          </button>
        </div>
      )}
    </>
  );
}
