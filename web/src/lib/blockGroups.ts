import type { FirewallGroup, FirewallGroupKind } from '../types';

// Os dois kinds que o LinkGuard mantém — espelham
// internal/nftables/groups.go (systemGroupForwardRules).
export const KIND_BLOCKED_HOSTS = 'blocked_hosts';
export const KIND_BLOCKLIST = 'blocklist';

// isSystemGroup é uma lista fechada dos dois kinds de sistema, nunca
// `kind !== 'admin'`: kind vazio (linhas criadas antes da coluna existir) e
// qualquer kind desconhecido contam como grupo do admin, que é o lado seguro
// — o erro caro seria travar a edição de um grupo que o admin criou. Mesma
// regra do backend.
export function isSystemGroup(kind: string): boolean {
  return kind === KIND_BLOCKED_HOSTS || kind === KIND_BLOCKLIST;
}

/**
 * BlockEnforcement é a resposta honesta a "este bloqueio está mesmo em
 * vigor?".
 *
 * Existe porque, desde que os bloqueios viraram grupos reordenáveis, marcar
 * um host como bloqueado deixou de ser garantia de nada: o grupo pode estar
 * desligado, as linhas de drop podem não estar vivas na forward, ou o admin
 * pode ter arrastado o bloqueio para depois de um grupo dele que faz accept.
 * Nos três casos o painel mostraria "bloqueado" enquanto o tráfego passa —
 * exatamente a confiança falsa que este produto existe para eliminar.
 *
 *  - `unknown`  não deu para verificar (sem permissão de firewall, falha ao
 *               carregar, ou o grupo não aparece na lista). Nunca afirmar
 *               "em vigor" nem "não está em vigor" a partir daqui.
 *  - `ok`       as linhas estão vivas e nada acima delas pode liberar antes.
 *  - `off`      o grupo do sistema está desligado: as linhas não são emitidas.
 *  - `not_applied` está ligado, mas o firewall não confirma as linhas na
 *               forward (reconciliação falhou ou ainda não alcançou).
 *  - `shadowed` está em vigor, porém depois de grupos do admin ligados, que
 *               podem decidir (accept) antes de o pacote chegar ao bloqueio.
 */
export type BlockEnforcementStatus = 'unknown' | 'ok' | 'off' | 'not_applied' | 'shadowed';

export interface BlockEnforcement {
  status: BlockEnforcementStatus;
  /** Frase curta com o motivo; vazia quando status é `ok`. */
  reason: string;
  /** O que fazer para resolver; vazia quando status é `ok`. */
  fix: string;
  /** Nomes dos grupos do admin ligados acima do bloqueio (status `shadowed`). */
  above: string[];
  /** O grupo do sistema em si, quando encontrado. */
  group?: FirewallGroup;
}

/**
 * blockEnforcement cruza um bloqueio com o estado do grupo de sistema que o
 * representa. `groups` é null quando a lista não pôde ser consultada — o que
 * dá `unknown`, e não um "está tudo certo" inventado.
 *
 * A ordem é a da lista: os grupos vêm ordenados por `position` pela API, mas
 * a função reordena por conta própria para não depender disso.
 */
export function blockEnforcement(
  groups: FirewallGroup[] | null,
  kind: FirewallGroupKind,
): BlockEnforcement {
  const none: BlockEnforcement = { status: 'unknown', reason: '', fix: '', above: [] };
  if (!groups) return none;

  const ordered = groups.slice().sort((a, b) => a.position - b.position);
  const idx = ordered.findIndex((g) => g.kind === kind);
  if (idx < 0) {
    return {
      status: 'unknown',
      reason: 'O grupo de bloqueio não aparece na lista de grupos do firewall.',
      fix: 'Confira a aba "Grupos de regras" do Firewall.',
      above: [],
    };
  }
  const group = ordered[idx];

  if (!group.enabled) {
    return {
      status: 'off',
      reason: `O grupo "${group.name}" está desligado — as linhas de bloqueio não são emitidas.`,
      fix: `Ligue o grupo "${group.name}" em Firewall › Grupos de regras.`,
      above: [],
      group,
    };
  }
  if (!group.applied) {
    return {
      status: 'not_applied',
      reason: `O firewall não confirma as linhas do grupo "${group.name}" na chain forward.`,
      fix: 'Confira a aba "Visão geral" do Firewall: a última aplicação pode ter falhado.',
      above: [],
      group,
    };
  }

  // Só grupo do admin LIGADO conta: um grupo desligado não põe linha nenhuma
  // na forward, então não tem como liberar nada antes — avisar por causa dele
  // seria alarme falso.
  const above = ordered
    .slice(0, idx)
    .filter((g) => !isSystemGroup(g.kind) && g.enabled)
    .map((g) => g.name);
  if (above.length > 0) {
    return {
      status: 'shadowed',
      reason: 'Regras acima deste bloqueio podem liberar tráfego que ele descartaria.',
      fix: `Em Firewall › Grupos de regras, arraste "${group.name}" para cima de ${above.length === 1 ? `"${above[0]}"` : 'seus grupos'}.`,
      above,
      group,
    };
  }

  return { status: 'ok', reason: '', fix: '', above: [], group };
}
