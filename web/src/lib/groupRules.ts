// As duas contas da tela de grupos que erram em silêncio: qual linha da chain
// é regra do admin, e onde cada regra de um grupo cai na lista GLOBAL.
//
// Elas moravam dentro de `components/FirewallGroups.tsx` (2.048 linhas), onde
// nada as alcançava sem montar a tela inteira. Aqui são funções puras — sem
// React e sem DOM, pelo mesmo motivo de `series.ts` e `grid.ts`: só assim dão
// para ser conferidas por asserção automática (veja `groupRules.check.ts`).
//
// O que está em jogo não é layout. `/api/nftables/rules/reorder` recebe a
// ordem global de TODAS as regras de TODOS os grupos e recusa lista parcial:
// um índice deslocado em um não reordena a tela errada, ele reescreve a ordem
// de avaliação do firewall — e um `accept` que sobe acima de um `drop` abre o
// que estava fechado, sem nenhuma mensagem de erro.

import type { FirewallGroup, GroupFallthrough, NftChainRule } from '../types';

// ─────────────────────────────────────────────────────────────────────────────
// Mover um item de lista
// ─────────────────────────────────────────────────────────────────────────────

/**
 * moveItem tira o item de `from` e o enfia em `to`, sem mutar a entrada.
 *
 * Semântica de arrastar-e-soltar: `to` é o índice de destino JÁ NA LISTA SEM O
 * item arrastado — que é o que o `splice` de duas etapas faz naturalmente, e o
 * que a tela quer dizer com "soltei em cima da linha i". Descer um item para
 * um índice maior, portanto, o deixa ANTES do item que ocupava aquele slot.
 *
 * É a mesma função para arrastar grupo e para arrastar regra dentro do grupo.
 */
export function moveItem<T>(arr: readonly T[], from: number, to: number): T[] {
  const next = arr.slice();
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
}

// ─────────────────────────────────────────────────────────────────────────────
// Separar o que a chain do grupo carrega
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A forma mínima que `splitGroupRules` lê de um grupo.
 *
 * Um `FirewallGroup` inteiro serve (é atribuível a isto estruturalmente), mas
 * pedir só estes dois campos deixa a asserção montar o caso sem inventar
 * handle, contador e chain que a conta não olha.
 *
 * `rules` é opcional e anulável de propósito: é o que a tela já tratava com
 * `g.rules?.rules ?? []`, e um grupo do sistema volta da API sem lista.
 */
export interface GroupRuleSource {
  fallthrough: GroupFallthrough;
  rules?: { rules?: NftChainRule[] } | null;
}

/** O que a chain mesclada do grupo carrega, já separado por quem o mantém. */
export interface GroupRuleSplit {
  /** Regras do admin: cada uma com `id` de banco, editáveis e arrastáveis. */
  rules: NftChainRule[];
  /** Linhas vivas sem linha no banco que NÃO são o veredito — divergência. */
  extras: NftChainRule[];
  /** O "e o que sobrar" do próprio grupo, quando ele emite uma linha. */
  fall?: NftChainRule;
}

/**
 * splitGroupRules separa o que a chain mesclada do grupo carrega.
 *
 * As regras do admin têm `id` estável de banco. As linhas do FIM sem id são só
 * do firewall vivo: principalmente o veredito "e o que sobrar" do grupo, que é
 * o campo `fallthrough` e NÃO uma linha em firewall_rules — ele nunca pode
 * ganhar botão de editar ou apagar. Qualquer outra sem id é divergência entre
 * o banco e a chain viva, e aparece (nunca some), mas também não é editável.
 *
 * Por isso a editabilidade se decide pela presença de `id` e nunca por
 * `managed === false`: a linha do veredito volta com managed=false igualzinho
 * a uma regra de verdade do admin.
 *
 * O corte é pelo FIM da lista, e não por um filtro: uma linha sem id no meio
 * das regras do admin é divergência de verdade, e um filtro a esconderia junto
 * com o veredito — mostrando ao operador uma chain que não é a que está
 * valendo.
 */
export function splitGroupRules(g: GroupRuleSource): GroupRuleSplit {
  const all = g.rules?.rules ?? [];
  let end = all.length;
  while (end > 0 && !all[end - 1].id) end--;
  const rules = all.slice(0, end);
  const tail = all.slice(end);
  const fall = g.fallthrough !== 'continue' && tail.length > 0 ? tail[tail.length - 1] : undefined;
  const extras = fall ? tail.slice(0, -1) : tail;
  return { rules, extras, fall };
}

/**
 * mergeGroupRules remonta a chain do jeito que a tela a desenha, depois de um
 * arrasto: as regras do admin na ordem nova, e atrás delas o que não é delas,
 * na mesma ordem em que a API mandou.
 *
 * É o inverso exato de `splitGroupRules`, e existe para que a atualização
 * otimista da tela não perca a divergência nem o veredito enquanto o POST não
 * volta. Perder o veredito aqui apagaria da tela a linha que decide o que o
 * grupo faz com o que sobrou — por alguns quadros, mas justamente na tela em
 * que alguém está conferindo se o arrasto fez o que queria.
 */
export function mergeGroupRules(next: readonly NftChainRule[], split: GroupRuleSplit): NftChainRule[] {
  return [...next, ...split.extras, ...(split.fall ? [split.fall] : [])];
}

// ─────────────────────────────────────────────────────────────────────────────
// Traduzir a ordem do grupo para a ordem global
// ─────────────────────────────────────────────────────────────────────────────

/**
 * O mínimo que a tradução lê de uma linha de `firewall_rules`: a que grupo ela
 * pertence e qual é o id dela. `FirewallRule` inteiro é atribuível a isto.
 *
 * Posição, note, é GLOBAL e não por grupo — é o que torna esta tradução
 * necessária em primeiro lugar.
 */
export interface GlobalRule {
  id: string;
  group_id: string;
}

/**
 * O resultado da tradução. `ok: false` não é detalhe de UI: é a tela dizendo
 * que o que ela tem na mão não descreve mais o banco, e a única resposta certa
 * é recarregar — mandar a lista assim reordenaria o firewall por um palpite.
 */
export type ReorderResult =
  | { ok: true; ids: string[] }
  | { ok: false; reason: 'out-of-sync'; noBanco: number; naTela: number };

/**
 * globalReorder reconstrói a lista global COMPLETA a partir da ordem nova de um
 * grupo só.
 *
 * Percorre todas as regras na ordem global atual e, em cada slot que é DESTE
 * grupo, deixa cair o próximo id da ordem nova. As regras de todos os outros
 * grupos ficam exatamente nos slots que já ocupavam — é isso que faz um arrasto
 * dentro de um grupo caber num endpoint global que recusa lista parcial.
 *
 * O contador `k` anda SÓ nos slots do grupo, nunca no índice da varredura: é aí
 * que mora o off-by-one. Andar `k` a cada linha (ou usar o índice global para
 * indexar `ids`) só produz a lista certa quando o grupo é o primeiro da lista
 * global e não tem buraco nenhum — que é exatamente o caso que um teste
 * distraído monta. Por isso as asserções montam o grupo do MEIO.
 *
 * A comparação de tamanho vem antes de qualquer coisa: com menos ids do que
 * slots, `ids[k++]` devolveria `undefined` no fim e a lista global sairia com
 * buracos — regras somem da ordem, e o backend reordena o firewall com elas
 * faltando.
 */
export function globalReorder(
  all: readonly GlobalRule[],
  groupId: string,
  nextRows: readonly { id?: string }[],
): ReorderResult {
  const ids = nextRows.map((r) => r.id).filter((id): id is string => !!id);
  const mine = all.filter((r) => r.group_id === groupId);
  if (mine.length !== ids.length) {
    return { ok: false, reason: 'out-of-sync', noBanco: mine.length, naTela: ids.length };
  }
  let k = 0;
  return { ok: true, ids: all.map((r) => (r.group_id === groupId ? ids[k++] : r.id)) };
}

// Um `FirewallGroup` de verdade tem que continuar servindo de entrada para
// `splitGroupRules` sem conversão nenhuma. Isto não gera código nenhum: é uma
// asserção de TIPO, e quebra o `tsc` se a forma do grupo mudar por baixo — o
// dia em que `rules` ou `fallthrough` saírem de lá, é aqui que aparece, e não
// numa tela que abriu vazia em produção.
type Assert<T extends true> = T;
export type _GroupIsSource = Assert<FirewallGroup extends GroupRuleSource ? true : false>;
