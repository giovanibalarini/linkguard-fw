// O vocabulário da tela de grupos: os quatro mapas que traduzem um campo do
// banco para o que o operador lê, e as funções puras que normalizam o que veio
// da API antes de qualquer pixel ser desenhado.
//
// Eles moravam no topo de `FirewallGroups.tsx`. Saíram porque as peças da tela
// (a lista, os dois modais, o detalhe do grupo do sistema) leem os MESMOS
// mapas: uma segunda cópia de ACTIONS ou de SCOPES numa das peças seria a tela
// dizendo `drop` num lugar e `descarta` no outro para a mesma linha do
// firewall.

// ATENÇÃO (issue #105): os campos `hint`, `title`, `what` e `empty` daqui
// guardam CHAVES do dicionário, não texto. Quem renderiza chama t(meta.hint).
// Os keywords do nftables (accept/drop/reject, continue, forward/input,
// `ct state new`) continuam literais de propósito: são o que o admin vai achar
// no `nft list ruleset`, e traduzi-los criaria um vocabulário só do painel.
import { Check, Ban, Slash, ArrowRightLeft, Server, Zap, DoorOpen } from 'lucide-react';
import { isSystemGroup, KIND_BLOCKED_HOSTS, KIND_BLOCKLIST } from '../../lib/blockGroups';
import type { FirewallGroup, GroupConnState, GroupFallthrough, GroupScope, NftManaged } from '../../types';

export type Action = 'accept' | 'drop' | 'reject';

export type Unit = 'bytes' | 'bits';

// The labels are the nftables keywords themselves, never translated: what
// the admin reads here is what they will find in `nft list ruleset`, with no
// panel-only vocabulary in between. `hint` carries the meaning in plain
// Portuguese for the rule form, where someone is choosing rather than
// reading. Same reasoning as rendering rule conditions in raw nft syntax
// (design spec §7.2.1).
export const ACTIONS: Record<Action, { label: string; hint: string; color: string; ring: string; Icon: typeof Check }> = {
  accept: { label: 'accept', hint: 'fw.action.accept.hint', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10', Icon: Check },
  drop: { label: 'drop', hint: 'fw.action.drop.hint', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10', Icon: Ban },
  reject: { label: 'reject', hint: 'fw.action.reject.hint', color: 'text-orange-400', ring: 'border-orange-500 bg-orange-500/10', Icon: Slash },
};

// "E o que sobrar?" is the group's own verdict for traffic that entered it
// and that none of its rules decided. The three values are nft keywords too
// (`continue` really is one), so they are not translated either — the short
// Portuguese sentence beside each one carries the meaning.
export const FALLTHROUGH: Record<GroupFallthrough, { hint: string; color: string; ring: string }> = {
  continue: { hint: 'fw.fallthrough.continue.hint', color: 'text-gray-300', ring: 'border-gray-600 bg-gray-700/30' },
  accept: { hint: 'fw.fallthrough.accept.hint', color: 'text-green-400', ring: 'border-green-500 bg-green-500/10' },
  drop: { hint: 'fw.fallthrough.drop.hint', color: 'text-red-400', ring: 'border-red-500 bg-red-500/10' },
};

/** O que um grupo do sistema é, na tela: ver SYSTEM_KINDS. */
export interface SystemKind {
  what: string;
  lines: string[];
  member: [string, string];
  empty: string;
}

/**
 * SYSTEM_KINDS descreve os dois grupos que o LinkGuard mantém (spec §2.1).
 *
 * `lines` são as linhas que o kind põe na chain forward, na mesma ordem em
 * que o backend as emite (systemGroupForwardRules, internal/nftables/
 * groups.go): o que se lê aqui é o que se acha no `nft list chain inet
 * linkguard forward`, sem um segundo dicionário no meio — mesma disciplina
 * das expressões das regras.
 *
 * `members` é o rótulo do conteúdo: um grupo do sistema não tem regras, tem
 * membros de um named set.
 */
export const SYSTEM_KINDS: Record<string, SystemKind> = {
  [KIND_BLOCKED_HOSTS]: {
    // O alcance real é o da chain: as duas linhas vivem na forward, e só
    // nela. Dizer "qualquer tráfego" era falso justamente onde mais engana —
    // um host "bloqueado" continua abrindo o painel, o SSH, o DNS e o DHCP
    // do próprio firewall, porque isso é input, não forward.
    what: 'fw.systemKind.blockedHosts.what',
    lines: ['ip saddr @blocked_hosts counter drop', 'ip daddr @blocked_hosts counter drop'],
    member: ['fw.systemKind.blockedHosts.member.one', 'fw.systemKind.blockedHosts.member.many'],
    empty: 'fw.systemKind.blockedHosts.empty',
  },
  [KIND_BLOCKLIST]: {
    // Mesma correção do kind acima, pelo mesmo motivo: só a forward. O que o
    // PRÓPRIO firewall inicia para um destino bloqueado (atualização,
    // consulta DNS dele) é output e não passa por estas linhas.
    what: 'fw.systemKind.blocklist.what',
    lines: ['ip daddr @blocklist counter drop', 'ip saddr @blocklist counter drop'],
    member: ['fw.systemKind.blocklist.member.one', 'fw.systemKind.blocklist.member.many'],
    empty: 'fw.systemKind.blocklist.empty',
  },
};

/**
 * SCOPES é "onde o grupo age" — o campo `scope` da Fase C2, que decide em qual
 * chain o `jump` do grupo é escrito.
 *
 * `chain` são os nomes de chain do próprio nftables (forward, input): não se
 * traduzem, aparecem em font-mono e são o que o admin vai achar no `nft list
 * ruleset`. A frase em português ao lado carrega o significado, do mesmo jeito
 * que ACTIONS e FALLTHROUGH fazem com os keywords deles.
 *
 * O escopo input é o único que pode trancar o operador para fora da máquina —
 * daí a cor de alerta dele, a mesma que a tela usa para avisar ANTES de salvar,
 * para marcar o grupo na lista e para a faixa da contagem regressiva.
 */
export const SCOPES: Record<'forward' | 'input', {
  chain: string;
  title: string;
  hint: string;
  color: string;
  ring: string;
  Icon: typeof Check;
}> = {
  forward: {
    chain: 'forward',
    title: 'fw.scope.forward.title',
    hint: 'fw.scope.forward.hint',
    color: 'text-gray-300',
    ring: 'border-gray-500 bg-gray-700/40',
    Icon: ArrowRightLeft,
  },
  input: {
    chain: 'input',
    title: 'fw.scope.input.title',
    hint: 'fw.scope.input.hint',
    color: 'text-orange-300',
    ring: 'border-orange-500 bg-orange-500/10',
    Icon: Server,
  },
};

// groupScope normaliza o que veio do banco, exatamente como GroupScope faz no
// backend: vazio é forward (todo grupo anterior à Fase C2), e qualquer coisa
// que não seja input também. Ler a coluna crua aqui faria a tela desenhar um
// grupo numa chain em que ele não está.
export function groupScope(g: { scope?: GroupScope; kind?: string }): 'forward' | 'input' {
  // Grupo do sistema é sempre forward, qualquer que seja a coluna — as linhas
  // dele são de um named set de tráfego atravessando (GroupHostChain).
  if (g.kind && isSystemGroup(g.kind)) return 'forward';
  return g.scope === 'input' ? 'input' : 'forward';
}

/**
 * CONN_STATES é "para quais conexões o grupo vale" — o campo `conn_state`.
 *
 * A diferença é dita em termos do que acontece com o que JÁ ESTÁ DE PÉ, que é
 * como o operador vive o problema ("quero cortar o que esse host tenta abrir,
 * sem derrubar a transferência que ele já está fazendo"), e não em termos de
 * conntrack — quem precisa da palavra `ct state new` a encontra em `expr`,
 * na linha exata que vai para o firewall.
 *
 * `expr` é o token do nftables e não se traduz: é o que o admin vai achar no
 * `nft list ruleset`, e é ele que a pré-visualização mostra em font-mono.
 * "toda conexão" não acrescenta token nenhum — é a linha de sempre, byte a
 * byte, que é o que protege toda máquina já instalada.
 */
export const CONN_STATES: Record<'any' | 'new', {
  title: string;
  hint: string;
  expr: string;
  color: string;
  ring: string;
  Icon: typeof Check;
}> = {
  any: {
    title: 'fw.connState.any.title',
    hint: 'fw.connState.any.hint',
    expr: '',
    color: 'text-gray-300',
    ring: 'border-gray-500 bg-gray-700/40',
    Icon: Zap,
  },
  new: {
    title: 'fw.connState.new.title',
    hint: 'fw.connState.new.hint',
    expr: 'ct state new',
    color: 'text-sky-300',
    ring: 'border-sky-500 bg-sky-500/10',
    Icon: DoorOpen,
  },
};

// groupConnState normaliza o que veio do banco, como GroupConnState faz no
// backend: vazio — e qualquer valor que esta tela não conheça — é "toda
// conexão", que é o que toda máquina em produção faz hoje. O lado seguro é
// este: mostrar "só conexões novas" onde o kernel derruba tudo seria a tela
// prometendo uma transferência preservada que não está preservada.
export function groupConnState(g: { conn_state?: GroupConnState; kind?: string }): 'any' | 'new' {
  // Grupo do sistema fica de fora da escolha (é lista fechada, renderizada por
  // um mapa próprio, e bloqueio de host é justamente onde se quer a marreta):
  // o backend ignora a coluna dele, e a tela não pode dizer o contrário.
  if (g.kind && isSystemGroup(g.kind)) return 'any';
  return g.conn_state === 'new' ? 'new' : 'any';
}

// O conteúdo de um grupo do sistema é a lista de membros do named set, não
// regras: `managed` é a leitura do set vivo (/api/nftables/managed), porque um
// grupo do sistema não tem chain e não vem em `rules`.
export function membersOf(g: Pick<FirewallGroup, 'kind'>, managed: NftManaged): string[] {
  if (g.kind === KIND_BLOCKED_HOSTS) return managed.blocked_hosts;
  if (g.kind === KIND_BLOCKLIST) return managed.blocklist;
  return [];
}

export const emptyRuleModal = {
  open: false, id: '', groupId: '', groupName: '', action: 'drop' as Action,
  iif: '', oif: '', saddr: '', daddr: '', proto: '', dport: '', description: '',
};
export type RuleModalState = typeof emptyRuleModal;

// O escopo padrão do modal é forward, e é o padrão certo: quem cria um grupo
// está quase sempre filtrando tráfego que atravessa, e é o único dos dois que
// não pode trancar ninguém para fora. Escolher input é uma decisão explícita.
// E "toda conexão" é o padrão da escolha de conexões pela mesma razão que
// pesa mais: é o que TODO grupo já gravado significa, e é o que o firewall
// vivo de toda máquina instalada faz hoje. Restringir a conexões novas é uma
// decisão explícita — inclusive porque ela desarma o teste de acesso da janela
// de 90 segundos.
export const emptyGroupModal = {
  open: false, id: '', name: '', cond_saddr: '', cond_daddr: '', cond_iif: '',
  fallthrough: 'continue' as GroupFallthrough, chain_name: '',
  scope: 'forward' as 'forward' | 'input',
  conn_state: 'any' as 'any' | 'new',
};
export type GroupModalState = typeof emptyGroupModal;

export function describeCondition(g: { cond_iif: string; cond_saddr: string; cond_daddr: string; scope?: GroupScope; kind?: string }): string {
  const parts: string[] = [];
  if (g.cond_iif) parts.push(`entrada ${g.cond_iif}`);
  if (g.cond_saddr) parts.push(`origem ${g.cond_saddr}`);
  if (g.cond_daddr) parts.push(`destino ${g.cond_daddr}`);
  if (parts.length) return parts.join(' · ');
  // Sem condição, o "tudo" de um grupo de input é outro tudo: não é o tráfego
  // que atravessa o firewall, é o que chega nele. Repetir a frase da forward
  // aqui descreveria o grupo errado — e é justamente o grupo que pode cortar o
  // acesso do operador.
  return groupScope(g) === 'input'
    ? 'todo o tráfego destinado ao firewall'
    : 'todo o tráfego que atravessa o firewall';
}

export function formatCount(bytes: number, unit: Unit): string {
  const value = unit === 'bits' ? bytes * 8 : bytes;
  const suffixes = unit === 'bits' ? ['b', 'Kb', 'Mb', 'Gb', 'Tb'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = value;
  let i = 0;
  while (v >= 1000 && i < suffixes.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${suffixes[i]}`;
}

// ruleAction derives the badge from the raw nft expression for a line the
// panel has no DB row for (the group's own verdict). Same palette as
// ACTIONS, same untranslated keywords.
export function ruleAction(expr: string): Action {
  if (/\baccept$/.test(expr)) return 'accept';
  if (/\breject/.test(expr)) return 'reject';
  return 'drop';
}
