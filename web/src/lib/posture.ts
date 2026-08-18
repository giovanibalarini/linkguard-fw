// A postura padrão do firewall (issues #78, #92, #94) — a LÓGICA, sem texto.
//
// Este arquivo já foi o dono das frases da tela. Elas saíram daqui na #105: uma
// tela que fala dois idiomas não pode ter o português cravado na camada de
// lógica. O que sobra é o que independe de idioma — a montagem do pedido, a
// linha de nftables, e o CASAMENTO de cada regra de sobrevivência com uma chave
// estável. O texto de cada chave mora em src/i18n/strings.yaml, nos dois
// idiomas, e é a tela que o resolve.
//
// Continua sendo só lógica, sem I/O e sem React: é o que permite afirmar sobre
// o casamento com asserção, em vez de clicar na tela.

export type Policy = 'accept' | 'drop';
export type PostureChain = 'forward' | 'input';

/** O corpo do PUT /api/nftables/policy. `chain` ausente é forward no backend,
 *  mas a tela SEMPRE manda explícito: o padrão implícito é conveniência de API,
 *  e um dia em que ele mudar não pode virar a tela bloqueando a chain errada. */
export interface PostureRequest {
  policy: Policy;
  chain: PostureChain;
}

export function postureRequest(chain: PostureChain, policy: Policy): PostureRequest {
  return { policy, chain };
}

// A ordem importa: forward primeiro. É a que quase todo mundo quer mexer, e
// a que o admin quer dizer quando fala em "bloquear tudo". A input é a rara e
// perigosa, e vem depois para não ser a primeira que a mão alcança.
export const POSTURE_ORDER: PostureChain[] = ['forward', 'input'];

/** A linha de nftables que a escolha produz — o que o modo avançado mostra. */
export function policyLine(chain: PostureChain, policy: Policy): string {
  const hook = chain === 'forward' ? 'forward' : 'input';
  return `chain ${chain} { type filter hook ${hook} priority filter ; policy ${policy} ; }`;
}

// SurvivalKey é o identificador estável de cada linha de sobrevivência. Ele é
// o que casa a regra crua vinda do backend com a explicação traduzida no
// dicionário (fw.posture.survival.<key>.what / .why). Estável de propósito:
// mudar o texto de um idioma não pode exigir mexer aqui, e vice-versa.
export type SurvivalKey =
  | 'established'
  | 'related'
  | 'dnat'
  | 'loopback'
  | 'icmpv6'
  | 'admin'
  | 'dhcpServed'
  | 'dnsServed'
  | 'dhcpClient';

// O casamento é por PADRÃO, não por posição: a lista vem do backend e a ordem
// dela é a de avaliação, que pode mudar. Casar por índice faria uma reordenação
// no Go trocar as legendas na tela sem quebrar nada. A ordem AQUI importa só
// para desempate — `established,related` tem de ser testada antes de `related`.
const MATCHERS: { casa: RegExp; key: SurvivalKey }[] = [
  { casa: /ct state established,related/, key: 'established' },
  { casa: /ct state related/, key: 'related' },
  { casa: /ct status dnat/, key: 'dnat' },
  { casa: /^iif lo/, key: 'loopback' },
  { casa: /icmpv6/, key: 'icmpv6' },
  { casa: /^tcp dport \{?\s*\d+/, key: 'admin' },
  { casa: /dport 67/, key: 'dhcpServed' },
  { casa: /dport 53/, key: 'dnsServed' },
  { casa: /dport 68/, key: 'dhcpClient' },
];

export interface SurvivalLine {
  /** A linha crua, como o backend a emitirá (sem o `counter`). */
  nft: string;
  /** A chave da explicação, ou null quando nenhuma casou. */
  key: SurvivalKey | null;
}

/** survivalLine casa uma linha crua do backend com a chave da explicação dela.
 *
 *  Linha desconhecida NÃO é escondida: ela volta com key=null e a tela a mostra
 *  crua. Uma regra nova no Go que esta tabela não conheça precisa ficar visível
 *  — omiti-la faria a tela afirmar que o firewall preserva menos do que
 *  preserva, que é o erro na direção que assusta o operador à toa. */
export function survivalLine(nft: string): SurvivalLine {
  const limpa = nft.replace(/\s+counter\b/g, '').trim();
  for (const m of MATCHERS) {
    if (m.casa.test(limpa)) return { nft: limpa, key: m.key };
  }
  return { nft: limpa, key: null };
}

export function survivalLines(linhas: string[] | null | undefined): SurvivalLine[] {
  return (linhas ?? []).map(survivalLine);
}
