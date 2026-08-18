// A postura padrão do firewall, traduzida (issues #78, #92, #94).
//
// O PROBLEMA. O produto sabe bloquear por padrão e liberar só o que foi
// autorizado desde a #92, mas a capacidade só existia na API. Quem instalou
// pelo .deb e entra pelo painel não tinha como saber que ela existe.
//
// E a dificuldade não é o botão, é a FRASE. "Política padrão: drop" não
// significa nada para quem não escreve nftables, e a diferença entre as duas
// chains, dita errado, é o operador se trancando fora da própria máquina.
//
// Só lógica, sem I/O e sem React: é o que permite afirmar sobre a tradução com
// asserção, em vez de clicar na tela.

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

export interface PostureCopy {
  /** O título do cartão, na linguagem de quem opera a rede. */
  titulo: string;
  /** Uma frase dizendo QUE tráfego é esse. */
  subtitulo: string;
  /** O que "liberar" significa nesta chain. */
  liberar: string;
  /** O que "bloquear" significa nesta chain. */
  bloquear: string;
  /** O que o operador perde se errar aqui. Vazio quando não há risco de
   *  perder o acesso — e o campo existe justamente para que as duas chains
   *  NÃO sejam apresentadas como se tivessem o mesmo peso. */
  risco: string;
}

// A ordem importa: forward primeiro. É a que quase todo mundo quer mexer, e
// a que o admin quer dizer quando fala em "bloquear tudo". A input é a rara e
// perigosa, e vem depois para não ser a primeira que a mão alcança.
export const POSTURE_ORDER: PostureChain[] = ['forward', 'input'];

export const POSTURE_COPY: Record<PostureChain, PostureCopy> = {
  forward: {
    titulo: 'Tráfego que atravessa o firewall',
    subtitulo: 'O que sai da sua rede para a internet, e o que vai de uma rede para outra.',
    liberar: 'Tudo passa, menos o que você bloquear. É como o firewall está hoje.',
    bloquear: 'Nada passa, menos o que você liberar. O que você esquecer de listar fica bloqueado — não solto.',
    risco: 'A rede inteira para de sair até você liberar o que precisa. O acesso a este painel não é afetado.',
  },
  input: {
    titulo: 'Tráfego destinado ao próprio LinkGuard',
    subtitulo: 'Quem pode falar com esta máquina: este painel, SSH, o DNS e o DHCP que ela serve.',
    liberar: 'Qualquer máquina que alcance o LinkGuard pode tentar falar com ele.',
    bloquear: 'Só o acesso administrativo listado abaixo continua chegando.',
    risco: 'Esta é a mudança que tranca o administrador do lado de fora. Se a lista abaixo não incluir o caminho que você usa, você perde o painel e o SSH ao mesmo tempo.',
  },
};

/** A linha de nftables que a escolha produz — o que o modo avançado mostra. */
export function policyLine(chain: PostureChain, policy: Policy): string {
  const hook = chain === 'forward' ? 'forward' : 'input';
  return `chain ${chain} { type filter hook ${hook} priority filter ; policy ${policy} ; }`;
}

export interface SurvivalLine {
  /** A linha crua, como o backend a emitirá. */
  nft: string;
  /** O que ela preserva, em português. */
  oque: string;
  /** Por que a ausência dela dói — e por que o sintoma engana. */
  porque: string;
}

// As explicações são casadas por PADRÃO, não por posição: a lista vem do
// backend e a ordem dela é a de avaliação, que pode mudar. Casar por índice
// faria uma reordenação no Go trocar as legendas na tela sem quebrar nada.
const EXPLICACOES: { casa: RegExp; oque: string; porque: string }[] = [
  {
    casa: /ct state established,related/,
    oque: 'Conexões que já estavam abertas',
    porque: 'Sem esta linha, bloquear não bloqueia "o que você não liberou": derruba tudo, inclusive cada download e cada chamada em curso.',
  },
  {
    casa: /ct state related/,
    oque: 'Respostas de erro e controle das conexões',
    porque: 'É o que mantém o "pacote grande demais" chegando de volta. Sem ela, conexões travam pela metade sem mensagem nenhuma.',
  },
  {
    casa: /ct status dnat/,
    oque: 'Os seus encaminhamentos de porta',
    porque: 'Sem esta linha, todo redirecionamento continua sendo traduzido e morre logo depois — o sintoma é "o encaminhamento parou", sem nada apontando para o firewall.',
  },
  {
    casa: /^iif lo/,
    oque: 'A própria máquina falando consigo',
    porque: 'O painel escutando em 127.0.0.1 ficaria inalcançável até por um túnel SSH.',
  },
  {
    casa: /icmpv6/,
    oque: 'Descoberta de vizinhança IPv6',
    porque: 'Sem ela o IPv6 morre inteiro, e só ele — o IPv4 continua bom, que é o que faz ninguém relacionar o sintoma com o firewall.',
  },
  {
    casa: /^tcp dport \{?\s*\d+/,
    oque: 'O seu acesso administrativo',
    porque: 'SSH e este painel, nas portas que esta máquina realmente usa.',
  },
  {
    casa: /dport 67/,
    oque: 'O DHCP que você serve à rede',
    porque: 'Sem ele os aparelhos param de pegar IP — e quem estiver na rede vai dizer que "a internet caiu".',
  },
  {
    casa: /dport 53/,
    oque: 'O DNS que você serve à rede',
    porque: 'Sem ele nada resolve nome, mesmo com a rede funcionando perfeitamente.',
  },
  {
    casa: /dport 68/,
    oque: 'O firewall pegando o próprio endereço',
    porque: 'A renovação de DHCP da WAN não passa por conntrack. O sintoma aparece dias depois de uma queda de link, como "a internet caiu sozinha na quarta".',
  },
];

/** explainSurvival casa uma linha crua do backend com a explicação dela.
 *
 *  Linha desconhecida NÃO é escondida: ela aparece com a explicação vazia. Uma
 *  regra nova no Go que esta tabela não conheça precisa ficar visível — omiti-la
 *  faria a tela afirmar que o firewall preserva menos do que preserva, que é o
 *  erro na direção que assusta o operador à toa. */
export function explainSurvival(nft: string): SurvivalLine {
  const limpa = nft.replace(/\s+counter\b/g, '').trim();
  for (const e of EXPLICACOES) {
    if (e.casa.test(limpa)) return { nft: limpa, oque: e.oque, porque: e.porque };
  }
  return { nft: limpa, oque: '', porque: '' };
}

export function explainAll(linhas: string[] | null | undefined): SurvivalLine[] {
  return (linhas ?? []).map(explainSurvival);
}

/** A frase do botão de confirmação, por chain. Ela diz o que vai acontecer,
 *  não "tem certeza?" — e nomeia o tráfego, porque é a última coisa que o
 *  operador lê antes de a rede mudar. */
export function confirmPrompt(chain: PostureChain, policy: Policy): string {
  const alvo = chain === 'forward' ? 'o tráfego que ATRAVESSA o firewall' : 'o acesso AO próprio LinkGuard';
  if (policy === 'drop') {
    return `Bloquear ${alvo} por padrão? A partir daí só passa o que você tiver liberado. `
      + 'Você tem 90 segundos para confirmar que ainda entra; se não confirmar, o LinkGuard desfaz sozinho.';
  }
  return `Liberar ${alvo} por padrão? Os seus bloqueios continuam valendo — o que muda é o que acontece com o tráfego que nenhuma regra menciona.`;
}
