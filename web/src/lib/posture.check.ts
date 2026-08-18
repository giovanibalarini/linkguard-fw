import assert from 'node:assert';
import {
  POSTURE_COPY, POSTURE_ORDER, confirmPrompt, explainAll, explainSurvival,
  policyLine, postureRequest,
} from './posture.ts';

let n = 0;
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };

// As linhas que o backend de verdade devolve, copiadas da resposta de uma
// máquina rodando (GET /api/nftables/policy). Escrevê-las à mão a partir do
// código Go seria testar a minha lembrança dele, não o produto.
const INPUT_REAL = [
  'ct state related counter accept',
  'iif lo counter accept',
  'icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept',
  'tcp dport { 22, 18099 } counter accept',
  'udp dport 67 ip saddr { 192.168.3.0/24 } counter accept',
  'udp dport 53 ip saddr { 192.168.3.0/24 } counter accept',
  'tcp dport 53 ip saddr { 192.168.3.0/24 } counter accept',
];
const FORWARD_REAL = [
  'ct state established,related counter accept',
  'ct status dnat counter accept',
];

{
  // A tela SEMPRE manda a chain explícita. O padrão implícito do backend é
  // conveniência de API; se ele mudar um dia, a tela não pode passar a
  // bloquear a chain errada em silêncio.
  eq(postureRequest('forward', 'drop'), { policy: 'drop', chain: 'forward' }, 'forward vai explícita');
  eq(postureRequest('input', 'accept'), { policy: 'accept', chain: 'input' }, 'input vai explícita');
}

{
  // A forward vem primeiro: é a que quase todo mundo quer mexer. A input é a
  // rara e perigosa, e não pode ser a primeira que a mão alcança.
  eq(POSTURE_ORDER[0], 'forward', 'a forward é a primeira da tela');
  eq(POSTURE_ORDER[1], 'input', 'a input vem depois');
}

{
  // As duas chains NÃO podem ser apresentadas com o mesmo peso. A da input é a
  // que tranca o admin fora, e o texto de risco dela tem de dizer isso.
  const inp = POSTURE_COPY.input.risco.toLowerCase();
  check(inp.includes('painel') && inp.includes('ssh'), 'o risco da input nomeia o que se perde');
  const fwd = POSTURE_COPY.forward.risco.toLowerCase();
  check(fwd.includes('não é afetado') || fwd.includes('nao e afetado'),
    'o risco da forward diz que o painel continua de pé — senão o operador não bloqueia nada por medo');
  check(POSTURE_COPY.forward.risco !== POSTURE_COPY.input.risco, 'os dois riscos são diferentes');
}

{
  // Nenhum dos textos pode ser "policy drop" disfarçado: a tela existe para
  // quem não escreve nftables.
  for (const c of Object.values(POSTURE_COPY)) {
    for (const t of [c.titulo, c.subtitulo, c.liberar, c.bloquear, c.risco]) {
      check(!/policy (accept|drop)/.test(t), `texto vazando jargão de nftables: ${t}`);
      check(t.length > 0, 'texto vazio');
    }
  }
}

{
  eq(policyLine('forward', 'drop'),
    'chain forward { type filter hook forward priority filter ; policy drop ; }',
    'a linha do modo avançado é a declaração real da chain');
  eq(policyLine('input', 'accept'),
    'chain input { type filter hook input priority filter ; policy accept ; }',
    'e a da input aponta para o hook input');
}

{
  // O `counter` sai: ele é detalhe de contabilidade e ocupa a largura que a
  // explicação precisa.
  const l = explainSurvival('ct state established,related counter accept');
  eq(l.nft, 'ct state established,related accept', 'o counter é removido da exibição');
  check(l.oque.length > 0, 'a linha de established tem explicação');
  check(l.porque.includes('derruba tudo'), 'e ela diz por que a ausência dói');
}

{
  // Toda linha que o backend de verdade emite tem de estar explicada. Uma
  // lista com metade das linhas mudas seria pior que nenhuma.
  for (const l of explainAll([...INPUT_REAL, ...FORWARD_REAL])) {
    check(l.oque.length > 0, `linha sem explicação: ${l.nft}`);
    check(l.porque.length > 0, `linha sem o porquê: ${l.nft}`);
  }
}

{
  // `established,related` e `related` sozinho são coisas diferentes e não
  // podem cair na mesma explicação: a primeira é da forward, a segunda é a que
  // a input já tem hoje.
  const est = explainSurvival('ct state established,related counter accept');
  const rel = explainSurvival('ct state related counter accept');
  check(est.oque !== rel.oque, 'established,related não é confundido com related');
}

{
  // Linha desconhecida aparece MESMO ASSIM, sem explicação. Escondê-la faria a
  // tela afirmar que o firewall preserva menos do que preserva — o erro na
  // direção que assusta o operador à toa.
  const desconhecida = explainSurvival('meta l4proto 132 counter accept');
  eq(desconhecida.nft, 'meta l4proto 132 accept', 'a linha desconhecida sobrevive');
  eq(desconhecida.oque, '', 'e vem sem explicação, em vez de sumir');
  eq(explainAll(['a', 'b']).length, 2, 'nenhuma linha é filtrada');
}

{
  eq(explainAll(null).length, 0, 'lista ausente não quebra a tela');
  eq(explainAll(undefined).length, 0, 'nem indefinida');
}

{
  // A confirmação diz o que vai acontecer e nomeia o tráfego — é a última
  // coisa que o operador lê antes de a rede mudar.
  const bloq = confirmPrompt('forward', 'drop');
  check(bloq.includes('ATRAVESSA'), 'a frase da forward nomeia o tráfego');
  check(bloq.includes('90 segundos'), 'e avisa da janela de reversão');
  check(!/tem certeza/i.test(bloq), 'não é um "tem certeza?"');

  const inp = confirmPrompt('input', 'drop');
  check(inp.includes('próprio LinkGuard'), 'a frase da input nomeia a máquina');
  check(inp !== bloq, 'as duas chains não compartilham a mesma frase');

  // Liberar não promete os 90 segundos de teste de acesso do mesmo jeito: o
  // risco é oposto, e prometer que "o LinkGuard desfaz" seria dizer que
  // liberar pode trancar alguém fora.
  const lib = confirmPrompt('forward', 'accept');
  check(!lib.includes('90 segundos'), 'liberar não copia o aviso de bloquear');
  check(lib.includes('continuam valendo'), 'e explica que os bloqueios existentes ficam');
}

console.log(`posture.check.ts: ${n} asserções OK`);
