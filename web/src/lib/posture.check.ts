import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import {
  POSTURE_ORDER, policyLine, postureRequest, survivalLine, survivalLines,
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
  const l = survivalLine('ct state established,related counter accept');
  eq(l.nft, 'ct state established,related accept', 'o counter é removido da exibição');
  eq(l.key, 'established', 'e a linha casa com a chave certa');
}

{
  // `established,related` e `related` sozinho são coisas diferentes e não podem
  // cair na mesma chave: a primeira é da forward, a segunda é a que a input já
  // tem hoje. A ordem dos matchers é o que garante isso.
  eq(survivalLine('ct state established,related counter accept').key, 'established', 'established primeiro');
  eq(survivalLine('ct state related counter accept').key, 'related', 'related sozinho é outra coisa');
}

{
  // Toda linha que o backend de verdade emite tem de casar com alguma chave.
  // Uma lista com metade das linhas mudas seria pior que nenhuma.
  for (const l of survivalLines([...INPUT_REAL, ...FORWARD_REAL])) {
    check(l.key !== null, `linha sem chave de explicação: ${l.nft}`);
  }
}

{
  // Linha desconhecida aparece MESMO ASSIM, com key null. Escondê-la faria a
  // tela afirmar que o firewall preserva menos do que preserva — o erro na
  // direção que assusta o operador à toa.
  const desconhecida = survivalLine('meta l4proto 132 counter accept');
  eq(desconhecida.nft, 'meta l4proto 132 accept', 'a linha desconhecida sobrevive');
  eq(desconhecida.key, null, 'e vem sem chave, em vez de sumir');
  eq(survivalLines(['a', 'b']).length, 2, 'nenhuma linha é filtrada');
}

{
  eq(survivalLines(null).length, 0, 'lista ausente não quebra a tela');
  eq(survivalLines(undefined).length, 0, 'nem indefinida');
}

// ─── O contrato com o dicionário (issue #105) ────────────────────────────────
//
// Estas asserções são a razão de as chaves serem estáveis. Elas ligam ESTE
// arquivo ao strings.yaml: uma chave nova aqui sem texto lá vira uma tela que
// mostra "fw.posture.survival.xyz.what" cru para o operador, e isso passaria
// despercebido — o gerador só sabe checar que uma chave EXISTENTE tem os dois
// idiomas, não que toda chave usada pelo código existe.
{
  const yaml = readFileSync(new URL('../i18n/strings.yaml', import.meta.url), 'utf8');
  const temChave = (k: string) => yaml.includes(`\n${k}:`);

  const TODAS_AS_KEYS = [
    'established', 'related', 'dnat', 'loopback', 'icmpv6',
    'admin', 'dhcpServed', 'dnsServed', 'dhcpClient',
  ];
  for (const k of TODAS_AS_KEYS) {
    check(temChave(`fw.posture.survival.${k}.what`), `falta fw.posture.survival.${k}.what no strings.yaml`);
    check(temChave(`fw.posture.survival.${k}.why`), `falta fw.posture.survival.${k}.why no strings.yaml`);
  }

  // E as chaves das duas chains, que a tela monta por interpolação do nome.
  for (const chain of POSTURE_ORDER) {
    for (const sufixo of ['title', 'subtitle', 'accept', 'drop', 'risk']) {
      check(temChave(`fw.posture.${chain}.${sufixo}`), `falta fw.posture.${chain}.${sufixo} no strings.yaml`);
    }
    check(temChave(`fw.posture.target.${chain}`), `falta fw.posture.target.${chain} no strings.yaml`);
  }
}

console.log(`posture.check.ts: ${n} asserções OK`);
