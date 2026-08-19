import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { describeRule, formatCond } from './ruleDesc.ts';

let n = 0;
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };

// Um t() de mentira que imita o de verdade: devolve a própria chave quando ela
// não existe, e interpola os marcadores.
const DIC: Record<string, string> = {
  'desc.dnat': 'Forwards {proto}/{porta} to {destino}',
  'desc.user.drop': 'Blocks {cond}',
  'desc.user.drop.any': 'Blocks any traffic',
  'desc.cond.saddr': 'from {v}',
  'desc.cond.daddr': 'to {v}',
  'desc.cond.iif': 'in {v}',
  'desc.cond.proto': '{v}',
};
const t = (k: string, vars?: Record<string, string | number>) => {
  let out = DIC[k] ?? k;
  for (const [kk, v] of Object.entries(vars ?? {})) out = out.split(`{${kk}}`).join(String(v));
  return out;
};

{
  // Sem descritor, a frase pronta do backend é usada. NÃO é defeito: é o caso
  // "o backend não soube descrever", em que ele devolve a expressão nft crua e
  // mostrar isso é mais honesto que inventar.
  eq(describeRule(undefined, 'meta l4proto 132 accept', t), 'meta l4proto 132 accept',
    'sem descritor, cai na frase do backend');
  eq(describeRule({ key: '' }, 'expressão crua', t), 'expressão crua',
    'chave vazia também cai no fallback');
}

{
  const r = describeRule({ key: 'desc.dnat', vars: { proto: 'TCP', porta: '8080', destino: '192.168.1.5:80' } }, 'x', t);
  eq(r, 'Forwards TCP/8080 to 192.168.1.5:80', 'os valores entram na frase traduzida');
  check(!r.includes('{'), 'nenhum marcador sobrou cru na tela');
}

{
  // A condição: rótulos traduzidos, valores intactos.
  eq(formatCond('saddr=10.0.0.0/8|proto=TCP:22', t), 'from 10.0.0.0/8, TCP:22',
    'rótulo traduz, valor não');
  eq(formatCond('iif=enp3s0', t), 'in enp3s0', 'nome de interface é preservado');
}

{
  // A frase inteira vem do dicionário, com a condição num marcador só.
  eq(describeRule({ key: 'desc.user.drop', vars: { cond: 'saddr=10.0.0.0/8' } }, 'x', t),
    'Blocks from 10.0.0.0/8',
    'a ordem das palavras é do idioma, não colagem de pedaços');
  eq(describeRule({ key: 'desc.user.drop.any' }, 'x', t), 'Blocks any traffic',
    'regra sem condição tem chave própria');
}

{
  // Rótulo desconhecido aparece cru, com o valor — nunca "desc.cond.xyz".
  const r = formatCond('xyz=algo', t);
  eq(r, 'xyz algo', 'rótulo desconhecido não vira id na tela');
  check(!r.includes('desc.cond'), 'e não vaza o prefixo da chave');
}

{
  // Todas as chaves que o Go emite têm de existir no YAML. O gerador confere
  // que uma chave existente tem os dois idiomas; ele NÃO sabe que o Go a pede.
  const yaml = readFileSync(new URL('../i18n/strings/firewall-resto.yaml', import.meta.url), 'utf8');
  const doGo = [
    'desc.masquerade', 'desc.ctRelated', 'desc.ntpAccept', 'desc.ntpAcceptFrom', 'desc.ntpDrop',
    'desc.jumpUserRules', 'desc.blockedHosts.to', 'desc.blockedHosts.from',
    'desc.blocklist.to', 'desc.blocklist.from', 'desc.markHost', 'desc.dnat',
  ];
  for (const k of doGo) check(yaml.includes(`\n${k}:`), `falta ${k} no YAML (o Go emite essa chave)`);
  for (const acao of ['accept', 'drop', 'reject', 'rule']) {
    check(yaml.includes(`\ndesc.user.${acao}:`), `falta desc.user.${acao}`);
    check(yaml.includes(`\ndesc.user.${acao}.any:`), `falta desc.user.${acao}.any`);
  }
  for (const rot of ['iif', 'oif', 'saddr', 'daddr', 'proto']) {
    check(yaml.includes(`\ndesc.cond.${rot}:`), `falta desc.cond.${rot}`);
  }
}

console.log(`ruleDesc.check.ts: ${n} asserções OK`);
