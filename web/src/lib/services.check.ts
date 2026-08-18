// Asserções do catálogo de serviços (node --experimental-strip-types).

import assert from 'node:assert';
import { SERVICES, searchServices, foldSearch, portLabel } from './services.ts';

let n = 0;
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };

{
  // A ordem é o ponto desta busca, não o filtro. Quem digita "53" quer o DNS
  // no topo — e 25565 (Minecraft) CONTÉM "55", 5432 contém "53". Sem o
  // ranqueamento por porta exata, o resultado certo aparecia em terceiro.
  const r = searchServices('53');
  eq(r[0].name, 'DNS', 'porta exata vem primeiro');
  check(r.length > 1, 'e os parciais continuam na lista');
}

{
  // Quem NÃO sabe a sigla digita o que a coisa faz. É este caso que decide se
  // o catálogo serve ao público do produto ou só a quem já sabia a resposta.
  const r = searchServices('remoto');
  const nomes = r.map((s) => s.name);
  check(nomes.includes('RDP'), '"remoto" acha a área de trabalho do Windows');
  check(nomes.includes('SSH'), '"remoto" acha o terminal');
  check(nomes.includes('VNC'), '"remoto" acha o acesso à tela');
}

{
  const r = searchServices('impressora');
  check(r.length >= 2, '"impressora" acha as duas formas de impressão de rede');
  check(r.every((s) => /Impress/.test(s.name)), 'e só elas');
}

{
  // Acento não pode separar quem digita de quem cadastrou.
  eq(searchServices('trafego').length, searchServices('tráfego').length, 'busca ignora acento');
  eq(foldSearch('Área de Trabalho'), 'area de trabalho', 'foldSearch tira acento e caixa');
}

{
  const r = searchServices('ssh');
  eq(r[0].name, 'SSH', 'sigla exata vem primeiro');
}

{
  // Busca vazia devolve o catálogo inteiro, na ordem curada — HTTPS antes de
  // HTTP, porque é o que uma rede de hoje usa.
  const r = searchServices('');
  eq(r.length, SERVICES.length, 'busca vazia devolve tudo');
  eq(r[0].name, SERVICES[0].name, 'e preserva a ordem do catálogo');
}

{
  eq(searchServices('nao-existe-isso').length, 0, 'busca sem resultado devolve vazio');
}

{
  // Duas entradas legítimas compartilham a porta 53 com protocolos diferentes;
  // o rótulo tem de escolher pela dupla, não só pelo número.
  eq(portLabel('53', 'udp'), 'DNS (53/udp)', 'rótulo casa porta+proto');
  eq(portLabel('53', 'tcp'), 'DNS (TCP) (53/tcp)', 'e distingue o TCP');
  eq(portLabel('9999', 'tcp'), 'porta 9999/tcp', 'porta desconhecida vira rótulo cru');
}

{
  // O catálogo não pode ter porta inválida nem entrada duplicada de
  // porta+proto: a segunda nunca seria alcançada por portLabel.
  const vistos = new Set<string>();
  for (const s of SERVICES) {
    check(/^\d+$/.test(s.port) && +s.port > 0 && +s.port < 65536, `porta válida em ${s.name}`);
    check(s.what.trim().length > 0, `${s.name} explica o que faz`);
    const k = `${s.port}/${s.proto}`;
    check(!vistos.has(k) || s.name.includes('('), `${k} duplicado sem distinção no nome (${s.name})`);
    vistos.add(k);
  }
}

console.log(`${n} asserções passaram.`);
