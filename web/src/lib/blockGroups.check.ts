import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { KIND_BLOCKED_HOSTS, KIND_BLOCKLIST, groupDisplayNameKey, isSystemGroup } from './blockGroups.ts';

let n = 0;
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };

// O nome exibido dos grupos (issue #106).
//
// A asserção que mais importa aqui é a terceira, e ela protege o admin: o
// casamento é pelo `kind`, nunca pelo nome. Se alguém trocar isso um dia, um
// grupo que o admin batizou de "Hosts bloqueados" passa a ser renomeado na tela
// dele — o produto reescrevendo o que a pessoa digitou.

{
  eq(groupDisplayNameKey(KIND_BLOCKED_HOSTS), 'fwx.systemGroup.blocked_hosts', 'grupo do sistema tem chave');
  eq(groupDisplayNameKey(KIND_BLOCKLIST), 'fwx.systemGroup.blocklist', 'o outro também');
}

{
  // Grupo do admin: nome mostrado como ele digitou.
  eq(groupDisplayNameKey(undefined), null, 'grupo sem kind não é traduzido');
  eq(groupDisplayNameKey(''), null, 'kind vazio também não');
  eq(groupDisplayNameKey('admin'), null, 'grupo do admin não é traduzido');
}

{
  // A armadilha: um grupo do ADMIN chamado exatamente como um do sistema.
  // Ele não tem kind de sistema, então não pode ser tocado.
  eq(groupDisplayNameKey('user'), null,
    'um grupo do admin chamado "Hosts bloqueados" NÃO pode ser renomeado na tela: o casamento é por kind, não por nome');
  check(!isSystemGroup('user'), 'isSystemGroup é lista fechada');
}

{
  // E as chaves existem de verdade no dicionário, nos dois idiomas — senão a
  // tela mostra o id cru justamente no lugar do nome do grupo.
  const yaml = readFileSync(new URL('../i18n/strings/firewall-resto.yaml', import.meta.url), 'utf8');
  for (const kind of [KIND_BLOCKED_HOSTS, KIND_BLOCKLIST]) {
    check(yaml.includes(`\nfwx.systemGroup.${kind}:`), `falta fwx.systemGroup.${kind} no YAML`);
  }
  // Os rótulos de dono, idem: eles vêm do Go com um Key estável.
  for (const key of ['nat', 'wan_steering', 'ntp', 'rule_groups', 'host_block', 'blocklist', 'port_forward']) {
    check(yaml.includes(`\nfwx.owner.${key}:`), `falta fwx.owner.${key} no YAML (o Go emite esse Key)`);
  }
}

console.log(`blockGroups.check.ts: ${n} asserções OK`);
