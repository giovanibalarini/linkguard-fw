import assert from 'node:assert';
import { buildRule, descreverRegra, ehEndereco, precisaDeServico, rotuloDoAlvo } from './ruleWizard.ts';
import type { Target } from './netTargets.ts';
import type { Service } from './services.ts';

let n = 0;
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };

const host: Target = { id: 'h', kind: 'host', label: 'notebook-maria', hint: '', value: '192.168.3.47' };
const rede: Target = { id: 'r', kind: 'rede', label: 'A LAN inteira', hint: '', value: '192.168.3.0/24' };
const wan: Target  = { id: 'w', kind: 'wan',  label: 'Fibra 500M',    hint: '', value: 'enp3s0' };
const smb: Service = { name: 'SMB', what: 'compartilhamento de arquivos', port: '445', proto: 'tcp' };

{
  const f = buildRule('bloquear', host, null);
  eq(f.action, 'drop', 'bloquear vira drop');
  eq(f.saddr, '192.168.3.47', 'o aparelho vira a ORIGEM');
  eq(f.daddr, '', 'e não o destino');
  check(f.description.includes('notebook-maria'), 'o rótulo nasce preenchido com o nome');
}

{
  // drop, não reject: avisar o aparelho de que foi bloqueado só ensina a
  // contornar, e o reject ainda gasta banda de saída por pacote descartado.
  eq(buildRule('bloquear', host, null).action, 'drop', 'bloqueio administrativo é silencioso');
}

{
  const f = buildRule('liberar', host, smb);
  eq(f.action, 'accept', 'liberar vira accept');
  eq(f.saddr, '192.168.3.47', 'quem é liberado é a origem');
  eq([f.proto, f.dport], ['tcp', '445'], 'o serviço vira protocolo e porta');
}

{
  // "Abrir para a internet" inverte o papel do alvo: ele RECEBE.
  const f = buildRule('porta', host, smb);
  eq(f.daddr, '192.168.3.47', 'o alvo vira DESTINO');
  eq(f.saddr, '', 'e não origem — senão a regra diria o contrário do pedido');
}

{
  // Link WAN não tem endereço: ele fala por interface.
  const bloq = buildRule('bloquear', wan, null);
  eq(bloq.iif, 'enp3s0', 'o link WAN vira interface de entrada');
  eq(bloq.saddr, '', 'e não endereço');
  const porta = buildRule('porta', wan, smb);
  eq(porta.oif, 'enp3s0', 'como destino, vira interface de saída');
}

{
  const f = buildRule('bloquear', rede, null);
  eq(f.saddr, '192.168.3.0/24', 'CIDR também é endereço');
}

{
  eq(buildRule('bloquear', null, null).saddr, '', 'sem alvo, nada é preenchido');
  eq(buildRule('avancada', host, smb).saddr, '', 'a intenção avançada não traduz nada');
}

{
  eq(ehEndereco('192.168.3.47'), true, 'IP é endereço');
  eq(ehEndereco('192.168.3.0/24'), true, 'CIDR é endereço');
  eq(ehEndereco('enp3s0'), false, 'nome de interface não é');
  eq(ehEndereco('br-lan'), false, 'bridge não é');
}

{
  eq(precisaDeServico('bloquear'), false, 'bloquear não pede serviço');
  eq(precisaDeServico('liberar'), true, 'liberar pede');
  eq(precisaDeServico('porta'), true, 'abrir porta pede');
  check(rotuloDoAlvo('porta').includes('recebe'), 'a pergunta muda quando o alvo recebe');
}

{
  // A frase é o que o público deste produto lê. Uma pré-visualização que só
  // mostra `ip saddr … counter drop` devolve ao admin o problema que o
  // assistente veio resolver.
  const d = descreverRegra('bloquear', host, null);
  check(d.includes('notebook-maria'), 'a frase nomeia o aparelho');
  check(!d.includes('saddr') && !d.includes('drop'), 'e não usa vocabulário de nftables');

  check(descreverRegra('liberar', host, null).includes('escolha o serviço'), 'passo incompleto orienta');
  check(descreverRegra('liberar', host, smb).includes('SMB'), 'com serviço, nomeia o serviço');
  check(descreverRegra('porta', host, smb).includes('internet'), 'abrir porta fala da internet');
  check(descreverRegra('bloquear', null, null).includes('Escolha'), 'sem alvo, pede o alvo');
}

console.log(`${n} asserções passaram.`);
