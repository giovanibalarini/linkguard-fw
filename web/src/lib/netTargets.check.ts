import assert from 'node:assert';
import {
  buildTargets, hostName, onlineRecently, searchTargets, describeTarget,
  type HostLike, type Target,
} from './netTargets.ts';

let n = 0;
const check = (c: unknown, m: string) => { assert.ok(c, m); n++; };
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };

const AGORA = Date.parse('2026-08-18T12:00:00Z');
const recente = new Date(AGORA - 60_000).toISOString();
const antigo = new Date(AGORA - 3 * 3600_000).toISOString();

const HOSTS: HostLike[] = [
  { mac: 'aa:00:01', ip: '192.168.3.47', hostname: 'DESKTOP-9F2C', alias: 'notebook-maria', last_seen: recente },
  { mac: 'aa:00:02', ip: '192.168.3.51', hostname: 'tv-sala', alias: '', last_seen: antigo },
  { mac: 'aa:00:03', ip: '', hostname: 'sem-ip', alias: '', last_seen: recente },
  { mac: 'aa:00:04', ip: '192.168.3.99', hostname: '', alias: '', last_seen: '' },
];

{
  // O apelido ganha do hostname: foi o ADMIN quem o escreveu, justamente para
  // reconhecer o aparelho. "DESKTOP-9F2C" não ajuda ninguém.
  eq(hostName(HOSTS[0]), 'notebook-maria', 'apelido tem precedência');
  eq(hostName(HOSTS[1]), 'tv-sala', 'sem apelido, usa o hostname');
  eq(hostName(HOSTS[3]), 'aa:00:04', 'sem os dois, o MAC — melhor que linha em branco');
}

{
  eq(onlineRecently(recente, AGORA), true, 'visto há 1 min está online');
  eq(onlineRecently(antigo, AGORA), false, 'visto há 3 h não está');
  eq(onlineRecently('', AGORA), false, 'sem carimbo não está');
  eq(onlineRecently('não-é-data', AGORA), false, 'data inválida não quebra');
}

{
  const t = buildTargets(HOSTS, [], [], '192.168.3.0/24', AGORA);
  // Host SEM IP fica de fora: uma regra precisa de endereço, e um item que não
  // dá para usar é pior do que nenhum item.
  check(!t.some((x) => x.label === 'sem-ip'), 'host sem IP não entra na lista');
  check(t.some((x) => x.kind === 'rede' && x.value === '192.168.3.0/24'), 'a LAN inteira é oferecida');
}

{
  // A MESMA máquina não pode aparecer duas vezes. Uma reserva cujo IP já é de
  // um host conhecido é fundida — duas linhas fariam o admin achar que são
  // dois aparelhos e bloquear o errado.
  const t = buildTargets(
    HOSTS,
    [{ mac: 'aa:00:01', ip: '192.168.3.47', hostname: 'reserva-maria' },
     { mac: 'bb:00:09', ip: '192.168.3.240', hostname: 'impressora' }],
    [], '192.168.3.0/24', AGORA);
  eq(t.filter((x) => x.value === '192.168.3.47').length, 1, 'IP repetido aparece uma vez só');
  check(t.some((x) => x.kind === 'reserva' && x.label === 'impressora'), 'reserva nova entra');
}

{
  // O link WAN carrega a INTERFACE, e não um IP: é assim que a regra fala de
  // "por onde o tráfego entra ou sai".
  const t = buildTargets([], [], [{ id: 'l1', name: 'Fibra 500M', interface: 'enp3s0' }], '', AGORA);
  const wan = t.find((x) => x.kind === 'wan')!;
  eq(wan.value, 'enp3s0', 'o valor do link é a interface');
  eq(wan.label, 'Fibra 500M', 'e o rótulo é o nome que o admin deu');
}

{
  const t = buildTargets(HOSTS, [], [], '192.168.3.0/24', AGORA);
  // Quem lembra do nome digita o nome; quem está olhando um log digita o IP.
  eq(searchTargets('maria', t)[0].label, 'notebook-maria', 'acha pelo nome');
  eq(searchTargets('3.51', t)[0].label, 'tv-sala', 'acha pelo endereço');
  eq(searchTargets('MARIA', t).length, 1, 'busca ignora caixa');
}

{
  // Na hora de bloquear alguém, é quase sempre alguém que está na rede AGORA.
  const t = buildTargets(HOSTS, [], [], '', AGORA);
  const hosts = searchTargets('', t).filter((x) => x.kind === 'host');
  eq(hosts[0].label, 'notebook-maria', 'host online vem antes do offline');
}

{
  const t = buildTargets(HOSTS, [], [{ id: 'l1', name: 'Fibra', interface: 'e0' }], '192.168.3.0/24', AGORA);
  const ordem = searchTargets('', t).map((x) => x.kind);
  const pos = (k: string) => ordem.indexOf(k as never);
  check(pos('host') < pos('rede'), 'aparelhos antes de redes');
  check(pos('rede') < pos('wan'), 'redes antes de links WAN');
}

{
  const alvo: Target = { id: 'x', kind: 'host', label: 'notebook-maria', hint: '', value: '192.168.3.47' };
  eq(describeTarget(alvo), 'notebook-maria (192.168.3.47)', 'descrição mostra nome E endereço');
  eq(describeTarget(null), 'qualquer origem', 'sem alvo, o texto do vazio');
  eq(describeTarget({ ...alvo, kind: 'wan', label: 'Fibra', value: 'e0' }), 'pelo link Fibra', 'link vira "pelo link"');
}

{
  eq(buildTargets([], [], [], '', AGORA).length, 0, 'sem dado nenhum, lista vazia — não quebra');
  eq(searchTargets('x', []).length, 0, 'busca em lista vazia');
}

console.log(`${n} asserções passaram.`);
