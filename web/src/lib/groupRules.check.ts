// Asserções de `groupRules.ts` — a tradução de ordem local → global e o corte
// da chain do grupo.
//
// O frontend não tem teste de render, e o CI só prova que o bundle compila:
// tudo o que estas duas contas erram, elas erram em silêncio e compilando. A
// que dói é a tradução da ordem: `/api/nftables/rules/reorder` recebe a lista
// GLOBAL de todas as regras de todos os grupos, então um índice deslocado não
// bagunça a tela — ele reescreve a ordem de avaliação do firewall, e um
// `accept` que sobe acima de um `drop` abre o que estava fechado sem nenhuma
// mensagem de erro.
//
// Mesmo formato de `series.check.ts`, `grid.check.ts` e `widgets.check.ts`: um
// programa comum, sem runner e sem dependência nova (spec §4.3 — num appliance
// de segurança, uma biblioteca de teste é superfície de cadeia de suprimentos
// por conveniência), executável pelo node que já está instalado e que sai com
// código ≠ 0 na falha.
//
// Como rodar (a partir de `web/`):
//
//     node --experimental-strip-types src/lib/groupRules.check.ts
//
// Não entra no bundle (nada em `main.tsx` o alcança), mas é, sim, verificado
// por `tsc --noEmit`.

import {
  globalReorder,
  mergeGroupRules,
  moveItem,
  splitGroupRules,
} from './groupRules.ts';
import type { GlobalRule, GroupRuleSource, ReorderResult } from './groupRules.ts';
import type { GroupFallthrough, NftChainRule } from '../types/index.ts';

let falhas = 0;
let total = 0;
let grupoAtual = '';

function grupo(nome: string) {
  grupoAtual = nome;
}

function assert(cond: boolean, msg: string) {
  total++;
  if (cond) return;
  falhas++;
  console.error(`  FALHOU [${grupoAtual}] ${msg}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fábricas
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Uma linha da chain como a API a devolve. `id` presente = regra do admin;
 * `id` ausente = linha que só existe no firewall vivo.
 *
 * `managed: false` no padrão é de propósito: é assim que a linha do veredito
 * volta, e é assim que uma regra de verdade do admin também pode voltar. Se o
 * corte dependesse de `managed`, este padrão sozinho já o quebraria.
 */
function linha(id?: string, expression = 'counter drop'): NftChainRule {
  return {
    chain: 'grp_meio',
    handle: 0,
    expression,
    has_counter: false,
    packets: 0,
    bytes: 0,
    managed: false,
    owner: { label: 'linkguard' },
    description: '',
    ...(id ? { id, enabled: true } : {}),
  };
}

function comoGrupo(fallthrough: GroupFallthrough, rules: NftChainRule[]): GroupRuleSource {
  return { fallthrough, rules: { rules } };
}

/** Lista global de regras: `a1 a2 | b1 b2 b3 | c1` em três grupos. */
function listaGlobal(...pares: Array<[string, string]>): GlobalRule[] {
  return pares.map(([group_id, id]) => ({ group_id, id }));
}

/**
 * A ordem global resultante, num texto comparável — e um marcador impossível
 * de confundir com uma lista quando a tradução recusou. Comparar o texto (e
 * não índice a índice) é de propósito: a asserção que falha imprime a ordem
 * INTEIRA que saiu, que é o que se precisa ler para entender um deslocamento.
 */
function ordem(r: ReorderResult): string {
  return r.ok ? r.ids.join(' ') : '(fora de sincronia)';
}

// ─────────────────────────────────────────────────────────────────────────────
// O grupo do MEIO — onde o off-by-one aparece
// ─────────────────────────────────────────────────────────────────────────────
// A lista global tem regras de OUTROS grupos antes e depois. É o caso que um
// teste distraído não monta: com o grupo alvo em primeiro lugar e sem buraco
// nenhum, "andar o contador a cada linha" e "andar só nos slots do grupo" dão
// o mesmo resultado, e a conta errada passa.
grupo('grupo do meio');
{
  // a1 a2 | b1 b2 b3 | c1 — e o grupo b, o do meio, vira b3 b1 b2.
  const todas = listaGlobal(
    ['a', 'a1'], ['a', 'a2'],
    ['b', 'b1'], ['b', 'b2'], ['b', 'b3'],
    ['c', 'c1'],
  );
  const r = globalReorder(todas, 'b', [linha('b3'), linha('b1'), linha('b2')]);
  assert(r.ok, 'a contagem bate, tinha que traduzir');
  assert(
    ordem(r) === 'a1 a2 b3 b1 b2 c1',
    `os slots do grupo b recebem a ordem nova e ninguém mais se mexe, obtive "${ordem(r)}"`,
  );

  // A prova de que o vizinho não andou, dita de novo por outro ângulo: fora
  // dos slots de `b`, a lista global é IDÊNTICA à de entrada. Um contador que
  // anda a cada linha erraria justamente aqui, deslocando a1/a2/c1.
  if (r.ok) {
    const foraDoGrupo = r.ids.filter((_, i) => todas[i].group_id !== 'b');
    assert(
      foraDoGrupo.join(' ') === 'a1 a2 c1',
      `regra de outro grupo não pode sair do lugar, obtive "${foraDoGrupo.join(' ')}"`,
    );
    assert(r.ids.length === todas.length, `a lista global tem que sair completa, obtive ${r.ids.length}`);
    assert(
      !r.ids.some((id) => id === undefined || id === null),
      'nenhum buraco na lista global: um undefined aqui apaga uma regra da ordem',
    );
  }
}

{
  // O mesmo grupo do meio, agora INTERCALADO: os slots de `b` não são
  // contíguos na ordem global. É o estado normal depois de alguns arrastos, e
  // é o que quebra qualquer tradução que use `slice`/offset em vez de andar
  // slot a slot.
  const todas = listaGlobal(
    ['a', 'a1'],
    ['b', 'b1'],
    ['c', 'c1'],
    ['b', 'b2'],
    ['a', 'a2'],
    ['b', 'b3'],
  );
  const r = globalReorder(todas, 'b', [linha('b3'), linha('b2'), linha('b1')]);
  assert(
    ordem(r) === 'a1 b3 c1 b2 a2 b1',
    `com os slots intercalados a ordem nova cai nos slots de b, na sequência, obtive "${ordem(r)}"`,
  );
}

{
  // Grupo do meio e a ordem NÃO mudou: traduzir tem que ser identidade. Se
  // este caso mexer em alguma coisa, todo arrasto cancelado reordenaria o
  // firewall à toa.
  const todas = listaGlobal(['a', 'a1'], ['b', 'b1'], ['b', 'b2'], ['c', 'c1']);
  const r = globalReorder(todas, 'b', [linha('b1'), linha('b2')]);
  assert(ordem(r) === 'a1 b1 b2 c1', `ordem igual entra e sai igual, obtive "${ordem(r)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Grupo com UMA regra só
// ─────────────────────────────────────────────────────────────────────────────
// Uma regra não tem para onde ir, então a tradução é identidade — mas ela é
// identidade da lista GLOBAL inteira, e é aí que uma conta trocada estraga a
// ordem dos vizinhos enquanto o grupo alvo parece intocado na tela.
grupo('grupo de uma regra só');
{
  const todas = listaGlobal(['a', 'a1'], ['a', 'a2'], ['b', 'b1'], ['c', 'c1'], ['c', 'c2']);
  const r = globalReorder(todas, 'b', [linha('b1')]);
  assert(r.ok, 'uma regra e um id: a contagem bate');
  assert(ordem(r) === 'a1 a2 b1 c1 c2', `a lista global sai intacta, obtive "${ordem(r)}"`);

  // E o grupo de uma regra só no PRIMEIRO e no ÚLTIMO slot da lista global —
  // as duas bordas, onde um índice deslocado por um estoura ou repete.
  const primeiro = globalReorder(listaGlobal(['b', 'b1'], ['a', 'a1'], ['a', 'a2']), 'b', [linha('b1')]);
  assert(ordem(primeiro) === 'b1 a1 a2', `grupo de uma regra no começo, obtive "${ordem(primeiro)}"`);
  const ultimo = globalReorder(listaGlobal(['a', 'a1'], ['a', 'a2'], ['b', 'b1']), 'b', [linha('b1')]);
  assert(ordem(ultimo) === 'a1 a2 b1', `grupo de uma regra no fim, obtive "${ordem(ultimo)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Grupo VAZIO
// ─────────────────────────────────────────────────────────────────────────────
// Zero regras é um estado, não um erro: o grupo existe, tem condição de
// entrada e um veredito, e só não tem regra nenhuma dentro. A tradução tem que
// devolver a lista global inteira, sem tocar em nada.
grupo('grupo vazio');
{
  const todas = listaGlobal(['a', 'a1'], ['a', 'a2'], ['c', 'c1']);
  const r = globalReorder(todas, 'b', []);
  assert(r.ok, 'zero slots e zero ids: a contagem bate, e vazio não é erro');
  assert(ordem(r) === 'a1 a2 c1', `nada muda na lista global, obtive "${ordem(r)}"`);

  // A lista global inteira vazia (nenhuma regra em grupo nenhum) também é uma
  // tela legítima — o firewall recém-instalado é exatamente isso.
  const nada = globalReorder([], 'b', []);
  assert(nada.ok, 'sem regra nenhuma no banco, reordenar um grupo vazio não é erro');
  assert(ordem(nada) === '', `a lista global vazia sai vazia, obtive "${ordem(nada)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fora de sincronia
// ─────────────────────────────────────────────────────────────────────────────
// A tela mostra uma quantidade de regras e o banco tem outra: alguém criou ou
// apagou regra em outra aba. Mandar a lista assim reordenaria o firewall por
// um palpite — com ids a menos, os slots do fim sairiam com `undefined`, e as
// regras que caíram do fim SOMEM da ordem global.
grupo('fora de sincronia');
{
  const todas = listaGlobal(['a', 'a1'], ['b', 'b1'], ['b', 'b2'], ['b', 'b3']);

  const menos = globalReorder(todas, 'b', [linha('b2'), linha('b1')]);
  assert(!menos.ok, 'tela com 2 e banco com 3 tem que recusar');
  if (!menos.ok) {
    assert(menos.noBanco === 3 && menos.naTela === 2, `os dois números vão no diagnóstico, obtive ${menos.noBanco}/${menos.naTela}`);
  }

  const mais = globalReorder(todas, 'b', [linha('b1'), linha('b2'), linha('b3'), linha('b4')]);
  assert(!mais.ok, 'tela com 4 e banco com 3 também tem que recusar');

  // Linha sem id na lista arrastada NÃO conta como regra: é o veredito ou uma
  // divergência, e ela não tem posição em firewall_rules para reordenar. Aqui
  // as três com id batem com o banco, então a tradução passa e a linha sem id
  // simplesmente não aparece na ordem global.
  const comVeredito = globalReorder(todas, 'b', [linha('b3'), linha('b1'), linha('b2'), linha(undefined)]);
  assert(comVeredito.ok, 'linha sem id não entra na contagem das regras do admin');
  assert(ordem(comVeredito) === 'a1 b3 b1 b2', `e não entra na lista global, obtive "${ordem(comVeredito)}"`);

  // Grupo que a tela conhece mas cujas regras sumiram todas do banco: recusar
  // é o certo, e o "vazio" acima (0 slots, 0 ids) continua sendo o caso ok.
  const sumiram = globalReorder(listaGlobal(['a', 'a1']), 'b', [linha('b1')]);
  assert(!sumiram.ok, 'a tela tem regra que o banco não tem: recusa');
}

// ─────────────────────────────────────────────────────────────────────────────
// Arrastar: moveItem
// ─────────────────────────────────────────────────────────────────────────────
// A outra metade do off-by-one. `to` é o índice de destino já na lista SEM o
// item arrastado, que é o que "soltei em cima da linha i" quer dizer na tela.
grupo('arrastar');
{
  const rows = ['r1', 'r2', 'r3', 'r4'];
  assert(moveItem(rows, 3, 0).join(' ') === 'r4 r1 r2 r3', 'a última sobe para o topo');
  assert(moveItem(rows, 0, 3).join(' ') === 'r2 r3 r4 r1', 'a primeira desce para o fim');
  assert(moveItem(rows, 1, 2).join(' ') === 'r1 r3 r2 r4', 'descer um degrau troca com o vizinho de baixo');
  assert(moveItem(rows, 2, 1).join(' ') === 'r1 r3 r2 r4', 'subir um degrau troca com o vizinho de cima');
  assert(moveItem(rows, 2, 2).join(' ') === 'r1 r2 r3 r4', 'soltar no próprio lugar não muda nada');
  assert(rows.join(' ') === 'r1 r2 r3 r4', 'moveItem não pode mutar a lista de entrada');
  assert(moveItem(['só'], 0, 0).join(' ') === 'só', 'lista de um item aguenta o arrasto');

  // O arrasto e a tradução juntos, no grupo do meio: é o caminho inteiro que a
  // tela percorre quando alguém solta uma regra em cima de outra.
  const todas = listaGlobal(['a', 'a1'], ['b', 'b1'], ['b', 'b2'], ['b', 'b3'], ['c', 'c1']);
  const linhas = [linha('b1'), linha('b2'), linha('b3')];
  const r = globalReorder(todas, 'b', moveItem(linhas, 2, 0));
  assert(ordem(r) === 'a1 b3 b1 b2 c1', `arrastar b3 para o topo do grupo do meio, obtive "${ordem(r)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
// splitGroupRules: quem tem botão de editar e quem não tem
// ─────────────────────────────────────────────────────────────────────────────
// O corte é pela presença de `id` e pelo FIM da lista, nunca por `managed`: a
// linha do veredito volta com managed=false igualzinho a uma regra do admin, e
// dar a ela botão de apagar ofereceria ao operador apagar um campo do grupo.
grupo('separar a chain');
{
  const g = comoGrupo('drop', [linha('r1'), linha('r2'), linha(undefined, 'counter drop')]);
  const { rules, extras, fall } = splitGroupRules(g);
  assert(rules.length === 2, `duas regras do admin, obtive ${rules.length}`);
  assert(rules.every((r) => !!r.id), 'toda regra do admin tem id — é o que libera editar e apagar');
  assert(!!fall, 'com fallthrough=drop, a última linha sem id é o veredito');
  assert(fall?.id === undefined, 'o veredito não tem id, e por isso nunca ganha botão');
  assert(extras.length === 0, 'sem divergência, extras é vazio');
}

{
  // fallthrough=continue não emite linha nenhuma: qualquer linha sem id no fim
  // é divergência entre o banco e a chain viva, e tem que APARECER como tal —
  // chamá-la de veredito a esconderia num campo que o grupo nem tem.
  const g = comoGrupo('continue', [linha('r1'), linha(undefined, 'counter accept')]);
  const { rules, extras, fall } = splitGroupRules(g);
  assert(rules.length === 1, `uma regra do admin, obtive ${rules.length}`);
  assert(fall === undefined, 'com continue não existe linha de veredito');
  assert(extras.length === 1, `a linha órfã aparece como divergência, obtive ${extras.length}`);
}

{
  // Veredito MAIS divergência: só a ÚLTIMA sem id é o veredito, as outras são
  // divergência. Tratar todas como veredito sumiria com linhas que estão
  // valendo no kernel.
  const g = comoGrupo('accept', [linha('r1'), linha(undefined, 'x'), linha(undefined, 'counter accept')]);
  const { rules, extras, fall } = splitGroupRules(g);
  assert(rules.length === 1, `uma regra do admin, obtive ${rules.length}`);
  assert(fall?.expression === 'counter accept', 'o veredito é a ÚLTIMA linha sem id');
  assert(extras.length === 1 && extras[0].expression === 'x', 'a do meio continua visível como divergência');
}

{
  // Uma linha sem id ANTES de regras do admin não é veredito nem some: o corte
  // é pelo fim, então ela fica dentro de `rules`. É divergência de verdade, e
  // a tela mostra a chain como ela está — um filtro por `id` a apagaria.
  const g = comoGrupo('drop', [linha(undefined, 'órfã no meio'), linha('r1'), linha(undefined, 'counter drop')]);
  const { rules, fall } = splitGroupRules(g);
  assert(rules.length === 2, `o corte é pelo fim: a órfã do começo fica na lista, obtive ${rules.length}`);
  assert(fall?.expression === 'counter drop', 'e o veredito continua sendo o do fim');
}

{
  // Grupo VAZIO, de novo, agora do lado do corte — inclusive o grupo do
  // sistema, que volta da API sem lista nenhuma. Nenhum dos dois pode explodir
  // nem inventar um veredito.
  const semRegra = splitGroupRules(comoGrupo('drop', []));
  assert(semRegra.rules.length === 0 && semRegra.extras.length === 0, 'grupo vazio: nada de nada');
  assert(semRegra.fall === undefined, 'grupo vazio não tem linha de veredito para mostrar');

  const semLista = splitGroupRules({ fallthrough: 'drop' });
  assert(semLista.rules.length === 0, 'grupo do sistema volta sem lista e não pode quebrar a tela');
  const listaNula = splitGroupRules({ fallthrough: 'accept', rules: null });
  assert(listaNula.rules.length === 0, 'rules: null também é uma tela vazia, não um erro');

  // Grupo de UMA regra só: a regra é do admin, e não veredito disfarçado.
  const uma = splitGroupRules(comoGrupo('continue', [linha('r1')]));
  assert(uma.rules.length === 1 && uma.rules[0].id === 'r1', 'a única regra é do admin e é editável');
  assert(uma.fall === undefined && uma.extras.length === 0, 'e não sobra nada atrás dela');

  // Só o veredito, sem regra nenhuma: a lista de regras é vazia e o veredito
  // continua desenhado. É o grupo recém-criado com "e o que sobrar = drop".
  const sóVeredito = splitGroupRules(comoGrupo('drop', [linha(undefined, 'counter drop')]));
  assert(sóVeredito.rules.length === 0, 'grupo novo não tem regra');
  assert(!!sóVeredito.fall, 'mas o veredito dele aparece');
}

// ─────────────────────────────────────────────────────────────────────────────
// splitGroupRules ∘ mergeGroupRules: o arrasto não pode perder linha
// ─────────────────────────────────────────────────────────────────────────────
// A tela remonta a chain otimista antes de o POST voltar. Perder o veredito ou
// a divergência aqui apagaria da tela, por alguns quadros, justamente a linha
// que decide o que o grupo faz com o que sobrou — na tela em que alguém está
// conferindo se o arrasto fez o que queria.
grupo('remontar depois do arrasto');
{
  const todas = [linha('r1'), linha('r2'), linha('r3'), linha(undefined, 'x'), linha(undefined, 'counter drop')];
  const g = comoGrupo('drop', todas);
  const split = splitGroupRules(g);
  const merged = mergeGroupRules(moveItem(split.rules, 2, 0), split);
  assert(merged.length === todas.length, `nenhuma linha some no caminho, obtive ${merged.length} de ${todas.length}`);
  assert(
    merged.slice(0, 3).map((r) => r.id).join(' ') === 'r3 r1 r2',
    'as regras do admin saem na ordem nova',
  );
  assert(merged[3].expression === 'x', 'a divergência continua atrás delas');
  assert(merged[4].expression === 'counter drop', 'e o veredito continua sendo a última linha');

  // Sem mexer em nada, remontar tem que devolver a MESMA chain que entrou.
  const igual = mergeGroupRules(split.rules, split);
  assert(
    igual.map((r) => r.expression).join('|') === todas.map((r) => r.expression).join('|'),
    'separar e remontar sem arrastar é identidade',
  );
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
