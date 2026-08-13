// Asserções de `series.ts`, a lógica que erra em silêncio.
//
// O projeto não tem runner de teste de frontend, e a restrição de "nenhuma
// dependência nova" (spec §4.3 — num appliance de segurança, uma biblioteca é
// superfície de cadeia de suprimentos por conveniência) vale também para
// vitest/jest. Então as asserções são um programa comum, executável pelo node
// que já está instalado, que sai com código ≠ 0 na falha.
//
// Como rodar (a partir de `web/`):
//
//     node --experimental-strip-types src/lib/series.check.ts
//
// Este arquivo não entra no bundle: nada em `main.tsx` o importa, então o
// Vite nunca o alcança. Ele é, sim, verificado por `tsc --noEmit`.

import {
  AXIS_LABEL_MAX,
  BITS_PER_BYTE,
  LOG_DECADES,
  axisPadLeft,
  contiguousRuns,
  formatBps,
  isEmptySeries,
  niceScale,
  pointsFromHistory,
  reduceToWidth,
  seriesMax,
} from './series.ts';
import type { Point } from './series.ts';

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
// O pico sobrevive à redução
// ─────────────────────────────────────────────────────────────────────────────
// Média esconde rajada. Um pico de 84 Mb/s dentro de um bucket cheio de
// tráfego baixo TEM que sobreviver à redução — é o pico que derruba link, e é
// ele que o operador está procurando quando abre esta tela.
grupo('pico sobrevive');
{
  const pts: Point[] = [
    { t: 0, rx: 1, tx: 0 },
    { t: 1, rx: 1, tx: 0 },
    { t: 2, rx: 84_000_000, tx: 0 },
    { t: 3, rx: 1, tx: 0 },
  ];
  const out = reduceToWidth(pts, 1);
  assert(out.length === 1, `um bucket, obtive ${out.length}`);
  assert(out[0].rx === 84_000_000, `o pico tem que sobreviver, obtive ${out[0].rx}`);
}

// O mesmo para tx, e com o pico no primeiro e no último ponto do bucket — a
// redução não pode depender de onde a rajada cai dentro do intervalo.
{
  const meio: Point[] = [
    { t: 0, rx: 0, tx: 5 },
    { t: 1, rx: 0, tx: 90_000_000 },
    { t: 2, rx: 0, tx: 5 },
  ];
  assert(reduceToWidth(meio, 1)[0].tx === 90_000_000, 'pico de tx no meio tem que sobreviver');

  const inicio: Point[] = [
    { t: 0, rx: 0, tx: 90_000_000 },
    { t: 1, rx: 0, tx: 5 },
    { t: 2, rx: 0, tx: 5 },
  ];
  assert(reduceToWidth(inicio, 1)[0].tx === 90_000_000, 'pico de tx no início tem que sobreviver');

  const fim: Point[] = [
    { t: 0, rx: 0, tx: 5 },
    { t: 1, rx: 0, tx: 5 },
    { t: 2, rx: 0, tx: 90_000_000 },
  ];
  assert(reduceToWidth(fim, 1)[0].tx === 90_000_000, 'pico de tx no fim tem que sobreviver');
}

// Com vários buckets, o máximo de cada intervalo continua sendo o máximo
// daquele intervalo — não do intervalo vizinho e não da série inteira.
{
  const pts: Point[] = [];
  for (let i = 0; i < 100; i++) pts.push({ t: i, rx: 10, tx: 10 });
  pts[5] = { t: 5, rx: 1_000_000, tx: 10 };
  pts[95] = { t: 95, rx: 10, tx: 2_000_000 };
  const out = reduceToWidth(pts, 10);
  assert(out.length === 10, `dez buckets, obtive ${out.length}`);
  assert(out[0].rx === 1_000_000, `o pico de rx fica no primeiro bucket, obtive ${out[0].rx}`);
  assert(out[9].tx === 2_000_000, `o pico de tx fica no último bucket, obtive ${out[9].tx}`);
  assert(out[4].rx === 10, `bucket sem rajada não herda o pico do vizinho, obtive ${out[4].rx}`);
  assert(seriesMax(out) === 2_000_000, `seriesMax tem que ver o maior dos dois, obtive ${seriesMax(out)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Sem amostra, sem linha
// ─────────────────────────────────────────────────────────────────────────────
// Zero é uma medição; ausência não é. Desenhar zero faria um link fora do ar
// parecer um link ocioso.
grupo('sem amostra fica em branco');
{
  const pts: Point[] = [
    { t: 0, rx: 5, tx: 5 },
    { t: 100, rx: 7, tx: 7 },
  ];
  const out = reduceToWidth(pts, 10);
  const vazios = out.filter((p) => p.rx === null);
  assert(vazios.length > 0, 'buckets sem amostra têm que vir null, não 0');
  assert(!out.some((p) => p.rx === 0), 'nenhum bucket vazio pode virar zero');
  assert(!out.some((p) => p.tx === 0), 'nenhum bucket vazio pode virar zero em tx');
  assert(out[0].rx === 5 && out[9].rx === 7, 'os buckets com amostra mantêm o valor medido');
}

// Zero medido continua sendo zero: o link ocioso desenha na linha do eixo, e
// não some. É a metade da regra que se esquece com facilidade.
{
  const out = reduceToWidth([{ t: 0, rx: 0, tx: 0 }], 1);
  assert(out[0].rx === 0, `zero medido tem que continuar 0, obtive ${out[0].rx}`);
  assert(!isEmptySeries(out), 'uma série de zeros medidos não é uma série vazia');
}

// Ausência num ponto individual (a API pode não ter uma das direções) não
// contamina o bucket, e um bucket só de ausências continua ausente.
{
  const out = reduceToWidth(
    [
      { t: 0, rx: null, tx: 100 },
      { t: 1, rx: 50, tx: null },
    ],
    1,
  );
  assert(out[0].rx === 50, `rx tem que ignorar o ponto sem medição, obtive ${out[0].rx}`);
  assert(out[0].tx === 100, `tx tem que ignorar o ponto sem medição, obtive ${out[0].tx}`);
}
{
  const out = reduceToWidth([{ t: 0, rx: null, tx: null }], 1);
  assert(out[0].rx === null && out[0].tx === null, 'bucket só de ausências continua ausente');
  assert(isEmptySeries(out), 'série só de ausências é vazia');
  assert(seriesMax(out) === 0, 'seriesMax de série vazia é 0');
}

// Casos de borda que não podem explodir nem inventar ponto.
{
  assert(reduceToWidth([], 10).length === 0, 'série vazia devolve vazio');
  assert(reduceToWidth([{ t: 0, rx: 1, tx: 1 }], 0).length === 0, 'zero buckets devolve vazio');
  const um = reduceToWidth([{ t: 5, rx: 3, tx: 4 }], 3);
  assert(um.length === 3, 'um único ponto ainda produz a largura pedida');
  assert(um.filter((p) => p.rx !== null).length === 1, 'um único ponto ocupa um único bucket');
  const fora = reduceToWidth(
    [
      { t: 10, rx: 1, tx: 1 },
      { t: 0, rx: 9, tx: 9 },
    ],
    2,
  );
  assert(fora[0].rx === 9, 'série fora de ordem é ordenada antes de reduzir');
}

// O buraco tem que virar buraco no desenho: a linha não pode atravessar um
// intervalo sem amostra ligando os dois lados — é o mesmo erro de desenhar
// zero, com outra aparência.
grupo('trechos contíguos');
{
  assert(JSON.stringify(contiguousRuns([1, 2, 3])) === '[[0,1,2]]', 'série inteira medida é um trecho só');
  assert(
    JSON.stringify(contiguousRuns([1, null, 3])) === '[[0],[2]]',
    `um buraco no meio separa em dois trechos, obtive ${JSON.stringify(contiguousRuns([1, null, 3]))}`,
  );
  assert(JSON.stringify(contiguousRuns([null, null])) === '[]', 'só ausência não desenha nada');
  assert(JSON.stringify(contiguousRuns([])) === '[]', 'série vazia não desenha nada');
  assert(
    JSON.stringify(contiguousRuns([null, 5, null])) === '[[1]]',
    'uma amostra isolada continua existindo — não desenhar o que falta não pode virar não desenhar o que existe',
  );
  assert(JSON.stringify(contiguousRuns([0, null, 0])) === '[[0],[2]]', 'zero medido conta como medido');
  const misto = contiguousRuns([1, 2, null, null, 3, null, 4, 5]);
  assert(JSON.stringify(misto) === '[[0,1],[4],[6,7]]', `obtive ${JSON.stringify(misto)}`);
  // Nenhum índice pode se perder nem aparecer duas vezes.
  const vals: (number | null)[] = [1, null, 2, 3, null, null, 4];
  const idx = contiguousRuns(vals).flat();
  assert(idx.length === vals.filter((v) => v !== null).length, 'todo índice medido tem que estar em algum trecho');
  assert(new Set(idx).size === idx.length, 'nenhum índice pode aparecer em dois trechos');
  assert(idx.every((i) => vals[i] !== null), 'nenhum índice ausente pode entrar num trecho');
}

// ─────────────────────────────────────────────────────────────────────────────
// Linear diz a verdade sobre magnitude; log revela a forma
// ─────────────────────────────────────────────────────────────────────────────
grupo('escala linear e log');
{
  const lin = niceScale(10_200_000, 'linear');
  const log = niceScale(10_200_000, 'log');
  assert(lin.project(510_000) !== log.project(510_000), 'a projeção tem que mudar');
  assert(
    log.project(510_000) > lin.project(510_000),
    `em log o tráfego pequeno tem que subir na tela — é o defeito que o modo existe para resolver ` +
      `(linear ${lin.project(510_000)}, log ${log.project(510_000)})`,
  );
  assert(
    lin.project(510_000) < 0.1,
    'em linear o tráfego de 510 kb/s embaixo de um pico de 10,2 Mb/s fica achatado — é o defeito real',
  );
  assert(log.project(510_000) > 0.4, 'em log ele tem que ocupar altura de verdade');
}

// O topo do eixo nunca corta o pico, nos dois modos, em várias magnitudes.
{
  for (const max of [1, 999, 1_000, 10_200_000, 84_000_000, 943_000_000]) {
    for (const mode of ['linear', 'log'] as const) {
      const s = niceScale(max, mode);
      assert(s.project(max) <= 1 + 1e-9, `${mode}: o pico não pode passar do topo (max ${max})`);
      assert(s.project(max) > 0.5, `${mode}: o pico não pode ficar espremido embaixo (max ${max})`);
      assert(s.max >= max * (1 - 1e-9), `${mode}: o topo do eixo tem que conter o pico (max ${max})`);
      assert(s.ticks.length >= 2, `${mode}: o eixo precisa de traços (max ${max})`);
      for (let i = 1; i < s.ticks.length; i++) {
        assert(s.ticks[i] > s.ticks[i - 1], `${mode}: os traços têm que ser crescentes (max ${max})`);
      }
    }
  }
}

// Monotonicidade e domínio: mais tráfego nunca desenha mais baixo, e nada sai
// da área de plotagem.
{
  for (const mode of ['linear', 'log'] as const) {
    const s = niceScale(10_200_000, mode);
    let anterior = -1;
    for (let v = 0; v <= 10_200_000; v += 51_000) {
      const p = s.project(v);
      assert(p >= 0 && p <= 1, `${mode}: projeção fora de [0,1] em ${v}: ${p}`);
      assert(p >= anterior - 1e-12, `${mode}: a projeção tem que ser monótona (em ${v})`);
      anterior = p;
    }
    assert(s.project(0) === 0, `${mode}: zero medido desenha na linha do eixo`);
    assert(s.project(-1) === 0, `${mode}: valor negativo (impossível) não pode virar projeção maluca`);
    assert(s.project(NaN) === 0, `${mode}: NaN não pode virar projeção maluca`);
  }
  assert(niceScale(0, 'linear').max > 0, 'série sem tráfego ainda tem eixo desenhável');
  assert(niceScale(0, 'log').max > 0, 'série sem tráfego ainda tem eixo desenhável em log');
}

// O log mostra a faixa de décadas que ele promete.
{
  const s = niceScale(10_200_000, 'log');
  const decadas = s.ticks.filter((t) => Math.abs(Math.log10(t) - Math.round(Math.log10(t))) < 1e-9);
  assert(
    decadas.length === LOG_DECADES,
    `o eixo log mostra ${LOG_DECADES} décadas, obtive ${decadas.length}`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// O rótulo do eixo não pode ser cortado
// ─────────────────────────────────────────────────────────────────────────────
// Isto saiu de um defeito real do mockup: padL pequeno demais transformou
// "10.2" em "0.2" na tela.
grupo('largura do rótulo do eixo');
{
  const s = niceScale(10_200_000, 'linear');
  const maiorRotulo = Math.max(...s.ticks.map((t) => formatBps(t).length));
  assert(maiorRotulo <= AXIS_LABEL_MAX, `o eixo tem que reservar largura para o maior rótulo, obtive ${maiorRotulo}`);
}

// A garantia de verdade: nenhum valor plausível de taxa produz rótulo maior
// que a largura reservada. Uma varredura, e não só o caso do mockup — foi
// exatamente "só o caso que eu imaginei" que deixou o defeito passar.
{
  let pior = 0;
  let piorValor = 0;
  for (let e = 0; e <= 13; e += 1) {
    for (const m of [1, 1.02, 1.5, 3.33, 5, 8.4, 9.99]) {
      const v = m * Math.pow(10, e);
      const len = formatBps(v).length;
      if (len > pior) {
        pior = len;
        piorValor = v;
      }
      for (const mode of ['linear', 'log'] as const) {
        for (const t of niceScale(v, mode).ticks) {
          const lt = formatBps(t).length;
          if (lt > pior) {
            pior = lt;
            piorValor = t;
          }
        }
      }
    }
  }
  assert(pior <= AXIS_LABEL_MAX, `nenhum rótulo pode passar de ${AXIS_LABEL_MAX} chars; pior: "${formatBps(piorValor)}" (${pior})`);
  assert(
    axisPadLeft() >= AXIS_LABEL_MAX * 6,
    `a margem esquerda tem que caber ${AXIS_LABEL_MAX} chars, obtive ${axisPadLeft()}px`,
  );
}

// Ausência é `—`, e nunca `0`: é a mesma regra do gráfico valendo no texto.
{
  assert(formatBps(null) === '—', `ausência é —, obtive "${formatBps(null)}"`);
  assert(formatBps(0) === '0', `zero medido é 0, obtive "${formatBps(0)}"`);
  assert(formatBps(NaN) === '—', 'NaN é ausência');
  assert(formatBps(510_000) === '510 kb/s', `obtive "${formatBps(510_000)}"`);
  assert(formatBps(10_200_000) === '10.2 Mb/s', `obtive "${formatBps(10_200_000)}"`);
  assert(formatBps(1_000_000_000) === '1.0 Gb/s', `obtive "${formatBps(1_000_000_000)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
// A API entrega bytes/s apesar do nome `_bps`
// ─────────────────────────────────────────────────────────────────────────────
// `internal/tsdb/traffic.go` divide o delta de /proc/net/dev (bytes) pelo
// intervalo em segundos. Quem lê link raciocina em bits: a conversão mora num
// lugar só para não ficar espalhada por cada tela.
grupo('conversão da API');
{
  const out = pointsFromHistory([{ timestamp: 1_700_000_000, rx_bps: 1_275_000, tx_bps: 0 }]);
  assert(out.length === 1, 'um ponto entra, um ponto sai');
  assert(out[0].t === 1_700_000_000_000, `timestamp em ms, obtive ${out[0].t}`);
  assert(out[0].rx === 1_275_000 * BITS_PER_BYTE, `bytes/s viram bits/s, obtive ${out[0].rx}`);
  assert(formatBps(out[0].rx) === '10.2 Mb/s', `10,2 Mb/s é o número do mockup, obtive "${formatBps(out[0].rx)}"`);
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
