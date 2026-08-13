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
  TRAFFIC_WINDOWS,
  axisPadLeft,
  bitsFromBytes,
  contiguousRuns,
  formatBps,
  formatVolume,
  isEmptySeries,
  latestSample,
  niceScale,
  pointsFromHistory,
  reduceToWidth,
  seriesMax,
  seriesPeak,
  totalBytes,
  windowFor,
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

// A ausência atravessa a conversão inteira, e não vira zero no caminho.
//
// Este defeito já existiu dos dois lados. No backend, a junção das duas séries
// lia o mapa sem `comma-ok` e devolvia o zero-value da chave ausente (corrigido
// em 63dbd91: os campos viraram ponteiro e o JSON traz `null`). Aqui, em
// JavaScript, `null * 8` é `0` — uma conversão ingênua reinventaria exatamente
// o mesmo zero, agora do lado da tela, e um link fora do ar voltaria a parecer
// um link ocioso.
{
  const out = pointsFromHistory([
    { timestamp: 1_700_000_000, rx_bps: 1_275_000, tx_bps: null },
    { timestamp: 1_700_000_001, rx_bps: null, tx_bps: null },
    { timestamp: 1_700_000_002, rx_bps: 0, tx_bps: 0 },
  ]);
  assert(out[0].tx === null, `null da API tem que chegar null ao Point, obtive ${out[0].tx}`);
  assert(out[0].rx === 1_275_000 * BITS_PER_BYTE, 'o sentido que FOI medido continua convertido');
  assert(out[1].rx === null && out[1].tx === null, 'instante sem nenhuma medição não vira dois zeros');
  assert(out[2].rx === 0 && out[2].tx === 0, 'zero medido continua zero — é medição, e se desenha');
  assert(
    formatBps(out[0].tx) === '—' && formatBps(out[2].tx) === '0',
    'na tela: `—` é não medido, `0` é medido e deu zero',
  );
  // A porta de entrada é uma só, então basta ela propagar para o resto do
  // arquivo tratar a ausência como já trata: aqui a prova de ponta a ponta.
  assert(seriesPeak([out[1]]) === null, 'uma série feita só de ausências continua sem pico');
  assert(contiguousRuns(out.map((p) => p.tx)).length === 1, 'o buraco continua sendo buraco depois da conversão');
}

// ─────────────────────────────────────────────────────────────────────────────
// A outra porta de entrada de taxa: /api/system/status
// ─────────────────────────────────────────────────────────────────────────────
// `deriveRate()` tira bytes/s dos contadores de /proc/net/dev. O app inteiro
// fala Mb/s (a unidade do link: os "100 mega" da operadora são bits), então
// essa taxa também passa por uma conversão única.
//
// Estas asserções existem porque a mudança de unidade multiplica por 8 um
// número que já estava em produção: um ponto que troque só o rótulo passa a
// mentir por 8×, e mentir por 8× é plausível o bastante para não saltar aos
// olhos de ninguém.
grupo('bytes/s do status viram bits/s');
{
  assert(bitsFromBytes(1) === 8, `1 B/s são 8 b/s, obtive ${bitsFromBytes(1)}`);
  assert(bitsFromBytes(0) === 0, 'zero medido continua zero');
  assert(
    bitsFromBytes(1_275_000) === 10_200_000,
    `1,275 MB/s são 10,2 Mb/s, obtive ${bitsFromBytes(1_275_000)}`,
  );
  // Rótulo e valor juntos: o mesmo contador que a tela antiga mostrava como
  // "1.2 MB/s" tem que aparecer agora como "10.2 Mb/s" — não como "1.2 Mb/s"
  // (só o rótulo trocado) nem como "10.2 MB/s" (só o valor trocado).
  assert(
    formatBps(bitsFromBytes(1_275_000)) === '10.2 Mb/s',
    `obtive "${formatBps(bitsFromBytes(1_275_000))}"`,
  );
  // Um link de 100 Mb/s saturado entrega ~12,5 MB/s nos contadores; a tela
  // tem que dizer 100 Mb/s, que é o número do plano contratado.
  assert(
    formatBps(bitsFromBytes(12_500_000)) === '100 Mb/s',
    `o plano de 100 mega tem que ler 100 Mb/s, obtive "${formatBps(bitsFromBytes(12_500_000))}"`,
  );
  assert(
    pointsFromHistory([{ timestamp: 0, rx_bps: 12_500_000, tx_bps: 0 }])[0].rx === bitsFromBytes(12_500_000),
    'histórico e status têm que chegar na mesma unidade para o mesmo byte/s',
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pico e total da faixa: ausência é `—`, zero medido é zero
// ─────────────────────────────────────────────────────────────────────────────
grupo('pico e total da faixa');
{
  assert(seriesPeak([]) === null, 'série vazia não tem pico');
  assert(
    seriesPeak([{ t: 0, rx: null, tx: null }]) === null,
    'série só de ausências não tem pico — `—`, não `0`',
  );
  assert(
    seriesPeak([{ t: 0, rx: 0, tx: 0 }]) === 0,
    'zero medido é pico 0, e continua sendo uma medição',
  );
  assert(
    seriesPeak([
      { t: 0, rx: 1_000, tx: null },
      { t: 1, rx: null, tx: 84_000_000 },
    ]) === 84_000_000,
    'o pico olha rx e tx',
  );
  assert(formatBps(seriesPeak([{ t: 0, rx: null, tx: null }])) === '—', 'e o texto do pico ausente é —');

  assert(totalBytes([], 1) === null, 'sem amostra não há total');
  assert(
    totalBytes([{ t: 0, rx: null, tx: null }], 60) === null,
    'só ausências não somam zero — somam nada',
  );
  // 1 MB/s durante 60 s de rx: 60 MB. Em bits/s isso é 8 Mb/s; a integral tem
  // que voltar para bytes, senão o "total" fica 8× maior que o real.
  assert(
    totalBytes([{ t: 0, rx: 8_000_000, tx: 0 }], 60) === 60_000_000,
    `60 s a 8 Mb/s são 60 MB, obtive ${totalBytes([{ t: 0, rx: 8_000_000, tx: 0 }], 60)}`,
  );
  assert(
    totalBytes([{ t: 0, rx: 8_000_000, tx: 8_000_000 }], 60) === 120_000_000,
    'rx e tx entram os dois no total',
  );
  assert(
    totalBytes(
      [
        { t: 0, rx: 8_000_000, tx: 0 },
        { t: 1, rx: null, tx: null },
      ],
      60,
    ) === 60_000_000,
    'o buraco não contribui com nada para o total',
  );
  assert(totalBytes([{ t: 0, rx: 8_000_000, tx: 0 }], 0) === null, 'sem passo não há integral');
}

grupo('formato de volume');
{
  assert(formatVolume(null) === '—', `volume ausente é —, obtive "${formatVolume(null)}"`);
  assert(formatVolume(0) === '0 B', `volume zero medido é 0 B, obtive "${formatVolume(0)}"`);
  assert(formatVolume(512) === '512 B', `obtive "${formatVolume(512)}"`);
  assert(formatVolume(1024) === '1.0 KB', `obtive "${formatVolume(1024)}"`);
  assert(formatVolume(1024 ** 3 * 4.2) === '4.2 GB', `obtive "${formatVolume(1024 ** 3 * 4.2)}"`);
  assert(formatVolume(NaN) === '—', 'NaN é ausência de volume');
  // Volume não é taxa, e o rótulo tem que deixar isso óbvio: GB (byte) para
  // "quanto passou", Mb/s (bit) para "quão rápido". Trocar um pelo outro é o
  // erro de 8× com outra fantasia.
  assert(!formatVolume(1024 ** 3).includes('/s'), 'volume não leva /s');
  assert(formatBps(1024 ** 3).includes('/s'), 'taxa leva /s');
}

// ─────────────────────────────────────────────────────────────────────────────
// A resolução se escolhe pela janela pedida
// ─────────────────────────────────────────────────────────────────────────────
// Pedir um ano em passo de 1 s são ~31 milhões de linhas lidas do SQLite para
// desenhar algumas centenas de colunas. Esta tabela espelha
// `internal/tsdb.rangeToStepDuration`; se alguém acrescentar uma janela nova
// apontando para a resolução errada, é aqui que aparece.
grupo('resolução por janela');
{
  const passoDoBackend: Record<string, number> = {
    '5m': 1,
    '30m': 1,
    '12h': 60,
    '30d': 900,
    '1y': 3600,
    '5y': 3600,
  };

  assert(TRAFFIC_WINDOWS.length === 4, `as quatro resoluções do tsdb, obtive ${TRAFFIC_WINDOWS.length}`);

  const passos = TRAFFIC_WINDOWS.map((w) => w.step);
  assert(
    JSON.stringify(passos) === JSON.stringify([1, 60, 900, 3600]),
    `uma janela por resolução do tsdb, obtive ${JSON.stringify(passos)}`,
  );

  for (const w of TRAFFIC_WINDOWS) {
    assert(
      passoDoBackend[w.range] === w.step,
      `a janela "${w.label}" pede range=${w.range}, que o backend serve em passo ${passoDoBackend[w.range]}s, não ${w.step}s`,
    );
    // Nenhuma janela pode pedir mais pontos do que uma tela consegue usar: o
    // gráfico reduz para umas poucas centenas de colunas, então acima de uns
    // milhares de pontos só se paga banco, rede e memória à toa.
    const pontos = w.spanSeconds / w.step;
    assert(
      pontos <= 12_000,
      `a janela "${w.label}" pediria ${Math.round(pontos)} pontos — resolução fina demais para a largura pedida`,
    );
    assert(pontos >= 100, `a janela "${w.label}" pediria só ${Math.round(pontos)} pontos — grossa demais`);
    assert(w.spanSeconds > 0 && w.step > 0, `a janela "${w.label}" precisa de largura e passo`);
  }

  for (let i = 1; i < TRAFFIC_WINDOWS.length; i++) {
    assert(
      TRAFFIC_WINDOWS[i].spanSeconds > TRAFFIC_WINDOWS[i - 1].spanSeconds,
      'janela mais larga vem depois',
    );
    assert(
      TRAFFIC_WINDOWS[i].step > TRAFFIC_WINDOWS[i - 1].step,
      'janela mais larga tem que vir com passo mais grosso, nunca com o mesmo ou mais fino',
    );
  }

  assert(windowFor('12h').step === 60, 'windowFor acha a janela pelo range');
  assert(windowFor('nao-existe').step === 1, 'range desconhecido cai na mais fina, que é a de menor custo por ponto');
}

// ─────────────────────────────────────────────────────────────────────────────
// A "taxa agora" dos widgets do painel
// ─────────────────────────────────────────────────────────────────────────────
// Pegar o último elemento da janela seria o defeito: o último intervalo pode
// não ter amostra, e viraria um `0` na tela — link fora do ar com cara de link
// ocioso, que é o mesmo erro que a Fase A já pegou duas vezes.
grupo('última amostra medida');
{
  assert(latestSample([]) === null, 'série vazia não tem última amostra');
  assert(
    latestSample([{ t: 0, rx: null, tx: null }]) === null,
    'série só de ausências não tem última amostra — `—`, e não `0`',
  );
  assert(
    latestSample([
      { t: 0, rx: 1_000, tx: 2_000 },
      { t: 1, rx: null, tx: null },
      { t: 2, rx: null, tx: null },
    ])?.rx === 1_000,
    'com o fim da janela vazio, vale a última MEDIDA, e não o último elemento',
  );
  assert(
    latestSample([
      { t: 0, rx: 1_000, tx: null },
      { t: 1, rx: 9_000, tx: null },
    ])?.rx === 9_000,
    'a mais recente é a do fim, não a do começo',
  );
  assert(
    latestSample([{ t: 0, rx: 0, tx: 0 }])?.rx === 0,
    'zero medido É uma amostra: zero é medição, ausência não',
  );
  assert(
    latestSample([
      { t: 0, rx: 500, tx: 500 },
      { t: 1, rx: null, tx: 700 },
    ])?.tx === 700,
    'um instante com só um dos sentidos medido ainda é uma amostra',
  );
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
