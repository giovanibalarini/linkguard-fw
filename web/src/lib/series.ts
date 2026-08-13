// Redução de série temporal e escala de eixo para o gráfico de tráfego.
//
// Funções puras, sem React e sem DOM, de propósito: é aqui que mora a lógica
// que erra em silêncio (um gráfico com média parece perfeitamente razoável e
// esconde exatamente a rajada que o operador foi procurar), e só sendo pura
// ela dá para ser conferida por asserção automática — veja `series.check.ts`.

/**
 * Um ponto da série. `rx`/`tx` em bits por segundo.
 *
 * `null` significa **não medido** e não se desenha; zero significa medido e
 * deu zero, e se desenha. Desenhar zero no lugar de ausência faria um link
 * fora do ar parecer um link ocioso.
 */
export type Point = { t: number; rx: number | null; tx: number | null };

/**
 * O que `GET /api/system/traffic-history` devolve por ponto.
 *
 * Dois detalhes desta API que já custaram tempo e estão registrados aqui para
 * não custarem de novo: o parâmetro de consulta é **`iface`** (não
 * `interface`), e os campos são **`rx_bps`/`tx_bps`** (não `rx`/`tx`).
 *
 * `rx_bps`/`tx_bps` são `number | null`: quando num instante só houve amostra
 * de um dos sentidos, o outro vem `null` — **não medido**, e não zero medido.
 */
export type HistorySample = { timestamp: number; rx_bps: number | null; tx_bps: number | null };

/**
 * Apesar do nome `_bps`, o backend grava **bytes** por segundo:
 * `internal/tsdb/traffic.go` divide o delta de `/proc/net/dev` (que é em
 * bytes) pelo intervalo em segundos. Quem lê link raciocina em bits por
 * segundo, então a conversão acontece uma vez só, aqui, e não espalhada por
 * cada tela que consome a API.
 */
export const BITS_PER_BYTE = 8;

/**
 * Converte a resposta da API para a série que o gráfico consome (bits/s).
 *
 * **A ausência é propagada, nunca multiplicada.** Em JavaScript `null * 8`
 * é `0`, então uma conversão ingênua transformaria o "não medido" que a API
 * acabou de passar a dizer (commit 63dbd91) num zero medido — o mesmo dado
 * falso que a correção do backend existiu para tirar, agora reinventado na
 * tela. Esta é a única porta de entrada do histórico no app, e o resto de
 * `series.ts` (`reduceToWidth`, `seriesMax`, `seriesPeak`, `totalBytes`,
 * `contiguousRuns`) já trata `null` corretamente.
 */
export function pointsFromHistory(samples: HistorySample[]): Point[] {
  return samples.map((s) => ({
    t: s.timestamp * 1000,
    // `typeof` e não `!== null`: pega também o campo ausente de uma resposta
    // de versão anterior, que em JSON chega como `undefined` e cairia no mesmo
    // zero por outro caminho.
    rx: typeof s.rx_bps === 'number' ? s.rx_bps * BITS_PER_BYTE : null,
    tx: typeof s.tx_bps === 'number' ? s.tx_bps * BITS_PER_BYTE : null,
  }));
}

/**
 * Converte uma taxa em **bytes por segundo** para **bits por segundo**.
 *
 * A outra porta de entrada de taxa no app é `/api/system/status`, de onde
 * `deriveRate()` (`lib/interfaceRates.ts`) tira bytes/s a partir dos
 * contadores de `/proc/net/dev`. Ela passa por aqui pelo mesmo motivo que o
 * histórico passa por `pointsFromHistory`: **a conversão mora num lugar só.**
 * Os três erros já cometidos com esta API (`iface` × `interface`,
 * `rx_bps` × `rx`, e bytes vendidos como bits) nasceram todos de mapear campo
 * na mão dentro de uma tela.
 *
 * A unidade do app é Mb/s porque Mb/s é a unidade de link: os "100 mega" da
 * operadora são bits, e é com o plano contratado que o operador compara.
 */
export function bitsFromBytes(bytesPerSecond: number): number {
  return bytesPerSecond * BITS_PER_BYTE;
}

/**
 * Reduz a série para caber em `buckets` colunas de tela.
 *
 * **Cada bucket guarda o MÁXIMO do intervalo, nunca a média.** Média esconde
 * rajada, e rajada é o que derruba link — o pico é justamente o que o
 * operador está procurando quando abre esta tela.
 *
 * Bucket sem nenhuma amostra devolve `null` em `rx`/`tx`, nunca `0`.
 */
export function reduceToWidth(points: Point[], buckets: number): Point[] {
  if (buckets <= 0 || points.length === 0) return [];

  const sorted = points.slice().sort((a, b) => a.t - b.t);
  const t0 = sorted[0].t;
  const t1 = sorted[sorted.length - 1].t;
  const span = t1 - t0;
  const width = span > 0 ? span / buckets : 0;

  const rx: (number | null)[] = new Array(buckets).fill(null);
  const tx: (number | null)[] = new Array(buckets).fill(null);

  for (const p of sorted) {
    let i = span > 0 ? Math.floor(((p.t - t0) / span) * buckets) : 0;
    if (i < 0) i = 0;
    if (i >= buckets) i = buckets - 1; // o último ponto cai exatamente na borda

    if (p.rx !== null && (rx[i] === null || p.rx > (rx[i] as number))) rx[i] = p.rx;
    if (p.tx !== null && (tx[i] === null || p.tx > (tx[i] as number))) tx[i] = p.tx;
  }

  const out: Point[] = new Array(buckets);
  for (let i = 0; i < buckets; i++) {
    // Centro do bucket: o ponto reduzido representa o intervalo inteiro, e o
    // instante exato do máximo de rx pode não ser o do máximo de tx.
    out[i] = { t: span > 0 ? t0 + (i + 0.5) * width : t0, rx: rx[i], tx: tx[i] };
  }
  return out;
}

/** Maior valor (rx ou tx) da série, ignorando ausências. 0 se não há amostra. */
export function seriesMax(points: Point[]): number {
  let max = 0;
  for (const p of points) {
    if (p.rx !== null && p.rx > max) max = p.rx;
    if (p.tx !== null && p.tx > max) max = p.tx;
  }
  return max;
}

/** true se a série não tem nenhuma amostra medida. */
export function isEmptySeries(points: Point[]): boolean {
  return !points.some((p) => p.rx !== null || p.tx !== null);
}

/**
 * Pico da janela em bits/s, ou `null` quando não há **nenhuma** amostra.
 *
 * `seriesMax` devolve `0` para uma série sem amostra, o que serve ao desenho
 * mas não serve ao texto: `0` na faixa faria um link fora do ar parecer um
 * link ocioso. Aqui a distinção é explícita — `null` vira `—`, e um zero
 * medido continua sendo `0`.
 */
export function seriesPeak(points: Point[]): number | null {
  if (isEmptySeries(points)) return null;
  return seriesMax(points);
}

/**
 * Volume acumulado na janela, em **bytes**, integrando a série (bits/s) pelo
 * passo do tsdb. `null` quando não há nenhuma amostra.
 *
 * Volume fica em bytes de propósito, mesmo com as *taxas* todas em bits: quem
 * lê "quanto passou" pensa em GB (é a unidade da franquia e a do disco), e
 * quem lê "quão rápido" pensa em Mb/s (é a unidade do link). São grandezas
 * diferentes, e o rótulo diz qual é qual em cada lugar.
 */
export function totalBytes(points: Point[], stepSeconds: number): number | null {
  if (isEmptySeries(points) || !(stepSeconds > 0)) return null;
  let bits = 0;
  for (const p of points) {
    if (p.rx !== null) bits += p.rx * stepSeconds;
    if (p.tx !== null) bits += p.tx * stepSeconds;
  }
  return bits / BITS_PER_BYTE;
}

/**
 * Índices agrupados em trechos contíguos de valores medidos.
 *
 * É isto que faz o buraco ser buraco: cada trecho vira um subcaminho próprio
 * no SVG, então a linha não atravessa o intervalo sem amostra ligando os dois
 * lados — que é o mesmo erro de desenhar zero, só com outra aparência.
 *
 * Trecho de um índice só existe de propósito: uma amostra isolada entre dois
 * buracos precisa aparecer (como ponto), senão "não desenhar o que falta"
 * vira "não desenhar o que existe".
 */
export function contiguousRuns(values: (number | null)[]): number[][] {
  const runs: number[][] = [];
  let atual: number[] = [];
  for (let i = 0; i < values.length; i++) {
    if (values[i] === null) {
      if (atual.length > 0) runs.push(atual);
      atual = [];
    } else {
      atual.push(i);
    }
  }
  if (atual.length > 0) runs.push(atual);
  return runs;
}

// Passos "redondos" para o topo do eixo. A lista é mais fina que o clássico
// 1-2-5 de propósito: com 1-2-5 um pico de 10,2 Mb/s empurra o topo para
// 20 Mb/s e a série inteira desce para a metade de baixo da tela sem motivo.
const NICE_STEPS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];

function niceCeil(x: number): number {
  if (!(x > 0) || !isFinite(x)) return 1;
  const exp = Math.floor(Math.log10(x));
  const base = Math.pow(10, exp);
  const frac = x / base;
  for (const s of NICE_STEPS) {
    if (frac <= s * (1 + 1e-9)) return s * base;
  }
  return 10 * base;
}

/** Quantas décadas o modo log mostra abaixo do topo. */
export const LOG_DECADES = 4;

export type ScaleMode = 'linear' | 'log';

export interface Scale {
  /** Valores dos traços do eixo, do menor para o maior. */
  ticks: number[];
  /** Projeta um valor em [0,1]: 0 = no eixo, 1 = na amplitude máxima. */
  project: (v: number) => number;
  /** Topo do eixo, em bits/s. */
  max: number;
  mode: ScaleMode;
}

/**
 * Escala do eixo vertical.
 *
 * **Linear é o padrão** porque é ela que diz a verdade sobre magnitude. O modo
 * **log** existe para um defeito real: um único pico de 10,2 Mb/s domina a
 * escala linear e achata numa linha reta os 99% do tráfego que vivem entre
 * 100 e 600 kb/s. Em log a forma real aparece, sem o pico deixar de estar
 * marcado.
 */
export function niceScale(max: number, mode: ScaleMode): Scale {
  const safeMax = max > 0 && isFinite(max) ? max : 1;

  if (mode === 'log') {
    const topDecade = Math.floor(Math.log10(safeMax));
    const lo = Math.pow(10, topDecade - (LOG_DECADES - 1));
    const hi = safeMax;
    const logLo = Math.log10(lo);
    const logHi = Math.log10(hi);
    const denom = logHi - logLo;

    const ticks: number[] = [];
    for (let e = topDecade - (LOG_DECADES - 1); e <= topDecade; e++) {
      ticks.push(Math.pow(10, e));
    }
    // O topo só vira traço próprio quando está longe o bastante da década de
    // cima para não virar dois rótulos praticamente iguais colados.
    if (hi >= Math.pow(10, topDecade) * 1.3) ticks.push(hi);

    return {
      ticks,
      max: hi,
      mode,
      project: (v: number) => {
        if (!(v > 0) || !isFinite(v)) return 0;
        if (denom <= 0) return v >= hi ? 1 : 0;
        const f = (Math.log10(v) - logLo) / denom;
        return f < 0 ? 0 : f > 1 ? 1 : f;
      },
    };
  }

  const top = niceCeil(safeMax);
  const ticks: number[] = [];
  const divisions = 4;
  for (let i = 0; i <= divisions; i++) ticks.push((top / divisions) * i);

  return {
    ticks,
    max: top,
    mode,
    project: (v: number) => {
      if (!isFinite(v) || v <= 0) return 0;
      const f = v / top;
      return f > 1 ? 1 : f;
    },
  };
}

/**
 * Largura máxima, em caracteres, que um rótulo de eixo pode ocupar.
 *
 * Existe por causa de um defeito real do mockup: a margem esquerda era menor
 * que o rótulo e "10.2" aparecia como "0.2" na tela. O eixo reserva largura
 * para o maior rótulo formatado, e não para o que couber.
 */
export const AXIS_LABEL_MAX = 9;

/** Largura aproximada de um caractere em JetBrains Mono a 10px. */
const AXIS_CHAR_PX = 6.2;
/** Respiro entre o fim do rótulo e o começo da área de plotagem. */
const AXIS_GUTTER_PX = 10;

/** Largura que o eixo vertical reserva à esquerda, em pixels. */
export function axisPadLeft(): number {
  return Math.ceil(AXIS_LABEL_MAX * AXIS_CHAR_PX) + AXIS_GUTTER_PX;
}

const RATE_UNITS = ['b/s', 'kb/s', 'Mb/s', 'Gb/s', 'Tb/s'];

/**
 * Formata bits por segundo curto o bastante para caber em `AXIS_LABEL_MAX`.
 * Ausência de medição é `—`, e nunca `0`.
 */
export function formatBps(v: number | null): string {
  if (v === null || !isFinite(v)) return '—';
  if (v <= 0) return '0';
  let i = Math.floor(Math.log10(v) / 3);
  if (i < 0) i = 0;
  if (i > RATE_UNITS.length - 1) i = RATE_UNITS.length - 1;
  const n = v / Math.pow(1000, i);
  // Uma casa até 99,9: sem ela um pico de 10,2 Mb/s vira "10 Mb/s" no eixo, e
  // o operador perde justamente a precisão do número que foi olhar.
  const decimals = n < 100 ? 1 : 0;
  return `${n.toFixed(decimals)} ${RATE_UNITS[i]}`;
}

const VOLUME_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

/**
 * Formata um volume acumulado em bytes (base 1024, como o resto do app).
 * Ausência de medição é `—`, e nunca `0`.
 */
export function formatVolume(bytes: number | null): string {
  if (bytes === null || !isFinite(bytes)) return '—';
  if (bytes <= 0) return '0 B';
  let i = Math.floor(Math.log(bytes) / Math.log(1024));
  if (i < 0) i = 0;
  if (i > VOLUME_UNITS.length - 1) i = VOLUME_UNITS.length - 1;
  const n = bytes / Math.pow(1024, i);
  return `${n.toFixed(i === 0 ? 0 : 1)} ${VOLUME_UNITS[i]}`;
}

/**
 * Uma janela de consulta da tela de tráfego, casada com a resolução que o
 * tsdb realmente mantém para ela.
 *
 * **A resolução se escolhe pela janela pedida, não pela mais fina que existe.**
 * Um ano em passo de 1 s seriam ~31 milhões de linhas lidas do SQLite e
 * jogadas no navegador para desenhar algumas centenas de colunas — castigo
 * para o banco e para a aba, sem um pixel a mais de informação.
 *
 * `step` é o passo que `internal/tsdb.rangeToStepDuration` devolve para
 * `range`; as asserções em `series.check.ts` guardam esse casamento, para que
 * uma janela nova não entre apontando para a resolução errada.
 */
export interface TrafficWindow {
  /** Valor do parâmetro `range` da API (e id do botão). */
  range: string;
  /** Rótulo em português. */
  label: string;
  /** Passo do tsdb, em segundos. */
  step: number;
  /** Como o passo aparece para o operador. */
  stepLabel: string;
  /** Largura da janela, em segundos. */
  spanSeconds: number;
}

/** As quatro janelas — uma por resolução mantida pelo tsdb. */
export const TRAFFIC_WINDOWS: TrafficWindow[] = [
  { range: '30m', label: '30 min', step: 1, stepLabel: '1 s', spanSeconds: 30 * 60 },
  { range: '12h', label: '12 h', step: 60, stepLabel: '1 min', spanSeconds: 12 * 3600 },
  { range: '30d', label: '30 dias', step: 900, stepLabel: '15 min', spanSeconds: 30 * 24 * 3600 },
  { range: '1y', label: '1 ano', step: 3600, stepLabel: '1 h', spanSeconds: 365 * 24 * 3600 },
];

/** A janela de um `range`, ou a primeira (a mais fina) se o id não existir. */
export function windowFor(range: string): TrafficWindow {
  return TRAFFIC_WINDOWS.find((w) => w.range === range) ?? TRAFFIC_WINDOWS[0];
}

/** Rótulo de horário para o eixo do tempo, na granularidade da janela. */
export function formatTime(t: number, spanMs: number): string {
  const d = new Date(t);
  if (spanMs > 3 * 24 * 3600 * 1000) {
    return d.toLocaleDateString([], { day: '2-digit', month: '2-digit' });
  }
  if (spanMs > 6 * 3600 * 1000) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (spanMs > 10 * 60 * 1000) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
