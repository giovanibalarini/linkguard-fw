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
 */
export type HistorySample = { timestamp: number; rx_bps: number; tx_bps: number };

/**
 * Apesar do nome `_bps`, o backend grava **bytes** por segundo:
 * `internal/tsdb/traffic.go` divide o delta de `/proc/net/dev` (que é em
 * bytes) pelo intervalo em segundos. Quem lê link raciocina em bits por
 * segundo, então a conversão acontece uma vez só, aqui, e não espalhada por
 * cada tela que consome a API.
 */
export const BITS_PER_BYTE = 8;

/** Converte a resposta da API para a série que o gráfico consome (bits/s). */
export function pointsFromHistory(samples: HistorySample[]): Point[] {
  return samples.map((s) => ({
    t: s.timestamp * 1000,
    rx: s.rx_bps * BITS_PER_BYTE,
    tx: s.tx_bps * BITS_PER_BYTE,
  }));
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
