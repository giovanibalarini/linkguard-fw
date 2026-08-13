import { bitsFromBytes } from './series';

export interface RateCounter {
  ts: number;
  rx: number;
  tx: number;
}

export interface InterfaceRate {
  /** bits por segundo */
  rx: number;
  /** bits por segundo */
  tx: number;
}

// Bits/segundo desde a amostra de contador anterior, ou null se ainda não há
// amostra prévia ou o relógio não avançou. Função pura — mesma fórmula usada
// em Interfaces.tsx (detalhe por interface), Dashboard.tsx (resumo WAN) e
// Traffic.tsx (faixa), para "taxa atual" significar a mesma coisa no app
// inteiro.
//
// Os contadores de /proc/net/dev são em BYTES; a saída é em BITS, porque a
// unidade do app é Mb/s — os "100 mega" da operadora são bits, e é com o
// plano contratado que o operador compara. A multiplicação não é feita aqui:
// ela mora em `bitsFromBytes` (`lib/series.ts`), junto com a do histórico,
// para existir num lugar só.
export function deriveRate(
  prev: RateCounter | undefined,
  current: { rx_bytes: number; tx_bytes: number },
  now: number,
): InterfaceRate | null {
  if (!prev) return null;
  const dt = (now - prev.ts) / 1000;
  if (dt <= 0) return null;
  const rxDelta = Math.max(0, current.rx_bytes - prev.rx);
  const txDelta = Math.max(0, current.tx_bytes - prev.tx);
  return { rx: bitsFromBytes(rxDelta / dt), tx: bitsFromBytes(txDelta / dt) };
}
