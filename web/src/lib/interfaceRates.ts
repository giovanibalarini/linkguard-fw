export interface RateCounter {
  ts: number;
  rx: number;
  tx: number;
}

export interface InterfaceRate {
  rx: number;
  tx: number;
}

// Bytes/segundo desde a amostra de contador anterior, ou null se ainda não
// há amostra prévia ou o relógio não avançou. Função pura — mesma fórmula
// usada em Interfaces.tsx (detalhe por interface) e Dashboard.tsx (resumo
// WAN), para "taxa atual" significar a mesma coisa no app inteiro.
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
  return { rx: rxDelta / dt, tx: txDelta / dt };
}
