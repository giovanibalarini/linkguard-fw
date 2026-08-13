import { useEffect, useMemo, useState } from 'react';
import client from '../../api/client';
import TrafficChart from '../TrafficChart';
import { WidgetNote, usePolled } from './WidgetCard';
import { pointsFromHistory } from '../../lib/series';
import type { Point, ScaleMode } from '../../lib/series';
import type { SystemMetrics, TrafficHistoryResponse } from '../../types';

/**
 * O gráfico grande da Fase A, do tamanho de um widget.
 *
 * O widget nasce com um padrão sensato e não é configurável por dentro (spec
 * §9): a interface é a que mais moveu bytes desde o boot, que é a que o
 * operador quer ver quando abre o painel sem escolher nada. A janela é a de
 * 30 min, na resolução de 1 s do tsdb.
 */
export default function InterfaceTrafficWidget({ height }: { height: number }) {
  const { data: sys, state } = usePolled<SystemMetrics>('/api/system/status', 30000);
  const [points, setPoints] = useState<Point[] | null>(null);
  const [mode, setMode] = useState<ScaleMode>('linear');

  const iface = useMemo(() => {
    const candidatas = (sys?.interfaces ?? []).filter((i) => i.name && i.name !== 'lo');
    if (candidatas.length === 0) return null;
    // A que mais moveu bytes: sem configuração por dentro, é o padrão que acerta
    // sozinho na máquina de quem instalou.
    return candidatas.reduce((a, b) =>
      (b.rx_bytes ?? 0) + (b.tx_bytes ?? 0) > (a.rx_bytes ?? 0) + (a.tx_bytes ?? 0) ? b : a,
    ).name;
  }, [sys]);

  useEffect(() => {
    if (!iface) return;
    let alive = true;
    const load = async () => {
      try {
        const { data } = await client.get<TrafficHistoryResponse>(
          `/api/system/traffic-history?iface=${encodeURIComponent(iface)}&range=30m`,
        );
        if (!alive) return;
        setPoints(pointsFromHistory(data.points ?? []));
      } catch {
        if (!alive) return;
        setPoints([]);
      }
    };
    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [iface]);

  if (state === 'loading') {
    return (
      <div className="card h-full">
        <WidgetNote>Carregando…</WidgetNote>
      </div>
    );
  }
  if (!iface) {
    return (
      <div className="card h-full">
        <WidgetNote>Nenhuma interface de rede para medir.</WidgetNote>
      </div>
    );
  }

  return (
    <div className="h-full min-h-0 overflow-y-auto">
      <TrafficChart
        points={points ?? []}
        iface={iface}
        mode={mode}
        onModeChange={setMode}
        height={height}
        loading={points === null}
      />
    </div>
  );
}
