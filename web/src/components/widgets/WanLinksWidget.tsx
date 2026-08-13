import { useEffect, useState } from 'react';
import client from '../../api/client';
import Sparkline, { type SparklinePoint } from '../ui/Sparkline';
import Tag, { type TagVariant } from '../ui/Tag';
import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import { formatBps, latestSample, pointsFromHistory } from '../../lib/series';
import type { Point } from '../../lib/series';
import type { TrafficHistoryResponse, WanLink } from '../../types';

const VARIANTE: Record<string, TagVariant> = {
  online: 'ok',
  offline: 'crit',
  degraded: 'warn',
  unknown: 'idle',
};

const ROTULO: Record<string, string> = {
  online: 'online',
  offline: 'offline',
  degraded: 'degradado',
  unknown: 'desconhecido',
};

/**
 * Links WAN: estado, latência, perda e taxa de cada link de internet.
 *
 * A taxa "agora" é a última amostra MEDIDA da série de 1 s do tsdb, e não uma
 * média nem uma estimativa. Link sem nenhuma amostra na janela mostra `—`:
 * um zero ali faria um link fora do ar parecer um link ocioso.
 */
export default function WanLinksWidget() {
  const { data: links, state } = usePolled<WanLink[]>('/api/links');
  const [series, setSeries] = useState<Record<string, Point[]>>({});

  const chaves = (links ?? []).map((l) => l.interface).join(',');

  useEffect(() => {
    if (!chaves) return;
    const ifaces = chaves.split(',');
    let alive = true;
    const load = async () => {
      const resultados = await Promise.all(
        ifaces.map(async (iface) => {
          try {
            const { data } = await client.get<TrafficHistoryResponse>(
              `/api/system/traffic-history?iface=${encodeURIComponent(iface)}&range=30m`,
            );
            // Sempre por `pointsFromHistory`: é ele que sabe que o campo se
            // chama `rx_bps` mas guarda BYTES/s, e que `null` é ausência de
            // medição e não zero.
            return [iface, pointsFromHistory(data.points ?? [])] as const;
          } catch {
            return [iface, [] as Point[]] as const;
          }
        }),
      );
      if (!alive) return;
      setSeries(Object.fromEntries(resultados));
    };
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [chaves]);

  const online = (links ?? []).filter((l) => l.status === 'online').length;

  return (
    <WidgetCard
      title="Links WAN"
      action={
        links && links.length > 0 ? (
          <span className="shrink-0 font-mono text-xs text-gray-500">
            {online}/{links.length} online
          </span>
        ) : undefined
      }
    >
      {state === 'loading' && <WidgetNote>Carregando…</WidgetNote>}
      {state === 'error' && <WidgetNote>Não foi possível ler os links agora.</WidgetNote>}
      {state === 'ok' && (links ?? []).length === 0 && (
        <WidgetNote>Nenhum link WAN configurado ainda.</WidgetNote>
      )}

      <div className="space-y-1.5">
        {(links ?? []).map((link) => {
          const pontos = series[link.interface] ?? [];
          const ultima = latestSample(pontos);
          const taxa = ultima === null ? null : (ultima.rx ?? 0) + (ultima.tx ?? 0);
          return (
            // Compacto de propósito: no tamanho de fábrica (4x2) o widget
            // precisa mostrar DOIS links sem rolar, que é o caso da máquina de
            // produção — um firewall de duas WANs.
            <div key={link.id} className="rounded-lg bg-gray-800/40 px-2.5 py-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm text-white">{link.name}</span>
                <Tag variant={VARIANTE[link.status] ?? 'idle'} dot>
                  {ROTULO[link.status] ?? link.status}
                </Tag>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-base text-white">{formatBps(taxa)}</span>
                <span className="text-[11px] text-gray-500">
                  {link.latency_ms > 0 ? `${link.latency_ms.toFixed(1)} ms` : '—'} ·{' '}
                  {link.packet_loss.toFixed(1)}% perda
                </span>
              </div>
              <Sparkline
                data={pontos.map((p): SparklinePoint => ({ ts: p.t, rx: p.rx, tx: p.tx }))}
                height={20}
              />
            </div>
          );
        })}
      </div>
    </WidgetCard>
  );
}
