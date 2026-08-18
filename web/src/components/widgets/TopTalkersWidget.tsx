import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import { useI18n } from '../../i18n';
import type { HostTraffic, NetHost } from '../../types';

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const k = 1024;
  const unidades = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(unidades.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${unidades[i]}`;
}

/**
 * Quem está consumindo agora.
 *
 * Volume em bytes, e não em bits: "quanto passou" é a grandeza da franquia e do
 * disco; "quão rápido" (Mb/s) é a do link. O rótulo diz qual é qual, e a
 * legenda diz que são fluxos ATIVOS, e não total acumulado — sem isso o número
 * parece um contador do dia e não é.
 */
export default function TopTalkersWidget() {
  const { t: traduz } = useI18n();
  const { data: talkers, state } = usePolled<HostTraffic[]>('/api/hosts/traffic');
  const { data: hosts } = usePolled<NetHost[]>('/api/hosts', 60000);

  const lista = (talkers ?? []).slice(0, 10);
  const maior = lista.length > 0 ? lista[0].rx_bytes + lista[0].tx_bytes || 1 : 1;

  return (
    <WidgetCard title={traduz('wid.talkers.title')}>
      {state === 'loading' && <WidgetNote>{traduz('wid.loading')}</WidgetNote>}
      {state === 'error' && <WidgetNote>{traduz('wid.talkers.error')}</WidgetNote>}
      {state === 'ok' && lista.length === 0 && <WidgetNote>{traduz('wid.talkers.empty')}</WidgetNote>}

      {lista.length > 0 && (
        <>
          <p className="mb-2 text-xs text-gray-500">{traduz('wid.talkers.note')}</p>
          <div className="space-y-2">
            {lista.map((t) => {
              const host = (hosts ?? []).find((h) => h.ip === t.ip);
              const nome = host?.alias || host?.hostname || t.ip;
              const total = t.rx_bytes + t.tx_bytes;
              const pct = Math.max(4, Math.round((total / maior) * 100));
              return (
                <div key={t.ip} className="flex items-center gap-3">
                  <span className="w-28 shrink-0 truncate text-sm text-gray-300" title={t.ip}>
                    {nome}
                  </span>
                  <div className="h-2 flex-1 rounded-full bg-gray-800">
                    <div className="h-2 rounded-full bg-blue-500" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="w-20 shrink-0 text-right font-mono text-xs text-gray-500">
                    {formatBytes(total)}
                  </span>
                </div>
              );
            })}
          </div>
        </>
      )}
    </WidgetCard>
  );
}
