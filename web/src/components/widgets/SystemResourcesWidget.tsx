import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import { useI18n } from '../../i18n';
import type { SystemMetrics } from '../../types';

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const k = 1024;
  const unidades = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(unidades.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${unidades[i]}`;
}

/** Verde até 75%, âmbar até 90%, vermelho acima — as cores do design system. */
function corDaBarra(pct: number): string {
  if (pct >= 90) return 'bg-crit';
  if (pct >= 75) return 'bg-warn';
  return 'bg-ok';
}

function Barra({ label, pct, detalhe }: { label: string; pct: number; detalhe: string }) {
  const seguro = Math.max(0, Math.min(100, pct));
  return (
    <div className="min-w-0">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs text-gray-400">{label}</span>
        <span className="font-mono text-xs text-white">{seguro.toFixed(0)}%</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-gray-800">
        <div className={`h-full ${corDaBarra(seguro)}`} style={{ width: `${seguro}%` }} />
      </div>
      <p className="mt-1 truncate font-mono text-[11px] text-gray-500">{detalhe}</p>
    </div>
  );
}

/** CPU, memória, disco, carga e tempo no ar — o estado da máquina em si. */
export default function SystemResourcesWidget() {
  const { t } = useI18n();
  const { data: sys, state } = usePolled<SystemMetrics>('/api/system/status');

  if (state === 'loading') {
    return (
      <WidgetCard title={t('wid.sys.title')}>
        <WidgetNote>{t('wid.loading')}</WidgetNote>
      </WidgetCard>
    );
  }
  if (!sys) {
    return (
      <WidgetCard title={t('wid.sys.title')}>
        <WidgetNote>{t('wid.sys.error')}</WidgetNote>
      </WidgetCard>
    );
  }

  const load = sys.load_avg ?? [0, 0, 0];

  return (
    <WidgetCard
      title={t('wid.sys.title')}
      action={
        <span className="shrink-0 font-mono text-xs text-gray-500">
          {t('wid.sys.uptime', { tempo: sys.uptime_str || '—' })}
        </span>
      }
    >
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Barra label="CPU" pct={sys.cpu_percent ?? 0} detalhe={`load ${load.map((n) => n.toFixed(2)).join(' ')}`} />
        <Barra
          label={t('wid.sys.mem')}
          pct={sys.mem_percent ?? 0}
          detalhe={`${formatBytes(sys.mem_used_bytes ?? 0)} / ${formatBytes(sys.mem_total_bytes ?? 0)}`}
        />
        <Barra
          label={t('wid.sys.disk')}
          pct={sys.disk_percent ?? 0}
          detalhe={`${formatBytes(sys.disk_used_bytes ?? 0)} / ${formatBytes(sys.disk_total_bytes ?? 0)}`}
        />
        <div className="min-w-0">
          <span className="text-xs text-gray-400">{t('wid.sys.interfaces')}</span>
          <p className="font-mono text-lg text-white">
            {(sys.interfaces ?? []).filter((i) => i.name !== 'lo').length}
          </p>
          <p className="truncate font-mono text-[11px] text-gray-500">{t('wid.sys.except')} <span className="font-mono">lo</span></p>
        </div>
      </div>
    </WidgetCard>
  );
}
