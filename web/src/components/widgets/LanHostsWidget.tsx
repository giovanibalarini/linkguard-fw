import { Link } from 'react-router-dom';
import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import { useI18n } from '../../i18n';
import type { NetHost } from '../../types';

/** Quem está na LAN agora, e quem já esteve. */
export default function LanHostsWidget() {
  const { t } = useI18n();
  const { data: hosts, state } = usePolled<NetHost[]>('/api/hosts', 30000);

  const lista = hosts ?? [];
  const online = lista.filter((h) => h.online);
  // Online primeiro, e dentro de cada grupo por IP — a ordem que o operador
  // procura é "quem está aí agora".
  const ordenados = lista
    .slice()
    .sort((a, b) => Number(b.online) - Number(a.online) || a.ip.localeCompare(b.ip, undefined, { numeric: true }));

  return (
    <WidgetCard
      title={t('wid.hosts.title')}
      action={
        <Link to="/hosts" className="shrink-0 text-xs text-gray-500 hover:text-gray-300">
          {t('wid.view.all')}
        </Link>
      }
    >
      {state === 'loading' && <WidgetNote>{t('wid.loading')}</WidgetNote>}
      {state === 'error' && <WidgetNote>{t('wid.hosts.error')}</WidgetNote>}
      {state === 'ok' && lista.length === 0 && <WidgetNote>{t('wid.hosts.empty')}</WidgetNote>}

      {lista.length > 0 && (
        <>
          <p className="mb-2 font-mono text-xs text-gray-500">
            {t('wid.hosts.count', { online: online.length, total: lista.length })}
          </p>
          <div className="space-y-1.5">
            {ordenados.slice(0, 12).map((h) => (
              <div key={h.mac || h.ip} className="flex items-center gap-2">
                <span
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${h.online ? 'bg-ok' : 'bg-gray-700'}`}
                  title={h.online ? t('wid.status.online') : t('wid.status.offline')}
                />
                <span className="min-w-0 flex-1 truncate text-sm text-gray-300">
                  {h.alias || h.hostname || h.ip}
                </span>
                <span className="shrink-0 font-mono text-[11px] text-gray-600">{h.ip}</span>
                {h.blocked && <span className="shrink-0 text-[11px] text-crit">{t('wid.hosts.blocked')}</span>}
              </div>
            ))}
          </div>
        </>
      )}
    </WidgetCard>
  );
}
