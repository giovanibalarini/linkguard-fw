import { Link } from 'react-router-dom';
import { AlertBadge } from '../StatusBadge';
import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import { useI18n } from '../../i18n';
import type { Alert } from '../../types';

const PESO: Record<string, number> = { critical: 0, warning: 1, info: 2 };

function tempoRelativo(iso: string, lang: 'pt' | 'en'): string {
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const min = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
  if (Math.abs(min) < 60) return rtf.format(min, 'minute');
  const horas = Math.round(min / 60);
  if (Math.abs(horas) < 24) return rtf.format(horas, 'hour');
  return rtf.format(Math.round(horas / 24), 'day');
}

/**
 * Alertas abertos, do mais grave para o menos.
 *
 * "Nenhum alerta aberto" é uma medição e se escreve; não é o mesmo que "não
 * consegui ler os alertas", que se escreve diferente. Confundir os dois é
 * anunciar tranquilidade quando o que houve foi silêncio.
 */
export default function OpenAlertsWidget() {
  const { lang } = useI18n();
  const { data: alerts, state } = usePolled<Alert[]>('/api/alerts?unresolved=true');

  const lista = (alerts ?? [])
    .slice()
    .sort((a, b) => (PESO[a.severity] ?? 3) - (PESO[b.severity] ?? 3));
  const criticos = lista.filter((a) => a.severity === 'critical').length;

  return (
    <WidgetCard
      title="Alertas abertos"
      action={
        <Link to="/alerts" className="shrink-0 text-xs text-gray-500 hover:text-gray-300">
          ver todos
        </Link>
      }
    >
      {state === 'loading' && <WidgetNote>Carregando…</WidgetNote>}
      {state === 'error' && <WidgetNote>Não foi possível ler os alertas agora.</WidgetNote>}
      {state === 'ok' && lista.length === 0 && <WidgetNote>Nenhum alerta aberto.</WidgetNote>}

      {criticos > 0 && (
        <p className="mb-2 rounded-lg border border-red-500/20 bg-red-500/10 px-2.5 py-1.5 text-xs text-red-300">
          {criticos} {criticos === 1 ? 'alerta crítico ativo' : 'alertas críticos ativos'}.
        </p>
      )}

      <div className="space-y-2">
        {lista.slice(0, 8).map((a) => (
          <div key={a.id} className="flex items-start gap-2.5 rounded-lg bg-gray-800/40 p-2.5">
            <AlertBadge severity={a.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-white">{a.title}</p>
              <p className="truncate text-xs text-gray-500">{a.message}</p>
            </div>
            <span className="shrink-0 text-xs text-gray-600">{tempoRelativo(a.created_at, lang)}</span>
          </div>
        ))}
      </div>
    </WidgetCard>
  );
}
