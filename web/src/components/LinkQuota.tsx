import { useCallback, useEffect, useState } from 'react';
import { Gauge, Loader2, AlertTriangle, Trash2, Check } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { LinkQuotaStatus } from '../types';

interface Props {
  canEdit: boolean;
}

/** GB decimais: é como a operadora vende e cobra. Ver o tipo no backend. */
function gb(bytes: number): string {
  return (bytes / 1_000_000_000).toFixed(1);
}

function cycleLabel(startUnix: number, endUnix: number): string {
  const f = (u: number) => new Date(u * 1000).toLocaleDateString();
  return `${f(startUnix)} – ${f(endUnix)}`;
}

/**
 * LinkQuota mostra quanto cada link WAN já consumiu no ciclo e avisa antes de
 * a franquia acabar. Existe para o cenário que originou o produto: quando o
 * link principal cai e o failover joga tudo no link móvel, a franquia vai
 * embora sem ninguém ver.
 */
export default function LinkQuota({ canEdit }: Props) {
  const { t } = useI18n();
  const [rows, setRows] = useState<LinkQuotaStatus[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [limitGB, setLimitGB] = useState('');
  const [cycleDay, setCycleDay] = useState('1');
  const [alertPct, setAlertPct] = useState('80');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const load = useCallback(async () => {
    try {
      const { data } = await client.get<LinkQuotaStatus[]>('/api/quotas');
      setRows(data ?? []);
    } catch { /* a tela mostra o erro da ação; o polling não grita */ }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 60000);
    return () => clearInterval(id);
  }, [load]);

  const startEdit = (r: LinkQuotaStatus) => {
    setEditing(r.link_id);
    setLimitGB(r.configured ? String(r.limit_gb) : '');
    setCycleDay(String(r.cycle_day || 1));
    setAlertPct(String(r.alert_pct || 80));
    setErr('');
  };

  const save = async (linkID: string) => {
    setBusy(true); setErr('');
    try {
      await client.put(`/api/quotas/${linkID}`, {
        limit_gb: Number(limitGB),
        cycle_day: Number(cycleDay),
        alert_pct: Number(alertPct),
        enabled: true,
      });
      setEditing(null);
      await load();
    } catch (e) { setErr(errMsg(e, t('links.quota.error.save'))); }
    finally { setBusy(false); }
  };

  const remove = async (linkID: string) => {
    setBusy(true); setErr('');
    try { await client.delete(`/api/quotas/${linkID}`); await load(); }
    catch (e) { setErr(errMsg(e, t('links.quota.error.remove'))); }
    finally { setBusy(false); }
  };

  if (rows.length === 0) return null;

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Gauge className="w-5 h-5 text-emerald-400" />
          <span className="text-white font-semibold">{t('links.quota.title')}</span>
          <HelpTip title={t('links.quota.help.title')}>
            <>{t('links.quota.help1')} <b>{t('links.quota.helpMeasuredTerm')}</b>{t('links.quota.help2')}</>
          </HelpTip>
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">{t('links.quota.subtitle')}</p>

      {err && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      <ul className="space-y-3">
        {rows.map((r) => {
          const over = r.configured && r.used_pct >= 100;
          const warn = r.configured && !over && r.used_pct >= r.alert_pct;
          const barColor = over ? 'bg-red-500' : warn ? 'bg-amber-500' : 'bg-emerald-500';
          return (
            <li key={r.link_id} className="rounded-lg border border-gray-800 p-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="text-white text-sm font-medium">
                  {r.link_name} <span className="text-gray-600 font-mono text-xs">{r.interface}</span>
                </span>
                <span className="text-xs text-gray-400">
                  {r.configured
                    ? t('links.quota.used', { used: gb(r.used_bytes), limit: r.limit_gb, pct: r.used_pct.toFixed(0) })
                    : t('links.quota.usedNoLimit', { used: gb(r.used_bytes) })}
                </span>
              </div>

              {r.configured && (
                <div className="mt-2 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                  <div className={`h-full ${barColor} transition-all`}
                    style={{ width: `${Math.min(100, Math.max(0, r.used_pct))}%` }} />
                </div>
              )}

              <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-gray-600">
                <span>{t('links.quota.cycle')}: {cycleLabel(r.cycle_start, r.cycle_end)}</span>
                <span>↓ {gb(r.rx_bytes)} GB · ↑ {gb(r.tx_bytes)} GB</span>
                {canEdit && editing !== r.link_id && (
                  <button onClick={() => startEdit(r)} className="text-blue-400 hover:text-blue-300">
                    {r.configured ? t('links.quota.edit') : t('links.quota.define')}
                  </button>
                )}
                {canEdit && r.configured && editing !== r.link_id && (
                  <button onClick={() => remove(r.link_id)} disabled={busy}
                    className="text-gray-500 hover:text-red-400 inline-flex items-center gap-1">
                    <Trash2 className="w-3 h-3" /> {t('links.quota.remove')}
                  </button>
                )}
              </div>

              {editing === r.link_id && (
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-4 gap-2 items-end">
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('links.quota.limit')}</span>
                    <input value={limitGB} onChange={(e) => setLimitGB(e.target.value.replace(/[^\d.]/g, ''))}
                      inputMode="decimal" placeholder="50" className="input mt-1 w-full font-mono" />
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('links.quota.cycleDay')}</span>
                    <input value={cycleDay} onChange={(e) => setCycleDay(e.target.value.replace(/\D/g, ''))}
                      inputMode="numeric" className="input mt-1 w-full font-mono" />
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('links.quota.alertAt')}</span>
                    <input value={alertPct} onChange={(e) => setAlertPct(e.target.value.replace(/\D/g, ''))}
                      inputMode="numeric" className="input mt-1 w-full font-mono" />
                  </label>
                  <div className="flex gap-2">
                    <button onClick={() => save(r.link_id)} disabled={busy || !limitGB}
                      className="btn-primary text-xs flex items-center gap-1 disabled:opacity-50">
                      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                      {t('links.quota.save')}
                    </button>
                    <button onClick={() => setEditing(null)} className="btn-secondary text-xs">
                      {t('links.quota.cancel')}
                    </button>
                  </div>
                  <p className="sm:col-span-4 text-[11px] text-gray-600">{t('links.quota.cycleDayHint')}</p>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
