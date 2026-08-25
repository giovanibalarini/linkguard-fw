import { useCallback, useEffect, useState } from 'react';
import { Gauge, Loader2, AlertTriangle, Trash2, Check, Info, Bell } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { HostQuotaStatus, HostQuotaPeriod } from '../types';

interface Props {
  canEdit: boolean;
}

/**
 * Unidades DECIMAIS, iguais às do backend (linkquota.HumanBytes): MB é 10^6 e
 * GB é 10^9. A tela e o alerta têm de dizer o mesmo número — se aqui fosse
 * 2^20 o painel discordaria do texto que chega no Telegram do admin.
 *
 * A unidade acompanha a grandeza pelo motivo já pago em máquina real na metade
 * de link: formatar tudo em GB fazia uma cota de 1 MB aparecer como
 * "0.0 GB de 0 GB".
 */
function humanBytes(b: number): string {
  if (b >= 1_000_000_000) return `${(b / 1_000_000_000).toFixed(1)} GB`;
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  return `${(b / 1000).toFixed(0)} KB`;
}

function humanGB(gb: number): string {
  return humanBytes(gb * 1_000_000_000);
}

function cycleLabel(startUnix: number, endUnix: number): string {
  const f = (u: number) => new Date(u * 1000).toLocaleDateString();
  return `${f(startUnix)} – ${f(endUnix)}`;
}

/**
 * HostQuota mostra quanto cada aparelho da LAN consumiu no ciclo e deixa
 * declarar um teto, mensal ou diário, com aviso.
 *
 * ELA NÃO TEM BOTÃO DE CORTAR NEM DE LIMITAR BANDA, de propósito — ver o
 * cabeçalho de internal/hostquota. As duas frases de honestidade (só IPv4, e
 * avisa mas não corta) são parte da tela, não rodapé: sem elas o painel vende
 * um controle que o produto não tem e um número que subconta em silêncio.
 */
export default function HostQuota({ canEdit }: Props) {
  const { t } = useI18n();
  const [rows, setRows] = useState<HostQuotaStatus[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [limitGB, setLimitGB] = useState('');
  const [period, setPeriod] = useState<HostQuotaPeriod>('monthly');
  const [cycleDay, setCycleDay] = useState('1');
  const [alertPct, setAlertPct] = useState('80');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const load = useCallback(async () => {
    try {
      const { data } = await client.get<HostQuotaStatus[]>('/api/hosts/quotas');
      setRows(data ?? []);
    } catch { /* a tela mostra o erro da ação; o polling não grita */ }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 60000);
    return () => clearInterval(id);
  }, [load]);

  const startEdit = (r: HostQuotaStatus) => {
    setEditing(r.mac);
    setLimitGB(r.configured ? String(r.limit_gb) : '');
    setPeriod(r.period ?? 'monthly');
    setCycleDay(String(r.cycle_day || 1));
    setAlertPct(String(r.alert_pct || 80));
    setErr('');
  };

  const save = async (mac: string) => {
    setBusy(true); setErr('');
    try {
      // O corpo NÃO manda alert_enabled. Quem decide se o aviso fica ligado é o
      // backend, a partir do limite: um campo booleano que a tela manda e nunca
      // lê de volta é a receita para uma cota desenhada e muda.
      await client.put(`/api/hosts/quotas/${encodeURIComponent(mac)}`, {
        limit_gb: Number(limitGB),
        period,
        cycle_day: Number(cycleDay),
        alert_pct: Number(alertPct),
      });
      setEditing(null);
      await load();
    } catch (e) { setErr(errMsg(e, t('svc.hosts.quota.error.save'))); }
    finally { setBusy(false); }
  };

  const remove = async (mac: string) => {
    setBusy(true); setErr('');
    try { await client.delete(`/api/hosts/quotas/${encodeURIComponent(mac)}`); await load(); }
    catch (e) { setErr(errMsg(e, t('svc.hosts.quota.error.remove'))); }
    finally { setBusy(false); }
  };

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Gauge className="w-5 h-5 text-emerald-400" />
          <span className="text-white font-semibold">{t('svc.hosts.quota.title')}</span>
          <HelpTip title={t('svc.hosts.quota.help.title')}>
            <>{t('svc.hosts.quota.help1')} <b>{t('svc.hosts.quota.helpMeasuredTerm')}</b>{t('svc.hosts.quota.help2')}</>
          </HelpTip>
        </span>
      }
      className="mb-6"
    >
      <p className="text-gray-500 text-xs">{t('svc.hosts.quota.subtitle')}</p>
      {/* As frases que impedem a tela de vender o que o produto não faz. Ficam
          SEMPRE visíveis, e não dentro do HelpTip: o admin que declara uma cota
          precisa saber, ANTES de declarar, que nada vai ser cortado — e até
          onde o aviso chega. Um aviso que o admin acha que vai para o telefone
          dele e pára no painel é pior que aviso nenhum. */}
      <div className="mt-2 mb-4 space-y-1.5">
        <p className="flex items-start gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs text-blue-300">
          <Info className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden="true" />
          {t('svc.hosts.quota.warnNoEnforcement')}
        </p>
        <p className="flex items-start gap-2 rounded-lg border border-blue-500/20 bg-blue-500/5 px-3 py-2 text-xs text-blue-300/80">
          <Bell className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden="true" />
          {t('svc.hosts.quota.warnWhereItStops')}
        </p>
      </div>

      {err && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      {rows.length === 0 ? (
        <p className="text-gray-500 text-sm">{t('svc.hosts.quota.empty')}</p>
      ) : (
      <ul className="space-y-3">
        {rows.map((r) => {
          const over = r.configured && r.used_pct >= 100;
          const warn = r.configured && !over && r.used_pct >= r.alert_pct;
          const barColor = over ? 'bg-red-500' : warn ? 'bg-amber-500' : 'bg-emerald-500';
          return (
            <li key={r.mac} className="rounded-lg border border-gray-800 p-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="text-white text-sm font-medium">
                  {r.name} <span className="text-gray-600 font-mono text-xs">{r.mac}</span>
                  {!r.present && <span className="ml-2 text-[11px] text-gray-500">({t('svc.hosts.quota.absent')})</span>}
                  {/* Cota declarada e NADA medido neste ciclo. Sem este rótulo,
                      um aparelho comportado com 0% da cota e um endereço físico
                      que não existe mais desenham a mesma barra verde. */}
                  {r.configured && r.measured_at === 0 && (
                    <span className="ml-2 text-[11px] text-amber-500/90" title={t('svc.hosts.quota.noMeasureHint')}>
                      ({t('svc.hosts.quota.noMeasure')})
                    </span>
                  )}
                </span>
                <span className="text-xs text-gray-400">
                  {r.configured
                    ? t('svc.hosts.quota.used', { used: humanBytes(r.used_bytes), limit: humanGB(r.limit_gb), pct: r.used_pct.toFixed(0) })
                    : t('svc.hosts.quota.usedNoLimit', { used: humanBytes(r.used_bytes) })}
                </span>
              </div>

              {r.configured && (
                <div className="mt-2 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                  <div className={`h-full ${barColor} transition-all`}
                    style={{ width: `${Math.min(100, Math.max(0, r.used_pct))}%` }} />
                </div>
              )}

              <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-gray-600">
                <span>{t('svc.hosts.quota.cycle')}: {cycleLabel(r.cycle_start, r.cycle_end)}</span>
                <span>↓ {humanBytes(r.rx_bytes)} · ↑ {humanBytes(r.tx_bytes)}</span>
                {canEdit && editing !== r.mac && (
                  <button onClick={() => startEdit(r)} className="text-blue-400 hover:text-blue-300">
                    {r.configured ? t('svc.hosts.quota.edit') : t('svc.hosts.quota.define')}
                  </button>
                )}
                {canEdit && r.configured && editing !== r.mac && (
                  <button onClick={() => remove(r.mac)} disabled={busy}
                    title={t('svc.hosts.quota.removeHint')}
                    className="text-gray-500 hover:text-red-400 inline-flex items-center gap-1">
                    <Trash2 className="w-3 h-3" /> {t('svc.hosts.quota.remove')}
                  </button>
                )}
              </div>

              {editing === r.mac && (
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-5 gap-2 items-end">
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('svc.hosts.quota.limit')}</span>
                    <input value={limitGB} onChange={(e) => setLimitGB(e.target.value.replace(/[^\d.]/g, ''))}
                      inputMode="decimal" placeholder="5" className="input mt-1 w-full font-mono" />
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('svc.hosts.quota.period')}</span>
                    <select value={period} onChange={(e) => setPeriod(e.target.value as HostQuotaPeriod)}
                      className="input mt-1 w-full">
                      <option value="monthly">{t('svc.hosts.quota.period.monthly')}</option>
                      <option value="daily">{t('svc.hosts.quota.period.daily')}</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('svc.hosts.quota.cycleDay')}</span>
                    <input value={cycleDay} onChange={(e) => setCycleDay(e.target.value.replace(/\D/g, ''))}
                      inputMode="numeric" disabled={period === 'daily'}
                      className="input mt-1 w-full font-mono disabled:opacity-40" />
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('svc.hosts.quota.alertAt')}</span>
                    <input value={alertPct} onChange={(e) => setAlertPct(e.target.value.replace(/\D/g, ''))}
                      inputMode="numeric" className="input mt-1 w-full font-mono" />
                  </label>
                  <div className="flex gap-2">
                    <button onClick={() => save(r.mac)} disabled={busy || !limitGB}
                      className="btn-primary text-xs flex items-center gap-1 disabled:opacity-50">
                      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                      {t('svc.hosts.quota.save')}
                    </button>
                    <button onClick={() => setEditing(null)} className="btn-secondary text-xs">
                      {t('svc.hosts.quota.cancel')}
                    </button>
                  </div>
                  <p className="sm:col-span-5 text-[11px] text-gray-600">{t('svc.hosts.quota.cycleDayHint')}</p>
                  {/* Trocar período ou dia de fechamento MOVE a chave do ciclo.
                      O backend leva o consumo junto e fecha os alertas abertos,
                      mas o admin precisa saber disso ANTES de salvar: sem o
                      aviso, ele vê o alerta sumir e acha que quebrou algo. */}
                  {r.configured && (period !== r.period || Number(cycleDay) !== r.cycle_day) && (
                    <p className="sm:col-span-5 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-300">
                      <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden="true" />
                      {t('svc.hosts.quota.periodChangeWarning')}
                    </p>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      )}
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
