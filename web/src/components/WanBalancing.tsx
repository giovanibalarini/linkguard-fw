import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Scale, Shield, AlertTriangle, Check, RotateCcw, Plus, Trash2, Clock,
  Loader2, ChevronDown, Info, Zap,
} from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import type { WanLink, BalanceStatus, BalanceSchedule } from '../types';

const WEEKDAYS = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];

interface Props {
  links: WanLink[];
  onChanged: () => void | Promise<void>;
}

/**
 * WanBalancing controls the egress default route across multiple WAN links:
 * a weighted multipath ("Balanceamento") mode vs. priority "Failover" mode, with
 * a safe apply that auto-rolls-back unless confirmed, plus scheduled rebalancing.
 */
export default function WanBalancing({ links, onChanged }: Props) {
  const [status, setStatus] = useState<BalanceStatus | null>(null);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [showSchedules, setShowSchedules] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const { data } = await client.get<BalanceStatus>('/api/routing/balance');
      setStatus(data);
    } catch {
      /* routes.read may be missing for this user — hide silently */
      setStatus(null);
    }
  }, []);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  // Seed editable weights from the live links.
  useEffect(() => {
    const w: Record<string, number> = {};
    links.forEach((l) => { w[l.id] = l.weight; });
    setWeights(w);
  }, [links]);

  // Tick once a second while a rollback is pending so the countdown updates.
  const pending = status?.plan.pending ?? false;
  useEffect(() => {
    if (!pending) return;
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, [pending]);

  // When the auto-rollback window elapses, refresh to pick up the reverted state.
  const expiry = status?.plan.pending_expiry ?? 0;
  useEffect(() => {
    if (pending && expiry > 0 && now >= expiry) fetchStatus();
  }, [pending, expiry, now, fetchStatus]);

  const wanLinks = useMemo(() => links.filter((l) => l.enabled), [links]);
  const onlineIds = useMemo(
    () => new Set((status?.plan.nexthops ?? []).map((n) => n.link_id)),
    [status],
  );
  const totalWeight = useMemo(
    () => wanLinks.filter((l) => onlineIds.has(l.id)).reduce((s, l) => s + (weights[l.id] || 0), 0),
    [wanLinks, onlineIds, weights],
  );

  if (!status) return null;
  const mode = status.config.mode;

  const setMode = async (m: 'failover' | 'balance') => {
    if (m === mode) return;
    setBusy(true); setError('');
    try {
      await client.put('/api/routing/balance', { ...status.config, mode: m });
      await fetchStatus();
    } catch (e) {
      setError(errMsg(e));
    } finally { setBusy(false); }
  };

  const saveWeightsAndApply = async () => {
    setBusy(true); setError('');
    try {
      // Persist any changed weights onto the links, then apply (armed).
      for (const l of wanLinks) {
        if (weights[l.id] !== l.weight) {
          await client.put(`/api/links/${l.id}`, { ...l, weight: weights[l.id] });
        }
      }
      await onChanged();
      await client.post('/api/routing/balance/apply?arm=true');
      await fetchStatus();
    } catch (e) {
      setError(errMsg(e));
    } finally { setBusy(false); }
  };

  const confirm = async () => {
    setBusy(true);
    try { await client.post('/api/routing/balance/confirm'); await fetchStatus(); }
    finally { setBusy(false); }
  };

  const rollback = async () => {
    setBusy(true);
    try { await client.post('/api/routing/balance/rollback'); await fetchStatus(); await onChanged(); }
    catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  };

  const persistSchedules = async (schedules: BalanceSchedule[]) => {
    setBusy(true); setError('');
    try {
      await client.put('/api/routing/balance', { ...status.config, schedules });
      await fetchStatus();
    } catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  };

  const saveDegradeReaction = async (patch: Partial<typeof status.config>) => {
    setBusy(true); setError('');
    try {
      await client.put('/api/routing/balance', { ...status.config, ...patch });
      await fetchStatus();
    } catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  };

  const secondsLeft = pending && expiry > 0 ? Math.max(0, expiry - now) : 0;

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Scale className="w-5 h-5 text-blue-400" />
        <h2 className="text-white font-semibold">Balanceamento de saída (multi-WAN)</h2>
        <HelpTip title="Balanceamento vs. Failover">
          <><b>Failover</b>: usa um link por vez e troca se ele cair. <b>Balanceamento</b>: distribui as
          conexões entre os links ao mesmo tempo, na proporção dos <b>pesos</b> — e ainda tira um link
          do rodízio automaticamente se ele cair.</>
        </HelpTip>
      </div>
      <p className="text-gray-500 text-xs mb-4">Define como o tráfego geral sai pelas suas internets.</p>

      {/* Mode selector */}
      <div className="flex items-center gap-1 rounded-lg bg-gray-800 p-1 w-full max-w-sm mb-4" role="group">
        <button
          onClick={() => setMode('failover')}
          disabled={busy}
          className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === 'failover' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <Shield className="w-4 h-4" /> Failover
        </button>
        <button
          onClick={() => setMode('balance')}
          disabled={busy}
          className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === 'balance' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <Scale className="w-4 h-4" /> Balanceamento
        </button>
      </div>

      {error && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
        </div>
      )}

      {/* Pending auto-rollback banner */}
      {pending && (
        <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3">
          <div className="flex items-center gap-2 text-amber-300 text-sm font-medium">
            <Clock className="w-4 h-4" />
            Confirme em {secondsLeft}s ou revertemos a rota automaticamente.
          </div>
          <p className="text-amber-200/70 text-xs mt-1">
            Verifique se a internet continua funcionando antes de confirmar. Em caso de dúvida, reverta.
          </p>
          <div className="flex gap-2 mt-3">
            <button onClick={confirm} disabled={busy} className="btn-primary text-xs flex items-center gap-1">
              <Check className="w-3.5 h-3.5" /> Manter alteração
            </button>
            <button onClick={rollback} disabled={busy} className="btn-secondary text-xs flex items-center gap-1">
              <RotateCcw className="w-3.5 h-3.5" /> Reverter agora
            </button>
          </div>
        </div>
      )}

      {mode === 'failover' ? (
        <div className="flex items-start gap-2 rounded-lg bg-gray-800/40 px-3 py-3 text-sm text-gray-400">
          <Info className="w-4 h-4 mt-0.5 shrink-0 text-gray-500" />
          <span>O balanceamento está desativado. Cada link é usado conforme a prioridade/failover.
            Ative o <b>Balanceamento</b> para distribuir o tráfego entre as WANs pelos pesos.</span>
        </div>
      ) : (
        <>
          {/* Per-link weights */}
          <div className="space-y-2.5">
            {wanLinks.map((l) => {
              const online = onlineIds.has(l.id);
              const share = online && totalWeight > 0 ? Math.round(((weights[l.id] || 0) / totalWeight) * 100) : 0;
              return (
                <div key={l.id} className="flex items-center gap-3">
                  <div className="w-36 sm:w-44 shrink-0 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${online ? 'bg-green-400' : 'bg-gray-600'}`} />
                      <span className="text-white text-sm truncate">{l.name}</span>
                    </div>
                    <div className="text-gray-600 text-xs font-mono truncate">{l.interface} · {l.gateway || '—'}</div>
                  </div>
                  <div className="flex-1 h-2 rounded-full bg-gray-800 overflow-hidden">
                    <div className={`h-full ${online ? 'bg-blue-500' : 'bg-gray-700'}`} style={{ width: `${share}%` }} />
                  </div>
                  <div className="shrink-0 flex items-center gap-2">
                    <input
                      type="number" min={0} max={1000}
                      value={weights[l.id] ?? 0}
                      onChange={(e) => setWeights((w) => ({ ...w, [l.id]: Math.max(0, Number(e.target.value)) }))}
                      className="w-20 rounded-md bg-gray-800 border border-gray-700 px-2 py-1 text-sm text-white text-right"
                      title="Peso (proporção do tráfego)"
                    />
                    <span className="text-gray-500 text-xs w-9 text-right">{online ? `${share}%` : 'off'}</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button onClick={saveWeightsAndApply} disabled={busy} className="btn-primary text-sm flex items-center gap-1.5">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Scale className="w-4 h-4" />}
              Aplicar pesos
            </button>
            <span className="text-gray-600 text-xs">Aplica com rede protegida (reverte sozinho se você não confirmar).</span>
          </div>

          {/* Live route detail */}
          {(status.plan.current_default || status.plan.command) && (
            <div className="mt-4 space-y-2 text-xs">
              {status.plan.current_default && (
                <div>
                  <span className="text-gray-500">Rota atual: </span>
                  <code className="text-gray-300">{status.plan.current_default}</code>
                </div>
              )}
              {status.plan.command && (
                <div>
                  <span className="text-gray-500">Rota alvo: </span>
                  <code className="text-blue-300 break-all">{status.plan.command}</code>
                </div>
              )}
            </div>
          )}

          {/* Reação a link degradado (expulsão ativa de conexões) */}
          <div className="mt-5 border-t border-gray-800 pt-4">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4 text-amber-400" />
              <span className="text-sm font-medium text-white">Reação a link degradado</span>
              <HelpTip title="Expulsar conexões de link degradado">
                <>Quando um link fica <b>degradado</b> (ping alto / oscilando, mas ainda vivo) por várias
                verificações seguidas, o LinkGuard pode <b>migrar as conexões ativas</b> dele para um link
                saudável. As conexões no link ruim são <b>reiniciadas</b> (reconectam na hora no link bom) —
                ideal para chamadas/VoIP que estavam travando. Só age se houver outro link saudável.</>
              </HelpTip>
            </div>

            <label className="flex items-center gap-2 mt-2 cursor-pointer">
              <input
                type="checkbox"
                checked={status.config.evict_on_degrade}
                disabled={busy}
                onChange={(e) => saveDegradeReaction({ evict_on_degrade: e.target.checked })}
                className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-blue-600"
              />
              <span className="text-sm text-gray-300">Expulsar conexões de link degradado</span>
            </label>

            {status.config.evict_on_degrade && (
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-lg">
                <label className="block">
                  <span className="text-xs text-gray-400">Amostras ruins seguidas antes de agir</span>
                  <input
                    type="number" min={1} max={20}
                    value={status.config.degraded_sustain_samples}
                    disabled={busy}
                    onChange={(e) => saveDegradeReaction({ degraded_sustain_samples: Math.max(1, Number(e.target.value)) })}
                    className="mt-1 w-full rounded-md bg-gray-800 border border-gray-700 px-2 py-1 text-sm text-white"
                  />
                  <span className="text-gray-600 text-xs">~10s por amostra (ex.: 3 ≈ 30s de link ruim).</span>
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Intervalo mínimo entre migrações (s)</span>
                  <input
                    type="number" min={10} max={3600}
                    value={status.config.evict_cooldown_seconds}
                    disabled={busy}
                    onChange={(e) => saveDegradeReaction({ evict_cooldown_seconds: Math.max(10, Number(e.target.value)) })}
                    className="mt-1 w-full rounded-md bg-gray-800 border border-gray-700 px-2 py-1 text-sm text-white"
                  />
                  <span className="text-gray-600 text-xs">Evita migrar repetidamente num link que oscila.</span>
                </label>
              </div>
            )}
          </div>
        </>
      )}

      {/* Schedules */}
      <div className="mt-5 border-t border-gray-800 pt-4">
        <button
          onClick={() => setShowSchedules((v) => !v)}
          className="flex w-full items-center justify-between text-left"
        >
          <span className="flex items-center gap-2 text-sm font-medium text-white">
            <Clock className="w-4 h-4 text-blue-400" /> Rebalanceamento agendado
            <span className="text-gray-600 text-xs font-normal">({(status.config.schedules ?? []).length})</span>
          </span>
          <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${showSchedules ? '' : '-rotate-90'}`} />
        </button>
        {showSchedules && (
          <ScheduleEditor
            schedules={status.config.schedules ?? []}
            links={wanLinks}
            busy={busy}
            onChange={persistSchedules}
          />
        )}
      </div>
    </div>
  );
}

// ─── Schedule editor ─────────────────────────────────────────────────────────

function ScheduleEditor({
  schedules, links, busy, onChange,
}: {
  schedules: BalanceSchedule[];
  links: WanLink[];
  busy: boolean;
  onChange: (s: BalanceSchedule[]) => void | Promise<void>;
}) {
  const [name, setName] = useState('');
  const [at, setAt] = useState('08:00');
  const [days, setDays] = useState<number[]>([1, 2, 3, 4, 5]);
  const [weights, setWeights] = useState<Record<string, number>>({});

  const toggleDay = (d: number) =>
    setDays((ds) => (ds.includes(d) ? ds.filter((x) => x !== d) : [...ds, d].sort()));

  const add = () => {
    if (!name.trim() || days.length === 0) return;
    const w: Record<string, number> = {};
    links.forEach((l) => { w[l.id] = weights[l.id] ?? l.weight; });
    const id = `sch-${at.replace(':', '')}-${days.join('')}-${name.trim().toLowerCase().replace(/\s+/g, '-')}`;
    onChange([...schedules, { id, name: name.trim(), enabled: true, days, at, weights: w }]);
    setName('');
  };

  const remove = (id: string) => onChange(schedules.filter((s) => s.id !== id));
  const toggleEnabled = (id: string) =>
    onChange(schedules.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)));

  return (
    <div className="mt-3 space-y-3">
      <p className="text-gray-500 text-xs">
        Aplica pesos diferentes em horários definidos (ex.: priorizar a WAN1 no horário comercial e
        equilibrar à noite). Roda no fuso do servidor.
      </p>

      {schedules.length > 0 && (
        <ul className="space-y-1.5">
          {schedules.map((s) => (
            <li key={s.id} className="flex items-center gap-3 rounded-lg bg-gray-800/40 px-3 py-2 text-sm">
              <button
                onClick={() => toggleEnabled(s.id)} disabled={busy}
                className={`w-2 h-2 rounded-full ${s.enabled ? 'bg-green-400' : 'bg-gray-600'}`}
                title={s.enabled ? 'Ativo — clique para pausar' : 'Pausado — clique para ativar'}
              />
              <span className="text-white font-medium">{s.at}</span>
              <span className="text-gray-400 min-w-0 flex-1 truncate">
                {s.name} · {s.days.map((d) => WEEKDAYS[d]).join(' ')} ·{' '}
                {links.map((l) => `${l.name.split(' ')[0]}:${s.weights[l.id] ?? 0}`).join(' / ')}
              </span>
              <button onClick={() => remove(s.id)} disabled={busy} className="text-gray-500 hover:text-red-400" title="Remover">
                <Trash2 className="w-4 h-4" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {/* Add form */}
      <div className="rounded-lg border border-gray-800 p-3 space-y-2.5">
        <div className="flex flex-wrap gap-2">
          <input
            value={name} onChange={(e) => setName(e.target.value)}
            placeholder="Nome (ex.: Horário comercial)"
            className="flex-1 min-w-[10rem] rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white"
          />
          <input
            type="time" value={at} onChange={(e) => setAt(e.target.value)}
            className="rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white"
          />
        </div>
        <div className="flex gap-1">
          {WEEKDAYS.map((d, i) => (
            <button
              key={i} onClick={() => toggleDay(i)}
              className={`px-2 py-1 rounded text-xs font-medium ${
                days.includes(i) ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-500 hover:text-gray-300'
              }`}
            >{d}</button>
          ))}
        </div>
        <div className="flex flex-wrap gap-3">
          {links.map((l) => (
            <label key={l.id} className="flex items-center gap-1.5 text-xs text-gray-400">
              {l.name}:
              <input
                type="number" min={0} max={1000}
                value={weights[l.id] ?? l.weight}
                onChange={(e) => setWeights((w) => ({ ...w, [l.id]: Math.max(0, Number(e.target.value)) }))}
                className="w-16 rounded-md bg-gray-800 border border-gray-700 px-1.5 py-1 text-white text-right"
              />
            </label>
          ))}
        </div>
        <button onClick={add} disabled={busy || !name.trim() || days.length === 0}
          className="btn-secondary text-xs flex items-center gap-1 disabled:opacity-50">
          <Plus className="w-3.5 h-3.5" /> Adicionar agendamento
        </button>
      </div>
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'Falha na operação. Tente novamente.';
}
