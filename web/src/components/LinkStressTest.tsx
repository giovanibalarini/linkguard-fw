import { useCallback, useEffect, useRef, useState } from 'react';
import {
  FlaskConical, Play, Square, Loader2, AlertTriangle, Check, X, Wifi, Globe,
} from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { WanLink, StressTest } from '../types';

interface Props {
  links: WanLink[];
  canRun: boolean;
}

/**
 * LinkStressTest lets an admin validate multi-WAN failover on demand: it injects
 * a fault (outage or degradation) on a chosen WAN, measures ping/DNS continuity
 * live while the balancer reacts, then auto-restores. Uncommon in open-source
 * firewalls — a real differentiator.
 */
export default function LinkStressTest({ links, canRun }: Props) {
  const [test, setTest] = useState<StressTest | null>(null);
  const [linkID, setLinkID] = useState('');
  const [mode, setMode] = useState<'outage' | 'degrade'>('outage');
  const [delayMs, setDelayMs] = useState(500);
  const [lossPct, setLossPct] = useState(20);
  const [durationSec, setDurationSec] = useState(90);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const running = test?.state === 'running';

  const fetchStatus = useCallback(async () => {
    try {
      const { data } = await client.get<StressTest>('/api/stresstest/status');
      setTest(data.state === 'idle' ? null : data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  // Poll while a test is running.
  useEffect(() => {
    if (running) {
      timer.current = setInterval(fetchStatus, 2000);
    } else if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [running, fetchStatus]);

  useEffect(() => { if (!linkID && links[0]) setLinkID(links[0].id); }, [links, linkID]);

  const start = async () => {
    setBusy(true); setErr('');
    try {
      const { data } = await client.post<StressTest>('/api/stresstest/start', {
        link_id: linkID, mode, delay_ms: delayMs, loss_pct: lossPct, duration_sec: durationSec,
      });
      setTest(data);
    } catch (e) { setErr(errMsg(e)); }
    finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try { await client.post('/api/stresstest/stop'); await fetchStatus(); }
    finally { setBusy(false); }
  };

  // samples includes the t=0 baseline sample, so subtract it before scaling by
  // the 2s interval (otherwise the bar reaches 100% one interval early).
  const samples = test?.samples ?? [];
  const elapsed = test && running ? Math.min(test.duration_sec, Math.max(0, samples.length - 1) * 2) : 0;
  const pct = test?.duration_sec ? Math.min(100, (elapsed / test.duration_sec) * 100) : 0;

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <FlaskConical className="w-5 h-5 text-amber-400" />
          <span className="text-white font-semibold">Stress-test dos links</span>
          <HelpTip title="Stress-test">
            <>Valida o failover multi-WAN <b>sob demanda</b>: derruba ou degrada uma WAN de propósito,
            mede a continuidade (ping/DNS) enquanto o balanceador reage, e <b>restaura sozinho</b>.
            Assim você confirma que o failover funciona sem esperar o provedor cair.</>
          </HelpTip>
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">Testa uma WAN de cada vez, com restauração automática (à prova de falha do próprio painel).</p>

      {err && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      {/* Config form */}
      {canRun && !running && (
        <div className="rounded-lg border border-gray-800 p-3 space-y-3 mb-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <label className="block">
              <span className="text-gray-400 text-xs">Link</span>
              <select value={linkID} onChange={(e) => setLinkID(e.target.value)} className="input mt-1 w-full">
                {links.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.interface})</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">Cenário</span>
              <select value={mode} onChange={(e) => setMode(e.target.value as 'outage' | 'degrade')} className="input mt-1 w-full">
                <option value="outage">Queda (link down)</option>
                <option value="degrade">Degradação (latência/perda)</option>
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">Duração: {durationSec}s</span>
              <input type="range" min={30} max={300} step={30} value={durationSec}
                onChange={(e) => setDurationSec(Number(e.target.value))} className="w-full mt-2 accent-amber-500" />
            </label>
          </div>
          {mode === 'degrade' && (
            <div className="grid grid-cols-2 gap-2 max-w-xs">
              <label className="block">
                <span className="text-gray-400 text-xs">Latência (ms)</span>
                <input type="number" min={0} value={delayMs} onChange={(e) => setDelayMs(Number(e.target.value))} className="input mt-1 w-full" />
              </label>
              <label className="block">
                <span className="text-gray-400 text-xs">Perda (%)</span>
                <input type="number" min={0} max={100} value={lossPct} onChange={(e) => setLossPct(Number(e.target.value))} className="input mt-1 w-full" />
              </label>
            </div>
          )}
          <div className="flex items-center gap-3">
            <button onClick={start} disabled={busy || !linkID} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Rodar teste
            </button>
            <span className="text-amber-300/70 text-xs">Metade do tempo com a falha, metade recuperando. A WAN escolhida será impactada de propósito.</span>
          </div>
        </div>
      )}

      {/* Live / result */}
      {test && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-white font-medium">{test.link_name}</span>
            <span className="text-gray-500">{test.mode === 'outage' ? 'Queda' : `Degradação ${test.delay_ms}ms/${test.loss_pct}%`}</span>
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs ${
              test.state === 'running' ? 'bg-amber-500/15 text-amber-300' :
              test.state === 'done' ? 'bg-green-500/15 text-green-400' : 'bg-gray-700 text-gray-300'
            }`}>
              {test.state === 'running' ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
              {test.state === 'running' ? 'rodando' : test.state === 'done' ? 'concluído' : test.state}
            </span>
            {running && (
              <button onClick={stop} disabled={busy} className="btn-secondary text-xs flex items-center gap-1 ml-auto">
                <Square className="w-3.5 h-3.5" /> Parar + restaurar
              </button>
            )}
          </div>

          {running && (
            <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden">
              <div className="h-full bg-amber-500 transition-all" style={{ width: `${pct}%` }} />
            </div>
          )}

          {/* Continuity result */}
          {test.state !== 'running' && (
            <div className="flex flex-wrap gap-4 text-sm">
              <span className="inline-flex items-center gap-1.5"><Wifi className="w-4 h-4 text-blue-400" /> Ping: <b className={test.ping_loss_pct < 5 ? 'text-green-400' : 'text-amber-300'}>{(100 - test.ping_loss_pct).toFixed(0)}%</b></span>
              <span className="inline-flex items-center gap-1.5"><Globe className="w-4 h-4 text-blue-400" /> DNS: <b className={test.dns_loss_pct < 5 ? 'text-green-400' : 'text-amber-300'}>{(100 - test.dns_loss_pct).toFixed(0)}%</b></span>
              {test.restored && <span className="inline-flex items-center gap-1 text-green-400 text-xs"><Check className="w-3.5 h-3.5" /> restaurado</span>}
            </div>
          )}
          {test.message && <p className="text-gray-400 text-xs">{test.message}</p>}

          {/* Timeline */}
          {samples.length > 0 && (
            <div>
              <div className="flex gap-0.5 flex-wrap">
                {samples.map((s, i) => (
                  <div key={i}
                    title={`${s.t} · ${s.phase}\nping ${s.ping ? 'ok' : 'FALHA'} · dns ${s.dns ? 'ok' : 'FALHA'}\n${s.route}`}
                    className={`w-2.5 h-6 rounded-sm ${
                      s.phase === 'baseline' ? 'bg-gray-600' :
                      !s.ping || !s.dns ? 'bg-red-500' :
                      s.phase === 'fault' ? 'bg-amber-500' : 'bg-green-500'
                    }`} />
                ))}
              </div>
              <div className="flex gap-3 mt-1.5 text-[11px] text-gray-500">
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-gray-600" /> baseline</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-500" /> falha</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500" /> recuperação</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500" /> perda (ping/DNS)</span>
              </div>
            </div>
          )}
        </div>
      )}

      {!canRun && <p className="text-gray-600 text-xs">Você não tem permissão para rodar testes (requer gestão de rotas).</p>}
    </Panel>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha ao iniciar o teste';
}
