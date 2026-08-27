import { useCallback, useEffect, useRef, useState } from 'react';
import {
  FlaskConical, Play, Square, Loader2, AlertTriangle, Check, X, Wifi, Globe, Gauge, Activity,
} from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import { benchmarkResultIsComplete } from '../lib/qos';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { QosComparison, QosLoadMeasurement, WanLink, StressTest } from '../types';

interface Props {
  links: WanLink[];
  canRun: boolean;
  canQosTest: boolean;
}

const QOS_BENCHMARK_TIMEOUT_MS = 45_000;

/**
 * Operational link tests: an honest per-WAN bufferbloat benchmark plus the
 * existing multi-WAN failover fault injection. Both paths auto-restore.
 */
export default function LinkStressTest({ links, canRun, canQosTest }: Props) {
  const { t } = useI18n();
  const [test, setTest] = useState<StressTest | null>(null);
  const [linkID, setLinkID] = useState('');
  const [mode, setMode] = useState<'outage' | 'degrade'>('outage');
  const [delayMs, setDelayMs] = useState(500);
  const [lossPct, setLossPct] = useState(20);
  const [durationSec, setDurationSec] = useState(90);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [benchmarkLinkID, setBenchmarkLinkID] = useState('');
  const [iperfServer, setIperfServer] = useState('');
  const [iperfPort, setIperfPort] = useState('5201');
  const [benchmark, setBenchmark] = useState<QosComparison | null>(null);
  const [benchmarkBusy, setBenchmarkBusy] = useState(false);
  const [benchmarkErr, setBenchmarkErr] = useState('');
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
  useEffect(() => { if (!benchmarkLinkID && links[0]) setBenchmarkLinkID(links[0].id); }, [links, benchmarkLinkID]);

  const start = async () => {
    setBusy(true); setErr('');
    try {
      const { data } = await client.post<StressTest>('/api/stresstest/start', {
        link_id: linkID, mode, delay_ms: delayMs, loss_pct: lossPct, duration_sec: durationSec,
      });
      setTest(data);
    } catch (e) { setErr(errMsg(e, t('links.stress.error.start'))); }
    finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try { await client.post('/api/stresstest/stop'); await fetchStatus(); }
    finally { setBusy(false); }
  };

  const runQosBenchmark = async () => {
    setBenchmarkBusy(true);
    setBenchmarkErr('');
    setBenchmark(null);
    try {
      const port = Number(iperfPort);
      const { data } = await client.post<QosComparison>(
        `/api/links/${benchmarkLinkID}/qos/test`,
        { server: iperfServer.trim(), port: Number.isInteger(port) ? port : -1 },
        { timeout: QOS_BENCHMARK_TIMEOUT_MS },
      );
      setBenchmark(data);
    } catch (e) {
      setBenchmarkErr(errMsg(e, t('links.qos.error.test')));
    } finally {
      setBenchmarkBusy(false);
    }
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
          <span className="text-white font-semibold">{t('links.stress.title')}</span>
          <HelpTip title={t('links.stress.help.title')}>
            <>{t('links.stress.help1')} <b>{t('links.stress.helpOnDemandTerm')}</b>{t('links.stress.help2')} <b>{t('links.stress.helpRestoreTerm')}</b>.{' '}
            {t('links.stress.help3')}</>
          </HelpTip>
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">{t('links.stress.subtitle')}</p>

      <div className="mb-5 space-y-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
        <div className="flex items-start gap-2">
          <Gauge className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
          <div>
            <h3 className="text-sm font-medium text-white">{t('links.qos.benchmark.title')}</h3>
            <p className="mt-1 text-[11px] text-gray-500">{t('links.qos.benchmark.help')}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_8rem]">
          <label className="block">
            <span className="text-xs text-gray-400">{t('links.stress.link')}</span>
            <select value={benchmarkLinkID} onChange={(e) => setBenchmarkLinkID(e.target.value)} className="input mt-1 w-full" disabled={benchmarkBusy}>
              {links.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.interface})</option>)}
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">{t('links.qos.benchmark.server')}</span>
            <input
              value={iperfServer}
              onChange={(e) => setIperfServer(e.target.value)}
              placeholder={t('links.qos.benchmark.serverPlaceholder')}
              disabled={benchmarkBusy}
              className="input mt-1 w-full font-mono"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">{t('links.qos.benchmark.port')}</span>
            <input
              type="number"
              min={1}
              max={65535}
              value={iperfPort}
              onChange={(e) => setIperfPort(e.target.value)}
              disabled={benchmarkBusy}
              className="input mt-1 w-full font-mono"
            />
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {canQosTest ? (
            <button
              type="button"
              onClick={runQosBenchmark}
              disabled={benchmarkBusy || !benchmarkLinkID}
              className="btn-secondary inline-flex items-center gap-2 text-xs disabled:opacity-50"
            >
              {benchmarkBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Activity className="h-3.5 w-3.5" />}
              {benchmarkBusy ? t('links.qos.benchmark.running') : t('links.qos.benchmark.run')}
            </button>
          ) : (
            <span className="text-xs text-gray-600">{t('links.qos.benchmark.noPermission')}</span>
          )}
          <span className="text-[11px] text-amber-300/80">{t('links.qos.benchmark.loadWarning')}</span>
        </div>

        {benchmarkErr && (
          <div role="alert" className="flex items-start gap-2 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {benchmarkErr}
          </div>
        )}
        {benchmark && <QosBenchmarkResult value={benchmark} />}
      </div>

      {err && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      {/* Config form */}
      {links.length >= 2 && canRun && !running && (
        <div className="rounded-lg border border-gray-800 p-3 space-y-3 mb-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <label className="block">
              <span className="text-gray-400 text-xs">{t('links.stress.link')}</span>
              <select value={linkID} onChange={(e) => setLinkID(e.target.value)} className="input mt-1 w-full">
                {links.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.interface})</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('links.stress.scenario')}</span>
              <select value={mode} onChange={(e) => setMode(e.target.value as 'outage' | 'degrade')} className="input mt-1 w-full">
                <option value="outage">{t('links.stress.mode.outage')}</option>
                <option value="degrade">{t('links.stress.mode.degrade')}</option>
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('links.stress.duration', { n: durationSec })}</span>
              <input type="range" min={30} max={300} step={30} value={durationSec}
                onChange={(e) => setDurationSec(Number(e.target.value))} className="w-full mt-2 accent-amber-500" />
            </label>
          </div>
          {mode === 'degrade' && (
            <div className="grid grid-cols-2 gap-2 max-w-xs">
              <label className="block">
                <span className="text-gray-400 text-xs">{t('links.stress.delay')}</span>
                <input type="number" min={0} value={delayMs} onChange={(e) => setDelayMs(Number(e.target.value))} className="input mt-1 w-full" />
              </label>
              <label className="block">
                <span className="text-gray-400 text-xs">{t('links.stress.loss')}</span>
                <input type="number" min={0} max={100} value={lossPct} onChange={(e) => setLossPct(Number(e.target.value))} className="input mt-1 w-full" />
              </label>
            </div>
          )}
          <div className="flex items-center gap-3">
            <button onClick={start} disabled={busy || !linkID} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} {t('links.stress.run')}
            </button>
            <span className="text-amber-300/70 text-xs">{t('links.stress.runHint')}</span>
          </div>
        </div>
      )}

      {/* Live / result */}
      {test && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="text-white font-medium">{test.link_name}</span>
            <span className="text-gray-500">{test.mode === 'outage' ? t('links.stress.state.outage') : t('links.stress.state.degrade', { delay: test.delay_ms, loss: test.loss_pct })}</span>
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs ${
              test.state === 'running' ? 'bg-amber-500/15 text-amber-300' :
              test.state === 'done' ? 'bg-green-500/15 text-green-400' : 'bg-gray-700 text-gray-300'
            }`}>
              {test.state === 'running' ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
              {test.state === 'running' ? t('links.stress.state.running') : test.state === 'done' ? t('links.stress.state.done') : test.state}
            </span>
            {running && (
              <button onClick={stop} disabled={busy} className="btn-secondary text-xs flex items-center gap-1 ml-auto">
                <Square className="w-3.5 h-3.5" /> {t('links.stress.stop')}
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
              {test.restored && <span className="inline-flex items-center gap-1 text-green-400 text-xs"><Check className="w-3.5 h-3.5" /> {t('links.stress.restored')}</span>}
            </div>
          )}
          {test.message && <p className="text-gray-400 text-xs">{test.message}</p>}

          {/* Timeline */}
          {samples.length > 0 && (
            <div>
              <div className="flex gap-0.5 flex-wrap">
                {samples.map((s, i) => (
                  <div key={i}
                    title={`${s.t} · ${s.phase}\nping ${s.ping ? 'ok' : t('links.stress.fail')} · dns ${s.dns ? 'ok' : t('links.stress.fail')}\n${s.route}`}
                    className={`w-2.5 h-6 rounded-xs ${
                      s.phase === 'baseline' ? 'bg-gray-600' :
                      !s.ping || !s.dns ? 'bg-red-500' :
                      s.phase === 'fault' ? 'bg-amber-500' : 'bg-green-500'
                    }`} />
                ))}
              </div>
              <div className="flex gap-3 mt-1.5 text-[11px] text-gray-500">
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-xs bg-gray-600" /> {t('links.stress.legend.baseline')}</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-xs bg-amber-500" /> {t('links.stress.legend.fault')}</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-xs bg-green-500" /> {t('links.stress.legend.recovery')}</span>
                <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-xs bg-red-500" /> {t('links.stress.legend.loss')}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {links.length >= 2 && !canRun && <p className="text-gray-600 text-xs">{t('links.stress.noPermission')}</p>}
    </Panel>
  );
}

function QosBenchmarkResult({ value }: { value: QosComparison }) {
  const { t } = useI18n();
  const complete = benchmarkResultIsComplete(value);
  return (
    <div role="status" aria-live="polite" aria-atomic="true" className="space-y-3 border-t border-cyan-500/15 pt-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`rounded px-2 py-0.5 ${complete ? 'bg-green-500/15 text-green-400' : 'bg-amber-500/15 text-amber-300'}`}>
          {complete ? t('links.qos.benchmark.complete') : t('links.qos.benchmark.limited')}
        </span>
        <span className={value.restored ? 'text-green-400' : 'text-red-400'}>
          {value.restored ? t('links.qos.benchmark.restored') : t('links.qos.benchmark.restoreUnknown')}
        </span>
        <span className="font-mono text-gray-500">
          {value.conditions.server || t('links.qos.benchmark.noServer')}:{value.conditions.port}
        </span>
      </div>

      {value.limitations.length > 0 && (
        <ul className="space-y-1 text-xs text-amber-200/90">
          {value.limitations.map((limitation) => (
            <li key={limitation}>• {t(`links.qos.benchmark.limitation.${limitation}`)}</li>
          ))}
        </ul>
      )}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <BenchmarkPhase title={t('links.qos.benchmark.baseline')} phase={value.baseline} />
        <BenchmarkPhase title={t('links.qos.benchmark.configured')} phase={value.configured} />
      </div>
      <p className="text-[11px] text-gray-500">{t('links.qos.benchmark.noClaim')}</p>
    </div>
  );
}

function BenchmarkPhase({ title, phase }: { title: string; phase: QosComparison['baseline'] }) {
  const { t } = useI18n();
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <p className="mb-2 text-xs font-medium text-gray-300">{title}</p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <BenchmarkDirection title={t('links.qos.benchmark.upload')} value={phase.upload} />
        <BenchmarkDirection title={t('links.qos.benchmark.download')} value={phase.download} />
      </div>
    </div>
  );
}

function BenchmarkDirection({ title, value }: { title: string; value: QosLoadMeasurement }) {
  const { t } = useI18n();
  const metric = (number: number | null, suffix: string) => number === null
    ? t('links.qos.benchmark.notMeasured')
    : `${number.toFixed(1)} ${suffix}`;
  return (
    <div className="rounded bg-gray-900/60 p-2">
      <p className="mb-1.5 text-[11px] font-medium text-cyan-300">{title} · {value.offered_mbps} Mbps</p>
      <dl className="space-y-1 text-[11px]">
        <BenchmarkMetric label={t('links.qos.benchmark.latency')} value={value.latency ? `${value.latency.avg_ms.toFixed(1)} / ${value.latency.max_ms.toFixed(1)} ms` : t('links.qos.benchmark.notMeasured')} />
        <BenchmarkMetric label={t('links.qos.test.loss')} value={value.latency ? `${value.latency.loss_pct.toFixed(1)}%` : t('links.qos.benchmark.notMeasured')} />
        <BenchmarkMetric label={t('links.qos.benchmark.iperfThroughput')} value={metric(value.throughput_mbps, 'Mbps')} />
        <BenchmarkMetric label={t('links.qos.benchmark.interfaceThroughput')} value={metric(value.interface_mbps, 'Mbps')} />
        <BenchmarkMetric label={t('links.qos.benchmark.cpu')} value={metric(value.cpu_percent, '%')} />
      </dl>
    </div>
  );
}

function BenchmarkMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-gray-600">{label}</dt>
      <dd className="text-right font-mono text-gray-300">{value}</dd>
    </div>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
