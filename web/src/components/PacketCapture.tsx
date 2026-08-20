import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Crosshair, Play, Square, Loader2, AlertTriangle, Download, Package, ShieldQuestion,
} from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { CaptureRun, CaptureStatus } from '../types';

interface Props {
  interfaces: string[];
  canCapture: boolean;
}

/**
 * PacketCapture é o "tcpdump sem SSH": captura limitada, só de cabeçalho, numa
 * interface, e devolve a tabela mais o resumo que responde o que a tabela
 * sozinha não responde — quem falou mais, que serviço era, e quem tentou
 * conectar e não obteve resposta (o sintoma de roteamento de retorno errado
 * numa caixa com duas WANs).
 */
export default function PacketCapture({ interfaces, canCapture }: Props) {
  const { t } = useI18n();
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [iface, setIface] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [proto, setProto] = useState('');
  const [direction, setDirection] = useState('any');
  const [durationSec, setDurationSec] = useState(15);
  const [saveFile, setSaveFile] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const cap: CaptureRun | undefined = status?.capture;
  const running = cap?.state === 'running';

  const fetchStatus = useCallback(async () => {
    try {
      const { data } = await client.get<CaptureStatus>('/api/traffic/capture');
      setStatus(data);
    } catch { /* silencioso: o painel já mostra o erro da ação */ }
  }, []);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  useEffect(() => {
    if (running) {
      timer.current = setInterval(fetchStatus, 1500);
    } else if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [running, fetchStatus]);

  useEffect(() => { if (!iface && interfaces[0]) setIface(interfaces[0]); }, [interfaces, iface]);

  const start = async () => {
    setBusy(true); setErr('');
    try {
      await client.post('/api/traffic/capture', {
        interface: iface,
        filter: { host: host.trim(), port: port ? Number(port) : 0, proto, direction },
        duration_sec: durationSec,
        save_file: saveFile,
      });
      await fetchStatus();
    } catch (e) { setErr(errMsg(e, t('mon.capture.error.start'))); }
    finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try { await client.delete('/api/traffic/capture'); await fetchStatus(); }
    finally { setBusy(false); }
  };

  const install = async () => {
    setBusy(true); setErr('');
    try { await client.post('/api/traffic/capture/install'); await fetchStatus(); }
    catch (e) { setErr(errMsg(e, t('mon.capture.error.install'))); }
    finally { setBusy(false); }
  };

  const download = async () => {
    setBusy(true); setErr('');
    try {
      const res = await client.get('/api/traffic/capture/file', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      a.href = url; a.download = `linkguard-${cap?.id ?? 'captura'}.pcap`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr(errMsg(e, t('mon.capture.error.download'))); }
    finally { setBusy(false); }
  };

  if (!canCapture) return null;

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Crosshair className="w-5 h-5 text-blue-400" />
          <span className="text-white font-semibold">{t('mon.capture.title')}</span>
          <HelpTip title={t('mon.capture.help.title')}>
            <>{t('mon.capture.help1')} <b>{t('mon.capture.helpHeadersTerm')}</b>{t('mon.capture.help2')}</>
          </HelpTip>
        </span>
      }
    >
      <p className="text-gray-500 text-xs mb-4">{t('mon.capture.subtitle')}</p>

      {err && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      {/* tcpdump ausente: oferece instalar em vez de deixar o admin descobrir no erro */}
      {status && !status.available && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm">
          <p className="text-amber-300 flex items-center gap-2">
            <Package className="w-4 h-4 shrink-0" /> {t('mon.capture.notInstalled')}
          </p>
          <button onClick={install} disabled={busy} className="btn-secondary text-xs mt-2 disabled:opacity-50">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} {t('mon.capture.install')}
          </button>
        </div>
      )}

      {status?.available && !running && (
        <div className="rounded-lg border border-gray-800 p-3 space-y-3 mb-4">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.interface')}</span>
              <select value={iface} onChange={(e) => setIface(e.target.value)} className="input mt-1 w-full">
                {interfaces.map((i) => <option key={i} value={i}>{i}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.host')}</span>
              <input value={host} onChange={(e) => setHost(e.target.value)}
                placeholder={t('mon.capture.hostPlaceholder')} className="input mt-1 w-full font-mono" />
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.port')}</span>
              <input value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))}
                inputMode="numeric" placeholder="443" className="input mt-1 w-full font-mono" />
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.proto')}</span>
              <select value={proto} onChange={(e) => setProto(e.target.value)} className="input mt-1 w-full">
                <option value="">{t('mon.capture.protoAny')}</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
              </select>
            </label>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.direction')}</span>
              <select value={direction} onChange={(e) => setDirection(e.target.value)} className="input mt-1 w-full">
                <option value="any">{t('mon.capture.dir.any')}</option>
                <option value="from">{t('mon.capture.dir.from')}</option>
                <option value="to">{t('mon.capture.dir.to')}</option>
              </select>
            </label>
            <label className="block">
              <span className="text-gray-400 text-xs">{t('mon.capture.duration', { n: durationSec })}</span>
              <input type="range" min={5} max={status.limits.max_duration_sec} step={5} value={durationSec}
                onChange={(e) => setDurationSec(Number(e.target.value))} className="w-full mt-2 accent-blue-500" />
            </label>
            <label className="flex items-center gap-2 mt-5 text-xs text-gray-400">
              <input type="checkbox" checked={saveFile} onChange={(e) => setSaveFile(e.target.checked)}
                className="accent-blue-500" />
              {t('mon.capture.saveFile', { min: Math.round(status.limits.file_ttl_sec / 60) })}
            </label>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={start} disabled={busy || !iface} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} {t('mon.capture.run')}
            </button>
            <span className="text-gray-500 text-xs">{t('mon.capture.auditHint')}</span>
          </div>
        </div>
      )}

      {cap && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="font-mono text-white">{cap.interface}</span>
            {cap.filter_expr && <span className="font-mono text-gray-500 text-xs">{cap.filter_expr}</span>}
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs ${
              cap.state === 'running' ? 'bg-blue-500/15 text-blue-300'
                : cap.state === 'done' ? 'bg-green-500/15 text-green-400'
                : cap.state === 'error' ? 'bg-red-500/15 text-red-400' : 'bg-gray-700 text-gray-300'
            }`}>
              {cap.state === 'running' ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
              {t(`mon.capture.state.${cap.state}`)}
            </span>
            {running && (
              <button onClick={stop} disabled={busy} className="btn-secondary text-xs flex items-center gap-1 ml-auto">
                <Square className="w-3.5 h-3.5" /> {t('mon.capture.stop')}
              </button>
            )}
            {!running && cap.has_file && (
              <button onClick={download} disabled={busy} className="btn-secondary text-xs flex items-center gap-1 ml-auto">
                <Download className="w-3.5 h-3.5" /> {t('mon.capture.download', { kb: Math.max(1, Math.round(cap.file_bytes / 1024)) })}
              </button>
            )}
          </div>

          {cap.message && <p className="text-gray-400 text-xs">{cap.message}</p>}

          {cap.state !== 'running' && cap.summary.packets > 0 && (
            <>
              {/* O que a tabela não responde sozinha */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Bloco titulo={t('mon.capture.topPairs')} linhas={cap.summary.pairs.slice(0, 5).map((c) => ({
                  chave: c.key, valor: t('mon.capture.pktCount', { n: c.count }),
                }))} vazio={t('mon.capture.none')} />
                <Bloco titulo={t('mon.capture.topPorts')} linhas={cap.summary.ports.slice(0, 5).map((c) => ({
                  chave: c.key, valor: t('mon.capture.pktCount', { n: c.count }),
                }))} vazio={t('mon.capture.none')} />
                <Bloco titulo={t('mon.capture.protos')} linhas={cap.summary.protos.map((c) => ({
                  chave: c.key, valor: t('mon.capture.pktCount', { n: c.count }),
                }))} vazio={t('mon.capture.none')} />
              </div>

              {(cap.summary.unanswered_total > 0 || cap.summary.refused_total > 0 || cap.summary.retransmits > 0) && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
                  <p className="text-amber-300 text-xs font-medium flex items-center gap-2">
                    <ShieldQuestion className="w-4 h-4" /> {t('mon.capture.diag.title')}
                  </p>
                  {cap.summary.unanswered_total > 0 && (
                    <div>
                      <p className="text-xs text-gray-300">
                        {t('mon.capture.diag.unanswered', { n: cap.summary.unanswered_total })}
                      </p>
                      <ul className="mt-1 space-y-0.5">
                        {cap.summary.unanswered.slice(0, 5).map((h, i) => (
                          <li key={i} className="font-mono text-[11px] text-gray-400">
                            {h.time} {h.src} → {h.dst}{h.tries > 1 ? ` (${t('mon.capture.diag.tries', { n: h.tries })})` : ''}
                          </li>
                        ))}
                      </ul>
                      {cap.summary.unanswered_total > cap.summary.unanswered.length && (
                        <p className="text-[11px] text-gray-600 mt-1">
                          {t('mon.capture.diag.listCut', {
                            shown: cap.summary.unanswered.length, total: cap.summary.unanswered_total,
                          })}
                        </p>
                      )}
                    </div>
                  )}
                  {cap.summary.refused_total > 0 && (
                    <p className="text-xs text-gray-300">{t('mon.capture.diag.refused', { n: cap.summary.refused_total })}</p>
                  )}
                  {cap.summary.retransmits > 0 && (
                    <p className="text-xs text-gray-300">{t('mon.capture.diag.retransmits', { n: cap.summary.retransmits })}</p>
                  )}
                </div>
              )}

              {/* A tabela */}
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 text-left">
                      <th className="py-1 pr-3 font-medium">{t('mon.capture.col.time')}</th>
                      <th className="py-1 pr-3 font-medium">{t('mon.capture.col.src')}</th>
                      <th className="py-1 pr-3 font-medium">{t('mon.capture.col.dst')}</th>
                      <th className="py-1 pr-3 font-medium">{t('mon.capture.col.proto')}</th>
                      <th className="py-1 pr-3 font-medium">{t('mon.capture.col.flags')}</th>
                      <th className="py-1 font-medium text-right">{t('mon.capture.col.len')}</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono">
                    {cap.packets.map((p, i) => (
                      <tr key={i} className="border-t border-gray-800/60">
                        <td className="py-0.5 pr-3 text-gray-500">{p.time}</td>
                        <td className="py-0.5 pr-3 text-gray-300">{p.src}</td>
                        <td className="py-0.5 pr-3 text-gray-300">{p.dst}</td>
                        <td className="py-0.5 pr-3 text-gray-400">{p.proto}</td>
                        <td className="py-0.5 pr-3 text-gray-400">{p.flags}</td>
                        <td className="py-0.5 text-right text-gray-500">{p.len}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {cap.truncated && (
                <p className="text-[11px] text-gray-600">
                  {t('mon.capture.rowsCut', { shown: cap.rows_shown, total: cap.summary.packets })}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </Panel>
  );
}

function Bloco({ titulo, linhas, vazio }: {
  titulo: string;
  linhas: { chave: string; valor: string }[];
  vazio: string;
}) {
  return (
    <div className="rounded-lg border border-gray-800 p-3">
      <p className="text-gray-400 text-xs mb-2">{titulo}</p>
      {linhas.length === 0 ? (
        <p className="text-gray-600 text-xs">{vazio}</p>
      ) : (
        <ul className="space-y-0.5">
          {linhas.map((l, i) => (
            <li key={i} className="flex justify-between gap-2 text-[11px]">
              <span className="font-mono text-gray-300 truncate">{l.chave}</span>
              <span className="text-gray-500 shrink-0">{l.valor}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
