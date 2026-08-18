import { useEffect, useRef, useState } from 'react';
import { Download, Upload, Loader2, AlertTriangle, Check, Send, Lock } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';
import {
  RestoreResult, BackupSchedule, BackupPassphraseStatusResponse, BackupScheduleResponse, BackupLastRunResponse,
} from '../types';

const SCHEDULE_OPTIONS: { value: BackupSchedule; labelKey: string }[] = [
  { value: 'off', labelKey: 'cfg.backup.schedule.off' },
  { value: 'daily', labelKey: 'cfg.backup.schedule.daily' },
  { value: 'weekly', labelKey: 'cfg.backup.schedule.weekly' },
  { value: 'monthly', labelKey: 'cfg.backup.schedule.monthly' },
];

/**
 * BackupRestore downloads/e-mails the full panel configuration, encrypted
 * with an admin-configured passphrase, and restores from an encrypted file.
 * Restore applies settings + DHCP reservations + DNS blocklist only (never
 * users/roles or live WAN links), so it can't lock the admin out.
 */
export default function BackupRestore() {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const [passphraseConfigured, setPassphraseConfigured] = useState(false);
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [savingPassphrase, setSavingPassphrase] = useState(false);

  const [schedule, setSchedule] = useState<BackupSchedule>('off');
  const [savingSchedule, setSavingSchedule] = useState(false);

  const [lastRun, setLastRun] = useState<BackupLastRunResponse | null>(null);
  const [sendingNow, setSendingNow] = useState(false);

  const errorPrefix = t('cfg.msg.errorPrefix');

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 6000); };

  const loadStatus = async () => {
    try {
      const [{ data: pp }, { data: sch }, { data: lr }] = await Promise.all([
        client.get<BackupPassphraseStatusResponse>('/api/backup/passphrase/status'),
        client.get<BackupScheduleResponse>('/api/backup/schedule'),
        client.get<BackupLastRunResponse>('/api/backup/last-run'),
      ]);
      setPassphraseConfigured(pp.configured);
      setSchedule(sch.schedule);
      setLastRun(lr);
    } catch { /* ignore */ }
  };
  useEffect(() => { loadStatus(); }, []);

  const savePassphrase = async () => {
    if (newPassphrase.length < 12) { flash(errorPrefix + t('cfg.backup.pass.tooShort')); return; }
    if (newPassphrase !== confirmPassphrase) { flash(errorPrefix + t('cfg.backup.pass.mismatch')); return; }
    setSavingPassphrase(true);
    try {
      await client.put('/api/backup/passphrase', { passphrase: newPassphrase });
      setNewPassphrase(''); setConfirmPassphrase('');
      setPassphraseConfigured(true);
      flash(t('cfg.backup.pass.saved'));
    } catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setSavingPassphrase(false); }
  };

  const download = async () => {
    setBusy(true);
    try {
      const res = await client.get('/api/backup', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'linkguard-backup.lgbak'; a.click();
      URL.revokeObjectURL(url);
      flash(t('cfg.backup.downloaded'));
    } catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setBusy(false); }
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setPendingFile(f);
    if (fileRef.current) fileRef.current.value = '';
  };

  const confirmRestore = async () => {
    if (!pendingFile) return;
    if (!restorePassphrase) { flash(errorPrefix + t('cfg.backup.restore.needPass')); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', pendingFile);
      form.append('passphrase', restorePassphrase);
      const { data } = await client.post<RestoreResult>('/api/backup/restore', form);
      setPendingFile(null);
      setRestorePassphrase('');
      setRestoreResult(data);
      flash(t('cfg.backup.restored'));
    } catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setBusy(false); }
  };

  const updateSchedule = async (next: BackupSchedule) => {
    if (next === schedule) return;
    setSavingSchedule(true);
    try {
      await client.put('/api/backup/schedule', { schedule: next });
      setSchedule(next);
      flash(t('cfg.backup.schedule.updated'));
    } catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setSavingSchedule(false); }
  };

  const sendNow = async () => {
    setSendingNow(true);
    try {
      await client.post('/api/backup/send-now');
      flash(t('cfg.backup.sent'));
      await loadStatus();
    } catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setSendingNow(false); }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Download className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">{t('cfg.backup.title')}</span><HelpTip title={t('cfg.backup.help.title')}>
          <>{t('cfg.backup.help.body')}</>
        </HelpTip></span>}>
      <div className="space-y-4">
      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith(errorPrefix) ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <div className="flex items-center gap-2 text-sm">
          <Lock className="w-4 h-4 text-gray-500" />
          <span className="text-gray-300">
            {passphraseConfigured ? t('cfg.backup.pass.configured') : t('cfg.backup.pass.none')}
          </span>
        </div>
        <p className="text-gray-600 text-xs">
          {t('cfg.backup.pass.note')}
        </p>
        <div className="flex flex-wrap gap-2">
          <input type="password" value={newPassphrase} onChange={(e) => setNewPassphrase(e.target.value)}
            placeholder={t('cfg.backup.pass.newPlaceholder')} className="input flex-1 min-w-[200px]" />
          <input type="password" value={confirmPassphrase} onChange={(e) => setConfirmPassphrase(e.target.value)}
            placeholder={t('cfg.backup.pass.confirmPlaceholder')} className="input flex-1 min-w-[200px]" />
          <button onClick={savePassphrase} disabled={savingPassphrase} className="btn-primary text-sm disabled:opacity-50">
            {savingPassphrase ? t('common.saving') : t('cfg.backup.pass.save')}
          </button>
        </div>
      </div>

      {restoreResult && (
        <div className="rounded-lg border border-green-500/40 bg-green-500/10 p-4 space-y-3">
          <div className="text-green-300 text-sm">
            <p className="font-medium">{t('cfg.backup.restore.summary', { settings: restoreResult.settings, reservations: restoreResult.reservations, blocklist: restoreResult.blocklist })}</p>
            <p className="text-green-400/70 text-xs mt-1">{t('cfg.backup.restore.reapply')}</p>
          </div>
          {restoreResult.secrets_to_reconfigure && restoreResult.secrets_to_reconfigure.length > 0 && (
            <div className="mt-3 p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
              <p className="font-medium mb-1">{t('cfg.backup.restore.secretsTitle')}</p>
              <ul className="list-disc list-inside space-y-0.5">
                {restoreResult.secrets_to_reconfigure.map(name => (
                  <li key={name}>
                    {name === 'github_update_token' ? t('cfg.backup.restore.secret.github') :
                     name === 'notifications' ? t('cfg.backup.restore.secret.notifications') :
                     name}
                  </li>
                ))}
              </ul>
              <p className="text-yellow-400/70 text-xs mt-1">
                {t('cfg.backup.restore.secretsNote')}
              </p>
            </div>
          )}
          <button onClick={() => setRestoreResult(null)} className="btn-secondary text-sm">{t('common.close')}</button>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button onClick={download} disabled={busy || !passphraseConfigured} title={!passphraseConfigured ? t('cfg.backup.needPassFirst') : undefined}
          className="btn-primary flex items-center gap-2 disabled:opacity-50">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} {t('cfg.backup.download')}
        </button>
        <button onClick={sendNow} disabled={sendingNow || !passphraseConfigured} title={!passphraseConfigured ? t('cfg.backup.needPassFirst') : undefined}
          className="btn-secondary flex items-center gap-2 disabled:opacity-50">
          {sendingNow ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} {t('cfg.backup.sendNow')}
        </button>
        <button onClick={() => fileRef.current?.click()} disabled={busy} className="btn-secondary flex items-center gap-2">
          <Upload className="w-4 h-4" /> {t('cfg.backup.restoreFromFile')}
        </button>
        <input ref={fileRef} type="file" accept=".lgbak" onChange={onFile} className="hidden" />
      </div>

      <p className="text-gray-600 text-xs">
        {t('cfg.backup.scope')}<b>{t('cfg.backup.scope.strong')}</b>{t('cfg.backup.scope.tail')}
      </p>

      {pendingFile && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <div className="flex items-center gap-2 text-amber-300 text-sm font-medium mb-2">
            <AlertTriangle className="w-4 h-4" /> {t('cfg.backup.restore.confirmTitle')}
          </div>
          <p className="text-amber-200/80 text-xs mb-3">{t('cfg.backup.restore.confirmBody')}</p>
          <input type="password" value={restorePassphrase} onChange={(e) => setRestorePassphrase(e.target.value)}
            placeholder={t('cfg.backup.restore.passPlaceholder')} className="input w-full mb-3" />
          <div className="flex gap-2">
            <button onClick={confirmRestore} disabled={busy || !restorePassphrase} className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} {t('cfg.backup.restore.now')}
            </button>
            <button onClick={() => { setPendingFile(null); setRestorePassphrase(''); }} className="btn-secondary text-sm">{t('common.cancel')}</button>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <p className="text-gray-400 text-xs font-semibold uppercase tracking-wide">{t('cfg.backup.auto.title')}</p>
        <div className="flex flex-wrap items-center gap-2">
          {SCHEDULE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              disabled={savingSchedule || (opt.value !== 'off' && !passphraseConfigured)}
              title={opt.value !== 'off' && !passphraseConfigured ? t('cfg.backup.needPassFirst') : undefined}
              onClick={() => updateSchedule(opt.value)}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                schedule === opt.value
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-gray-900 text-gray-300 border border-gray-700 hover:border-gray-500'
              } disabled:opacity-50`}
            >
              {t(opt.labelKey)}
            </button>
          ))}
        </div>
        <p className="text-gray-600 text-xs">
          {t('cfg.backup.auto.note')}
        </p>
        {lastRun && lastRun.at > 0 && (
          <p className={`text-xs ${lastRun.ok ? 'text-gray-500' : 'text-red-400'}`}>
            {t('cfg.backup.lastRun', {
              status: lastRun.ok ? t('cfg.backup.lastRun.ok') : t('cfg.backup.lastRun.failed', { error: lastRun.error ?? '' }),
              when: new Date(lastRun.at * 1000).toLocaleString(),
            })}
          </p>
        )}
      </div>
      </div>
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
