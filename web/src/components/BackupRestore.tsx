import { useEffect, useRef, useState } from 'react';
import { Download, Upload, Loader2, AlertTriangle, Check, Send, Lock } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import {
  RestoreResult, BackupSchedule, BackupPassphraseStatusResponse, BackupScheduleResponse, BackupLastRunResponse,
} from '../types';

const SCHEDULE_OPTIONS: { value: BackupSchedule; label: string }[] = [
  { value: 'off', label: 'Desligado' },
  { value: 'daily', label: 'Diário' },
  { value: 'weekly', label: 'Semanal' },
  { value: 'monthly', label: 'Mensal' },
];

/**
 * BackupRestore downloads/e-mails the full panel configuration, encrypted
 * with an admin-configured passphrase, and restores from an encrypted file.
 * Restore applies settings + DHCP reservations + DNS blocklist only (never
 * users/roles or live WAN links), so it can't lock the admin out.
 */
export default function BackupRestore() {
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
    if (newPassphrase.length < 12) { flash('Erro: a senha precisa ter pelo menos 12 caracteres.'); return; }
    if (newPassphrase !== confirmPassphrase) { flash('Erro: as senhas não coincidem.'); return; }
    setSavingPassphrase(true);
    try {
      await client.put('/api/backup/passphrase', { passphrase: newPassphrase });
      setNewPassphrase(''); setConfirmPassphrase('');
      setPassphraseConfigured(true);
      flash('Senha de backup configurada.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
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
      flash('Backup baixado.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
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
    if (!restorePassphrase) { flash('Erro: informe a senha do backup.'); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', pendingFile);
      form.append('passphrase', restorePassphrase);
      const { data } = await client.post<RestoreResult>('/api/backup/restore', form);
      setPendingFile(null);
      setRestorePassphrase('');
      setRestoreResult(data);
      flash('Restaurado com sucesso.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const updateSchedule = async (next: BackupSchedule) => {
    if (next === schedule) return;
    setSavingSchedule(true);
    try {
      await client.put('/api/backup/schedule', { schedule: next });
      setSchedule(next);
      flash('Agendamento atualizado.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setSavingSchedule(false); }
  };

  const sendNow = async () => {
    setSendingNow(true);
    try {
      await client.post('/api/backup/send-now');
      flash('Backup enviado por e-mail.');
      await loadStatus();
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setSendingNow(false); }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Download className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">Backup e restauração</span><HelpTip title="Backup">
          <>Salva num arquivo todas as suas configurações (links, firewall, DHCP/DNS, balanceamento,
          notificações...). Útil antes de mexer em algo ou para migrar de máquina. O arquivo é sempre
          cifrado com a senha configurada abaixo.</>
        </HelpTip></span>}>
      <div className="space-y-4">
      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <div className="flex items-center gap-2 text-sm">
          <Lock className="w-4 h-4 text-gray-500" />
          <span className="text-gray-300">
            {passphraseConfigured ? 'Senha de backup configurada' : 'Nenhuma senha de backup configurada'}
          </span>
        </div>
        <p className="text-gray-600 text-xs">
          Protege o arquivo de backup (topologia de rede e inventário de hosts). Trocar a senha não
          recifra backups já gerados — eles continuam abrindo só com a senha usada na hora.
        </p>
        <div className="flex flex-wrap gap-2">
          <input type="password" value={newPassphrase} onChange={(e) => setNewPassphrase(e.target.value)}
            placeholder="Nova senha (mínimo 12 caracteres)" className="input flex-1 min-w-[200px]" />
          <input type="password" value={confirmPassphrase} onChange={(e) => setConfirmPassphrase(e.target.value)}
            placeholder="Confirmar senha" className="input flex-1 min-w-[200px]" />
          <button onClick={savePassphrase} disabled={savingPassphrase} className="btn-primary text-sm disabled:opacity-50">
            {savingPassphrase ? 'Salvando...' : 'Salvar senha'}
          </button>
        </div>
      </div>

      {restoreResult && (
        <div className="rounded-lg border border-green-500/40 bg-green-500/10 p-4 space-y-3">
          <div className="text-green-300 text-sm">
            <p className="font-medium">Restaurado: {restoreResult.settings} configs, {restoreResult.reservations} reservas, {restoreResult.blocklist} domínios.</p>
            <p className="text-green-400/70 text-xs mt-1">Reaplique DHCP/DNS e Firewall onde necessário.</p>
          </div>
          {restoreResult.secrets_to_reconfigure && restoreResult.secrets_to_reconfigure.length > 0 && (
            <div className="mt-3 p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
              <p className="font-medium mb-1">Reconfigure estas credenciais:</p>
              <ul className="list-disc list-inside space-y-0.5">
                {restoreResult.secrets_to_reconfigure.map(name => (
                  <li key={name}>
                    {name === 'github_update_token' ? 'Token do GitHub (Configurações → Atualizações)' :
                     name === 'notifications' ? 'Notificações (Configurações → Notificações)' :
                     name}
                  </li>
                ))}
              </ul>
              <p className="text-yellow-400/70 text-xs mt-1">
                Segredos nunca fazem parte do arquivo de backup — precisam ser reinformados manualmente.
              </p>
            </div>
          )}
          <button onClick={() => setRestoreResult(null)} className="btn-secondary text-sm">Fechar</button>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button onClick={download} disabled={busy || !passphraseConfigured} title={!passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
          className="btn-primary flex items-center gap-2 disabled:opacity-50">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} Baixar backup
        </button>
        <button onClick={sendNow} disabled={sendingNow || !passphraseConfigured} title={!passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
          className="btn-secondary flex items-center gap-2 disabled:opacity-50">
          {sendingNow ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />} Enviar por e-mail agora
        </button>
        <button onClick={() => fileRef.current?.click()} disabled={busy} className="btn-secondary flex items-center gap-2">
          <Upload className="w-4 h-4" /> Restaurar de arquivo
        </button>
        <input ref={fileRef} type="file" accept=".lgbak" onChange={onFile} className="hidden" />
      </div>

      <p className="text-gray-600 text-xs">
        A restauração aplica configurações, reservas de DHCP e blocklist de DNS. <b>Não</b> altera usuários/papéis nem os links WAN ativos — então não há risco de te trancar para fora. Depois de restaurar, reaplique DHCP/DNS e Firewall.
      </p>

      {pendingFile && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <div className="flex items-center gap-2 text-amber-300 text-sm font-medium mb-2">
            <AlertTriangle className="w-4 h-4" /> Confirmar restauração?
          </div>
          <p className="text-amber-200/80 text-xs mb-3">Isto sobrescreve as configurações atuais pelas do arquivo. Recomendamos baixar um backup antes.</p>
          <input type="password" value={restorePassphrase} onChange={(e) => setRestorePassphrase(e.target.value)}
            placeholder="Senha do backup" className="input w-full mb-3" />
          <div className="flex gap-2">
            <button onClick={confirmRestore} disabled={busy || !restorePassphrase} className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Restaurar agora
            </button>
            <button onClick={() => { setPendingFile(null); setRestorePassphrase(''); }} className="btn-secondary text-sm">Cancelar</button>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
        <p className="text-gray-400 text-xs font-semibold uppercase tracking-wide">Backup automático por e-mail</p>
        <div className="flex flex-wrap items-center gap-2">
          {SCHEDULE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              disabled={savingSchedule || (opt.value !== 'off' && !passphraseConfigured)}
              title={opt.value !== 'off' && !passphraseConfigured ? 'Configure uma senha de backup primeiro' : undefined}
              onClick={() => updateSchedule(opt.value)}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                schedule === opt.value
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-gray-900 text-gray-300 border border-gray-700 hover:border-gray-500'
              } disabled:opacity-50`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <p className="text-gray-600 text-xs">
          Envia o backup cifrado por e-mail no intervalo escolhido, usando o e-mail já configurado em
          Notificações.
        </p>
        {lastRun && lastRun.at > 0 && (
          <p className={`text-xs ${lastRun.ok ? 'text-gray-500' : 'text-red-400'}`}>
            Último envio automático: {lastRun.ok ? 'ok' : `falhou — ${lastRun.error}`}, {new Date(lastRun.at * 1000).toLocaleString()}
          </p>
        )}
      </div>
      </div>
    </Panel>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
