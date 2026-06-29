import { useRef, useState } from 'react';
import { Download, Upload, Loader2, AlertTriangle, Check } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';

/**
 * BackupRestore downloads the full panel configuration as a JSON file and
 * restores it. Restore applies settings + DHCP reservations + DNS blocklist
 * only (never users/roles or live WAN links), so it can't lock the admin out.
 */
export default function BackupRestore() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [pending, setPending] = useState<object | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 6000); };

  const download = async () => {
    setBusy(true);
    try {
      const res = await client.get('/api/backup', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      const date = new Date().toISOString().slice(0, 10);
      a.href = url; a.download = `linkguard-backup-${date}.json`; a.click();
      URL.revokeObjectURL(url);
      flash('Backup baixado.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        if (parsed?.kind !== 'linkguard-fw-backup') { flash('Erro: arquivo não é um backup do LinkGuard FW.'); return; }
        setPending(parsed);
      } catch { flash('Erro: arquivo inválido.'); }
    };
    reader.readAsText(f);
    if (fileRef.current) fileRef.current.value = '';
  };

  const confirmRestore = async () => {
    if (!pending) return;
    setBusy(true);
    try {
      const { data } = await client.post<{ settings: number; reservations: number; blocklist: number }>('/api/backup/restore', pending);
      setPending(null);
      flash(`Restaurado: ${data.settings} configs, ${data.reservations} reservas, ${data.blocklist} domínios. Reaplique DHCP/DNS e Firewall onde necessário.`);
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <Download className="w-5 h-5 text-blue-400" />
        <h3 className="text-white font-semibold">Backup e restauração</h3>
        <HelpTip title="Backup">
          <>Salva num arquivo todas as suas configurações (links, firewall, DHCP/DNS, VPN, balanceamento,
          notificações...). Útil antes de mexer em algo ou para migrar de máquina.</>
        </HelpTip>
      </div>

      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}

      <div className="flex flex-wrap gap-2">
        <button onClick={download} disabled={busy} className="btn-primary flex items-center gap-2">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} Baixar backup
        </button>
        <button onClick={() => fileRef.current?.click()} disabled={busy} className="btn-secondary flex items-center gap-2">
          <Upload className="w-4 h-4" /> Restaurar de arquivo
        </button>
        <input ref={fileRef} type="file" accept="application/json,.json" onChange={onFile} className="hidden" />
      </div>

      <p className="text-gray-600 text-xs">
        A restauração aplica configurações, reservas de DHCP e blocklist de DNS. <b>Não</b> altera usuários/papéis nem os links WAN ativos — então não há risco de te trancar para fora. Depois de restaurar, reaplique DHCP/DNS e Firewall.
      </p>

      {pending && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <div className="flex items-center gap-2 text-amber-300 text-sm font-medium mb-2">
            <AlertTriangle className="w-4 h-4" /> Confirmar restauração?
          </div>
          <p className="text-amber-200/80 text-xs mb-3">Isto sobrescreve as configurações atuais pelas do arquivo. Recomendamos baixar um backup antes.</p>
          <div className="flex gap-2">
            <button onClick={confirmRestore} disabled={busy} className="btn-primary text-sm flex items-center gap-1.5">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Restaurar agora
            </button>
            <button onClick={() => setPending(null)} className="btn-secondary text-sm">Cancelar</button>
          </div>
        </div>
      )}
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
