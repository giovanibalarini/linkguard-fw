import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, Copy, Check, Loader2 } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';

type Stage = 'idle' | 'enrolling';

/**
 * TwoFactorSettings lets the logged-in user enable/disable TOTP two-factor auth
 * for their own account. Without a bundled QR library it shows the secret for
 * manual entry plus the otpauth:// URI.
 */
export default function TwoFactorSettings() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [stage, setStage] = useState<Stage>('idle');
  const [secret, setSecret] = useState('');
  const [otpauth, setOtpauth] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [copied, setCopied] = useState(false);

  const fetchStatus = async () => {
    try { const { data } = await client.get<{ enabled: boolean }>('/api/auth/2fa'); setEnabled(data.enabled); }
    catch { setEnabled(false); }
  };
  useEffect(() => { fetchStatus(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 4000); };

  const beginSetup = async () => {
    setBusy(true); setMsg('');
    try {
      const { data } = await client.post<{ secret: string; otpauth_url: string }>('/api/auth/2fa/setup');
      setSecret(data.secret); setOtpauth(data.otpauth_url); setStage('enrolling'); setCode('');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const activate = async () => {
    setBusy(true);
    try { await client.post('/api/auth/2fa/activate', { code }); setStage('idle'); setSecret(''); setCode(''); await fetchStatus(); flash('2FA ativado!'); }
    catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const disable = async () => {
    setBusy(true);
    try { await client.post('/api/auth/2fa/disable', { code }); setCode(''); await fetchStatus(); flash('2FA desativado.'); }
    catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const copySecret = () => { navigator.clipboard.writeText(secret); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        {enabled ? <ShieldCheck className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}
        <h3 className="text-white font-semibold">Verificação em duas etapas (2FA)</h3>
        <HelpTip title="2FA">
          <>Além da senha, pede um <b>código que muda a cada 30s</b> gerado por um app autenticador
          (Google Authenticator, Authy, etc.). Mesmo que descubram sua senha, não entram sem o código.</>
        </HelpTip>
      </div>

      {msg && <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {enabled === null ? (
        <p className="text-gray-500 text-sm animate-pulse">Carregando...</p>
      ) : enabled ? (
        <div className="space-y-3">
          <p className="text-green-400 text-sm flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> 2FA está ativo na sua conta.</p>
          <p className="text-gray-500 text-xs">Para desativar, confirme com um código atual do seu app.</p>
          <div className="flex gap-2 max-w-xs">
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" className="input font-mono tracking-widest text-center" />
            <button onClick={disable} disabled={busy || code.length !== 6} className="btn-danger text-sm disabled:opacity-50">Desativar</button>
          </div>
        </div>
      ) : stage === 'idle' ? (
        <div>
          <p className="text-gray-400 text-sm mb-3">Sua conta está protegida apenas por senha. Ative o 2FA para uma camada extra.</p>
          <button onClick={beginSetup} disabled={busy} className="btn-primary flex items-center gap-2">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />} Ativar 2FA
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <ol className="text-sm text-gray-300 space-y-2 list-decimal list-inside">
            <li>Abra seu app autenticador e adicione uma conta manualmente.</li>
            <li>
              Use esta chave secreta:
              <div className="flex items-center gap-2 mt-1">
                <code className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-blue-300 font-mono text-xs break-all">{secret}</code>
                <button onClick={copySecret} className="text-gray-400 hover:text-blue-400" title="Copiar">
                  {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <a href={otpauth} className="text-blue-400 text-xs underline mt-1 inline-block break-all">ou abra pelo link otpauth://</a>
            </li>
            <li>Digite o código de 6 dígitos que o app mostrar:</li>
          </ol>
          <div className="flex gap-2 max-w-xs">
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="000000" autoFocus className="input font-mono tracking-widest text-center" />
            <button onClick={activate} disabled={busy || code.length !== 6} className="btn-primary text-sm disabled:opacity-50">Ativar</button>
          </div>
          <button onClick={() => { setStage('idle'); setSecret(''); }} className="text-gray-500 text-xs hover:text-gray-300">Cancelar</button>
        </div>
      )}
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
