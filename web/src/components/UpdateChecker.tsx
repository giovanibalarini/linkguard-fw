import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Download, CheckCircle2, ExternalLink, Loader2, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';

interface CheckResult {
  current: string;
  latest: string;
  update_available: boolean;
  notes_url: string;
  deb_url: string;
  package_missing: boolean;
}

/**
 * UpdateChecker compares the running version against the latest GitHub release
 * and can install it in place. After "apply" the service restarts, so we poll
 * health and reload once it is back.
 */
export default function UpdateChecker() {
  const { t } = useI18n();
  const [res, setRes] = useState<CheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [msg, setMsg] = useState('');
  const [tokenConfigured, setTokenConfigured] = useState<boolean | null>(null);
  const [tokenInput, setTokenInput] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [savingToken, setSavingToken] = useState(false);

  const check = useCallback(async () => {
    setChecking(true); setMsg('');
    try { const { data } = await client.get<CheckResult>('/api/system/update/check'); setRes(data); }
    catch (e) { setMsg(t('shell.update.error', { msg: errMsg(e, t('shell.update.opFailed')) })); }
    finally { setChecking(false); }
  }, [t]);

  const loadTokenStatus = useCallback(async () => {
    try { const { data } = await client.get<{ configured: boolean }>('/api/system/update/token'); setTokenConfigured(data.configured); }
    catch { /* ignore */ }
  }, []);

  const saveToken = async () => {
    setSavingToken(true); setMsg('');
    try {
      const { data } = await client.put<{ configured: boolean }>('/api/system/update/token', { token: tokenInput.trim() });
      setTokenConfigured(data.configured);
      setTokenInput(''); setShowToken(false);
      setMsg(t('shell.update.token.saved'));
      check();
    } catch (e) { setMsg(t('shell.update.error', { msg: errMsg(e, t('shell.update.opFailed')) })); }
    finally { setSavingToken(false); }
  };

  useEffect(() => { check(); loadTokenStatus(); }, [check, loadTokenStatus]);

  const waitForRestart = async () => {
    // Poll until the service answers again, then reload onto the new version.
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 3000));
      try {
        await client.get('/api/health');
        window.location.reload();
        return;
      } catch { /* still restarting */ }
    }
    setMsg(t('shell.update.restartSlow'));
  };

  const apply = async () => {
    if (!confirm(t('shell.update.confirmApply', { version: String(res?.latest) }))) return;
    setApplying(true); setMsg('');
    try {
      const { data } = await client.post<{ message: string }>('/api/system/update/apply');
      setMsg(data.message);
      waitForRestart();
    } catch (e) { setMsg(t('shell.update.error', { msg: errMsg(e, t('shell.update.opFailed')) })); setApplying(false); }
  };

  const errPrefix = t('shell.update.errorPrefix');

  return (
    <Panel
      title={t('shell.update.title')}
      action={
        <button onClick={check} disabled={checking || applying} className="btn-secondary text-sm flex items-center gap-1.5">
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} /> {t('shell.update.check')}
        </button>
      }
    >
      <div className="space-y-4">
      {msg && (
        <div className={`px-3 py-2 rounded-lg text-sm flex items-start gap-2 ${msg.startsWith(errPrefix) ? 'bg-red-500/10 text-red-400' : 'bg-blue-500/10 text-blue-300'}`}>
          {applying && !msg.startsWith(errPrefix) ? <Loader2 className="w-4 h-4 mt-0.5 animate-spin shrink-0" /> : <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />}
          <span>{msg}</span>
        </div>
      )}

      <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="text-sm text-gray-300">
            {t('shell.update.token.label')}{' '}
            {tokenConfigured == null ? <span className="text-gray-500">—</span>
              : tokenConfigured ? <span className="text-green-400">{t('shell.update.token.configured')}</span>
              : <span className="text-amber-400">{t('shell.update.token.missing')}</span>}
          </div>
          <button onClick={() => setShowToken((v) => !v)} className="btn-secondary text-xs">
            {showToken ? t('shell.update.token.close') : (tokenConfigured ? t('shell.update.token.change') : t('shell.update.token.set'))}
          </button>
        </div>
        {!tokenConfigured && (
          <p className="text-gray-500 text-xs">{t('shell.update.token.why')}</p>
        )}
        {showToken && (
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="password" value={tokenInput} onChange={(e) => setTokenInput(e.target.value)}
              placeholder={t('shell.update.token.placeholder')}
              className="flex-1 min-w-[200px] rounded-md bg-gray-800 border border-gray-700 px-2 py-1 text-sm text-white"
            />
            <button onClick={saveToken} disabled={savingToken} className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50">
              {savingToken ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} {t('shell.update.token.save')}
            </button>
          </div>
        )}
      </div>

      {res && (
        <div className="space-y-3">
          <div className="flex items-center gap-6 text-sm">
            <div><span className="text-gray-500">{t('shell.update.current')}</span><span className="text-white font-mono">v{res.current}</span></div>
            <div><span className="text-gray-500">{t('shell.update.latest')}</span><span className="text-white font-mono">v{res.latest}</span></div>
          </div>

          {res.update_available ? (
            <div className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-3">
              <p className="text-blue-300 text-sm mb-2">{t('shell.update.available')}<b>v{res.latest}</b></p>
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={apply} disabled={applying} className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
                  {applying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} {t('shell.update.apply')}
                </button>
                {res.notes_url && (
                  <a href={res.notes_url} target="_blank" rel="noreferrer" className="text-blue-400 text-sm inline-flex items-center gap-1 hover:underline">
                    {t('shell.update.notes')} <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          ) : res.package_missing ? (
            /* TRÊS ESTADOS, E NÃO DOIS. "Não há versão nova" e "há versão nova
               sem pacote para esta arquitetura" davam os dois o mesmo `false`,
               e a tela respondia "está atualizado" em verde LOGO ABAIXO de
               mostrar duas versões diferentes. A janela em que isso acontece é
               curta e é justamente a que o admin pega: entre o release ser
               criado e os pacotes terminarem de subir. */
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <p className="text-amber-300 text-sm flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                {t('shell.update.packageMissing')}
              </p>
              {res.notes_url && (
                <a href={res.notes_url} target="_blank" rel="noreferrer" className="text-blue-400 text-sm inline-flex items-center gap-1 hover:underline mt-2">
                  {t('shell.update.notes')} <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}
            </div>
          ) : (
            <p className="text-green-400 text-sm flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> {t('shell.update.upToDate')}</p>
          )}
        </div>
      )}
      </div>
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
