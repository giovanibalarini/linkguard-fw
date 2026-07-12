import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Download, CheckCircle2, ExternalLink, Loader2, AlertTriangle } from 'lucide-react';
import client from '../api/client';

interface CheckResult {
  current: string;
  latest: string;
  update_available: boolean;
  notes_url: string;
  deb_url: string;
}

/**
 * UpdateChecker compares the running version against the latest GitHub release
 * and can install it in place. After "apply" the service restarts, so we poll
 * health and reload once it is back.
 */
export default function UpdateChecker() {
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
    catch (e) { setMsg('Erro: ' + errMsg(e)); }
    finally { setChecking(false); }
  }, []);

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
      setMsg('Token salvo.');
      check();
    } catch (e) { setMsg('Erro: ' + errMsg(e)); }
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
    setMsg('A atualização foi disparada, mas o serviço demorou a responder. Recarregue a página manualmente.');
  };

  const apply = async () => {
    if (!confirm(`Atualizar para ${res?.latest}? O serviço vai reiniciar (alguns segundos de indisponibilidade).`)) return;
    setApplying(true); setMsg('');
    try {
      const { data } = await client.post<{ message: string }>('/api/system/update/apply');
      setMsg(data.message);
      waitForRestart();
    } catch (e) { setMsg('Erro: ' + errMsg(e)); setApplying(false); }
  };

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-white font-semibold">Atualizações</h3>
        <button onClick={check} disabled={checking || applying} className="btn-secondary text-sm flex items-center gap-1.5">
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} /> Verificar
        </button>
      </div>

      {msg && (
        <div className={`px-3 py-2 rounded-lg text-sm flex items-start gap-2 ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-blue-500/10 text-blue-300'}`}>
          {applying && !msg.startsWith('Erro') ? <Loader2 className="w-4 h-4 mt-0.5 animate-spin shrink-0" /> : <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />}
          <span>{msg}</span>
        </div>
      )}

      <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="text-sm text-gray-300">
            Token do GitHub (repo privado):{' '}
            {tokenConfigured == null ? <span className="text-gray-500">—</span>
              : tokenConfigured ? <span className="text-green-400">configurado</span>
              : <span className="text-amber-400">não configurado</span>}
          </div>
          <button onClick={() => setShowToken((v) => !v)} className="btn-secondary text-xs">
            {showToken ? 'Fechar' : (tokenConfigured ? 'Alterar' : 'Configurar')}
          </button>
        </div>
        {!tokenConfigured && (
          <p className="text-gray-500 text-xs">O repositório é privado; sem um token de acesso (PAT read-only), a verificação retorna 404.</p>
        )}
        {showToken && (
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="password" value={tokenInput} onChange={(e) => setTokenInput(e.target.value)}
              placeholder="ghp_… (vazio remove)"
              className="flex-1 min-w-[200px] rounded-md bg-gray-800 border border-gray-700 px-2 py-1 text-sm text-white"
            />
            <button onClick={saveToken} disabled={savingToken} className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50">
              {savingToken ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} Salvar token
            </button>
          </div>
        )}
      </div>

      {res && (
        <div className="space-y-3">
          <div className="flex items-center gap-6 text-sm">
            <div><span className="text-gray-500">Versão atual: </span><span className="text-white font-mono">v{res.current}</span></div>
            <div><span className="text-gray-500">Última: </span><span className="text-white font-mono">v{res.latest}</span></div>
          </div>

          {res.update_available ? (
            <div className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-3">
              <p className="text-blue-300 text-sm mb-2">Nova versão disponível: <b>v{res.latest}</b></p>
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={apply} disabled={applying} className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
                  {applying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} Atualizar agora
                </button>
                {res.notes_url && (
                  <a href={res.notes_url} target="_blank" rel="noreferrer" className="text-blue-400 text-sm inline-flex items-center gap-1 hover:underline">
                    Ver novidades <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          ) : (
            <p className="text-green-400 text-sm flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> Você está na versão mais recente.</p>
          )}
        </div>
      )}
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
