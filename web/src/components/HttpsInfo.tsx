import { Lock, ShieldAlert } from 'lucide-react';
import HelpTip from './HelpTip';

/**
 * HttpsInfo shows whether the panel is currently served over HTTPS and explains
 * how to enable it. TLS is config-driven (a restart-level change), so this is an
 * informational card rather than a live toggle — keeping the listener switch off
 * the request path where a mistake could lock the admin out.
 */
export default function HttpsInfo() {
  const secure = typeof window !== 'undefined' && window.location.protocol === 'https:';

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        {secure ? <Lock className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}
        <h3 className="text-white font-semibold">Acesso ao painel (HTTPS)</h3>
        <HelpTip title="HTTPS">
          <>HTTPS criptografa o tráfego entre o seu navegador e o painel. Importante se o painel
          for acessível pela internet ou por uma rede não confiável.</>
        </HelpTip>
      </div>

      <p className={`text-sm ${secure ? 'text-green-400' : 'text-amber-300'}`}>
        {secure
          ? 'Você está acessando via HTTPS (conexão criptografada). 🔒'
          : 'Você está acessando via HTTP — o tráfego não é criptografado.'}
      </p>

      {!secure && (
        <div className="text-sm text-gray-400 space-y-2">
          <p>Para ativar o HTTPS, no arquivo <code className="text-blue-300">/etc/linkguard-fw/config.json</code> defina:</p>
          <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto">{`"tls_enabled": true`}</pre>
          <p>e reinicie o serviço: <code className="text-blue-300">systemctl restart linkguard-fw</code>.</p>
          <p className="text-gray-500 text-xs">
            Um certificado <b>autoassinado</b> é gerado automaticamente (o navegador mostrará um aviso na 1ª vez — normal).
            Para um certificado confiável, aponte <code>tls_cert</code> e <code>tls_key</code> para os seus arquivos.
            Depois, acesse por <code className="text-blue-300">https://…</code>.
          </p>
        </div>
      )}
    </div>
  );
}
