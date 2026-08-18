import { Lock, ShieldAlert } from 'lucide-react';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';

/**
 * HttpsInfo shows whether the panel is currently served over HTTPS and explains
 * how to enable it. TLS is config-driven (a restart-level change), so this is an
 * informational card rather than a live toggle — keeping the listener switch off
 * the request path where a mistake could lock the admin out.
 */
export default function HttpsInfo() {
  const { t } = useI18n();
  const secure = typeof window !== 'undefined' && window.location.protocol === 'https:';

  return (
    <Panel title={<span className="flex items-center gap-2">{secure ? <Lock className="w-5 h-5 text-green-400" /> : <ShieldAlert className="w-5 h-5 text-amber-400" />}<span className="text-white font-semibold">{t('cfg.https.title')}</span><HelpTip title={t('cfg.https.help.title')}>
          <>{t('cfg.https.help.body')}</>
        </HelpTip></span>}>
      <div className="space-y-3">
      <p className={`text-sm ${secure ? 'text-green-400' : 'text-amber-300'}`}>
        {secure
          ? t('cfg.https.secure')
          : t('cfg.https.insecure')}
      </p>

      {!secure && (
        <div className="text-sm text-gray-400 space-y-2">
          <p>{t('cfg.https.enable')}<code className="text-blue-300">/etc/linkguard-fw/config.json</code>{t('cfg.https.enable.tail')}</p>
          <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto">{`"tls_enabled": true`}</pre>
          <p>{t('cfg.https.restart')}<code className="text-blue-300">systemctl restart linkguard-fw</code>.</p>
          <p className="text-gray-500 text-xs">
            {t('cfg.https.cert')}<b>{t('cfg.https.cert.strong')}</b>{t('cfg.https.cert.tail')}<code>tls_cert</code>{t('cfg.https.cert.and')}<code>tls_key</code>{t('cfg.https.cert.tail2')}<code className="text-blue-300">https://…</code>.
          </p>
        </div>
      )}
      </div>
    </Panel>
  );
}
