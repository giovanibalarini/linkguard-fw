import { useEffect, useState } from 'react';
import { Bell, Webhook, Send, Mail, Loader2, Check, AlertTriangle, MessageCircle } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';

interface WebhookCfg { enabled: boolean; url: string }
interface TelegramCfg { enabled: boolean; token: string; chat_id: string }
interface WhatsAppCfg { enabled: boolean; token: string; phone: string }
interface EmailCfg { enabled: boolean; host: string; port: number; username: string; password: string; from: string; to: string }
interface NotifyConfig {
  min_severity: 'info' | 'warning' | 'critical';
  webhook: WebhookCfg;
  telegram: TelegramCfg;
  whatsapp: WhatsAppCfg;
  email: EmailCfg;
}

const empty: NotifyConfig = {
  min_severity: 'warning',
  webhook: { enabled: false, url: '' },
  telegram: { enabled: false, token: '', chat_id: '' },
  whatsapp: { enabled: false, token: '', phone: '' },
  email: { enabled: false, host: '', port: 587, username: '', password: '', from: '', to: '' },
};

/**
 * NotificationSettings configures where alerts are delivered (webhook, Telegram,
 * e-mail). Stored secrets come back masked; submitting the mask unchanged keeps
 * the existing secret server-side.
 */
export default function NotificationSettings() {
  const { t } = useI18n();
  const [cfg, setCfg] = useState<NotifyConfig>(empty);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [testing, setTesting] = useState('');

  const errorPrefix = t('cfg.msg.errorPrefix');

  const fetchCfg = async () => {
    try {
      const { data } = await client.get<NotifyConfig>('/api/notifications');
      setCfg({ ...empty, ...data, webhook: { ...empty.webhook, ...data.webhook }, telegram: { ...empty.telegram, ...data.telegram }, whatsapp: { ...empty.whatsapp, ...data.whatsapp }, email: { ...empty.email, ...data.email } });
    } catch { /* ignore */ }
  };
  useEffect(() => { fetchCfg(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 4000); };

  const save = async () => {
    setBusy(true);
    try { const { data } = await client.put<NotifyConfig>('/api/notifications', cfg); setCfg((c) => ({ ...c, ...data })); flash(t('cfg.notify.saved')); }
    catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setBusy(false); }
  };

  const test = async (channel: string) => {
    setTesting(channel);
    try { await client.post(`/api/notifications/test?channel=${channel}`, cfg); flash(t('cfg.notify.tested', { channel })); }
    catch (e) { flash(errorPrefix + errMsg(e, t('cfg.msg.opFailed'))); }
    finally { setTesting(''); }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Bell className="w-5 h-5 text-blue-400" /><span className="text-white font-semibold">{t('cfg.notify.title')}</span><HelpTip title={t('cfg.notify.help.title')}>
          <>{t('cfg.notify.help.body')}</>
        </HelpTip></span>}>
      <div className="space-y-5">
      {msg && (
        <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith(errorPrefix) ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>
      )}

      <label className="block">
        <span className="text-gray-400 text-xs">{t('cfg.notify.minSeverity')}</span>
        <select value={cfg.min_severity} onChange={(e) => setCfg({ ...cfg, min_severity: e.target.value as NotifyConfig['min_severity'] })} className="input mt-1 max-w-xs">
          <option value="info">{t('cfg.notify.sev.info')}</option>
          <option value="warning">{t('cfg.notify.sev.warning')}</option>
          <option value="critical">{t('cfg.notify.sev.critical')}</option>
        </select>
      </label>

      {/* Webhook */}
      <Channel icon={Webhook} title="Webhook" enabled={cfg.webhook.enabled}
        onToggle={(v) => setCfg({ ...cfg, webhook: { ...cfg.webhook, enabled: v } })}
        onTest={() => test('webhook')} testing={testing === 'webhook'} canTest={!!cfg.webhook.url}>
        <input value={cfg.webhook.url} onChange={(e) => setCfg({ ...cfg, webhook: { ...cfg.webhook, url: e.target.value } })}
          placeholder={t('cfg.notify.webhook.placeholder')} className="input w-full" />
      </Channel>

      {/* Telegram */}
      <Channel icon={Send} title="Telegram" enabled={cfg.telegram.enabled}
        onToggle={(v) => setCfg({ ...cfg, telegram: { ...cfg.telegram, enabled: v } })}
        onTest={() => test('telegram')} testing={testing === 'telegram'} canTest={!!cfg.telegram.token && !!cfg.telegram.chat_id}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.telegram.token} onChange={(e) => setCfg({ ...cfg, telegram: { ...cfg.telegram, token: e.target.value } })}
            placeholder={t('cfg.notify.telegram.token')} className="input w-full" />
          <input value={cfg.telegram.chat_id} onChange={(e) => setCfg({ ...cfg, telegram: { ...cfg.telegram, chat_id: e.target.value } })}
            placeholder={t('cfg.notify.telegram.chatId')} className="input w-full" />
        </div>
      </Channel>

      {/* WhatsApp (zapvite) */}
      <Channel icon={MessageCircle} title="WhatsApp" enabled={cfg.whatsapp.enabled}
        onToggle={(v) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, enabled: v } })}
        onTest={() => test('whatsapp')} testing={testing === 'whatsapp'} canTest={!!cfg.whatsapp.token && !!cfg.whatsapp.phone}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.whatsapp.phone} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, phone: e.target.value } })}
            placeholder={t('cfg.notify.whatsapp.phone')} className="input w-full" />
          <input value={cfg.whatsapp.token} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, token: e.target.value } })}
            placeholder={t('cfg.notify.whatsapp.token')} className="input w-full" />
        </div>
        <p className="text-gray-600 text-xs mt-1">{t('cfg.notify.whatsapp.note')}</p>
      </Channel>

      {/* Email */}
      <Channel icon={Mail} title={t('cfg.notify.email.title')} enabled={cfg.email.enabled}
        onToggle={(v) => setCfg({ ...cfg, email: { ...cfg.email, enabled: v } })}
        onTest={() => test('email')} testing={testing === 'email'} canTest={!!cfg.email.host && !!cfg.email.to}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.email.host} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, host: e.target.value } })} placeholder={t('cfg.notify.email.host')} className="input w-full" />
          <input type="number" value={cfg.email.port || ''} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, port: Number(e.target.value) } })} placeholder={t('cfg.notify.email.port')} className="input w-full" />
          <input value={cfg.email.username} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, username: e.target.value } })} placeholder={t('cfg.notify.email.username')} className="input w-full" />
          <input type="password" value={cfg.email.password} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, password: e.target.value } })} placeholder={t('cfg.notify.email.password')} className="input w-full" />
          <input value={cfg.email.from} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, from: e.target.value } })} placeholder={t('cfg.notify.email.from')} className="input w-full" />
          <input value={cfg.email.to} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, to: e.target.value } })} placeholder={t('cfg.notify.email.to')} className="input w-full" />
        </div>
        <p className="text-gray-600 text-xs mt-1 flex items-start gap-1"><AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {t('cfg.notify.email.hint')}</p>
      </Channel>

      <button onClick={save} disabled={busy} className="btn-primary flex items-center gap-2">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} {t('common.save')}
      </button>
      </div>
    </Panel>
  );
}

function Channel({
  icon: Icon, title, enabled, onToggle, onTest, testing, canTest, children,
}: {
  icon: typeof Webhook; title: string; enabled: boolean;
  onToggle: (v: boolean) => void; onTest: () => void; testing: boolean; canTest: boolean;
  children: React.ReactNode;
}) {
  const { t } = useI18n();
  return (
    <div className={`rounded-lg border p-3 ${enabled ? 'border-blue-500/30 bg-blue-500/5' : 'border-gray-800'}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4 text-blue-400" />
        <span className="text-white text-sm font-medium">{title}</span>
        <label className="ml-auto inline-flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={enabled} onChange={(e) => onToggle(e.target.checked)} className="accent-blue-500" />
          {t('cfg.notify.channel.enabled')}
        </label>
        <button onClick={onTest} disabled={!canTest || testing} className="btn-secondary text-xs flex items-center gap-1 disabled:opacity-40">
          {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : null} {t('cfg.notify.channel.test')}
        </button>
      </div>
      {children}
    </div>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
