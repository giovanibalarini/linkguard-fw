import { useEffect, useState } from 'react';
import { Bell, Webhook, Send, Mail, Loader2, Check, AlertTriangle, MessageCircle } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';

interface WebhookCfg { enabled: boolean; url: string }
interface TelegramCfg { enabled: boolean; token: string; chat_id: string }
interface WhatsAppCfg { enabled: boolean; url: string; token: string; phone: string }
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
  whatsapp: { enabled: false, url: '', token: '', phone: '' },
  email: { enabled: false, host: '', port: 587, username: '', password: '', from: '', to: '' },
};

/**
 * NotificationSettings configures where alerts are delivered (webhook, Telegram,
 * e-mail). Stored secrets come back masked; submitting the mask unchanged keeps
 * the existing secret server-side.
 */
export default function NotificationSettings() {
  const [cfg, setCfg] = useState<NotifyConfig>(empty);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [testing, setTesting] = useState('');

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
    try { const { data } = await client.put<NotifyConfig>('/api/notifications', cfg); setCfg((c) => ({ ...c, ...data })); flash('Configuração salva.'); }
    catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const test = async (channel: string) => {
    setTesting(channel);
    try { await client.post(`/api/notifications/test?channel=${channel}`, cfg); flash(`Teste enviado por ${channel}.`); }
    catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setTesting(''); }
  };

  return (
    <div className="card space-y-5">
      <div className="flex items-center gap-2">
        <Bell className="w-5 h-5 text-blue-400" />
        <h3 className="text-white font-semibold">Notificações</h3>
        <HelpTip title="Notificações">
          <>Avise você fora do painel quando algo importante acontecer (um link cair, falha de regra...).
          Escolha um ou mais canais e o nível mínimo de severidade.</>
        </HelpTip>
      </div>

      {msg && (
        <div className={`px-3 py-2 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'}`}>{msg}</div>
      )}

      <label className="block">
        <span className="text-gray-400 text-xs">Avisar a partir de</span>
        <select value={cfg.min_severity} onChange={(e) => setCfg({ ...cfg, min_severity: e.target.value as NotifyConfig['min_severity'] })} className="input mt-1 max-w-xs">
          <option value="info">Tudo (info)</option>
          <option value="warning">Avisos e críticos (recomendado)</option>
          <option value="critical">Só críticos</option>
        </select>
      </label>

      {/* Webhook */}
      <Channel icon={Webhook} title="Webhook" enabled={cfg.webhook.enabled}
        onToggle={(v) => setCfg({ ...cfg, webhook: { ...cfg.webhook, enabled: v } })}
        onTest={() => test('webhook')} testing={testing === 'webhook'} canTest={!!cfg.webhook.url}>
        <input value={cfg.webhook.url} onChange={(e) => setCfg({ ...cfg, webhook: { ...cfg.webhook, url: e.target.value } })}
          placeholder="https://… (recebe um POST JSON)" className="input w-full" />
      </Channel>

      {/* Telegram */}
      <Channel icon={Send} title="Telegram" enabled={cfg.telegram.enabled}
        onToggle={(v) => setCfg({ ...cfg, telegram: { ...cfg.telegram, enabled: v } })}
        onTest={() => test('telegram')} testing={testing === 'telegram'} canTest={!!cfg.telegram.token && !!cfg.telegram.chat_id}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.telegram.token} onChange={(e) => setCfg({ ...cfg, telegram: { ...cfg.telegram, token: e.target.value } })}
            placeholder="Token do bot (BotFather)" className="input w-full" />
          <input value={cfg.telegram.chat_id} onChange={(e) => setCfg({ ...cfg, telegram: { ...cfg.telegram, chat_id: e.target.value } })}
            placeholder="Chat ID" className="input w-full" />
        </div>
      </Channel>

      {/* WhatsApp (zapvite) */}
      <Channel icon={MessageCircle} title="WhatsApp" enabled={cfg.whatsapp.enabled}
        onToggle={(v) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, enabled: v } })}
        onTest={() => test('whatsapp')} testing={testing === 'whatsapp'} canTest={!!cfg.whatsapp.token && !!cfg.whatsapp.phone}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.whatsapp.phone} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, phone: e.target.value } })}
            placeholder="Telefone com DDI (ex.: 5527999999999)" className="input w-full" />
          <input value={cfg.whatsapp.token} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, token: e.target.value } })}
            placeholder="Token (Bearer) — expira, atualize aqui" className="input w-full" />
          <input value={cfg.whatsapp.url} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, url: e.target.value } })}
            placeholder="URL da API" className="input w-full sm:col-span-2" />
        </div>
        <p className="text-gray-600 text-xs mt-1">Provedor zapvite. O token expira — quando parar de enviar, gere um novo e cole aqui.</p>
      </Channel>

      {/* Email */}
      <Channel icon={Mail} title="E-mail (SMTP)" enabled={cfg.email.enabled}
        onToggle={(v) => setCfg({ ...cfg, email: { ...cfg.email, enabled: v } })}
        onTest={() => test('email')} testing={testing === 'email'} canTest={!!cfg.email.host && !!cfg.email.to}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.email.host} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, host: e.target.value } })} placeholder="Servidor SMTP (ex.: smtp.gmail.com)" className="input w-full" />
          <input type="number" value={cfg.email.port || ''} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, port: Number(e.target.value) } })} placeholder="Porta (587)" className="input w-full" />
          <input value={cfg.email.username} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, username: e.target.value } })} placeholder="Usuário" className="input w-full" />
          <input type="password" value={cfg.email.password} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, password: e.target.value } })} placeholder="Senha" className="input w-full" />
          <input value={cfg.email.from} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, from: e.target.value } })} placeholder="De (remetente)" className="input w-full" />
          <input value={cfg.email.to} onChange={(e) => setCfg({ ...cfg, email: { ...cfg.email, to: e.target.value } })} placeholder="Para (destinatário)" className="input w-full" />
        </div>
        <p className="text-gray-600 text-xs mt-1 flex items-start gap-1"><AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> Use porta 587 (STARTTLS). Para Gmail, gere uma "senha de app".</p>
      </Channel>

      <button onClick={save} disabled={busy} className="btn-primary flex items-center gap-2">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Salvar
      </button>
    </div>
  );
}

function Channel({
  icon: Icon, title, enabled, onToggle, onTest, testing, canTest, children,
}: {
  icon: typeof Webhook; title: string; enabled: boolean;
  onToggle: (v: boolean) => void; onTest: () => void; testing: boolean; canTest: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className={`rounded-lg border p-3 ${enabled ? 'border-blue-500/30 bg-blue-500/5' : 'border-gray-800'}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4 text-blue-400" />
        <span className="text-white text-sm font-medium">{title}</span>
        <label className="ml-auto inline-flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={enabled} onChange={(e) => onToggle(e.target.checked)} className="accent-blue-500" />
          Ativo
        </label>
        <button onClick={onTest} disabled={!canTest || testing} className="btn-secondary text-xs flex items-center gap-1 disabled:opacity-40">
          {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : null} Testar
        </button>
      </div>
      {children}
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
