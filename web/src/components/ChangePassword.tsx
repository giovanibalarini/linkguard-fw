import { useState } from 'react';
import { KeyRound, Loader2 } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import { useI18n } from '../i18n';

const MIN_LENGTH = 8;

/**
 * ChangePassword lets the logged-in user change their OWN password.
 *
 * Até a v1.0.82 isto não existia: a única forma de trocar senha era a tela de
 * usuários, que exige a permissão users.manage. Quem não administra usuários
 * ficava preso à senha que alguém definiu — inclusive a da instalação.
 *
 * A troca invalida todos os tokens do usuário (o backend sobe password_version),
 * então a tela manda para o login logo em seguida.
 */
export default function ChangePassword() {
  const { t } = useI18n();
  const { logout } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  const tooShort = next.length > 0 && next.length < MIN_LENGTH;
  const mismatch = confirm.length > 0 && next !== confirm;
  const ready = current.length > 0 && next.length >= MIN_LENGTH && next === confirm && !busy;

  const submit = async () => {
    setBusy(true);
    setMsg('');
    try {
      await client.post('/api/auth/change-password', {
        current_password: current,
        new_password: next,
      });
      setMsg(t('cfg.pwd.success'));
      setCurrent('');
      setNext('');
      setConfirm('');
      // O token atual já não vale (o backend subiu password_version), então não
      // adianta continuar na tela. logout() limpa o estado do React também, e
      // não só o localStorage.
      setTimeout(logout, 2000);
    } catch (e) {
      setMsg(t('cfg.msg.errorPrefix') + errMsg(e, t('cfg.msg.opFailed')));
      setBusy(false);
    }
  };

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-blue-400" />
          <span className="text-white font-semibold">{t('cfg.pwd.title')}</span>
          <HelpTip title={t('cfg.pwd.help.title')}>
            <>
              {t('cfg.pwd.help.body')}<b>{t('cfg.pwd.help.body.strong')}</b>{t('cfg.pwd.help.body.tail')}
            </>
          </HelpTip>
        </span>
      }
    >
      <div className="space-y-4">
        {msg && (
          <div
            className={`px-3 py-2 rounded-lg text-sm ${
              msg.startsWith(t('cfg.msg.errorPrefix')) ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'
            }`}
          >
            {msg}
          </div>
        )}

        <div className="space-y-3 max-w-sm">
          <label className="block">
            <span className="text-gray-400 text-sm">{t('cfg.pwd.current')}</span>
            <input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              className="input mt-1 w-full"
            />
          </label>

          <label className="block">
            <span className="text-gray-400 text-sm">{t('cfg.pwd.new')}</span>
            <input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              className="input mt-1 w-full"
            />
            {tooShort && (
              <span className="text-amber-400 text-xs mt-1 block">
                {t('cfg.pwd.minLength', { n: MIN_LENGTH })}
              </span>
            )}
          </label>

          <label className="block">
            <span className="text-gray-400 text-sm">{t('cfg.pwd.repeat')}</span>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="input mt-1 w-full"
            />
            {mismatch && (
              <span className="text-amber-400 text-xs mt-1 block">{t('cfg.pwd.mismatch')}</span>
            )}
          </label>

          <button onClick={submit} disabled={!ready} className="btn-primary flex items-center gap-2 disabled:opacity-50">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
            {t('cfg.pwd.submit')}
          </button>
        </div>
      </div>
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
