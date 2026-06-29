import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import { ShieldCheck, Eye, EyeOff, KeyRound } from 'lucide-react';

export default function Login() {
  const { login } = useAuth();
  const { t } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [needCode, setNeedCode] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password, needCode ? code : undefined);
    } catch (err) {
      const ax = err as { response?: { status?: number; data?: { totp_required?: boolean; locked_out?: boolean } } };
      const data = ax?.response?.data;
      if (data?.totp_required) {
        setNeedCode(true);
        setError(needCode && code ? t('login.invalidCode') : '');
      } else if (data?.locked_out) {
        setError(t('login.locked'));
      } else {
        setError(t('login.invalid'));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600/20 mb-4">
            <ShieldCheck className="w-8 h-8 text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">LinkGuard FW</h1>
          <p className="text-gray-500 mt-1">{t('login.subtitle')}</p>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold text-white mb-6">{t('login.title')}</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label" htmlFor="login-username">{t('login.username')}</label>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input w-full"
                placeholder="admin"
                autoComplete="username"
                autoFocus
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="login-password">{t('login.password')}</label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input w-full pr-10"
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  title={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                  aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            {needCode && (
              <div>
                <label className="label flex items-center gap-1.5" htmlFor="login-code">
                  <KeyRound className="w-3.5 h-3.5 text-blue-400" /> {t('login.code')}
                </label>
                <input
                  id="login-code"
                  type="text"
                  inputMode="numeric"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="input w-full tracking-[0.4em] text-center font-mono"
                  placeholder="000000"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                />
                <p className="text-gray-600 text-xs mt-1">{t('login.code.hint')}</p>
              </div>
            )}
            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg text-sm">
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? t('login.loading') : needCode ? t('login.verify') : t('login.submit')}
            </button>
          </form>
          <p className="text-gray-600 text-xs text-center mt-4">
            Usuário padrão: admin / Senha inicial definida no setup
          </p>
        </div>
      </div>
    </div>
  );
}
