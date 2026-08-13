import { createContext, useCallback, useContext, useEffect, useState } from 'react';

/**
 * Lightweight i18n layer. Strings live in the dictionaries below keyed by a
 * dotted id; t(key) returns the active language's string (falling back to the
 * key). Portuguese is the default; English is provided for the app shell and
 * common surfaces, with page bodies translated incrementally.
 */
export type Lang = 'pt' | 'en';

const STORAGE_KEY = 'lg_lang';

type Dict = Record<string, string>;

const pt: Dict = {
  'app.tagline': 'Firewall Manager',
  // nav
  'nav.dashboard': 'Painel',
  'nav.traffic': 'Tráfego',
  'nav.links': 'Links WAN',
  'nav.firewall': 'Firewall',
  'nav.hosts': 'Hosts',
  'nav.dhcp': 'DHCP',
  'nav.dns': 'DNS',
  'nav.ntp': 'NTP',
  'nav.interfaces': 'Interfaces',
  'nav.routes': 'Rotas',
  'nav.monitoring': 'Monitoramento',
  'nav.alerts': 'Alertas',
  'nav.logs': 'Logs',
  'nav.settings': 'Configurações',
  'nav.admin': 'Administração',
  'nav.changelog': 'Novidades',
  'group.operacao': 'Operação',
  'group.rede': 'Rede',
  'group.seguranca': 'Segurança',
  'group.advanced': 'Avançado',
  'group.system': 'Sistema',
  'mode.simple': 'Simples',
  'mode.advanced': 'Avançado',
  'action.logout': 'Sair',
  // login
  'login.subtitle': 'Gestão de Firewall Linux',
  'login.title': 'Entrar',
  'login.username': 'Usuário',
  'login.password': 'Senha',
  'login.code': 'Código de verificação (2FA)',
  'login.code.hint': 'Abra seu app autenticador e digite o código de 6 dígitos.',
  'login.submit': 'Entrar',
  'login.verify': 'Verificar',
  'login.loading': 'Entrando...',
  'login.invalid': 'Usuário ou senha inválidos',
  'login.locked': 'Muitas tentativas. Aguarde alguns minutos e tente de novo.',
  'login.invalidCode': 'Código inválido. Tente novamente.',
  // dashboard
  'dashboard.title': 'Dashboard',
  'dashboard.subtitle': 'Visão geral do sistema',
};

const en: Dict = {
  'app.tagline': 'Firewall Manager',
  'nav.dashboard': 'Dashboard',
  'nav.traffic': 'Traffic',
  'nav.links': 'WAN Links',
  'nav.firewall': 'Firewall',
  'nav.hosts': 'Hosts',
  'nav.dhcp': 'DHCP',
  'nav.dns': 'DNS',
  'nav.ntp': 'NTP',
  'nav.interfaces': 'Interfaces',
  'nav.routes': 'Routes',
  'nav.monitoring': 'Monitoring',
  'nav.alerts': 'Alerts',
  'nav.logs': 'Logs',
  'nav.settings': 'Settings',
  'nav.admin': 'Administration',
  'nav.changelog': "What's new",
  'group.operacao': 'Operations',
  'group.rede': 'Network',
  'group.seguranca': 'Security',
  'group.advanced': 'Advanced',
  'group.system': 'System',
  'mode.simple': 'Simple',
  'mode.advanced': 'Advanced',
  'action.logout': 'Log out',
  'login.subtitle': 'Linux Firewall Management',
  'login.title': 'Sign in',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.code': 'Verification code (2FA)',
  'login.code.hint': 'Open your authenticator app and enter the 6-digit code.',
  'login.submit': 'Sign in',
  'login.verify': 'Verify',
  'login.loading': 'Signing in...',
  'login.invalid': 'Invalid username or password',
  'login.locked': 'Too many attempts. Wait a few minutes and try again.',
  'login.invalidCode': 'Invalid code. Please try again.',
  'dashboard.title': 'Dashboard',
  'dashboard.subtitle': 'System overview',
};

const dicts: Record<Lang, Dict> = { pt, en };

interface I18nValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nValue | undefined>(undefined);

function readStored(): Lang {
  return localStorage.getItem(STORAGE_KEY) === 'en' ? 'en' : 'pt';
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(readStored);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, lang);
    document.documentElement.lang = lang === 'en' ? 'en' : 'pt-BR';
  }, [lang]);

  const setLang = useCallback((l: Lang) => setLangState(l), []);
  const t = useCallback((key: string) => dicts[lang][key] ?? dicts.pt[key] ?? key, [lang]);

  return <I18nContext.Provider value={{ lang, setLang, t }}>{children}</I18nContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('useI18n must be used within I18nProvider');
  return ctx;
}
