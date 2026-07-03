import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useUIMode } from '../context/UIModeContext';
import { useI18n } from '../i18n';
import {
  LayoutDashboard, Network, Route, Shield, Bell, FileText,
  Activity, Settings, LogOut, ShieldCheck, Users, MonitorSmartphone,
  Menu, X, AlertTriangle, Cable, Server, Globe, ChevronDown, Sparkles, SlidersHorizontal, Lock,
} from 'lucide-react';

interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  perm: string[];
  end?: boolean;
}

interface NavGroup {
  id: string;
  label: string | null;
  advanced?: boolean;
  items: NavItem[];
}

// Grouped navigation. The "Avançado" group is collapsed in Simple mode (one
// click expands it) and expanded in Advanced mode. `perm` lists the permissions
// that reveal an item; the item shows when the user holds at least one.
// `label` holds an i18n key resolved with t() at render time.
const navGroups: NavGroup[] = [
  {
    id: 'main', label: null,
    items: [
      { to: '/', label: 'nav.dashboard', icon: LayoutDashboard, end: true, perm: ['dashboard.read'] },
      { to: '/links', label: 'nav.links', icon: Network, perm: ['links.read'] },
      { to: '/firewall', label: 'nav.firewall', icon: Shield, perm: ['firewall.read'] },
      { to: '/hosts', label: 'nav.hosts', icon: MonitorSmartphone, perm: ['hosts.read'] },
      { to: '/dhcp', label: 'nav.dhcp', icon: Server, perm: ['dhcp.read'] },
      { to: '/dns', label: 'nav.dns', icon: Globe, perm: ['dns.read'] },
      { to: '/vpn', label: 'nav.vpn', icon: Lock, perm: ['vpn.read'] },
    ],
  },
  {
    id: 'advanced', label: 'group.advanced', advanced: true,
    items: [
      { to: '/interfaces', label: 'nav.interfaces', icon: Cable, perm: ['system.read'] },
      { to: '/routes', label: 'nav.routes', icon: Route, perm: ['routes.read'] },
      { to: '/monitoring', label: 'nav.monitoring', icon: Activity, perm: ['monitoring.read'] },
      { to: '/alerts', label: 'nav.alerts', icon: Bell, perm: ['monitoring.read'] },
      { to: '/logs', label: 'nav.logs', icon: FileText, perm: ['logs.read'] },
    ],
  },
  {
    id: 'system', label: 'group.system',
    items: [
      { to: '/settings', label: 'nav.settings', icon: Settings, perm: ['system.read'] },
      { to: '/admin', label: 'nav.admin', icon: Users, perm: ['users.manage', 'roles.manage'] },
      { to: '/changelog', label: 'nav.changelog', icon: Sparkles, perm: ['dashboard.read'] },
    ],
  },
];

const allItems = navGroups.flatMap((g) => g.items);

export default function Layout() {
  const { user, logout, can, permsLoaded } = useAuth();
  const { isSimple, mode, setMode } = useUIMode();
  const { t, lang, setLang } = useI18n();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showSecWarn, setShowSecWarn] = useState(true);
  const [advOpen, setAdvOpen] = useState(false);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => { setSidebarOpen(false); }, [location.pathname]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const itemVisible = (item: NavItem) => !permsLoaded || item.perm.some((p) => can(p));

  // Current page label for the mobile top bar (longest matching path wins).
  const currentItem = [...allItems]
    .sort((a, b) => b.to.length - a.to.length)
    .find((n) => (n.to === '/' ? location.pathname === '/' : location.pathname.startsWith(n.to)));
  const currentLabel = currentItem ? t(currentItem.label) : 'LinkGuard FW';

  // The advanced group expands automatically in advanced mode, when the active
  // route lives inside it, or when the user clicks to expand it.
  const onAdvancedRoute = navGroups
    .find((g) => g.advanced)!
    .items.some((i) => location.pathname.startsWith(i.to) && i.to !== '/');
  const advExpanded = !isSimple || advOpen || onAdvancedRoute;

  const renderItem = (item: NavItem) => {
    const { to, label, icon: Icon, end } = item;
    return (
      <li key={to}>
        <NavLink
          to={to}
          end={end}
          className={({ isActive }) =>
            `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
              isActive
                ? 'bg-blue-600/20 text-blue-400 font-medium'
                : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`
          }
        >
          <Icon className="w-4 h-4 flex-shrink-0" />
          {t(label)}
        </NavLink>
      </li>
    );
  };

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar — static on desktop, slide-in drawer on mobile */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 border-r border-gray-800 flex flex-col
          transform transition-transform duration-200 ease-in-out
          lg:static lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        {/* Logo */}
        <div className="px-6 py-5 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-7 h-7 text-blue-500" />
            <div>
              <p className="text-white font-bold text-sm">LinkGuard FW</p>
              <p className="text-gray-500 text-xs">{t('app.tagline')}</p>
            </div>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden text-gray-400 hover:text-gray-200"
            aria-label="Fechar menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          {navGroups.map((group) => {
            const items = group.items.filter(itemVisible);
            if (items.length === 0) return null;

            // Advanced group: collapsible in Simple mode, plain section otherwise.
            if (group.advanced && isSimple) {
              return (
                <div key={group.id} className="mt-4">
                  <button
                    onClick={() => setAdvOpen((v) => !v)}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-gray-500 hover:text-gray-300"
                    aria-expanded={advExpanded}
                  >
                    <span>{group.label ? t(group.label) : ''}</span>
                    <ChevronDown className={`w-3.5 h-3.5 transition-transform ${advExpanded ? '' : '-rotate-90'}`} />
                  </button>
                  {advExpanded && <ul className="mt-1 space-y-1">{items.map(renderItem)}</ul>}
                </div>
              );
            }

            return (
              <div key={group.id} className={group.label ? 'mt-4' : ''}>
                {group.label && (
                  <p className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-gray-600">{t(group.label)}</p>
                )}
                <ul className="space-y-1">{items.map(renderItem)}</ul>
              </div>
            );
          })}
        </nav>

        {/* Mode switch + language */}
        <div className="px-3 pt-3 border-t border-gray-800 space-y-2">
          <div className="flex items-center gap-1 rounded-lg bg-gray-800 p-1" role="group" aria-label="Modo de exibição">
            <button
              onClick={() => setMode('simple')}
              className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-colors ${
                mode === 'simple' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" /> {t('mode.simple')}
            </button>
            <button
              onClick={() => setMode('advanced')}
              className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-colors ${
                mode === 'advanced' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" /> {t('mode.advanced')}
            </button>
          </div>
          <div className="flex items-center gap-1 rounded-lg bg-gray-800 p-1" role="group" aria-label="Language">
            {(['pt', 'en'] as const).map((l) => (
              <button
                key={l}
                onClick={() => setLang(l)}
                className={`flex-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                  lang === l ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {l === 'pt' ? 'Português' : 'English'}
              </button>
            ))}
          </div>
        </div>

        {/* User / Logout */}
        <div className="px-3 py-4">
          <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-gray-800">
            <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
              {user?.username?.[0]?.toUpperCase() ?? 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium truncate">{user?.username}</p>
              <p className="text-gray-500 text-xs truncate">{user?.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="text-gray-500 hover:text-red-400 transition-colors flex-shrink-0"
              title={t('action.logout')}
              aria-label={t('action.logout')}
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* Mobile top bar with hamburger */}
        <header className="lg:hidden flex items-center gap-3 px-4 h-14 bg-gray-900 border-b border-gray-800 flex-shrink-0">
          <button
            onClick={() => setSidebarOpen(true)}
            className="text-gray-300 hover:text-white"
            aria-label="Abrir menu"
          >
            <Menu className="w-6 h-6" />
          </button>
          <div className="flex items-center gap-2 min-w-0">
            <ShieldCheck className="w-5 h-5 text-blue-500 flex-shrink-0" />
            <span className="text-white font-semibold text-sm truncate">{currentLabel}</span>
          </div>
        </header>

        {/* Security nudge: still using the default admin account */}
        {user?.username === 'admin' && showSecWarn && (
          <div className="flex items-start gap-3 px-4 py-2.5 bg-amber-500/10 border-b border-amber-500/30 text-amber-300 text-sm flex-shrink-0">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <p className="flex-1">
              Você está usando a conta padrão <span className="font-semibold">admin</span>. Crie usuários nominais e troque a senha em{' '}
              <NavLink to="/admin" className="underline font-medium hover:text-amber-200">Administração</NavLink>.
            </p>
            <button onClick={() => setShowSecWarn(false)} className="text-amber-400 hover:text-amber-200 flex-shrink-0" aria-label="Dispensar aviso" title="Dispensar">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
