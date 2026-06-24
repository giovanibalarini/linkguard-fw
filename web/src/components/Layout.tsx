import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard, Network, Route, Shield, Bell, FileText,
  Activity, Settings, LogOut, ShieldCheck, Users, MonitorSmartphone
} from 'lucide-react';

// `perm` lists the permissions that reveal a nav item; an item with no `perm`
// (or matching any of several) is shown when the user holds at least one.
const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true, perm: ['dashboard.read'] },
  { to: '/links', label: 'Links WAN', icon: Network, perm: ['links.read'] },
  { to: '/interfaces', label: 'Interfaces', icon: Network, perm: ['system.read'] },
  { to: '/routes', label: 'Rotas', icon: Route, perm: ['routes.read'] },
  { to: '/firewall', label: 'Firewall', icon: Shield, perm: ['firewall.read'] },
  { to: '/hosts', label: 'Hosts', icon: MonitorSmartphone, perm: ['hosts.read'] },
  { to: '/monitoring', label: 'Monitoramento', icon: Activity, perm: ['monitoring.read'] },
  { to: '/alerts', label: 'Alertas', icon: Bell, perm: ['monitoring.read'] },
  { to: '/logs', label: 'Logs', icon: FileText, perm: ['logs.read'] },
  { to: '/settings', label: 'Configurações', icon: Settings, perm: ['system.read'] },
  { to: '/admin', label: 'Administração', icon: Users, perm: ['users.manage', 'roles.manage'] },
];

export default function Layout() {
  const { user, logout, can, permsLoaded } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Until permissions load, show everything to avoid an empty sidebar flash;
  // afterwards, hide items the user has no permission for.
  const visibleNav = navItems.filter(
    (item) => !permsLoaded || item.perm.some((p) => can(p)),
  );

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        {/* Logo */}
        <div className="px-6 py-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-7 h-7 text-blue-500" />
            <div>
              <p className="text-white font-bold text-sm">LinkGuard FW</p>
              <p className="text-gray-500 text-xs">Firewall Manager</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          <ul className="space-y-1">
            {visibleNav.map(({ to, label, icon: Icon, end }) => (
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
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        {/* User / Logout */}
        <div className="px-3 py-4 border-t border-gray-800">
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
              title="Sair"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
