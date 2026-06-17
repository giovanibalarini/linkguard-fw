import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Links from './pages/Links';
import Routes_ from './pages/Routes';
import Firewall from './pages/Firewall';
import Alerts from './pages/Alerts';
import Logs from './pages/Logs';
import Monitoring from './pages/Monitoring';
import Settings from './pages/Settings';
import Interfaces from './pages/Interfaces';

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <Login />} />
        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="links" element={<Links />} />
          <Route path="routes" element={<Routes_ />} />
          <Route path="firewall" element={<Firewall />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="logs" element={<Logs />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route path="interfaces" element={<Interfaces />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}
