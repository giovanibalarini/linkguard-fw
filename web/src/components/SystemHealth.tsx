import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import client from '../api/client';
import type { HealthItem } from '../types';

// Friendly labels for known service unit names.
const LABEL: Record<string, string> = {
  'nftables': 'Firewall',
  'kea-dhcp4-server': 'DHCP',
  'unbound': 'DNS',
};

export default function SystemHealth() {
  const [items, setItems] = useState<HealthItem[]>([]);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const { data } = await client.get<HealthItem[]>('/api/monitoring/health'); if (alive) setItems(data ?? []); }
      catch { /* best-effort */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (items.length === 0) return null;
  return (
    <div className="card">
      <h2 className="text-white font-semibold mb-3">Saúde do sistema</h2>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {items.map((it) => (
          <div key={`${it.kind}:${it.name}`}
            className={`flex items-center gap-2 rounded-lg border p-3 ${it.up ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/30 bg-red-500/10'}`}>
            {it.up ? <ShieldCheck className="w-4 h-4 text-green-400 shrink-0" /> : <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />}
            <div className="min-w-0">
              <div className="text-white text-sm truncate">{LABEL[it.name] ?? it.name}</div>
              <div className={`text-xs ${it.up ? 'text-green-400' : 'text-red-400'}`}>{it.up ? 'no ar' : 'fora do ar'}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
