import { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import type { HealthItem, UpdatesReport } from '../types';

// Friendly labels for known service unit names.
const LABEL: Record<string, string> = {
  'nftables': 'Firewall',
  'kea-dhcp4-server': 'DHCP',
  'unbound': 'DNS',
  'ntp-sync': 'Sincronização de horário',
  'smart-health': 'Disco (SMART)',
  'boot-time': 'Tempo de boot',
  'journal-integrity': 'Integridade dos logs',
  'firewall-nat': 'Regra de NAT',
  'wan-interface': 'Interfaces WAN',
  'dns-resolver': 'Resolver DNS',
  'system-updates': 'Atualizações do sistema',
};

export default function SystemHealth() {
  const [items, setItems] = useState<HealthItem[]>([]);
  const [updates, setUpdates] = useState<UpdatesReport | null>(null);
  const [showUpdates, setShowUpdates] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const { data } = await client.get<HealthItem[]>('/api/monitoring/health'); if (alive) setItems(data ?? []); }
      catch { /* best-effort */ }
      try { const { data } = await client.get<UpdatesReport>('/api/system/updates'); if (alive) setUpdates(data); }
      catch { /* best-effort, igual ao health */ }
    };
    load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (items.length === 0) return null;
  return (
    <Panel title="Saúde do sistema">
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
      {updates && updates.total > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-800/50">
          <button onClick={() => setShowUpdates(!showUpdates)} className="text-sm text-gray-400 hover:text-white">
            {updates.total} atualização(ões) pendente(s)
            {updates.security > 0 && <span className="text-amber-400"> — {updates.security} de segurança</span>}
            <span className="text-gray-600"> {showUpdates ? '▲' : '▼'}</span>
          </button>
          {showUpdates && (
            <div className="mt-2 space-y-1">
              {updates.packages.map((p) => (
                <div key={p.name} className="flex items-center justify-between text-xs">
                  <span className={p.security ? 'text-amber-400' : 'text-gray-400'}>{p.name}</span>
                  <span className="text-gray-600 font-mono">{p.current_version || '—'} → {p.new_version}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
