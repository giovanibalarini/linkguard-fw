import { useEffect, useState } from 'react';
import client from '../api/client';
import Panel from './ui/Panel';
import { useUIMode } from '../context/UIModeContext';
import type { MonitoringConfig } from '../types';

const empty: MonitoringConfig = { enabled: true, services: [], disk_threshold_pct: 90 };

export default function MonitoringSettings() {
  const { isSimple } = useUIMode();
  const advanced = !isSimple;
  const [cfg, setCfg] = useState<MonitoringConfig>(empty);
  const [msg, setMsg] = useState('');

  useEffect(() => { (async () => {
    try { const { data } = await client.get<MonitoringConfig>('/api/monitoring/config'); setCfg(data); } catch {/*ignore*/}
  })(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 4000); };

  const save = async (next: MonitoringConfig) => {
    setCfg(next);
    try { const { data } = await client.put<MonitoringConfig>('/api/monitoring/config', next); setCfg(data); flash('Salvo.'); }
    catch { flash('Erro ao salvar.'); }
  };

  return (
    <Panel title="Vigilância">
      <p className="text-gray-500 text-xs mb-3">Avisa no seu canal de notificação quando algo cai (e quando volta).</p>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={cfg.enabled} onChange={(e) => save({ ...cfg, enabled: e.target.checked })} />
        <span className="text-white text-sm">Me avise de qualquer queda</span>
      </label>
      {advanced && (
        <div className="mt-3 space-y-2">
          <label className="block text-xs text-gray-400">Serviços vigiados (separados por vírgula)
            <input className="input mt-1 w-full" defaultValue={cfg.services.join(', ')}
              onBlur={(e) => save({ ...cfg, services: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
          </label>
          <label className="block text-xs text-gray-400">Alerta de disco acima de (%)
            <input type="number" min={50} max={99} className="input mt-1 w-32" defaultValue={cfg.disk_threshold_pct}
              onBlur={(e) => save({ ...cfg, disk_threshold_pct: Number(e.target.value) })} />
          </label>
        </div>
      )}
      {msg && <div className="mt-2 text-xs text-gray-400">{msg}</div>}
    </Panel>
  );
}
