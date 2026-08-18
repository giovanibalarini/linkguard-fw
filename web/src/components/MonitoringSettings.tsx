import { useEffect, useState } from 'react';
import client from '../api/client';
import Panel from './ui/Panel';
import { useUIMode } from '../context/UIModeContext';
import { useI18n } from '../i18n';
import type { MonitoringConfig } from '../types';

const empty: MonitoringConfig = {
  enabled: true,
  services: [],
  disk_threshold_pct: 90,
  smart_reallocated_threshold: 0,
  smart_temp_threshold_c: 55,
  boot_time_threshold_sec: 180,
  journal_verify_interval_days: 7,
};

export default function MonitoringSettings() {
  const { t } = useI18n();
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
    try { const { data } = await client.put<MonitoringConfig>('/api/monitoring/config', next); setCfg(data); flash(t('mon.watch.saved')); }
    catch { flash(t('mon.watch.saveError')); }
  };

  return (
    <Panel title={t('mon.watch.title')}>
      <p className="text-gray-500 text-xs mb-3">{t('mon.watch.subtitle')}</p>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={cfg.enabled} onChange={(e) => save({ ...cfg, enabled: e.target.checked })} />
        <span className="text-white text-sm">{t('mon.watch.enabled')}</span>
      </label>
      {advanced && (
        <div className="mt-3 space-y-2">
          <label className="block text-xs text-gray-400">{t('mon.watch.services')}
            <input className="input mt-1 w-full" defaultValue={cfg.services.join(', ')}
              onBlur={(e) => save({ ...cfg, services: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
          </label>
          <label className="block text-xs text-gray-400">{t('mon.watch.diskThreshold')}
            <input type="number" min={50} max={99} className="input mt-1 w-32" defaultValue={cfg.disk_threshold_pct}
              onBlur={(e) => save({ ...cfg, disk_threshold_pct: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">{t('mon.watch.smartRealloc')}
            <input type="number" min={0} max={999} className="input mt-1 w-32" defaultValue={cfg.smart_reallocated_threshold}
              onBlur={(e) => save({ ...cfg, smart_reallocated_threshold: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">{t('mon.watch.smartTemp')}
            <input type="number" min={30} max={80} className="input mt-1 w-32" defaultValue={cfg.smart_temp_threshold_c}
              onBlur={(e) => save({ ...cfg, smart_temp_threshold_c: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">{t('mon.watch.bootTime')}
            <input type="number" min={30} max={900} className="input mt-1 w-32" defaultValue={cfg.boot_time_threshold_sec}
              onBlur={(e) => save({ ...cfg, boot_time_threshold_sec: Number(e.target.value) })} />
          </label>
          <label className="block text-xs text-gray-400">{t('mon.watch.journalInterval')}
            <input type="number" min={1} max={90} className="input mt-1 w-32" defaultValue={cfg.journal_verify_interval_days}
              onBlur={(e) => save({ ...cfg, journal_verify_interval_days: Number(e.target.value) })} />
          </label>
        </div>
      )}
      {msg && <div className="mt-2 text-xs text-gray-400">{msg}</div>}
    </Panel>
  );
}
