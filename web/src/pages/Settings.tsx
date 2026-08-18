import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Info, Database, Bell, ShieldCheck, Download, RefreshCw, Sparkles } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import NotificationSettings from '../components/NotificationSettings';
import MonitoringSettings from '../components/MonitoringSettings';
import TwoFactorSettings from '../components/TwoFactorSettings';
import ChangePassword from '../components/ChangePassword';
import HttpsInfo from '../components/HttpsInfo';
import BackupRestore from '../components/BackupRestore';
import UpdateChecker from '../components/UpdateChecker';
import AISettings from '../components/AISettings';
import { useI18n } from '../i18n';
import type { TrafficRetentionResponse } from '../types';

type RetentionProfile = '30d' | '1y' | '5y';

// Ordem crescente de retenção; índice menor = janela mais curta.
const PROFILE_ORDER: RetentionProfile[] = ['30d', '1y', '5y'];

const FEATURE_KEYS = [
  'cfg.about.feature.wan',
  'cfg.about.feature.failover',
  'cfg.about.feature.routes',
  'cfg.about.feature.iptables',
  'cfg.about.feature.backup',
  'cfg.about.feature.metrics',
  'cfg.about.feature.alerts',
  'cfg.about.feature.audit',
];

export default function Settings() {
  const { t } = useI18n();
  const [activeSection, setActiveSection] = useState('about');
  const [version, setVersion] = useState('');
  const [retentionProfile, setRetentionProfile] = useState<RetentionProfile>('30d');
  const [savingProfile, setSavingProfile] = useState(false);
  const [loadingRetention, setLoadingRetention] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [profileError, setProfileError] = useState('');
  const [profileSaved, setProfileSaved] = useState(false);
  const [pendingShorten, setPendingShorten] = useState<RetentionProfile | null>(null);

  useEffect(() => {
    const loadRetention = async () => {
      setLoadingRetention(true);
      setLoadError('');
      try {
        const res = await client.get<TrafficRetentionResponse>('/api/system/traffic-retention');
        if (res.data.profile) {
          setRetentionProfile(res.data.profile);
        }
      } catch (e) {
        console.error(e);
        setLoadError(t('cfg.retention.loadError'));
      } finally {
        setLoadingRetention(false);
      }
    };
    loadRetention();
  }, [t]);

  useEffect(() => {
    client.get<{ version: string }>('/api/health')
      .then((res) => setVersion(res.data.version))
      .catch(() => {});
  }, []);

  const persistRetentionProfile = async (profile: RetentionProfile) => {
    setSavingProfile(true);
    setProfileError('');
    setProfileSaved(false);
    try {
      await client.put('/api/system/traffic-retention', { profile });
      setRetentionProfile(profile);
      setProfileSaved(true);
      setTimeout(() => setProfileSaved(false), 3000);
    } catch (e) {
      console.error(e);
      setProfileError(t('cfg.retention.saveError'));
    } finally {
      setSavingProfile(false);
    }
  };

  const updateRetentionProfile = (profile: RetentionProfile) => {
    if (profile === retentionProfile) return;
    setProfileError('');
    setProfileSaved(false);
    // Confirmar apenas quando a retenção for reduzida (janela mais curta).
    const isShortening = PROFILE_ORDER.indexOf(profile) < PROFILE_ORDER.indexOf(retentionProfile);
    if (isShortening) {
      setPendingShorten(profile);
      return;
    }
    persistRetentionProfile(profile);
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">{t('cfg.title')}</h1>
        <p className="text-gray-500 text-sm">{t('cfg.subtitle')}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Panel className="space-y-1">
          {[
            { id: 'about', label: t('cfg.nav.about'), icon: Info },
            { id: 'general', label: t('cfg.nav.general'), icon: SettingsIcon },
            { id: 'security', label: t('cfg.nav.security'), icon: ShieldCheck },
            { id: 'notifications', label: t('cfg.nav.notifications'), icon: Bell },
            { id: 'ai', label: t('cfg.nav.ai'), icon: Sparkles },
            { id: 'backup', label: t('cfg.nav.backup'), icon: Download },
            { id: 'updates', label: t('cfg.nav.updates'), icon: RefreshCw },
            { id: 'traffic-retention', label: t('cfg.nav.retention'), icon: Database },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveSection(id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                activeSection === id ? 'bg-blue-600/20 text-blue-400' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </Panel>

        <div className="md:col-span-3">
          {activeSection === 'about' && (
            <Panel title={t('cfg.about.title')} className="space-y-4">
              <div className="space-y-3 text-sm">
                <InfoRow label={t('cfg.about.version')} value={version || '—'} />
                <InfoRow label={t('cfg.about.description')} value={t('cfg.about.description.value')} />
                <InfoRow label={t('cfg.about.tech')} value="Go, React, SQLite, nftables, iproute2" />
                <InfoRow label={t('cfg.about.license')} value="MIT" />
              </div>
              <div className="pt-4 border-t border-gray-800">
                <h3 className="text-white font-medium mb-3">{t('cfg.about.features')}</h3>
                <ul className="space-y-2 text-sm text-gray-400">
                  {FEATURE_KEYS.map((k, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-blue-400 mt-0.5">•</span>
                      {t(k)}
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}

          {activeSection === 'general' && (
            <Panel title={t('cfg.general.title')} className="space-y-4">
              <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                {t('cfg.general.readonly')}
              </div>
              <p className="text-gray-500 text-sm">
                {t('cfg.general.intro')}
              </p>
              <div className="bg-gray-800 rounded-lg p-4">
                <p className="text-gray-400 text-sm font-mono">
                  {t('cfg.general.defaultPath')} <span className="text-blue-400">/etc/linkguard-fw/config.json</span>
                </p>
              </div>
              <div className="space-y-3 text-sm text-gray-400">
                <p><span className="text-white">listen_addr:</span> {t('cfg.general.listenAddr')}</p>
                <p><span className="text-white">port:</span> {t('cfg.general.port')}</p>
                <p><span className="text-white">dry_run:</span> {t('cfg.general.dryRun')}</p>
                <p><span className="text-white">monitor_interval_seconds:</span> {t('cfg.general.monitorInterval')}</p>
                <p><span className="text-white">failover_enabled:</span> {t('cfg.general.failoverEnabled')}</p>
                <p><span className="text-white">fail_threshold:</span> {t('cfg.general.failThreshold')}</p>
                <p><span className="text-white">recover_threshold:</span> {t('cfg.general.recoverThreshold')}</p>
              </div>
            </Panel>
          )}

          {activeSection === 'traffic-retention' && (
            <Panel title={t('cfg.retention.title')} className="space-y-4">
              <p className="text-gray-500 text-sm">
                {t('cfg.retention.intro')}
              </p>

              {loadError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{loadError}</div>
              )}
              {profileError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{profileError}</div>
              )}
              {profileSaved && (
                <div className="px-4 py-3 rounded-lg text-sm bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">{t('cfg.retention.saved')}</div>
              )}

              {loadingRetention ? (
                <div className="text-gray-500 text-sm py-2 animate-pulse">{t('cfg.retention.loading')}</div>
              ) : (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border border-gray-800 bg-gray-900/50 p-2">
                  {PROFILE_ORDER.map((p) => (
                    <button
                      key={p}
                      disabled={savingProfile}
                      title={t(`cfg.retention.profile.${p}`)}
                      onClick={() => updateRetentionProfile(p)}
                      className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                        retentionProfile === p
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : 'bg-gray-900 text-gray-300 border border-gray-700 hover:border-gray-500'
                      } disabled:opacity-50`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              )}

              <div className="rounded-lg border border-gray-800 bg-gray-950/70 p-4 space-y-2 text-sm text-gray-400">
                <p>
                  {t('cfg.retention.active')} <span className="text-white font-mono">{retentionProfile}</span>
                </p>
                <p>
                  {t('cfg.retention.storage')} <span className="text-blue-400 font-mono">/var/lib/linkguard-fw/linkguard.db</span>
                </p>
                <p>
                  {t('cfg.retention.table')} <span className="text-blue-400 font-mono">traffic_samples</span>
                </p>
                <p className="text-xs text-gray-500">
                  {t('cfg.retention.dbPathHint')}<span className="font-mono">db_path</span>{t('cfg.retention.dbPathHint.tail')}
                </p>
              </div>
            </Panel>
          )}

          {activeSection === 'security' && (
            <div className="space-y-6">
              <ChangePassword />
              <TwoFactorSettings />
              <HttpsInfo />
            </div>
          )}

          {activeSection === 'notifications' && (
            <div className="space-y-6">
              <NotificationSettings />
              <MonitoringSettings />
            </div>
          )}

          {activeSection === 'ai' && <AISettings />}

          {activeSection === 'backup' && <BackupRestore />}

          {activeSection === 'updates' && <UpdateChecker />}
        </div>
      </div>

      <Modal open={!!pendingShorten} onClose={() => setPendingShorten(null)} title={t('cfg.retention.confirm.title')} size="sm" className="bg-gray-900 border border-gray-800 rounded-xl">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            {t('cfg.retention.confirm.body')}
          </p>
          <p className="text-gray-500 text-xs">
            {t('cfg.retention.confirm.current')} <span className="font-mono text-gray-300">{retentionProfile}</span> →{' '}
            {t('cfg.retention.confirm.new')} <span className="font-mono text-gray-300">{pendingShorten}</span>
          </p>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              disabled={savingProfile}
              onClick={() => {
                const target = pendingShorten;
                setPendingShorten(null);
                if (target) persistRetentionProfile(target);
              }}
              className="btn-primary flex-1 disabled:opacity-50"
            >
              {t('cfg.retention.confirm.continue')}
            </button>
            <button
              type="button"
              onClick={() => setPendingShorten(null)}
              className="btn-secondary flex-1"
            >
              {t('common.cancel')}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-4">
      <span className="text-gray-500 w-28 shrink-0">{label}</span>
      <span className="text-gray-200">{value}</span>
    </div>
  );
}
