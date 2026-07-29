import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Info, Database, Bell, ShieldCheck, Download, RefreshCw, Sparkles } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import NotificationSettings from '../components/NotificationSettings';
import MonitoringSettings from '../components/MonitoringSettings';
import TwoFactorSettings from '../components/TwoFactorSettings';
import HttpsInfo from '../components/HttpsInfo';
import BackupRestore from '../components/BackupRestore';
import UpdateChecker from '../components/UpdateChecker';
import AISettings from '../components/AISettings';
import type { TrafficRetentionResponse } from '../types';

type RetentionProfile = '30d' | '1y' | '5y';

// Ordem crescente de retenção; índice menor = janela mais curta.
const PROFILE_ORDER: RetentionProfile[] = ['30d', '1y', '5y'];

export default function Settings() {
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
        setLoadError('Não foi possível carregar o perfil de retenção atual.');
      } finally {
        setLoadingRetention(false);
      }
    };
    loadRetention();
  }, []);

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
      setProfileError('Erro ao salvar perfil de retenção.');
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
        <h1 className="text-xl font-bold text-white">Configurações</h1>
        <p className="text-gray-500 text-sm">Configurações do sistema</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Panel className="space-y-1">
          {[
            { id: 'about', label: 'Sobre', icon: Info },
            { id: 'general', label: 'Geral', icon: SettingsIcon },
            { id: 'security', label: 'Segurança', icon: ShieldCheck },
            { id: 'notifications', label: 'Notificações', icon: Bell },
            { id: 'ai', label: 'Assistente de IA', icon: Sparkles },
            { id: 'backup', label: 'Backup', icon: Download },
            { id: 'updates', label: 'Atualizações', icon: RefreshCw },
            { id: 'traffic-retention', label: 'Retenção de tráfego', icon: Database },
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
            <Panel title="Sobre o LinkGuard FW" className="space-y-4">
              <div className="space-y-3 text-sm">
                <InfoRow label="Versão" value={version ? `v${version}` : '—'} />
                <InfoRow label="Descrição" value="Ferramenta de gestão de firewall Linux para servidores Debian com múltiplos links de internet" />
                <InfoRow label="Tecnologias" value="Go, React, SQLite, nftables, iproute2" />
                <InfoRow label="Licença" value="MIT" />
              </div>
              <div className="pt-4 border-t border-gray-800">
                <h3 className="text-white font-medium mb-3">Funcionalidades</h3>
                <ul className="space-y-2 text-sm text-gray-400">
                  {[
                    'Gestão de links WAN com monitoramento contínuo',
                    'Failover automático com dry-run mode',
                    'Visualização de tabelas de roteamento',
                    'Listagem de regras iptables',
                    'Backup e restore de regras',
                    'Métricas Prometheus em /metrics',
                    'Alertas de sistema',
                    'Logs de auditoria',
                  ].map((f, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-blue-400 mt-0.5">•</span>
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}

          {activeSection === 'general' && (
            <Panel title="Configurações Gerais" className="space-y-4">
              <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                Somente leitura — editável via arquivo de configuração.
              </div>
              <p className="text-gray-500 text-sm">
                As configurações são gerenciadas via arquivo de configuração JSON.
                Reinicie o serviço após alterar as configurações.
              </p>
              <div className="bg-gray-800 rounded-lg p-4">
                <p className="text-gray-400 text-sm font-mono">
                  Caminho padrão: <span className="text-blue-400">/etc/linkguard-fw/config.json</span>
                </p>
              </div>
              <div className="space-y-3 text-sm text-gray-400">
                <p><span className="text-white">listen_addr:</span> Endereço de escuta (padrão: 127.0.0.1)</p>
                <p><span className="text-white">port:</span> Porta HTTP (padrão: 8080)</p>
                <p><span className="text-white">dry_run:</span> Modo dry-run para comandos de firewall</p>
                <p><span className="text-white">monitor_interval_seconds:</span> Intervalo de verificação dos links</p>
                <p><span className="text-white">failover_enabled:</span> Habilitar failover automático</p>
                <p><span className="text-white">fail_threshold:</span> Falhas consecutivas para marcar offline</p>
                <p><span className="text-white">recover_threshold:</span> Sucessos para marcar online</p>
              </div>
            </Panel>
          )}

          {activeSection === 'traffic-retention' && (
            <Panel title="Retenção de tráfego (RRD)" className="space-y-4">
              <p className="text-gray-500 text-sm">
                Define por quanto tempo as amostras históricas de tráfego ficam persistidas.
                Esta configuração afeta as janelas de 30d, 1y e 5y usadas na aba Interfaces.
              </p>

              {loadError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{loadError}</div>
              )}
              {profileError && (
                <div className="px-4 py-3 rounded-lg text-sm bg-red-500/10 text-red-400 border border-red-500/20">{profileError}</div>
              )}
              {profileSaved && (
                <div className="px-4 py-3 rounded-lg text-sm bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">Perfil salvo</div>
              )}

              {loadingRetention ? (
                <div className="text-gray-500 text-sm py-2 animate-pulse">Carregando perfil de retenção...</div>
              ) : (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border border-gray-800 bg-gray-900/50 p-2">
                  {PROFILE_ORDER.map((p) => (
                    <button
                      key={p}
                      disabled={savingProfile}
                      title={p === '30d' ? '30 dias' : p === '1y' ? '1 ano' : '5 anos'}
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
                  Perfil ativo: <span className="text-white font-mono">{retentionProfile}</span>
                </p>
                <p>
                  Armazenamento dos dados: <span className="text-blue-400 font-mono">/var/lib/linkguard-fw/linkguard.db</span>
                </p>
                <p>
                  Tabela: <span className="text-blue-400 font-mono">traffic_samples</span>
                </p>
                <p className="text-xs text-gray-500">
                  O caminho do banco pode ser alterado pela chave <span className="font-mono">db_path</span> no arquivo de configuração.
                </p>
              </div>
            </Panel>
          )}

          {activeSection === 'security' && (
            <div className="space-y-6">
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

      <Modal open={!!pendingShorten} onClose={() => setPendingShorten(null)} title="Reduzir retenção de tráfego" size="sm">
        <div className="p-6 space-y-4">
          <p className="text-gray-300 text-sm">
            Reduzir a retenção pode descartar amostras antigas. Continuar?
          </p>
          <p className="text-gray-500 text-xs">
            Perfil atual: <span className="font-mono text-gray-300">{retentionProfile}</span> →{' '}
            novo perfil: <span className="font-mono text-gray-300">{pendingShorten}</span>
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
              Continuar
            </button>
            <button
              type="button"
              onClick={() => setPendingShorten(null)}
              className="btn-secondary flex-1"
            >
              Cancelar
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
      <span className="text-gray-500 w-28 flex-shrink-0">{label}</span>
      <span className="text-gray-200">{value}</span>
    </div>
  );
}
