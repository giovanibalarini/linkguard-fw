import { useState } from 'react';
import { Settings as SettingsIcon, Info } from 'lucide-react';

export default function Settings() {
  const [activeSection, setActiveSection] = useState('about');

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Configurações</h1>
        <p className="text-gray-500 text-sm">Configurações do sistema</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card space-y-1">
          {[
            { id: 'about', label: 'Sobre', icon: Info },
            { id: 'general', label: 'Geral', icon: SettingsIcon },
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
        </div>

        <div className="md:col-span-3">
          {activeSection === 'about' && (
            <div className="card space-y-4">
              <h2 className="text-white font-semibold">Sobre o LinkGuard FW</h2>
              <div className="space-y-3 text-sm">
                <InfoRow label="Versão" value="1.0.0" />
                <InfoRow label="Descrição" value="Ferramenta de gestão de firewall Linux para servidores Debian com múltiplos links de internet" />
                <InfoRow label="Tecnologias" value="Go, React, SQLite, iptables, iproute2" />
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
            </div>
          )}

          {activeSection === 'general' && (
            <div className="card space-y-4">
              <h2 className="text-white font-semibold">Configurações Gerais</h2>
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
            </div>
          )}
        </div>
      </div>
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
