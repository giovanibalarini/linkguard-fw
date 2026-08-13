import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RefreshCw, Database, Download, RotateCcw, Terminal,
} from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import IconButton from '../components/ui/IconButton';
import { useAuth } from '../context/AuthContext';
import PortForwarding from '../components/PortForwarding';
import FirewallOverview from '../components/FirewallOverview';
import FirewallGroups from '../components/FirewallGroups';
import WanSteering from '../components/WanSteering';
import type { IptablesBackup, MsgLevel, NftChainInfo, SystemMetrics } from '../types';

// A aba "blocks" (Bloqueios e direcionamento) se dissolveu: os dois bloqueios
// viraram grupos do sistema, dentro de "Grupos de regras", e o direcionamento
// por WAN ganhou casa própria (spec de 2026-08-12, §3).
const TABS = [
  ['overview', 'Visão geral'],
  ['groups', 'Grupos de regras'],
  ['steering', 'Direcionamento por WAN'],
  ['portforward', 'Encaminhamento'],
  ['ruleset', 'Ruleset'],
  ['backups', 'Snapshots'],
] as const;

type Tab = (typeof TABS)[number][0];

// O âmbar do aviso é o mesmo da faixa do confirmar-ou-reverte (o `warn` do
// design system), e não por acaso: a mensagem "o prazo acabou e a alteração foi
// revertida" é o epílogo daquela faixa, e ler as duas com a mesma cor é ler a
// mesma história.
const MSG_STYLES: Record<MsgLevel, string> = {
  ok: 'border-green-500/30 bg-green-500/10 text-green-400',
  warn: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  error: 'border-red-500/30 bg-red-500/10 text-red-400',
};

function isTab(v: string | null): v is Tab {
  return !!v && TABS.some(([id]) => id === v);
}

export default function Firewall() {
  const { can } = useAuth();
  const canWrite = can('firewall.write');
  // ?tab=groups deixa outra tela apontar direto para a aba certa — é o que a
  // tela de Hosts usa para levar o admin ao grupo "Hosts bloqueados" quando
  // um bloqueio não está em vigor. Sem isso, o link só conseguiria dizer
  // "vá ao Firewall e procure".
  const [params, setParams] = useSearchParams();
  const [overview, setOverview] = useState<NftChainInfo[]>([]);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState('');
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  // A faixa de mensagem tem TRÊS tons, não dois. O terceiro nasceu de um recado
  // concreto: "o prazo acabou sem confirmação e a alteração foi revertida" não
  // é sucesso nem erro — é um aviso, e em verde ele diz ao operador o oposto do
  // que aconteceu com a mudança dele.
  //
  // Quem não passa o tom continua caindo na regra antiga (texto começando com
  // "Erro" é vermelho, o resto é verde), então as outras abas que compartilham
  // esta faixa não mudam de comportamento.
  const [msg, setMsg] = useState<{ text: string; level: MsgLevel }>({ text: '', level: 'ok' });
  const notify = (text: string, level: MsgLevel = text.startsWith('Erro') ? 'error' : 'ok') =>
    setMsg({ text, level });

  const tabParam = params.get('tab');
  const activeTab: Tab = isTab(tabParam) ? tabParam : 'overview';
  const setActiveTab = (t: Tab) => {
    const next = new URLSearchParams(params);
    if (t === 'overview') next.delete('tab');
    else next.set('tab', t);
    setParams(next, { replace: true });
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const [ov, rs, bk, sys] = await Promise.all([
        client.get<NftChainInfo[]>('/api/nftables/overview'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
        client.get<IptablesBackup[]>('/api/nftables/backups'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setOverview(ov.data ?? []);
      setRuleset(rs.data?.ruleset ?? '');
      setBackups(bk.data ?? []);
      setIfaces((sys.data?.interfaces ?? []).map((i) => i.name).filter((n) => n && n !== 'lo'));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true);
    notify('');
    try {
      await fn();
      if (ok) notify(ok);
      await fetchData();
    } catch (e: any) {
      notify(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleBackup =() => run(() => client.post('/api/nftables/backup', { label: '' }), 'Snapshot criado.');
  const handleRollback = (b: IptablesBackup) => confirm(`Restaurar o ruleset do snapshot "${b.label}"?`) && run(() => client.post('/api/nftables/rollback', { backup_id: b.id }), 'Ruleset restaurado.');

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Firewall</h1>
          <p className="text-gray-500 text-sm">Gestão nativa via nftables (table inet linkguard)</p>
        </div>
        <div className="flex gap-2">
          {canWrite && (
            <button onClick={handleBackup} disabled={busy} className="btn-secondary flex items-center gap-2 disabled:opacity-50">
              <Database className="w-4 h-4" /> Snapshot
            </button>
          )}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Atualizar
          </button>
        </div>
      </div>

      {/* O aviso de "a última reconciliação falhou" mora agora dentro de
          FirewallGroups, que é quem lê /api/nftables/groups e, portanto,
          quem tem o apply_status junto do que ele descreve. */}
      {msg.text && (
        <div className={`card border text-sm ${MSG_STYLES[msg.level]}`}>{msg.text}</div>
      )}

      <div className="flex gap-2 border-b border-gray-800 overflow-x-auto">
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap shrink-0 ${activeTab === id ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
            {id === 'backups' ? `${label} (${backups.length})` : label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : activeTab === 'overview' ? (
        <FirewallOverview
          chains={overview}
          onOpenGroupsTab={() => setActiveTab('groups')}
          onOpenSteeringTab={() => setActiveTab('steering')}
          onOpenPortForwardTab={() => setActiveTab('portforward')}
        />
      ) : activeTab === 'groups' ? (
        <FirewallGroups ifaces={ifaces} canWrite={canWrite} onMsg={notify} />
      ) : activeTab === 'steering' ? (
        <WanSteering canWrite={canWrite} onMsg={notify} />
      ) : activeTab === 'portforward' ? (
        <PortForwarding ifaces={ifaces} canWrite={canWrite} onMsg={notify} />
      ) : activeTab === 'ruleset' ? (
        <Panel className="p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500"><Terminal className="w-3.5 h-3.5" /><span className="font-mono">nft list ruleset</span></div>
          {ruleset.trim() ? <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre> : <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>}
        </Panel>
      ) : (
        <>
          {/* I-1: Restore (`nft -f`) reloads everything the snapshot
              captured — WAN steering, bloqueios, encaminhamentos de porta,
              as chains estruturais — but suas regras personalizadas (aba
              "Grupos de regras") continuam vindo do banco de dados, não do
              snapshot: logo após restaurar, elas são reaplicadas por cima de
              qualquer coisa que o snapshot tinha em user_rules. Um
              "Restaurar" não desfaz uma alteração feita nas suas regras
              desde o snapshot — só nos outros elementos do firewall. */}
          <p className="text-gray-500 text-xs">
            Restaurar um snapshot recarrega direcionamento por WAN, destinos bloqueados, encaminhamentos de porta e as chains internas exatamente como estavam.
            As suas regras personalizadas (aba "Grupos de regras") não fazem parte do snapshot — elas continuam vindo do banco de dados e são reaplicadas por cima logo em seguida.
          </p>
          <Panel>
          {backups.length === 0 ? (
            <div className="text-center py-12"><Download className="w-12 h-12 text-gray-700 mx-auto mb-3" /><p className="text-gray-400">Nenhum snapshot disponível</p></div>
          ) : (
            <>
              {/* Mobile: stacked cards (< sm) */}
              <div className="sm:hidden space-y-2">
                {backups.map((b) => (
                  <div key={b.id} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-white font-medium truncate">{b.label}</div>
                      </div>
                      {canWrite && (
                        <IconButton
                          icon={RotateCcw}
                          onClick={() => handleRollback(b)}
                          disabled={busy}
                          label="Restaurar"
                          className="shrink-0"
                        />
                      )}
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                      <dt className="text-gray-500">Tamanho</dt>
                      <dd className="text-gray-400 font-mono">{(b.rules.length / 1024).toFixed(1)} KB</dd>
                      <dt className="text-gray-500">Data</dt>
                      <dd className="text-gray-400 font-mono">{new Date(b.created_at).toLocaleString()}</dd>
                    </dl>
                  </div>
                ))}
              </div>

              {/* Desktop: table (>= sm) */}
              <div className="hidden sm:block overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="text-left text-gray-500 border-b border-gray-800"><th className="pb-3 pr-4 font-medium">Label</th><th className="pb-3 pr-4 font-medium">Tamanho</th><th className="pb-3 pr-4 font-medium">Data</th>{canWrite && <th className="pb-3 font-medium">Ações</th>}</tr></thead>
                  <tbody>
                    {backups.map((b) => (
                      <tr key={b.id} className="table-row">
                        <td className="py-3 pr-4 text-white">{b.label}</td>
                        <td className="py-3 pr-4 text-gray-400">{(b.rules.length / 1024).toFixed(1)} KB</td>
                        <td className="py-3 pr-4 text-gray-400">{new Date(b.created_at).toLocaleString()}</td>
                        {canWrite && (
                          <td className="py-3">
                            <IconButton
                              icon={RotateCcw}
                              onClick={() => handleRollback(b)}
                              disabled={busy}
                              label="Restaurar"
                            />
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          </Panel>
        </>
      )}

    </div>
  );
}
