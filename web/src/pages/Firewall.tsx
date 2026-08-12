import { useEffect, useState } from 'react';
import {
  RefreshCw, Database, Download, RotateCcw, Terminal, Plus, X, Network, Ban,
  ShieldOff,
} from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import IconButton from '../components/ui/IconButton';
import { useAuth } from '../context/AuthContext';
import PortForwarding from '../components/PortForwarding';
import FirewallOverview from '../components/FirewallOverview';
import FirewallGroups from '../components/FirewallGroups';
import type { IptablesBackup, NftChainInfo, NftManaged, SystemMetrics } from '../types';

type Tab = 'overview' | 'rules' | 'portforward' | 'ruleset' | 'backups';

export default function Firewall() {
  const { can } = useAuth();
  const canWrite = can('firewall.write');
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  const [overview, setOverview] = useState<NftChainInfo[]>([]);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState('');
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [newWan, setNewWan] = useState('');
  const [newBlock, setNewBlock] = useState('');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [mg, ov, rs, bk, sys] = await Promise.all([
        client.get<NftManaged>('/api/nftables/managed'),
        client.get<NftChainInfo[]>('/api/nftables/overview'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
        client.get<IptablesBackup[]>('/api/nftables/backups'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setManaged(mg.data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
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
    setMsg('');
    try {
      await fn();
      if (ok) setMsg(ok);
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  // Managed sets/map
  const addWan = () => newWan.trim() && run(() => client.post('/api/nftables/wan-host', { ip: newWan.trim() }), 'Host direcionado para a WAN2.').then(() => setNewWan(''));
  const delWan = (ip: string) => run(() => client.delete('/api/nftables/wan-host', { data: { ip } }), 'Host revertido para a WAN1.');
  const addBlock = () => newBlock.trim() && run(() => client.post('/api/nftables/blocklist', { cidr: newBlock.trim() }), 'Destino bloqueado.').then(() => setNewBlock(''));
  const delBlock = (cidr: string) => run(() => client.delete('/api/nftables/blocklist', { data: { cidr } }), 'Destino desbloqueado.');

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
      {msg && (
        <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>
      )}

      <div className="flex gap-2 border-b border-gray-800 overflow-x-auto">
        {([['overview', 'Visão geral'], ['rules', 'Regras'], ['portforward', 'Encaminhamento'], ['ruleset', 'Ruleset'], ['backups', `Snapshots (${backups.length})`]] as [Tab, string][]).map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap shrink-0 ${activeTab === id ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>{label}</button>
        ))}
      </div>

      {loading ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : activeTab === 'overview' ? (
        <FirewallOverview
          chains={overview}
          onOpenRulesTab={() => setActiveTab('rules')}
          onOpenPortForwardTab={() => setActiveTab('portforward')}
        />
      ) : activeTab === 'rules' ? (
        <div className="space-y-4">
          <FirewallGroups ifaces={ifaces} canWrite={canWrite} onMsg={setMsg} />

          {/* WAN steering */}
          <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Direcionamento por WAN</span></span>}>
            <p className="text-gray-500 text-xs mb-3">Hosts nesta lista saem pela <span className="text-blue-300">WAN2 (sumicity)</span>; os demais pela WAN1 (padrão).</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder="IP do host (ex.: 192.168.3.50)" value={newWan} onChange={(e) => setNewWan(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addWan()} />
                <button onClick={addWan} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> Adicionar</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {managed.wan_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host direcionado.</span>}
              {managed.wan_hosts.map((h) => (
                <span key={h.ip} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{h.ip}<span className="text-blue-400 text-xs font-sans">WAN2</span>{canWrite && <button onClick={() => delWan(h.ip)} className="text-gray-500 hover:text-red-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </Panel>

          {/* Blocklist */}
          <Panel title={<span className="flex items-center gap-2"><Ban className="w-4 h-4 text-red-400" /><span className="text-white font-semibold">Destinos bloqueados</span></span>}>
            <p className="text-gray-500 text-xs mb-3">IPs/CIDRs cujo tráfego forward é descartado (origem e destino).</p>
            {canWrite && (
              <div className="flex flex-col sm:flex-row gap-2 mb-3">
                <input className="input flex-1" placeholder="CIDR ou IP (ex.: 163.116.128.0/17)" value={newBlock} onChange={(e) => setNewBlock(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addBlock()} />
                <button onClick={addBlock} disabled={busy} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50"><Plus className="w-4 h-4" /> Bloquear</button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {managed.blocklist.length === 0 && <span className="text-gray-600 text-sm">Nenhum destino bloqueado.</span>}
              {managed.blocklist.map((c) => (
                <span key={c} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{c}{canWrite && <button onClick={() => delBlock(c)} className="text-gray-500 hover:text-green-400"><X className="w-3.5 h-3.5" /></button>}</span>
              ))}
            </div>
          </Panel>

          {/* Blocked hosts (read-only) */}
          <Panel title={<span className="flex items-center gap-2"><ShieldOff className="w-4 h-4 text-orange-400" /><span className="text-white font-semibold">Hosts bloqueados</span></span>}>
            <p className="text-gray-500 text-xs mb-3">Bloqueie/desbloqueie na página <span className="text-gray-300">Hosts</span> (mantém o inventário em sincronia).</p>
            <div className="flex flex-wrap gap-2">
              {managed.blocked_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host bloqueado.</span>}
              {managed.blocked_hosts.map((ip) => (<span key={ip} className="px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">{ip}</span>))}
            </div>
          </Panel>
        </div>
      ) : activeTab === 'portforward' ? (
        <PortForwarding ifaces={ifaces} canWrite={canWrite} onMsg={setMsg} />
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
              "Regras") continuam vindo do banco de dados, não do snapshot:
              logo após restaurar, elas são reaplicadas por cima de qualquer
              coisa que o snapshot tinha em user_rules. Um "Restaurar" não
              desfaz uma alteração feita nas suas regras desde o snapshot —
              só nos outros elementos do firewall. */}
          <p className="text-gray-500 text-xs">
            Restaurar um snapshot recarrega direcionamento por WAN, destinos bloqueados, encaminhamentos de porta e as chains internas exatamente como estavam.
            As suas regras personalizadas (aba "Regras") não fazem parte do snapshot — elas continuam vindo do banco de dados e são reaplicadas por cima logo em seguida.
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
