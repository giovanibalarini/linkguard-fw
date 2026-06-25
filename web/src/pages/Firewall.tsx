import { useEffect, useState } from 'react';
import { RefreshCw, Database, Download, RotateCcw, Terminal } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { IptablesBackup } from '../types';

export default function Firewall() {
  const { can } = useAuth();
  const canWrite = can('firewall.write');
  const [ruleset, setRuleset] = useState('');
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'ruleset' | 'backups'>('ruleset');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [rs, bk] = await Promise.all([
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
        client.get<IptablesBackup[]>('/api/nftables/backups'),
      ]);
      setRuleset(rs.data?.ruleset ?? '');
      setBackups(bk.data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleBackup = async () => {
    setBusy(true);
    setMsg('');
    try {
      await client.post('/api/nftables/backup', { label: '' });
      setMsg('Snapshot do ruleset criado com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleRollback = async (b: IptablesBackup) => {
    if (!confirm(`Restaurar o ruleset do snapshot "${b.label}"? Isso recarrega o nftables.`)) return;
    setBusy(true);
    setMsg('');
    try {
      await client.post('/api/nftables/rollback', { backup_id: b.id });
      setMsg('Ruleset restaurado com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBusy(false);
    }
  };

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
              <Database className="w-4 h-4" />
              {busy ? '...' : 'Snapshot'}
            </button>
          )}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Atualizar
          </button>
        </div>
      </div>

      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
          {msg}
        </div>
      )}

      <div className="flex gap-2 border-b border-gray-800">
        <button onClick={() => setActiveTab('ruleset')} className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === 'ruleset' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          <Terminal className="w-4 h-4" /> Ruleset
        </button>
        <button onClick={() => setActiveTab('backups')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === 'backups' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          Snapshots ({backups.length})
        </button>
      </div>

      {loading ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : activeTab === 'ruleset' ? (
        <div className="card p-0 overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-800 flex items-center gap-2 text-xs text-gray-500">
            <Terminal className="w-3.5 h-3.5" />
            <span className="font-mono">nft list ruleset</span>
          </div>
          {ruleset.trim() ? (
            <pre className="p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed whitespace-pre">{ruleset}</pre>
          ) : (
            <p className="p-8 text-center text-gray-600 text-sm">Ruleset vazio.</p>
          )}
        </div>
      ) : (
        <div className="card">
          {backups.length === 0 ? (
            <div className="text-center py-12">
              <Download className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-400">Nenhum snapshot disponível</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Label</th>
                    <th className="pb-3 pr-4 font-medium">Tamanho</th>
                    <th className="pb-3 pr-4 font-medium">Data</th>
                    {canWrite && <th className="pb-3 font-medium">Ações</th>}
                  </tr>
                </thead>
                <tbody>
                  {backups.map((b) => (
                    <tr key={b.id} className="table-row">
                      <td className="py-3 pr-4 text-white">{b.label}</td>
                      <td className="py-3 pr-4 text-gray-400">{(b.rules.length / 1024).toFixed(1)} KB</td>
                      <td className="py-3 pr-4 text-gray-400">{new Date(b.created_at).toLocaleString()}</td>
                      {canWrite && (
                        <td className="py-3">
                          <button
                            onClick={() => handleRollback(b)}
                            disabled={busy}
                            className="text-gray-400 hover:text-blue-400 transition-colors flex items-center gap-1 disabled:opacity-50"
                            title="Restaurar este ruleset"
                          >
                            <RotateCcw className="w-4 h-4" /> Restaurar
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
