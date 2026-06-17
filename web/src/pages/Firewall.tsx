import { useEffect, useState } from 'react';
import { RefreshCw, Shield, Database, Download, Pencil, Trash2, Plus } from 'lucide-react';
import client from '../api/client';
import type { IptablesTable, IptablesBackup } from '../types';

type RuleModalMode = 'create' | 'edit' | 'delete' | null;

interface RuleModalState {
  mode: RuleModalMode;
  table: string;
  chain: string;
  line: number;
  ruleSpec: string;
}

export default function Firewall() {
  const [tables, setTables] = useState<IptablesTable[]>([]);
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'rules' | 'backups'>('rules');
  const [activeTable, setActiveTable] = useState<string>('filter');
  const [backingUp, setBackingUp] = useState(false);
  const [updatingRule, setUpdatingRule] = useState(false);
  const [msg, setMsg] = useState('');
  const [modal, setModal] = useState<RuleModalState>({
    mode: null,
    table: 'filter',
    chain: '',
    line: 0,
    ruleSpec: '',
  });

  const fetchData = async () => {
    setLoading(true);
    try {
      const [tablesRes, backupsRes] = await Promise.all([
        client.get<IptablesTable[]>('/api/iptables/rules'),
        client.get<IptablesBackup[]>('/api/firewall/backups'),
      ]);
      setTables(tablesRes.data ?? []);
      setBackups(backupsRes.data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleBackup = async () => {
    setBackingUp(true);
    setMsg('');
    try {
      await client.post('/api/firewall/backup', { label: '' });
      setMsg('Backup criado com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setBackingUp(false);
    }
  };

  const defaultRuleSpec = (rule: any) => {
    if (rule.options && rule.options.length > 0) {
      return rule.options.join(' ');
    }
    const parts = String(rule.raw || '').trim().split(/\s+/);
    if (parts.length > 10) {
      return parts.slice(10).join(' ');
    }
    return '';
  };

  const handleDeleteRule = async (table: string, chain: string, line: number) => {
    setUpdatingRule(true);
    setMsg('');
    try {
      await client.delete('/api/firewall/rules', { data: { table, chain, line } });
      setMsg('Regra removida com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setUpdatingRule(false);
    }
  };

  const handleEditRule = async (table: string, chain: string, line: number, currentSpec: string) => {
    if (!currentSpec.trim()) {
      setMsg('Erro: rule spec não pode ser vazio.');
      return;
    }
    setUpdatingRule(true);
    setMsg('');
    try {
      await client.put('/api/firewall/rules', {
        table,
        chain,
        line,
        rule_spec: currentSpec.trim(),
      });
      setMsg('Regra atualizada com sucesso!');
      await fetchData();
    } catch (e: any) {
      setMsg(`Erro: ${e.response?.data?.error || e.message}`);
    } finally {
      setUpdatingRule(false);
    }
  };

  const currentTable = tables.find(t => t.name === activeTable);

  const openCreateModal = () => {
    const chain = currentTable?.chains[0]?.name || 'INPUT';
    setModal({
      mode: 'create',
      table: activeTable,
      chain,
      line: 0,
      ruleSpec: '-s 192.168.0.0/24 -p tcp --dport 443 -j ACCEPT',
    });
  };

  const openEditModal = (table: string, chain: string, line: number, currentSpec: string) => {
    setModal({
      mode: 'edit',
      table,
      chain,
      line,
      ruleSpec: currentSpec,
    });
  };

  const openDeleteModal = (table: string, chain: string, line: number) => {
    setModal({
      mode: 'delete',
      table,
      chain,
      line,
      ruleSpec: '',
    });
  };

  const closeModal = () => {
    setModal((m) => ({ ...m, mode: null }));
  };

  const submitModal = async () => {
    if (!modal.mode) return;
    if (!modal.table || !modal.chain) {
      setMsg('Erro: tabela e chain são obrigatórias.');
      return;
    }

    if (modal.mode === 'create') {
      if (!modal.ruleSpec.trim()) {
        setMsg('Erro: rule spec não pode ser vazio.');
        return;
      }
      setUpdatingRule(true);
      setMsg('');
      try {
        await client.post('/api/firewall/rules', {
          table: modal.table,
          chain: modal.chain,
          line: modal.line > 0 ? modal.line : 0,
          rule_spec: modal.ruleSpec.trim(),
        });
        setMsg('Regra criada com sucesso!');
        closeModal();
        await fetchData();
      } catch (e: any) {
        setMsg(`Erro: ${e.response?.data?.error || e.message}`);
      } finally {
        setUpdatingRule(false);
      }
      return;
    }

    if (modal.mode === 'edit') {
      await handleEditRule(modal.table, modal.chain, modal.line, modal.ruleSpec);
      closeModal();
      return;
    }

    await handleDeleteRule(modal.table, modal.chain, modal.line);
    closeModal();
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Firewall</h1>
          <p className="text-gray-500 text-sm">Regras iptables com edição assistida e backup automático</p>
        </div>
        <div className="flex gap-2">
          {activeTab === 'rules' && (
            <button onClick={openCreateModal} className="btn-primary flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Nova Regra
            </button>
          )}
          <button onClick={handleBackup} disabled={backingUp} className="btn-secondary flex items-center gap-2 disabled:opacity-50">
            <Database className="w-4 h-4" />
            {backingUp ? 'Salvando...' : 'Backup'}
          </button>
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Atualizar
          </button>
        </div>
      </div>

      {msg && (
        <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
          {msg}
        </div>
      )}

      <div className="flex gap-2 border-b border-gray-800">
        <button onClick={() => setActiveTab('rules')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === 'rules' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          Regras
        </button>
        <button onClick={() => setActiveTab('backups')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeTab === 'backups' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
          Backups ({backups.length})
        </button>
      </div>

      {activeTab === 'rules' ? (
        <>
          {/* Table tabs */}
          <div className="flex gap-2">
            {['filter', 'nat', 'mangle'].map(t => (
              <button
                key={t}
                onClick={() => setActiveTable(t)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  activeTable === t ? 'bg-blue-600/20 text-blue-400' : 'bg-gray-800 text-gray-400 hover:text-gray-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {loading ? (
            <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
          ) : !currentTable ? (
            <div className="card text-center py-8">
              <Shield className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">Tabela não disponível</p>
            </div>
          ) : (
            currentTable.chains.map(chain => (
              <div key={chain.name} className="card">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-white font-mono font-semibold">{chain.name}</h3>
                  {chain.policy && (
                    <span className="text-xs text-gray-500">Política: <span className="text-gray-300">{chain.policy}</span></span>
                  )}
                </div>
                {!chain.rules || chain.rules.length === 0 ? (
                  <p className="text-gray-600 text-sm">Nenhuma regra</p>
                ) : (
                  <div className="space-y-1">
                    {chain.rules.map((rule, i) => (
                      <div key={i} className="bg-gray-800 rounded px-3 py-2 font-mono text-xs text-gray-300 flex items-center justify-between gap-3">
                        <div className="overflow-x-auto">
                          <span className="text-gray-500 mr-3 select-none">{rule.num || i + 1}</span>
                          {rule.raw}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            onClick={() => openEditModal(currentTable.name, chain.name, Number(rule.num || i + 1), defaultRuleSpec(rule))}
                            disabled={updatingRule}
                            className="text-gray-400 hover:text-blue-400 transition-colors disabled:opacity-50"
                            title="Editar regra"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => openDeleteModal(currentTable.name, chain.name, Number(rule.num || i + 1))}
                            disabled={updatingRule}
                            className="text-gray-400 hover:text-red-400 transition-colors disabled:opacity-50"
                            title="Remover regra"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </>
      ) : (
        <div className="card">
          {backups.length === 0 ? (
            <div className="text-center py-12">
              <Download className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-400">Nenhum backup disponível</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">Label</th>
                    <th className="pb-3 pr-4 font-medium">Tamanho</th>
                    <th className="pb-3 font-medium">Data</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map(b => (
                    <tr key={b.id} className="table-row">
                      <td className="py-3 pr-4 text-white">{b.label}</td>
                      <td className="py-3 pr-4 text-gray-400">{(b.rules.length / 1024).toFixed(1)} KB</td>
                      <td className="py-3 text-gray-400">{new Date(b.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {modal.mode && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-800">
              <h3 className="text-white font-semibold">
                {modal.mode === 'create' && 'Nova Regra de Firewall'}
                {modal.mode === 'edit' && 'Editar Regra de Firewall'}
                {modal.mode === 'delete' && 'Confirmar Remoção'}
              </h3>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="label">Tabela</label>
                  <input className="input w-full" value={modal.table} onChange={(e) => setModal({ ...modal, table: e.target.value })} disabled={modal.mode === 'edit' || modal.mode === 'delete'} />
                </div>
                <div>
                  <label className="label">Chain</label>
                  <input className="input w-full" value={modal.chain} onChange={(e) => setModal({ ...modal, chain: e.target.value })} disabled={modal.mode === 'edit' || modal.mode === 'delete'} />
                </div>
                <div>
                  <label className="label">Linha</label>
                  <input type="number" min={0} className="input w-full" value={modal.line} onChange={(e) => setModal({ ...modal, line: Number(e.target.value || 0) })} disabled={modal.mode === 'delete'} />
                </div>
              </div>

              {modal.mode !== 'delete' ? (
                <div>
                  <label className="label">Rule Spec</label>
                  <textarea
                    className="input w-full min-h-28"
                    value={modal.ruleSpec}
                    onChange={(e) => setModal({ ...modal, ruleSpec: e.target.value })}
                    placeholder="-s 192.168.0.0/24 -p tcp --dport 443 -j ACCEPT"
                  />
                  <p className="text-xs text-gray-500 mt-1">Dica: inclua apenas o spec da regra, sem -A/-I chain.</p>
                </div>
              ) : (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                  Remover regra {modal.table}/{modal.chain} na linha {modal.line}? Um backup automático será criado antes da alteração.
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button onClick={submitModal} disabled={updatingRule} className="btn-primary flex-1 disabled:opacity-50">
                  {updatingRule ? 'Processando...' : modal.mode === 'delete' ? 'Confirmar Remoção' : 'Salvar'}
                </button>
                <button onClick={closeModal} type="button" className="btn-secondary flex-1">Cancelar</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
