import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Shield, Database, Download, Pencil, Trash2, Plus } from 'lucide-react';
import client from '../api/client';
import type { IptablesTable, IptablesBackup, SystemMetrics } from '../types';

type RuleModalMode = 'create' | 'edit' | 'delete' | null;

interface RuleModalState {
  mode: RuleModalMode;
  table: string;
  chain: string;
  line: number;
  source: string;
  destination: string;
  inInterface: string;
  outInterface: string;
  protocol: string;
  jump: string;
  sourcePort: string;
  destinationPort: string;
  extra: string;
}

interface RuleFormOption {
  value: string;
  label: string;
}

const protocolOptions = ['all', 'tcp', 'udp', 'icmp', 'esp', 'ah'];
const jumpOptions = ['ACCEPT', 'DROP', 'REJECT', 'RETURN', 'LOG', 'MARK', 'MASQUERADE', 'SNAT', 'DNAT'];
const knownTables = ['filter', 'nat', 'mangle', 'raw', 'security'];
const knownChains = ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING'];

function parseRuleSpec(ruleSpec: string) {
  const tokens: string[] = String(ruleSpec || '').trim().match(/(?:[^"]+|"[^"]*")+/g) || [];
  const valueFor = (flag: string) => {
    const idx = tokens.indexOf(flag);
    if (idx >= 0 && idx + 1 < tokens.length) {
      return tokens[idx + 1].replace(/^"|"$/g, '');
    }
    return '';
  };
  const jump = valueFor('-j');
  const extraFlags = ['-m', '--dport', '--sport', '--dports', '--sports', '--ctstate', '--state', '--tcp-flags', '--mark'];
  const extras: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (['-s', '-d', '-i', '-o', '-p', '-j'].includes(token)) {
      i++;
      continue;
    }
    if (extraFlags.includes(token)) {
      extras.push(token);
      if (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) {
        extras.push(tokens[i + 1]);
        i++;
      }
      continue;
    }
    extras.push(token);
  }

  return {
    source: valueFor('-s'),
    destination: valueFor('-d'),
    inInterface: valueFor('-i'),
    outInterface: valueFor('-o'),
    protocol: valueFor('-p') || 'all',
    jump,
    sourcePort: valueFor('--sport') || valueFor('--sports'),
    destinationPort: valueFor('--dport') || valueFor('--dports'),
    extra: extras.join(' ').trim(),
  };
}

function buildRuleSpec(form: RuleModalState) {
  const parts: string[] = [];
  if (form.source.trim()) parts.push('-s', form.source.trim());
  if (form.destination.trim()) parts.push('-d', form.destination.trim());
  if (form.inInterface.trim()) parts.push('-i', form.inInterface.trim());
  if (form.outInterface.trim()) parts.push('-o', form.outInterface.trim());
  if (form.protocol.trim() && form.protocol !== 'all') parts.push('-p', form.protocol.trim());
  if (form.sourcePort.trim()) parts.push('--sport', form.sourcePort.trim());
  if (form.destinationPort.trim()) parts.push('--dport', form.destinationPort.trim());
  if (form.extra.trim()) parts.push(form.extra.trim());
  if (form.jump.trim()) parts.push('-j', form.jump.trim());
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

function buildRuleSpecPreview(form: RuleModalState) {
  return buildRuleSpec(form) || 'Preencha os campos para montar a regra.';
}

function chainOptionsForTable(table: string, currentChains: string[] = []): RuleFormOption[] {
  const options = new Set<string>(currentChains);
  if (table === 'filter') {
    ['INPUT', 'FORWARD', 'OUTPUT'].forEach((item) => options.add(item));
  } else if (table === 'nat') {
    ['PREROUTING', 'POSTROUTING', 'OUTPUT'].forEach((item) => options.add(item));
  } else if (table === 'mangle') {
    ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'].forEach((item) => options.add(item));
  } else if (table === 'raw') {
    ['PREROUTING', 'OUTPUT'].forEach((item) => options.add(item));
  } else if (table === 'security') {
    ['INPUT', 'FORWARD', 'OUTPUT'].forEach((item) => options.add(item));
  }
  return Array.from(options)
    .filter(Boolean)
    .sort()
    .map((value) => ({ value, label: value }));
}

export default function Firewall() {
  const [tables, setTables] = useState<IptablesTable[]>([]);
  const [backups, setBackups] = useState<IptablesBackup[]>([]);
  const [interfaces, setInterfaces] = useState<string[]>([]);
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
    source: '',
    destination: '',
    inInterface: '',
    outInterface: '',
    protocol: 'all',
    jump: 'ACCEPT',
    sourcePort: '',
    destinationPort: '',
    extra: '',
  });

  const fetchData = async () => {
    setLoading(true);
    try {
      const [tablesRes, backupsRes, sysRes] = await Promise.all([
        client.get<IptablesTable[]>('/api/iptables/rules'),
        client.get<IptablesBackup[]>('/api/firewall/backups'),
        client.get<SystemMetrics>('/api/system/status'),
      ]);
      setTables(tablesRes.data ?? []);
      setBackups(backupsRes.data ?? []);
      setInterfaces((sysRes.data?.interfaces ?? []).map((iface) => iface.name).filter((name) => name && name !== 'lo'));
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

  const modalSpec = useMemo(() => buildRuleSpec(modal), [modal]);

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
  const tableOptions = useMemo(() => {
    const map = new Map<string, IptablesTable>();
    for (const table of tables) {
      map.set(table.name, table);
    }
    for (const tableName of knownTables) {
      if (!map.has(tableName)) {
        map.set(tableName, { name: tableName, chains: [] });
      }
    }
    return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, [tables]);

  const interfaceOptions = useMemo(() => interfaces.map((name) => ({ value: name, label: name })), [interfaces]);

  const activeTableData = tables.find((table) => table.name === activeTable) ?? tableOptions.find((table) => table.name === activeTable) ?? null;

  const openCreateModal = () => {
    const table = activeTableData?.name || 'filter';
    const chain = (activeTableData?.chains[0]?.name) || chainOptionsForTable(table)[0]?.value || 'INPUT';
    const activeChain = activeTableData?.chains.find((item) => item.name === chain);
    setModal({
      mode: 'create',
      table,
      chain,
      line: 0,
      source: '',
      destination: '',
      inInterface: '',
      outInterface: '',
      protocol: 'tcp',
      jump: activeChain?.policy || 'ACCEPT',
      sourcePort: '',
      destinationPort: '',
      extra: '',
    });
  };

  const openEditModal = (table: string, chain: string, line: number, currentSpec: string) => {
    const parsed = parseRuleSpec(currentSpec);
    setModal({
      mode: 'edit',
      table,
      chain,
      line,
      source: parsed.source,
      destination: parsed.destination,
      inInterface: parsed.inInterface,
      outInterface: parsed.outInterface,
      protocol: parsed.protocol,
      jump: parsed.jump || 'ACCEPT',
      sourcePort: parsed.sourcePort,
      destinationPort: parsed.destinationPort,
      extra: parsed.extra,
    });
  };

  const openDeleteModal = (table: string, chain: string, line: number) => {
    setModal({
      mode: 'delete',
      table,
      chain,
      line,
      source: '',
      destination: '',
      inInterface: '',
      outInterface: '',
      protocol: 'all',
      jump: '',
      sourcePort: '',
      destinationPort: '',
      extra: '',
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
      if (!modalSpec.trim()) {
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
          rule_spec: modalSpec,
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
      await handleEditRule(modal.table, modal.chain, modal.line, modalSpec);
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
          <div className="flex flex-wrap gap-2">
            {tableOptions.map((t) => (
              <button
                key={t.name}
                onClick={() => setActiveTable(t.name)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  activeTable === t.name ? 'bg-blue-600/20 text-blue-400' : 'bg-gray-800 text-gray-400 hover:text-gray-200'
                }`}
              >
                {t.name}
              </button>
            ))}
          </div>

          {loading ? (
            <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
          ) : !activeTableData ? (
            <div className="card text-center py-8">
              <Shield className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">Tabela não disponível</p>
            </div>
          ) : (
            activeTableData.chains.map(chain => (
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
                      <div
                        key={i}
                        className="bg-gray-800 rounded px-3 py-2 font-mono text-xs text-gray-300 flex items-center justify-between gap-3 cursor-pointer hover:bg-gray-700/70 transition-colors"
                        onClick={() => openEditModal(activeTableData.name, chain.name, Number(rule.num || i + 1), defaultRuleSpec(rule))}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            openEditModal(activeTableData.name, chain.name, Number(rule.num || i + 1), defaultRuleSpec(rule));
                          }
                        }}
                      >
                        <div className="overflow-x-auto">
                          <span className="text-gray-500 mr-3 select-none">{rule.num || i + 1}</span>
                          {rule.raw}
                        </div>
                        <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => openEditModal(activeTableData.name, chain.name, Number(rule.num || i + 1), defaultRuleSpec(rule))}
                            disabled={updatingRule}
                            className="text-gray-400 hover:text-blue-400 transition-colors disabled:opacity-50"
                            title="Editar regra"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => openDeleteModal(activeTableData.name, chain.name, Number(rule.num || i + 1))}
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
                  <select
                    className="input w-full"
                    value={modal.table}
                    onChange={(e) => {
                      const nextTable = e.target.value;
                      const nextChains = chainOptionsForTable(nextTable, tables.find((table) => table.name === nextTable)?.chains.map((chain) => chain.name) || []);
                      setModal({
                        ...modal,
                        table: nextTable,
                        chain: nextChains[0]?.value || '',
                      });
                    }}
                    disabled={modal.mode === 'edit' || modal.mode === 'delete'}
                  >
                    {tableOptions.map((table) => (
                      <option key={table.name} value={table.name}>{table.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label">Chain</label>
                  <select
                    className="input w-full"
                    value={modal.chain}
                    onChange={(e) => setModal({ ...modal, chain: e.target.value })}
                    disabled={modal.mode === 'edit' || modal.mode === 'delete'}
                  >
                    {chainOptionsForTable(modal.table, tables.find((table) => table.name === modal.table)?.chains.map((chain) => chain.name) || []).map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label">Linha</label>
                  <input type="number" min={0} className="input w-full" value={modal.line} onChange={(e) => setModal({ ...modal, line: Number(e.target.value || 0) })} disabled={modal.mode === 'delete'} />
                </div>
              </div>

              {modal.mode !== 'delete' ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="label">Origem (-s)</label>
                      <input className="input w-full" placeholder="192.168.0.0/24 ou ! 10.0.0.0/8" value={modal.source} onChange={(e) => setModal({ ...modal, source: e.target.value })} />
                    </div>
                    <div>
                      <label className="label">Destino (-d)</label>
                      <input className="input w-full" placeholder="0.0.0.0/0, IP ou CIDR" value={modal.destination} onChange={(e) => setModal({ ...modal, destination: e.target.value })} />
                    </div>
                    <div>
                      <label className="label">Interface entrada (-i)</label>
                      <select className="input w-full" value={modal.inInterface} onChange={(e) => setModal({ ...modal, inInterface: e.target.value })}>
                        <option value="">Selecione</option>
                        {interfaceOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Interface saída (-o)</label>
                      <select className="input w-full" value={modal.outInterface} onChange={(e) => setModal({ ...modal, outInterface: e.target.value })}>
                        <option value="">Selecione</option>
                        {interfaceOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Protocolo (-p)</label>
                      <select className="input w-full" value={modal.protocol} onChange={(e) => setModal({ ...modal, protocol: e.target.value })}>
                        {protocolOptions.map((option) => <option key={option} value={option}>{option}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Ação / Jump (-j)</label>
                      <select className="input w-full" value={modal.jump} onChange={(e) => setModal({ ...modal, jump: e.target.value })}>
                        {jumpOptions.map((option) => <option key={option} value={option}>{option}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Porta origem (--sport)</label>
                      <input className="input w-full" placeholder="443, 1024:65535..." value={modal.sourcePort} onChange={(e) => setModal({ ...modal, sourcePort: e.target.value })} />
                    </div>
                    <div>
                      <label className="label">Porta destino (--dport)</label>
                      <input className="input w-full" placeholder="80,443,1000:2000..." value={modal.destinationPort} onChange={(e) => setModal({ ...modal, destinationPort: e.target.value })} />
                    </div>
                  </div>

                  <div>
                    <label className="label">Opções extras</label>
                    <textarea
                      className="input w-full min-h-24"
                      value={modal.extra}
                      onChange={(e) => setModal({ ...modal, extra: e.target.value })}
                      placeholder='-m conntrack --ctstate NEW,ESTABLISHED'
                    />
                    <p className="text-xs text-gray-500 mt-1">Use aqui só o que não entrou nos campos guiados. O preview abaixo é o spec final da regra.</p>
                  </div>

                  <div className="rounded-lg border border-gray-700 bg-gray-950/60 p-3">
                    <label className="label mb-2 block">Preview do rule spec</label>
                    <div className="font-mono text-xs text-gray-200 break-all">{buildRuleSpecPreview(modal)}</div>
                  </div>
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
