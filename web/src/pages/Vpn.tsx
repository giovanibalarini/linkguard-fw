import { useEffect, useState } from 'react';
import {
  Lock, Plus, Trash2, RefreshCw, Loader2, Power, Copy, Download, X, Check, Smartphone,
} from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import HelpTip from '../components/HelpTip';
import Panel from '../components/ui/Panel';
import Modal from '../components/ui/Modal';
import type { VPNView, VPNConfig, AddPeerResponse } from '../types';

export default function Vpn() {
  const { can } = useAuth();
  const canWrite = can('vpn.write');
  const [view, setView] = useState<VPNView | null>(null);
  const [form, setForm] = useState<Partial<VPNConfig>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [newName, setNewName] = useState('');
  const [reveal, setReveal] = useState<{ name: string; config: string } | null>(null);

  const fetchData = async () => {
    try {
      const { data } = await client.get<VPNView>('/api/vpn');
      setView(data);
      setForm(data.config);
    } catch { setMsg('Erro ao carregar.'); }
  };
  useEffect(() => { fetchData(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(''), 4000); };

  const saveConfig = async (override?: Partial<VPNConfig>) => {
    setBusy(true);
    try {
      const body = { ...form, ...override };
      const { data } = await client.put<VPNView>('/api/vpn/config', body);
      setView(data); setForm(data.config);
      flash('Configuração aplicada.');
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const toggleEnabled = () => saveConfig({ enabled: !form.enabled });

  const addPeer = async () => {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      const { data } = await client.post<AddPeerResponse>('/api/vpn/peers', { name: newName.trim() });
      setNewName('');
      setReveal({ name: data.peer.name, config: data.config });
      await fetchData();
    } catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const delPeer = async (id: string) => {
    setBusy(true);
    try { await client.delete(`/api/vpn/peers/${id}`); await fetchData(); flash('Cliente removido.'); }
    catch (e) { flash('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const showPeerConfig = async (id: string, name: string) => {
    try {
      const { data } = await client.get<{ config: string }>(`/api/vpn/peers/${id}/config`);
      setReveal({ name, config: data.config });
    } catch (e) { flash('Erro: ' + errMsg(e)); }
  };

  if (!view) return <div className="p-6 text-gray-500 animate-pulse">Carregando...</div>;
  const online = view.status.trim() !== '';
  const cfg = view.config;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-blue-400" /> VPN (WireGuard)
            <HelpTip title="Para que serve a VPN?">
              <>Permite que você acesse a sua <b>rede de casa com segurança quando está fora</b> —
              como se o seu celular/notebook estivesse dentro de casa. Cada aparelho vira um "cliente"
              com sua própria chave.</>
            </HelpTip>
          </h1>
          <p className="text-gray-500 text-sm">Acesso remoto seguro à sua rede</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Atualizar</button>
          {canWrite && (
            <button onClick={toggleEnabled} disabled={busy}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${cfg.enabled ? 'bg-green-600/20 text-green-400 border border-green-600/30' : 'bg-gray-800 text-gray-400 border border-gray-700'}`}>
              <Power className="w-4 h-4" /> {cfg.enabled ? 'Ativada' : 'Desativada'}
            </button>
          )}
        </div>
      </div>

      {msg && <div className={`card border text-sm ${msg.startsWith('Erro') ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>{msg}</div>}

      {/* Status */}
      <Panel>
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${cfg.enabled && online ? 'bg-green-400' : cfg.enabled ? 'bg-amber-400' : 'bg-gray-600'}`} />
          <span className="text-white font-medium">
            {!cfg.enabled ? 'VPN desativada' : online ? 'Servidor WireGuard ativo' : 'Ativada (aguardando interface)'}
          </span>
          {cfg.public_key && <span className="text-gray-600 text-xs font-mono ml-auto truncate max-w-[40%]">srv: {cfg.public_key}</span>}
        </div>
        {online && <pre className="mt-3 text-xs font-mono text-gray-400 overflow-x-auto whitespace-pre-wrap">{view.status}</pre>}
      </Panel>

      {/* Server settings */}
      <Panel title="Servidor">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="Endereço público (endpoint)" hint="IP público ou DDNS pelo qual os clientes chegam">
            <input value={form.endpoint ?? ''} onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
              placeholder="ex.: meufirewall.duckdns.org" disabled={!canWrite}
              className="input" />
          </Field>
          <Field label="Porta (UDP)">
            <input type="number" value={form.listen_port ?? 51820} onChange={(e) => setForm({ ...form, listen_port: Number(e.target.value) })}
              disabled={!canWrite} className="input" />
          </Field>
          <Field label="Sub-rede da VPN" hint="Faixa interna dos clientes">
            <input value={form.subnet ?? ''} onChange={(e) => setForm({ ...form, subnet: e.target.value })}
              placeholder="10.7.0.0/24" disabled={!canWrite} className="input font-mono" />
          </Field>
          <Field label="DNS para clientes" hint="Geralmente o IP do firewall (unbound)">
            <input value={form.dns ?? ''} onChange={(e) => setForm({ ...form, dns: e.target.value })}
              placeholder="10.7.0.1" disabled={!canWrite} className="input font-mono" />
          </Field>
        </div>
        {canWrite && (
          <button onClick={() => saveConfig()} disabled={busy} className="btn-primary mt-4 flex items-center gap-2">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Salvar e aplicar
          </button>
        )}
        <p className="text-gray-600 text-xs mt-2">A porta {form.listen_port ?? 51820}/UDP precisa chegar ao firewall (encaminhe no modem se houver).</p>
      </Panel>

      {/* Clients */}
      <Panel title={<span className="flex items-center gap-2"><Smartphone className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Clientes ({cfg.peers.length})</span></span>}>

        {canWrite && (
          <div className="flex gap-2 mb-4">
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Nome do aparelho (ex.: Meu celular)"
              className="input flex-1" onKeyDown={(e) => e.key === 'Enter' && addPeer()} />
            <button onClick={addPeer} disabled={busy || !newName.trim()} className="btn-primary flex items-center gap-1.5 disabled:opacity-50">
              <Plus className="w-4 h-4" /> Adicionar
            </button>
          </div>
        )}

        {cfg.peers.length === 0 ? (
          <p className="text-gray-600 text-sm">Nenhum cliente. Adicione um aparelho para gerar a configuração.</p>
        ) : (
          <div className="space-y-2">
            {cfg.peers.map((p) => (
              <div key={p.id} className="flex items-center gap-3 bg-gray-800/50 rounded-lg px-3 py-2">
                <Smartphone className="w-4 h-4 text-gray-500 shrink-0" />
                <span className="text-white text-sm font-medium min-w-0 truncate">{p.name}</span>
                <span className="text-gray-500 text-xs font-mono">{p.allowed_ip}</span>
                <div className="ml-auto flex items-center gap-1">
                  <button onClick={() => showPeerConfig(p.id, p.name)} className="text-gray-400 hover:text-blue-400 p-1" title="Ver configuração">
                    <Download className="w-4 h-4" />
                  </button>
                  {canWrite && (
                    <button onClick={() => delPeer(p.id)} disabled={busy} className="text-gray-400 hover:text-red-400 p-1" title="Remover">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {reveal && <PeerConfigModal name={reveal.name} config={reveal.config} onClose={() => setReveal(null)} />}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-gray-400 text-xs">{label}</span>
      {children}
      {hint && <span className="text-gray-600 text-xs mt-0.5 block">{hint}</span>}
    </label>
  );
}

function PeerConfigModal({ name, config, onClose }: { name: string; config: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(config); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const download = () => {
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${name.replace(/\s+/g, '-').toLowerCase()}.conf`;
    a.click(); URL.revokeObjectURL(url);
  };
  return (
    <Modal
      open
      onClose={onClose}
      closeOnBackdropClick
      title={`Configuração de "${name}"`}
      size="md"
      className="bg-gray-900 border border-gray-800 rounded-xl p-5"
      action={<button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="w-5 h-5" /></button>}
    >
      <p className="text-gray-500 text-xs mb-3">Importe este arquivo no app WireGuard do aparelho (ou cole o conteúdo). Guarde com cuidado: contém a chave privada do cliente.</p>
      <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre max-h-60">{config}</pre>
      <div className="flex gap-2 mt-4">
        <button onClick={copy} className="btn-secondary flex items-center gap-1.5 text-sm">
          {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />} {copied ? 'Copiado' : 'Copiar'}
        </button>
        <button onClick={download} className="btn-primary flex items-center gap-1.5 text-sm"><Download className="w-4 h-4" /> Baixar .conf</button>
      </div>
    </Modal>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
