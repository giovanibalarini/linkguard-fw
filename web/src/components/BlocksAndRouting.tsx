import { useEffect, useState } from 'react';
import { Plus, X, Network, Ban, ShieldOff, ShieldAlert } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import type { NftManaged } from '../types';

interface Props {
  canWrite: boolean;
  onMsg: (m: string) => void;
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } }; message?: string };
  return ax?.response?.data?.error || ax?.message || 'falha na operação';
}

/**
 * BlocksAndRouting is "Bloqueios e direcionamento" (design spec §7): the
 * three panels that decide what never reaches a rule group at all —
 * direcionamento por WAN, destinos bloqueados e hosts bloqueados. Moved out
 * of the groups tab in Task 10, unchanged in behaviour and endpoints; only
 * the home changed.
 *
 * Ordem de avaliação (spec §3): a razão de ter uma aba própria é que, desde
 * a inversão, tudo aqui é avaliado ANTES dos grupos de regras e sempre
 * vence — um "accept" de grupo não desfaz um bloqueio feito aqui. Isso era o
 * contrário até esta entrega (as regras do admin venciam), então a faixa
 * abaixo é fixa, não uma mensagem transitória.
 */
export default function BlocksAndRouting({ canWrite, onMsg }: Props) {
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [newWan, setNewWan] = useState('');
  const [newBlock, setNewBlock] = useState('');

  const load = async () => {
    try {
      const { data } = await client.get<NftManaged>('/api/nftables/managed');
      setManaged(data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
    } catch (e) {
      onMsg('Erro: ' + errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    onMsg('');
    try {
      await fn();
      onMsg(ok);
      await load();
    } catch (e) {
      onMsg('Erro: ' + errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const addWan = () => newWan.trim() && run(() => client.post('/api/nftables/wan-host', { ip: newWan.trim() }), 'Host direcionado para a WAN2.').then(() => setNewWan(''));
  const delWan = (ip: string) => run(() => client.delete('/api/nftables/wan-host', { data: { ip } }), 'Host revertido para a WAN1.');
  const addBlock = () => newBlock.trim() && run(() => client.post('/api/nftables/blocklist', { cidr: newBlock.trim() }), 'Destino bloqueado.').then(() => setNewBlock(''));
  const delBlock = (cidr: string) => run(() => client.delete('/api/nftables/blocklist', { data: { cidr } }), 'Destino desbloqueado.');

  if (loading) {
    return <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>;
  }

  return (
    <div className="space-y-4">
      {/* Ordem de avaliação (spec §3): faixa fixa, porque a inversão é
          mudança de comportamento numa máquina em produção. */}
      <div className="card flex items-start gap-2 text-sm">
        <ShieldAlert className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
        <p className="text-gray-300 text-xs">
          Tudo nesta aba é avaliado antes dos seus grupos de regras e sempre vence. Bloqueou aqui, nenhuma regra de grupo consegue liberar.
        </p>
      </div>

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
  );
}
