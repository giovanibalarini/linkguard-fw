import { useEffect, useState } from 'react';
import { Plus, X, Network } from 'lucide-react';
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
 * WanSteering é a aba "Direcionamento por WAN" (spec de 2026-08-12, §3).
 *
 * Ela existe separada porque este é o único controle do firewall que NÃO
 * filtra: ele não decide se o pacote passa, decide por qual porta ele sai.
 * Acontece em outra chain (`mark_hosts`, hook prerouting, mangle), num
 * estágio anterior ao dos grupos — misturá-lo na lista de grupos diria ao
 * admin que ele é avaliado junto com os outros, o que é falso.
 *
 * E fica dentro do Firewall, não na tela de Hosts, porque por baixo é uma
 * regra de nftables como qualquer outra: mandar o admin sair do firewall
 * para mexer numa regra de firewall foi rejeitado pelo operador.
 *
 * A aba antiga "Bloqueios e direcionamento" (BlocksAndRouting) se dissolveu:
 * os dois bloqueios viraram grupos do sistema, na lista de grupos.
 */
export default function WanSteering({ canWrite, onMsg }: Props) {
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [newWan, setNewWan] = useState('');

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

  if (loading) {
    return <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>;
  }

  return (
    <div className="space-y-4">
      <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">Direcionamento por WAN</span></span>}>
        {/* A explicação da spec §3, palavra por palavra: este controle é o
            único do firewall que não filtra, e sem essa frase ele parece
            mais um bloqueio. */}
        <p className="text-gray-400 text-sm mb-1">
          Estes hosts saem pela <span className="text-blue-300">WAN2</span>; os demais pela WAN1.
        </p>
        <p className="text-gray-500 text-xs mb-3">
          Isto não bloqueia nem libera nada — só escolhe por qual link o tráfego sai. Acontece antes de qualquer regra de grupo, na etapa de marcação (chain <span className="font-mono">mark_hosts</span>).
        </p>
        {canWrite && (
          <div className="flex flex-col sm:flex-row gap-2 mb-3">
            <input
              className="input flex-1"
              placeholder="IP do host (ex.: 192.168.3.50)"
              value={newWan}
              onChange={(e) => setNewWan(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addWan()}
            />
            <button onClick={addWan} disabled={busy || !newWan.trim()} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50">
              <Plus className="w-4 h-4" /> Adicionar
            </button>
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          {managed.wan_hosts.length === 0 && <span className="text-gray-600 text-sm">Nenhum host direcionado.</span>}
          {managed.wan_hosts.map((h) => (
            <span key={h.ip} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">
              {h.ip}
              {/* A marca vem do próprio elemento do map host_wan — é o que o
                  nft tem, não um rótulo do painel. */}
              <span className="text-blue-400 text-xs">{h.mark}</span>
              {canWrite && (
                <button onClick={() => delWan(h.ip)} disabled={busy} className="text-gray-500 hover:text-red-400 disabled:opacity-50" aria-label={`Reverter ${h.ip} para a WAN1`}>
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </span>
          ))}
        </div>
        <p className="text-[11px] text-gray-600 mt-3">
          A tela de <span className="text-gray-400">Hosts</span> é onde a máquina é reconhecida pelo nome e MAC; a edição do direcionamento mora aqui, no Firewall.
        </p>
      </Panel>
    </div>
  );
}
