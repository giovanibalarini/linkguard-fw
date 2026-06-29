import { useEffect, useState } from 'react';
import { Plus, Trash2, ArrowRight, Loader2, Network, Power } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import type { PortForward } from '../types';

interface Props {
  ifaces: string[];
  canWrite: boolean;
  onMsg: (m: string) => void;
}

const emptyForm: Omit<PortForward, 'id'> = {
  name: '', enabled: true, proto: 'tcp', interface: '', ext_port: 0, dest_ip: '', dest_port: 0,
};

/**
 * PortForwarding manages external→internal DNAT mappings. The user thinks in
 * terms of "open port X to device Y"; the server renders it into the nftables
 * prerouting DNAT chain.
 */
export default function PortForwarding({ ifaces, canWrite, onMsg }: Props) {
  const [list, setList] = useState<PortForward[]>([]);
  const [form, setForm] = useState(emptyForm);
  const [busy, setBusy] = useState(false);

  const fetchList = async () => {
    try {
      const { data } = await client.get<PortForward[]>('/api/portforward');
      setList(data ?? []);
    } catch { /* ignore */ }
  };
  useEffect(() => { fetchList(); }, []);

  const valid =
    form.name.trim() !== '' &&
    form.ext_port >= 1 && form.ext_port <= 65535 &&
    form.dest_port >= 1 && form.dest_port <= 65535 &&
    /^(\d{1,3}\.){3}\d{1,3}$/.test(form.dest_ip.trim());

  const submit = async () => {
    if (!valid) return;
    setBusy(true);
    try {
      const { data } = await client.post<PortForward[]>('/api/portforward', { ...form, dest_ip: form.dest_ip.trim(), name: form.name.trim() });
      setList(data ?? []);
      setForm(emptyForm);
      onMsg('Encaminhamento salvo e aplicado.');
    } catch (e) {
      onMsg('Erro: ' + errMsg(e));
    } finally { setBusy(false); }
  };

  const toggle = async (pf: PortForward) => {
    setBusy(true);
    try {
      const { data } = await client.post<PortForward[]>('/api/portforward', { ...pf, enabled: !pf.enabled });
      setList(data ?? []);
    } catch (e) { onMsg('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  const remove = async (id: string) => {
    setBusy(true);
    try {
      const { data } = await client.delete<PortForward[]>(`/api/portforward?id=${encodeURIComponent(id)}`);
      setList(data ?? []);
      onMsg('Encaminhamento removido.');
    } catch (e) { onMsg('Erro: ' + errMsg(e)); }
    finally { setBusy(false); }
  };

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Network className="w-4 h-4 text-blue-400" />
        <h3 className="text-white font-semibold">Encaminhamento de portas</h3>
        <HelpTip title="O que é encaminhar uma porta?">
          <>Permite que algo de <b>fora</b> (internet) alcance um <b>serviço dentro da sua rede</b> —
          como um servidor, câmera ou jogo. Você diz: "conexões que chegam na porta X da minha internet
          devem ir para o aparelho Y na porta Z". Abra só o necessário.</>
        </HelpTip>
      </div>
      <p className="text-gray-500 text-xs mb-4">Redireciona uma porta externa (WAN) para um aparelho da sua rede (DNAT).</p>

      {list.length === 0 ? (
        <p className="text-gray-600 text-sm mb-4">Nenhum encaminhamento configurado.</p>
      ) : (
        <div className="space-y-2 mb-4">
          {list.map((pf) => (
            <div key={pf.id} className={`flex items-center gap-3 rounded-lg px-3 py-2 ${pf.enabled ? 'bg-gray-800/60' : 'bg-gray-800/30 opacity-60'}`}>
              {canWrite && (
                <button onClick={() => toggle(pf)} disabled={busy} title={pf.enabled ? 'Ativo — clique para desativar' : 'Inativo — clique para ativar'}>
                  <Power className={`w-4 h-4 ${pf.enabled ? 'text-green-400' : 'text-gray-600'}`} />
                </button>
              )}
              <span className="text-white text-sm font-medium min-w-0 truncate">{pf.name}</span>
              <span className="inline-flex items-center gap-2 text-sm text-gray-300 font-mono ml-auto whitespace-nowrap">
                <span className="text-gray-500">{pf.interface || 'qualquer'}</span>
                <span className="uppercase text-xs text-blue-400">{pf.proto}</span>
                <span>:{pf.ext_port}</span>
                <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
                <span>{pf.dest_ip}:{pf.dest_port}</span>
              </span>
              {canWrite && (
                <button onClick={() => remove(pf.id)} disabled={busy} className="text-gray-500 hover:text-red-400 shrink-0" title="Remover">
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {canWrite && (
        <div className="rounded-lg border border-gray-800 p-3 space-y-2.5">
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
            <input
              value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Nome (ex.: Câmera)"
              className="col-span-2 rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white"
            />
            <select value={form.interface} onChange={(e) => setForm({ ...form, interface: e.target.value })}
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white">
              <option value="">Qualquer WAN</option>
              {ifaces.map((i) => <option key={i} value={i}>{i}</option>)}
            </select>
            <select value={form.proto} onChange={(e) => setForm({ ...form, proto: e.target.value as 'tcp' | 'udp' })}
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <input
              type="number" min={1} max={65535} value={form.ext_port || ''}
              onChange={(e) => setForm({ ...form, ext_port: Number(e.target.value) })}
              placeholder="Porta ext."
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white"
            />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
            <input
              value={form.dest_ip} onChange={(e) => setForm({ ...form, dest_ip: e.target.value })}
              placeholder="IP do aparelho (192.168.x.y)"
              className="col-span-2 sm:col-span-3 rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white font-mono"
            />
            <input
              type="number" min={1} max={65535} value={form.dest_port || ''}
              onChange={(e) => setForm({ ...form, dest_port: Number(e.target.value) })}
              placeholder="Porta interna"
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white"
            />
            <button onClick={submit} disabled={!valid || busy}
              className="col-span-2 btn-primary text-sm flex items-center justify-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />} Adicionar
            </button>
          </div>
          <p className="text-gray-600 text-xs">
            Dica: reserve um IP fixo para o aparelho no DHCP antes, para o encaminhamento não "mudar de dono".
          </p>
        </div>
      )}
    </div>
  );
}

function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || 'falha na operação';
}
