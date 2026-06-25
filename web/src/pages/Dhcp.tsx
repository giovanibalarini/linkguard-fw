import { useEffect, useState } from 'react';
import { RefreshCw, Plus, Pencil, Trash2, Server, Network, ListChecks, Play } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { DHCPData, DHCPReservation, NetsvcConfig } from '../types';

const emptyRes = { mac: '', ip: '', hostname: '' };

export default function Dhcp() {
  const { can } = useAuth();
  const canWrite = can('dhcp.write');
  const [data, setData] = useState<DHCPData | null>(null);
  const [cfg, setCfg] = useState<NetsvcConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [resModal, setResModal] = useState<typeof emptyRes & { editing: boolean } | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await client.get<DHCPData>('/api/dhcp');
      setData(res.data);
      setCfg(res.data.config);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { fetchData(); }, []);

  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true); setMsg('');
    try { await fn(); if (ok) setMsg(ok); await fetchData(); }
    catch (e: any) { setMsg(`Erro: ${e.response?.data?.error || e.message}`); }
    finally { setBusy(false); }
  };

  const saveConfig = () => cfg && run(() => client.put('/api/dhcp/config', cfg), 'Config DHCP salva. Clique em Aplicar para ativar.');
  const saveRes = () => {
    if (!resModal) return;
    run(() => client.post('/api/dhcp/reservations', { mac: resModal.mac, ip: resModal.ip, hostname: resModal.hostname }), 'Reserva salva.').then(() => setResModal(null));
  };
  const delRes = (r: DHCPReservation) => confirm(`Remover a reserva de ${r.ip} (${r.mac})?`) && run(() => client.delete('/api/dhcp/reservations', { data: { mac: r.mac } }), 'Reserva removida.');
  const apply = () => confirm('Aplicar a config e reiniciar o serviço DHCP (Kea)? Pode haver uma breve interrupção nas renovações de lease.') && run(() => client.post('/api/netsvc/apply'), 'Aplicado com sucesso.');

  const expiresIn = (epoch: number) => {
    const s = epoch - Math.floor(Date.now() / 1000);
    if (s <= 0) return 'expirado';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m`;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">DHCP</h1>
          <p className="text-gray-500 text-sm">Servidor DHCP {data?.backend === 'kea-unbound' ? '(Kea)' : ''} — config, reservas e leases</p>
        </div>
        <div className="flex gap-2">
          {canWrite && <button onClick={apply} disabled={busy} className="btn-primary flex items-center gap-2 disabled:opacity-50"><Play className="w-4 h-4" /> Aplicar</button>}
          <button onClick={fetchData} className="btn-secondary flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Atualizar</button>
        </div>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">Falha ao carregar. <button onClick={fetchData} className="underline">Tentar novamente</button></div>}
      {msg && <div className={`px-4 py-3 rounded-lg text-sm ${msg.startsWith('Erro') ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>{msg}</div>}

      {loading || !cfg ? (
        <div className="card text-center py-8 text-gray-500 animate-pulse">Carregando...</div>
      ) : (
        <>
          {/* Config */}
          <div className="card">
            <div className="flex items-center gap-2 mb-3"><Server className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Configuração</h3></div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <div><label className="label">Interface (LAN)</label><input className="input w-full" value={cfg.interface} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, interface: e.target.value })} /></div>
              <div><label className="label">Sub-rede (CIDR)</label><input className="input w-full" value={cfg.subnet_cidr} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, subnet_cidr: e.target.value })} /></div>
              <div><label className="label">Gateway</label><input className="input w-full" value={cfg.gateway} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, gateway: e.target.value })} /></div>
              <div><label className="label">Início do range</label><input className="input w-full" value={cfg.range_start} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, range_start: e.target.value })} /></div>
              <div><label className="label">Fim do range</label><input className="input w-full" value={cfg.range_end} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, range_end: e.target.value })} /></div>
              <div><label className="label">Lease (horas)</label><input type="number" className="input w-full" value={cfg.lease_hours} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, lease_hours: +e.target.value })} /></div>
              <div className="sm:col-span-2 lg:col-span-3"><label className="label">DNS para os clientes (separados por vírgula)</label><input className="input w-full" value={cfg.dns_to_clients.join(', ')} disabled={!canWrite} onChange={(e) => setCfg({ ...cfg, dns_to_clients: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} /></div>
            </div>
            {canWrite && <div className="mt-4"><button onClick={saveConfig} disabled={busy} className="btn-primary disabled:opacity-50">Salvar config</button></div>}
          </div>

          {/* Reservations */}
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
              <div className="flex items-center gap-2"><ListChecks className="w-4 h-4 text-blue-400" /><h3 className="text-white font-semibold">Reservas (IP fixo por MAC)</h3></div>
              {canWrite && <button onClick={() => setResModal({ ...emptyRes, editing: false })} className="btn-primary flex items-center gap-2 w-full sm:w-auto justify-center"><Plus className="w-4 h-4" /> Nova reserva</button>}
            </div>
            {(data?.reservations.length ?? 0) === 0 ? (
              <p className="text-gray-600 text-sm">Nenhuma reserva. Reservas dão IP estável por MAC (conserta o pin de WAN).</p>
            ) : (
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-left text-gray-500 border-b border-gray-800"><th className="pb-3 pr-4 font-medium">Hostname</th><th className="pb-3 pr-4 font-medium">IP</th><th className="pb-3 pr-4 font-medium">MAC</th>{canWrite && <th className="pb-3 font-medium">Ações</th>}</tr></thead>
                <tbody>{data!.reservations.map((r) => (
                  <tr key={r.mac} className="table-row">
                    <td className="py-3 pr-4 text-white">{r.hostname || '—'}</td>
                    <td className="py-3 pr-4 text-gray-300 font-mono text-xs">{r.ip}</td>
                    <td className="py-3 pr-4 text-gray-500 font-mono text-xs">{r.mac}</td>
                    {canWrite && <td className="py-3"><div className="flex gap-2">
                      <button onClick={() => setResModal({ mac: r.mac, ip: r.ip, hostname: r.hostname, editing: true })} aria-label="Editar" className="text-gray-400 hover:text-blue-400"><Pencil className="w-4 h-4" /></button>
                      <button onClick={() => delRes(r)} aria-label="Remover" className="text-gray-400 hover:text-red-400"><Trash2 className="w-4 h-4" /></button>
                    </div></td>}
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </div>

          {/* Active leases */}
          <div className="card">
            <div className="flex items-center gap-2 mb-3"><Network className="w-4 h-4 text-green-400" /><h3 className="text-white font-semibold">Leases ativos ({data?.leases.length ?? 0})</h3></div>
            {(data?.leases.length ?? 0) === 0 ? (
              <p className="text-gray-600 text-sm">Nenhum lease ativo (o servidor DHCP pode ainda não estar ativo).</p>
            ) : (
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-left text-gray-500 border-b border-gray-800"><th className="pb-3 pr-4 font-medium">Hostname</th><th className="pb-3 pr-4 font-medium">IP</th><th className="pb-3 pr-4 font-medium">MAC</th><th className="pb-3 font-medium">Expira em</th></tr></thead>
                <tbody>{data!.leases.map((l) => (
                  <tr key={l.ip + l.mac} className="table-row">
                    <td className="py-3 pr-4 text-white">{l.hostname || '—'}</td>
                    <td className="py-3 pr-4 text-gray-300 font-mono text-xs">{l.ip}</td>
                    <td className="py-3 pr-4 text-gray-500 font-mono text-xs">{l.mac}</td>
                    <td className="py-3 text-gray-400">{expiresIn(l.expiry)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </div>
        </>
      )}

      {/* Reservation modal */}
      {resModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-gray-800"><h2 className="text-white font-semibold">{resModal.editing ? 'Editar reserva' : 'Nova reserva'}</h2></div>
            <div className="p-6 space-y-4">
              <div><label className="label">MAC *</label><input className="input w-full disabled:opacity-50" placeholder="aa:bb:cc:dd:ee:ff" value={resModal.mac} disabled={resModal.editing} onChange={(e) => setResModal({ ...resModal, mac: e.target.value })} /></div>
              <div><label className="label">IP *</label><input className="input w-full" placeholder="192.168.3.50" value={resModal.ip} onChange={(e) => setResModal({ ...resModal, ip: e.target.value })} /></div>
              <div><label className="label">Hostname</label><input className="input w-full" placeholder="opcional" value={resModal.hostname} onChange={(e) => setResModal({ ...resModal, hostname: e.target.value })} /></div>
              <div className="flex gap-3 pt-2">
                <button onClick={saveRes} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">{busy ? 'Salvando...' : 'Salvar'}</button>
                <button onClick={() => setResModal(null)} className="btn-secondary flex-1">Cancelar</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
