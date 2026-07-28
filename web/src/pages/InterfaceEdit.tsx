import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import type { IfaceAddrMode, IfaceView, PreviewResult } from '../types';

export default function InterfaceEdit() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const [iface, setIface] = useState<IfaceView | null>(null);
  const [addrMode, setAddrMode] = useState<IfaceAddrMode>('dhcp');
  const [cidr, setCidr] = useState('');
  const [gateway, setGateway] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { data } = await client.get<IfaceView[]>('/api/interfaces');
        const found = data.find((i) => i.name === name);
        if (!alive) return;
        if (!found) {
          setError('Interface não encontrada.');
        } else if (found.kind !== 'physical') {
          setError('Só é possível editar interfaces físicas nesta fase.');
        } else {
          setIface(found);
          setAddrMode(found.addr_mode);
          setCidr(found.cidr ?? '');
          setGateway(found.gateway ?? '');
          setDescription(found.description ?? '');
        }
      } catch {
        if (alive) setError('Falha ao carregar a interface.');
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [name]);

  const handleReview = async () => {
    setSubmitting(true);
    setError('');
    try {
      const { data } = await client.post<PreviewResult>('/api/interfaces/preview', {
        name, addr_mode: addrMode, cidr, gateway, description,
      });
      navigate(`/interfaces/${encodeURIComponent(name ?? '')}/review`, { state: { edit: { name, addr_mode: addrMode, cidr, gateway, description }, preview: data } });
    } catch (e) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || 'Falha ao gerar a prévia.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <div className="p-6 text-gray-500">Carregando...</div>;

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <button onClick={() => navigate('/interfaces')} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> Voltar
      </button>

      <div>
        <h1 className="text-xl font-bold text-white">Editar {iface?.alias || name}</h1>
        <p className="text-gray-500 text-sm mt-0.5 font-mono">{name}</p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>
      )}

      {iface && (
        <Panel title="Endereçamento">
          <div className="space-y-4">
            <div>
              <label className="label">Modo</label>
              <select className="input w-full" value={addrMode} onChange={(e) => setAddrMode(e.target.value as IfaceAddrMode)}>
                <option value="dhcp">DHCP</option>
                <option value="static">Estático</option>
                <option value="none">Nenhum</option>
              </select>
            </div>
            {addrMode === 'static' && (
              <>
                <div>
                  <label className="label">Endereço (CIDR)</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.3/24" value={cidr} onChange={(e) => setCidr(e.target.value)} />
                </div>
                <div>
                  <label className="label">Gateway (opcional)</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.1" value={gateway} onChange={(e) => setGateway(e.target.value)} />
                </div>
              </>
            )}
            <div>
              <label className="label">Descrição</label>
              <input className="input w-full" placeholder="ex: patch painel P02, sala dos servidores" value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>
        </Panel>
      )}

      {iface && (
        <button onClick={handleReview} disabled={submitting} className="btn-primary">
          {submitting ? 'Gerando prévia...' : 'Revisar mudanças'}
        </button>
      )}
    </div>
  );
}
