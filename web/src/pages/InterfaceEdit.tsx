import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import Panel from '../components/ui/Panel';
import type { IfaceAddrMode, IfaceView, PreviewResult } from '../types';

export default function InterfaceEdit() {
  const { t } = useI18n();
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
          setError(t('net.ifedit.notFound'));
        } else if (found.kind !== 'physical') {
          setError(t('net.ifedit.physicalOnly'));
        } else {
          setIface(found);
          setAddrMode(found.addr_mode);
          // found.cidr só vem preenchido depois que a interface já foi
          // adotada pelo LinkGuard (apply+confirm). Antes disso — o caso de
          // toda interface configurada fora do LinkGuard, como as WAN em
          // produção hoje — cai no endereço real observado no kernel, senão
          // o formulário abre em branco mesmo a interface já tendo um IP.
          const liveCidr = found.live.addresses?.find((a) => a.family === 'ipv4')?.cidr;
          setCidr(found.cidr || liveCidr || '');
          setGateway(found.gateway ?? '');
          setDescription(found.description ?? '');
        }
      } catch {
        if (alive) setError(t('net.ifedit.loadFailed'));
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
      setError(msg || t('net.ifedit.previewFailed'));
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <div className="p-6 text-gray-500">{t('common.loading')}</div>;

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <button onClick={() => navigate('/interfaces')} className="flex items-center gap-2 text-gray-400 hover:text-white text-sm">
        <ArrowLeft className="w-4 h-4" /> {t('net.action.back')}
      </button>

      <div>
        <h1 className="text-xl font-bold text-white">{t('net.ifedit.title', { name: iface?.alias || name || '' })}</h1>
        <p className="text-gray-500 text-sm mt-0.5 font-mono">{name}</p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>
      )}

      {iface && (
        <Panel title={t('net.ifedit.addressing')}>
          <div className="space-y-4">
            <div>
              <label className="label">{t('net.ifedit.mode')}</label>
              <select className="input w-full" value={addrMode} onChange={(e) => setAddrMode(e.target.value as IfaceAddrMode)}>
                <option value="dhcp">DHCP</option>
                <option value="static">{t('net.ifedit.mode.static')}</option>
                <option value="none">{t('net.ifedit.mode.none')}</option>
              </select>
            </div>
            {addrMode === 'static' && (
              <>
                <div>
                  <label className="label">{t('net.ifedit.cidr')}</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.3/24" value={cidr} onChange={(e) => setCidr(e.target.value)} />
                </div>
                <div>
                  <label className="label">{t('net.ifedit.gateway')}</label>
                  <input className="input w-full font-mono" placeholder="192.168.3.1" value={gateway} onChange={(e) => setGateway(e.target.value)} />
                </div>
              </>
            )}
            <div>
              <label className="label">{t('net.ifedit.description')}</label>
              <input className="input w-full" placeholder={t('net.ifedit.description.ph')} value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>
        </Panel>
      )}

      {iface && (
        <button onClick={handleReview} disabled={submitting} className="btn-primary">
          {submitting ? t('net.ifedit.generating') : t('net.ifedit.review')}
        </button>
      )}
    </div>
  );
}
