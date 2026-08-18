import { useEffect, useState } from 'react';
import { useI18n } from '../i18n';
import { Plus, Trash2, ArrowRight, Loader2, Network, Power } from 'lucide-react';
import client from '../api/client';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { MsgLevel, PortForward } from '../types';

interface Props {
  ifaces: string[];
  canWrite: boolean;
  // O tom é explícito nas falhas: a faixa do pai só adivinha "vermelho" quando o
  // texto começa com "Erro", e essa palavra deixou de ser constante quando a
  // mensagem passou a vir do dicionário.
  onMsg: (m: string, level?: MsgLevel) => void;
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
  const { t } = useI18n();
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
      onMsg(t('fw.toast.pf.saved'));
    } catch (e) {
      onMsg(t('fwx.error', { msg: errMsg(e, t('fwx.err.generic')) }), 'error');
    } finally { setBusy(false); }
  };

  const toggle = async (pf: PortForward) => {
    setBusy(true);
    try {
      const { data } = await client.post<PortForward[]>('/api/portforward', { ...pf, enabled: !pf.enabled });
      setList(data ?? []);
    } catch (e) { onMsg(t('fwx.error', { msg: errMsg(e, t('fwx.err.generic')) }), 'error'); }
    finally { setBusy(false); }
  };

  const remove = async (id: string) => {
    setBusy(true);
    try {
      const { data } = await client.delete<PortForward[]>(`/api/portforward?id=${encodeURIComponent(id)}`);
      setList(data ?? []);
      onMsg(t('fw.toast.pf.removed'));
    } catch (e) { onMsg(t('fwx.error', { msg: errMsg(e, t('fwx.err.generic')) }), 'error'); }
    finally { setBusy(false); }
  };

  return (
    <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('fw.pf.title')}</span><HelpTip title={t('fw.pf.whatIs')}>
          <>{t('fwx.pf.help.1')}<b>{t('fw.pf.outside')}</b>{t('fwx.pf.help.2')}<b>{t('fw.pf.reachService')}</b>{t('fwx.pf.help.3')}</>
        </HelpTip></span>}>
      <p className="text-gray-500 text-xs mb-4">{t('fw.pf.explain')}</p>

      {list.length === 0 ? (
        <p className="text-gray-600 text-sm mb-4">{t('fw.pf.empty')}</p>
      ) : (
        <div className="space-y-2 mb-4">
          {list.map((pf) => (
            <div key={pf.id} className={`flex items-center gap-3 rounded-lg px-3 py-2 ${pf.enabled ? 'bg-gray-800/60' : 'bg-gray-800/30 opacity-60'}`}>
              {canWrite && (
                <button onClick={() => toggle(pf)} disabled={busy} title={pf.enabled ? t('fwx.pf.toggle.on') : t('fwx.pf.toggle.off')}>
                  <Power className={`w-4 h-4 ${pf.enabled ? 'text-green-400' : 'text-gray-600'}`} />
                </button>
              )}
              <span className="text-white text-sm font-medium min-w-0 truncate">{pf.name}</span>
              <span className="inline-flex items-center gap-2 text-sm text-gray-300 font-mono ml-auto whitespace-nowrap">
                <span className="text-gray-500">{pf.interface || t('fwx.pf.anyIface')}</span>
                <span className="uppercase text-xs text-blue-400">{pf.proto}</span>
                <span>:{pf.ext_port}</span>
                <ArrowRight className="w-3.5 h-3.5 text-gray-600" />
                <span>{pf.dest_ip}:{pf.dest_port}</span>
              </span>
              {canWrite && (
                <button onClick={() => remove(pf.id)} disabled={busy} className="text-gray-500 hover:text-red-400 shrink-0" title={t('fw.pf.remove')}>
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
              placeholder={t('fw.pf.name.placeholder')}
              className="col-span-2 rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white"
            />
            <select value={form.interface} onChange={(e) => setForm({ ...form, interface: e.target.value })}
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white">
              <option value="">{t('fw.pf.anyWan')}</option>
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
              placeholder={t('fw.pf.extPort.placeholder')}
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white"
            />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
            <input
              value={form.dest_ip} onChange={(e) => setForm({ ...form, dest_ip: e.target.value })}
              placeholder={t('fw.pf.deviceIp.placeholder')}
              className="col-span-2 sm:col-span-3 rounded-md bg-gray-800 border border-gray-700 px-2.5 py-1.5 text-sm text-white font-mono"
            />
            <input
              type="number" min={1} max={65535} value={form.dest_port || ''}
              onChange={(e) => setForm({ ...form, dest_port: Number(e.target.value) })}
              placeholder={t('fw.pf.intPort.placeholder')}
              className="rounded-md bg-gray-800 border border-gray-700 px-2 py-1.5 text-sm text-white"
            />
            <button onClick={submit} disabled={!valid || busy}
              className="col-span-2 btn-primary text-sm flex items-center justify-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />} {t('fwx.btn.add')}
            </button>
          </div>
          <p className="text-gray-600 text-xs">
            {t('fwx.pf.tip')}
          </p>
        </div>
      )}
    </Panel>
  );
}

function errMsg(e: unknown, generico: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || generico;
}
