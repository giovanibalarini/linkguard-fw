import { useEffect, useState } from 'react';
import { useI18n } from '../i18n';
import { Plus, X, Network } from 'lucide-react';
import client from '../api/client';
import Panel from './ui/Panel';
import type { MsgLevel, NftManaged } from '../types';

interface Props {
  canWrite: boolean;
  // O tom é explícito nas falhas: a faixa do pai só adivinha "vermelho" quando o
  // texto começa com "Erro", e essa palavra deixou de ser constante quando a
  // mensagem passou a vir do dicionário.
  onMsg: (m: string, level?: MsgLevel) => void;
}

function errMsg(e: unknown, generico: string): string {
  const ax = e as { response?: { data?: { error?: string } }; message?: string };
  return ax?.response?.data?.error || ax?.message || generico;
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
  const { t } = useI18n();
  const [managed, setManaged] = useState<NftManaged>({ wan_hosts: [], blocklist: [], blocked_hosts: [] });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [newWan, setNewWan] = useState('');

  const load = async () => {
    try {
      const { data } = await client.get<NftManaged>('/api/nftables/managed');
      setManaged(data ?? { wan_hosts: [], blocklist: [], blocked_hosts: [] });
    } catch (e) {
      onMsg(t('fwx.error', { msg: errMsg(e, t('fwx.err.generic')) }), 'error');
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
      onMsg(t('fwx.error', { msg: errMsg(e, t('fwx.err.generic')) }), 'error');
    } finally {
      setBusy(false);
    }
  };

  const addWan = () => newWan.trim() && run(() => client.post('/api/nftables/wan-host', { ip: newWan.trim() }), t('fw.toast.steering.toWan2')).then(() => setNewWan(''));
  const delWan = (ip: string) => run(() => client.delete('/api/nftables/wan-host', { data: { ip } }), t('fw.toast.steering.toWan1'));

  if (loading) {
    return <div className="card text-center py-8 text-gray-500 animate-pulse">{t('common.loading')}</div>;
  }

  return (
    <div className="space-y-4">
      <Panel title={<span className="flex items-center gap-2"><Network className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('fw.steering.title')}</span></span>}>
        {/* A explicação da spec §3, palavra por palavra: este controle é o
            único do firewall que não filtra, e sem essa frase ele parece
            mais um bloqueio. */}
        <p className="text-gray-400 text-sm mb-1">
          {t('fwx.steering.line.head')}<span className="text-blue-300">WAN2</span>{t('fwx.steering.line.tail')}
        </p>
        <p className="text-gray-500 text-xs mb-3">
          {t('fwx.steering.notFilter')}<span className="font-mono">mark_hosts</span>).
        </p>
        {canWrite && (
          <div className="flex flex-col sm:flex-row gap-2 mb-3">
            <input
              className="input flex-1"
              placeholder={t('fw.steering.hostIp.placeholder')}
              value={newWan}
              onChange={(e) => setNewWan(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addWan()}
            />
            <button onClick={addWan} disabled={busy || !newWan.trim()} className="btn-primary flex items-center gap-2 justify-center disabled:opacity-50">
              <Plus className="w-4 h-4" /> {t('fwx.btn.add')}
            </button>
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          {managed.wan_hosts.length === 0 && <span className="text-gray-600 text-sm">{t('fw.steering.empty')}</span>}
          {managed.wan_hosts.map((h) => (
            <span key={h.ip} className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-gray-800 text-sm text-gray-200 font-mono">
              {h.ip}
              {/* A marca vem do próprio elemento do map host_wan — é o que o
                  nft tem, não um rótulo do painel. */}
              <span className="text-blue-400 text-xs">{h.mark}</span>
              {canWrite && (
                <button onClick={() => delWan(h.ip)} disabled={busy} className="text-gray-500 hover:text-red-400 disabled:opacity-50" aria-label={t('fwx.steering.revert.aria', { ip: h.ip })}>
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </span>
          ))}
        </div>
        <p className="text-[11px] text-gray-600 mt-3">
          {t('fwx.steering.hostsNote.head')}<span className="text-gray-400">{t('fw.steering.hosts')}</span>{t('fwx.steering.hostsNote.tail')}
        </p>
      </Panel>
    </div>
  );
}
