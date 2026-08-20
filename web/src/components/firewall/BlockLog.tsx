import { useCallback, useEffect, useRef, useState } from 'react';
import { Ban, Loader2, RefreshCw } from 'lucide-react';
import client from '../../api/client';
import { useI18n } from '../../i18n';
import Panel from '../ui/Panel';
import type { BlockLogEntry, BlockLogResponse } from '../../types';

interface Props {
  canWrite: boolean;
  onMsg: (text: string) => void;
}

/**
 * BlockLog responde a pergunta mais comum de quem opera firewall — "por que
 * isso não passa?" — que o contador por regra não responde: ele diz QUANTOS
 * pacotes caíram, não QUAIS (issue #122).
 *
 * Fica desligado por padrão porque registrar todo descarte custa I/O no mesmo
 * disco que guarda o banco.
 */
export default function BlockLog({ canWrite, onMsg }: Props) {
  const { t } = useI18n();
  const [enabled, setEnabled] = useState(false);
  const [entries, setEntries] = useState<BlockLogEntry[]>([]);
  const [filtro, setFiltro] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const carregar = useCallback(async () => {
    try {
      const { data } = await client.get<BlockLogResponse>(
        `/api/nftables/block-log/entries?limit=200&q=${encodeURIComponent(filtro)}`,
      );
      setEnabled(data.enabled);
      setEntries(data.entries ?? []);
    } catch { /* a faixa de mensagem já cobre erro de ação */ }
    finally { setLoading(false); }
  }, [filtro]);

  useEffect(() => { carregar(); }, [carregar]);

  // Só atualiza sozinho quando há o que atualizar: com o registro desligado,
  // consultar o journal a cada 5s seria gasto sem resposta possível.
  useEffect(() => {
    if (enabled) timer.current = setInterval(carregar, 5000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [enabled, carregar]);

  const alternar = async () => {
    setBusy(true);
    try {
      const { data } = await client.put<{ enabled: boolean }>('/api/nftables/block-log', { enabled: !enabled });
      setEnabled(data.enabled);
      onMsg(data.enabled ? t('fwx.blocklog.turnedOn') : t('fwx.blocklog.turnedOff'));
      await carregar();
    } catch (e) {
      const ax = e as { response?: { data?: { error?: string } } };
      onMsg('Erro: ' + (ax?.response?.data?.error || t('fwx.blocklog.toggleError')));
    } finally { setBusy(false); }
  };

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Ban className="w-5 h-5 text-red-400" />
          <span className="text-white font-semibold">{t('fwx.blocklog.title')}</span>
        </span>
      }
      action={
        <div className="flex items-center gap-2">
          <button onClick={carregar} className="text-gray-500 hover:text-gray-300" title={t('common.refresh')}>
            <RefreshCw className="w-4 h-4" />
          </button>
          {canWrite && (
            <button onClick={alternar} disabled={busy}
              className={`text-xs px-3 py-1.5 rounded disabled:opacity-50 ${enabled ? 'btn-secondary' : 'btn-primary'}`}>
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
              {enabled ? t('fwx.blocklog.turnOff') : t('fwx.blocklog.turnOn')}
            </button>
          )}
        </div>
      }
    >
      <p className="text-gray-500 text-xs mb-3">{t('fwx.blocklog.explain')}</p>

      {!enabled ? (
        // Desligado e vazio são coisas diferentes, e dizer a errada mandaria o
        // admin procurar defeito onde não há: aqui não há registro porque
        // ninguém pediu, não porque nada foi bloqueado.
        <p className="text-gray-600 text-sm py-6 text-center">{t('fwx.blocklog.off')}</p>
      ) : (
        <>
          <input
            className="input w-full mb-3 font-mono text-sm"
            placeholder={t('fwx.blocklog.filter')}
            value={filtro}
            onChange={(e) => setFiltro(e.target.value)}
          />
          {loading ? (
            <p className="text-gray-600 text-sm py-6 text-center animate-pulse">{t('common.loading')}</p>
          ) : entries.length === 0 ? (
            <p className="text-gray-600 text-sm py-6 text-center">{t('fwx.blocklog.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 text-left">
                    <th className="py-1 pr-3 font-medium">{t('fwx.blocklog.col.time')}</th>
                    <th className="py-1 pr-3 font-medium">{t('fwx.blocklog.col.why')}</th>
                    <th className="py-1 pr-3 font-medium">{t('fwx.blocklog.col.src')}</th>
                    <th className="py-1 pr-3 font-medium">{t('fwx.blocklog.col.dst')}</th>
                    <th className="py-1 pr-3 font-medium">{t('fwx.blocklog.col.proto')}</th>
                    <th className="py-1 font-medium">{t('fwx.blocklog.col.path')}</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {entries.map((e, i) => (
                    <tr key={i} className="border-t border-gray-800/60">
                      <td className="py-0.5 pr-3 text-gray-500">{e.time}</td>
                      <td className="py-0.5 pr-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${e.kind === 'host' ? 'bg-red-500/15 text-red-400' : 'bg-amber-500/15 text-amber-300'}`}>
                          {t(e.kind === 'host' ? 'fwx.blocklog.kind.host' : 'fwx.blocklog.kind.dest')}
                        </span>
                      </td>
                      <td className="py-0.5 pr-3 text-gray-300">{e.src}{e.sport ? `:${e.sport}` : ''}</td>
                      <td className="py-0.5 pr-3 text-gray-300">{e.dst}{e.dport ? `:${e.dport}` : ''}</td>
                      <td className="py-0.5 pr-3 text-gray-400">{e.proto}</td>
                      <td className="py-0.5 text-gray-600">{e.in}{e.out ? ` → ${e.out}` : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
