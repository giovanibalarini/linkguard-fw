import { useCallback, useEffect, useState } from 'react';
import { Globe, Loader2, AlertTriangle, Check } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import HelpTip from './HelpTip';
import Panel from './ui/Panel';
import type { DdnsView } from '../types';

interface Props {
  canEdit: boolean;
}

/**
 * LinkDdns mantém um nome de DNS apontando para o endereço público de cada WAN
 * (issue #129). Sem isso, o encaminhamento de porta — que o painel já oferece —
 * aponta para um endereço que o provedor troca sem avisar.
 */
export default function LinkDdns({ canEdit }: Props) {
  const { t } = useI18n();
  const [rows, setRows] = useState<DdnsView[]>([]);
  const [editando, setEditando] = useState<string | null>(null);
  const [form, setForm] = useState({ hostname: '', url_template: '', username: '', secret: '' });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const carregar = useCallback(async () => {
    try {
      const { data } = await client.get<DdnsView[]>('/api/ddns');
      setRows(data ?? []);
    } catch { /* silencioso: a faixa de erro cobre a ação */ }
  }, []);

  useEffect(() => {
    carregar();
    const id = setInterval(carregar, 60000);
    return () => clearInterval(id);
  }, [carregar]);

  const abrir = (r: DdnsView) => {
    setEditando(r.link_id);
    setForm({
      hostname: r.hostname ?? '',
      url_template: r.url_template ?? '',
      username: r.username ?? '',
      secret: '', // nunca preenchido: o segredo não volta do servidor
    });
    setErr('');
  };

  const salvar = async (linkID: string, enabled: boolean) => {
    setBusy(true); setErr('');
    try {
      await client.put('/api/ddns', { link_id: linkID, enabled, ...form });
      setEditando(null);
      await carregar();
    } catch (e) { setErr(errMsg(e, t('links.ddns.error.save'))); }
    finally { setBusy(false); }
  };

  const verificar = async () => {
    setBusy(true); setErr('');
    try { await client.post('/api/ddns/check'); await carregar(); }
    catch (e) { setErr(errMsg(e, t('links.ddns.error.check'))); }
    finally { setBusy(false); }
  };

  if (rows.length === 0) return null;

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-sky-400" />
          <span className="text-white font-semibold">{t('links.ddns.title')}</span>
          <HelpTip title={t('links.ddns.help.title')}>
            <>{t('links.ddns.help1')} <b>{t('links.ddns.helpPerLinkTerm')}</b>{t('links.ddns.help2')}</>
          </HelpTip>
        </span>
      }
      action={canEdit && (
        <button onClick={verificar} disabled={busy} className="btn-secondary text-xs disabled:opacity-50">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} {t('links.ddns.checkNow')}
        </button>
      )}
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">{t('links.ddns.subtitle')}</p>

      {err && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {err}
        </div>
      )}

      <ul className="space-y-3">
        {rows.map((r) => (
          <li key={r.link_id} className="rounded-lg border border-gray-800 p-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="text-white text-sm font-medium">
                {r.link_name} <span className="text-gray-600 font-mono text-xs">{r.interface}</span>
              </span>
              <span className="text-xs text-gray-400 font-mono">
                {r.enabled && r.hostname ? r.hostname : t('links.ddns.notSet')}
              </span>
            </div>

            {r.enabled && (
              <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px]">
                {r.state?.public_ip ? (
                  <span className="text-gray-400 font-mono">{r.state.public_ip}</span>
                ) : (
                  <span className="text-gray-600">{t('links.ddns.noAddressYet')}</span>
                )}
                {r.state?.last_error ? (
                  <span className="text-red-400">{r.state.last_error}</span>
                ) : r.state?.updated_at ? (
                  <span className="text-green-400 inline-flex items-center gap-1">
                    <Check className="w-3 h-3" /> {t('links.ddns.ok')}
                  </span>
                ) : null}
                {/* Atrás de CGNAT o encaminhamento de porta não funciona de
                    jeito nenhum — dizer isso aqui evita horas de diagnóstico
                    numa tela que não tem nada a ver com o problema. */}
                {r.state?.behind_nat && (
                  <span className="text-amber-300/90">{t('links.ddns.behindNat')}</span>
                )}
              </div>
            )}

            <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px]">
              {canEdit && editando !== r.link_id && (
                <button onClick={() => abrir(r)} className="text-blue-400 hover:text-blue-300">
                  {r.hostname ? t('links.ddns.edit') : t('links.ddns.configure')}
                </button>
              )}
              {canEdit && r.enabled && editando !== r.link_id && (
                <button onClick={() => salvar(r.link_id, false)} disabled={busy}
                  className="text-gray-500 hover:text-red-400">
                  {t('links.ddns.disable')}
                </button>
              )}
            </div>

            {editando === r.link_id && (
              <div className="mt-3 space-y-2">
                <label className="block">
                  <span className="text-gray-400 text-xs">{t('links.ddns.hostname')}</span>
                  <input className="input mt-1 w-full font-mono text-sm" value={form.hostname}
                    placeholder="casa.exemplo.org"
                    onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
                </label>
                <label className="block">
                  <span className="text-gray-400 text-xs">{t('links.ddns.urlTemplate')}</span>
                  <input className="input mt-1 w-full font-mono text-sm" value={form.url_template}
                    placeholder="https://www.duckdns.org/update?domains={hostname}&token=SEU_TOKEN&ip={ip}"
                    onChange={(e) => setForm({ ...form, url_template: e.target.value })} />
                  <span className="text-gray-600 text-[11px]">{t('links.ddns.urlHint')}</span>
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <label className="block">
                    <span className="text-gray-400 text-xs">{t('links.ddns.username')}</span>
                    <input className="input mt-1 w-full font-mono text-sm" value={form.username}
                      onChange={(e) => setForm({ ...form, username: e.target.value })} />
                  </label>
                  <label className="block">
                    <span className="text-gray-400 text-xs">
                      {t('links.ddns.secret')}{r.secret_set ? ` ${t('links.ddns.secretStored')}` : ''}
                    </span>
                    <input type="password" className="input mt-1 w-full font-mono text-sm" value={form.secret}
                      placeholder={r.secret_set ? '••••••••' : ''}
                      onChange={(e) => setForm({ ...form, secret: e.target.value })} />
                  </label>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => salvar(r.link_id, true)} disabled={busy || !form.hostname}
                    className="btn-primary text-xs disabled:opacity-50">
                    {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} {t('links.ddns.save')}
                  </button>
                  <button onClick={() => setEditando(null)} className="btn-secondary text-xs">
                    {t('links.ddns.cancel')}
                  </button>
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function errMsg(e: unknown, fallback: string): string {
  const ax = e as { response?: { data?: { error?: string } } };
  return ax?.response?.data?.error || fallback;
}
