import { useEffect, useMemo, useState } from 'react';
import { Sparkles, ExternalLink, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import { parseReleases, type ChangeType, type ParsedRelease, type RawRelease } from '../lib/releaseNotes';
import { useI18n } from '../i18n';

// As novidades vêm das releases publicadas, e não de um arquivo curado à mão.
//
// O arquivo (src/data/changelog.ts) parou na 1.0.82 enquanto o produto chegava
// à 1.0.110 — 28 versões em que esta tela afirmava que nada tinha mudado desde
// julho. Curadoria manual atrasa porque depende de alguém lembrar, e lembrar é
// a parte que falha. Desde a issue #63 a nota de release sai do próprio
// histórico de commits, no workflow de publicação.

// `label` guarda uma chave de i18n resolvida com t() na hora de desenhar.
const TYPE_META: Record<ChangeType, { label: string; cls: string }> = {
  feat: { label: 'shell.changelog.type.feat', cls: 'bg-green-500/10 text-green-400 border border-green-500/20' },
  fix: { label: 'shell.changelog.type.fix', cls: 'bg-blue-500/10 text-blue-400 border border-blue-500/20' },
  security: { label: 'shell.changelog.type.security', cls: 'bg-amber-500/10 text-amber-300 border border-amber-500/20' },
  chore: { label: 'shell.changelog.type.chore', cls: 'bg-gray-500/10 text-gray-400 border border-gray-500/20' },
};

interface ChangelogResponse {
  releases: RawRelease[];
  stale: boolean;
  fetched_at: number;
  error?: string;
}

function fmtDate(iso: string): string {
  const [y, m, d] = iso.split('-');
  if (!y || !m || !d) return iso;
  return `${d}/${m}/${y}`;
}

export default function Changelog() {
  const { t } = useI18n();
  const [releases, setReleases] = useState<ParsedRelease[]>([]);
  const [stale, setStale] = useState(false);
  const [fetchedAt, setFetchedAt] = useState(0);
  const [erro, setErro] = useState('');
  const [carregando, setCarregando] = useState(true);
  // As mudanças internas ficam escondidas por padrão.
  //
  // A lista vem do histórico de commits, que é escrito para quem desenvolve:
  // "as dez mutações usam ApplyGuarded" é verdade e não diz nada a quem opera
  // um firewall em casa. Segurança, correções e novidades são o que muda a vida
  // dele; reestruturação interna, testes e manutenção são ruído NA PRIMEIRA
  // LEITURA — mas não são mentira, e por isso ficam a um clique, não fora.
  const [verInternas, setVerInternas] = useState(false);

  const visiveis = useMemo(
    () => releases.map((r) => ({
      ...r,
      changes: verInternas ? r.changes : r.changes.filter((c) => c.type !== 'chore'),
    })),
    [releases, verInternas],
  );
  const internasEscondidas = useMemo(
    () => releases.reduce((n, r) => n + r.changes.filter((c) => c.type === 'chore').length, 0),
    [releases],
  );

  useEffect(() => {
    let vivo = true;
    (async () => {
      try {
        const res = await client.get<ChangelogResponse>('/api/system/changelog');
        if (!vivo) return;
        setReleases(parseReleases(res.data.releases));
        setStale(res.data.stale);
        setFetchedAt(res.data.fetched_at);
      } catch (e: unknown) {
        if (!vivo) return;
        // A mensagem do servidor explica o caso mais comum (firewall sem
        // internet na primeira visita) melhor do que qualquer texto genérico.
        const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
        setErro(msg || t('shell.changelog.loadError'));
      } finally {
        if (vivo) setCarregando(false);
      }
    })();
    return () => { vivo = false; };
  }, [t]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Sparkles className="w-5 h-5 text-blue-400" />
        <div>
          <h1 className="text-xl font-bold text-white">{t('shell.changelog.title')}</h1>
          <p className="text-gray-500 text-sm">{t('shell.changelog.subtitle')}</p>
        </div>
        {internasEscondidas > 0 && (
          <button
            type="button"
            onClick={() => setVerInternas((v) => !v)}
            className="ml-auto text-xs text-gray-400 hover:text-gray-200 border border-gray-700 rounded px-2 py-1"
          >
            {verInternas
              ? t('shell.changelog.hideInternal')
              : t('shell.changelog.showInternal', { n: internasEscondidas })}
          </button>
        )}
      </div>

      {/* Servir cache velho sem dizer que é velho seria o painel mentindo sobre
          a idade do que mostra — o mesmo defeito que "configurado" × "em vigor"
          existe para evitar no resto do produto. */}
      {stale && (
        <div className="card flex items-start gap-2.5 text-sm border-amber-500/20">
          <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
          <span className="text-gray-300">
            {t('shell.changelog.stale')}
            {fetchedAt > 0 && ` (${new Date(fetchedAt * 1000).toLocaleString('pt-BR')})`}.
          </span>
        </div>
      )}

      {carregando && <div className="card text-gray-500 text-sm">{t('shell.changelog.loading')}</div>}

      {!carregando && erro && (
        <div className="card text-gray-300 text-sm">{erro}</div>
      )}

      {!carregando && !erro && releases.length === 0 && (
        <div className="card text-gray-500 text-sm">{t('shell.changelog.empty')}</div>
      )}

      <div className="space-y-4">
        {visiveis.map((entry) => (
          <div key={entry.version} className="card">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 mb-3">
              <span className="text-white font-semibold">v{entry.version}</span>
              <a
                href={entry.url}
                target="_blank"
                rel="noreferrer"
                className="text-gray-500 hover:text-gray-300 inline-flex items-center gap-1 text-xs"
              >
                {t('shell.changelog.viewOnGitHub')} <ExternalLink className="w-3 h-3" />
              </a>
              <span className="text-gray-600 text-xs ml-auto">{fmtDate(entry.date)}</span>
            </div>

            {entry.hasContent && entry.changes.length === 0 ? (
              <p className="text-gray-500 text-sm">
                {t('shell.changelog.onlyInternal')}
              </p>
            ) : entry.hasContent ? (
              <ul className="space-y-2">
                {entry.changes.map((c, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm">
                    <span className={`shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[11px] font-medium ${TYPE_META[c.type].cls}`}>
                      {t(TYPE_META[c.type].label)}
                    </span>
                    <span className="text-gray-300">
                      {c.scope && <span className="text-gray-500">{c.scope} · </span>}
                      {c.text}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              // A versão fica na lista mesmo sem mudança reconhecível: sumir com
              // ela faria o admin concluir que ela não existiu.
              <p className="text-gray-500 text-sm">
                {t('shell.changelog.unparsed')}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
