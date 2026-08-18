// A pré-visualização da linha nft NÃO é montada aqui.
//
// Ela vem de POST /api/nftables/{rules,groups}/preview, renderizada pelo mesmo
// código que monta a linha que vai para o kernel. Enquanto existia uma cópia em
// TypeScript, os dois lados carregavam um comentário dizendo que a ordem dos
// campos não era estética — e nada verificava que continuavam iguais. Ver
// useNftPreview e internal/nftables.RenderRule.

import { useNftPreview } from '../../lib/useNftPreview';
import { useI18n } from '../../i18n';
import type { GroupConnState, GroupScope } from '../../types';

export default function NftPreview({ endpoint, body, className }: { endpoint: string; body: unknown; className?: string }) {
  const { t } = useI18n();
  const { rendered, erro } = useNftPreview(endpoint, body);
  if (erro) return <p className={`font-mono text-[11px] text-amber-400/90 break-all ${className ?? ''}`}>{erro}</p>;
  if (!rendered) return <p className={`font-mono text-[11px] text-gray-700 break-all ${className ?? ''}`}>{t('fwx.preview.rendering')}</p>;
  return <p className={`font-mono text-[11px] text-gray-500 break-all ${className ?? ''}`}>{rendered}</p>;
}

// groupPreviewBody manda ao backend só o que decide a linha de jump.
export function groupPreviewBody(g: {
  chain_name?: string; cond_iif: string; cond_saddr: string; cond_daddr: string;
  kind?: string; scope?: GroupScope; conn_state?: GroupConnState; fallthrough?: string;
}) {
  return {
    chain_name: g.chain_name ?? '', cond_iif: g.cond_iif,
    cond_saddr: g.cond_saddr, cond_daddr: g.cond_daddr,
    kind: g.kind ?? '', scope: g.scope ?? '', conn_state: g.conn_state ?? '',
    fallthrough: g.fallthrough ?? '',
  };
}
