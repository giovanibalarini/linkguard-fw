// Converte o markdown de uma nota de release nas seções que a tela "Novidades"
// desenha.
//
// A nota é gerada por scripts/release-notes.sh a partir do histórico de commits
// (issue #63), com um cabeçalho `### <Seção>` por tipo de conventional commit e
// uma linha `- (escopo) assunto` por commit. Esta função é o outro lado desse
// contrato.
//
// POR QUE O PARSING FICA AQUI, e não no servidor: assim o servidor guarda a
// nota EXATAMENTE como o GitHub a publicou. Se o formato mudar, quem se adapta
// é esta função — e o cache no banco não precisa ser invalidado nem migrado,
// porque ele tem o texto cru.

export type ChangeType = 'feat' | 'fix' | 'security' | 'chore';

export interface ParsedChange {
  type: ChangeType;
  /** Escopo do commit — "firewall", "web" —, ou '' quando não havia. */
  scope: string;
  text: string;
}

export interface ParsedRelease {
  version: string;
  /** ISO 'YYYY-MM-DD', ou '' se a data não veio. */
  date: string;
  url: string;
  changes: ParsedChange[];
  /** Seções que não viraram mudança (o rodapé de instalação, por exemplo). */
  hasContent: boolean;
}

// Cada seção da nota vira um tipo que a tela já sabe pintar. O que não estiver
// aqui — "Reestruturação interna", "Testes", "Documentação", "Manutenção" —
// cai em 'chore': elas mudaram o produto e merecem aparecer, mas não competem
// por atenção com uma correção de segurança.
const SECTION_TYPE: Record<string, ChangeType> = {
  'segurança': 'security',
  'seguranca': 'security',
  'correções': 'fix',
  'correcoes': 'fix',
  'novidades': 'feat',
  'desempenho': 'feat',
};

/** normaliza um título de seção para a busca no mapa acima. */
function sectionKey(title: string): string {
  return title.trim().toLowerCase();
}

/**
 * parseReleaseBody separa o markdown da nota em mudanças tipadas.
 *
 * Para tudo o que vier depois do `---` (o rodapé com instalação e checksum),
 * porque aquilo é instrução de download, não mudança — e repeti-la em cada
 * cartão da tela empurraria o conteúdo real para fora da vista.
 */
export function parseReleaseBody(body: string): ParsedChange[] {
  const out: ParsedChange[] = [];
  let type: ChangeType | null = null;

  for (const raw of (body || '').split('\n')) {
    const line = raw.trim();
    if (line === '---') break;

    const header = /^###\s+(.+)$/.exec(line);
    if (header) {
      type = SECTION_TYPE[sectionKey(header[1])] ?? 'chore';
      continue;
    }
    if (!type) continue;

    const item = /^-\s+(.*)$/.exec(line);
    if (!item) continue;

    let text = item[1].trim();
    let scope = '';
    // "(web) sobe o React" → escopo "web". O escopo é um rótulo à parte na
    // tela; deixá-lo no meio da frase faria toda linha começar com parêntese.
    const scoped = /^\(([^)]+)\)\s*(.+)$/.exec(text);
    if (scoped) {
      scope = scoped[1].trim();
      text = scoped[2].trim();
    }
    if (text) out.push({ type, scope, text });
  }
  return out;
}

/** yyyy-mm-dd a partir do published_at do GitHub (ISO 8601 completo). */
export function isoDate(publishedAt: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(publishedAt || '');
  return m ? m[1] : '';
}

/** v1.0.110 → 1.0.110 (a tela já escreve o "v"). */
export function versionOf(tag: string): string {
  return (tag || '').replace(/^v/, '');
}

export interface RawRelease {
  tag: string;
  name: string;
  published_at: string;
  html_url: string;
  body: string;
  prerelease: boolean;
}

/**
 * parseReleases prepara a lista inteira para a tela.
 *
 * Releases sem nenhuma mudança reconhecível são MANTIDAS, com hasContent
 * false: sumir com uma versão da lista faria o admin concluir que ela não
 * existiu. A tela mostra o cartão com um link para a nota no GitHub.
 */
export function parseReleases(raw: RawRelease[]): ParsedRelease[] {
  return (raw || []).map((r) => {
    const changes = parseReleaseBody(r.body);
    return {
      version: versionOf(r.tag),
      date: isoDate(r.published_at),
      url: r.html_url,
      changes,
      hasContent: changes.length > 0,
    };
  });
}
