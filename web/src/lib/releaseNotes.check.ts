// Asserções do parser das notas de release (node --experimental-strip-types).
//
// O corpo usado no primeiro bloco é a nota REAL da v1.0.109, copiada da
// release publicada. É a única forma de este teste provar alguma coisa: um
// markdown inventado por mim casaria com o parser que eu escrevi, e os dois
// poderiam estar errados juntos.

import assert from 'node:assert';
import { parseReleaseBody, parseReleases, isoDate, versionOf } from './releaseNotes.ts';

let n = 0;
const check = (cond: unknown, msg: string) => { assert.ok(cond, msg); n++; };
const eq = (a: unknown, b: unknown, msg: string) => { assert.deepStrictEqual(a, b, msg); n++; };

const NOTA_REAL = `## O que mudou em v1.0.109

Comparado com [\`v1.0.108\`](https://github.com/x/y/compare/v1.0.108...v1.0.109) — 8 commits.

### Reestruturação interna

- (handlers) as dez mutações usam ApplyGuarded; os helpers antigos saem (#20, parte 6)
- (firewall) a ordem do confirmar-ou-reverte ganha um lugar só (#20, parte 1)

### Testes

- (vm) bateria do confirmar-ou-reverte contra um sistema instalado (#20)

---

Instalação e atualização: veja [Installation no README](https://github.com/x/y/blob/main/README.md#installation).

Confira os artefatos antes de instalar:

\`\`\`bash
wget https://github.com/x/y/releases/download/v1.0.109/sha256sums.txt
sha256sum -c sha256sums.txt
\`\`\`

Build automático do commit e0c9fd9.`;

{
  const c = parseReleaseBody(NOTA_REAL);
  eq(c.length, 3, 'a nota real tem 3 mudanças');
  eq(c[0].scope, 'handlers', 'o escopo é extraído do começo da linha');
  check(!c[0].text.startsWith('('), 'o escopo sai do texto, senão toda linha começa com parêntese');
  eq(c[0].type, 'chore', '"Reestruturação interna" não compete com correção de segurança');
  eq(c[2].scope, 'vm', 'a última mudança é a da seção Testes');
}

{
  // O RODAPÉ NÃO PODE VIRAR MUDANÇA. Sem o corte no `---`, as linhas de
  // instalação entravam na lista e empurravam o conteúdo real para fora da
  // vista — em TODA release, porque o rodapé é fixo.
  const c = parseReleaseBody(NOTA_REAL);
  // A busca é por trechos que SÓ existem no rodapé. A primeira versão deste
  // teste procurava /Instala/i e ficou vermelha por causa de "contra um sistema
  // instalado", que é uma mudança legítima — o teste é que estava largo demais.
  check(!c.some((x) => /sha256sums|wget https|Build automático/.test(x.text)),
    'nada do rodapé de instalação virou mudança');
  check(!c.some((x) => x.text.startsWith('Instalação e atualização')),
    'a linha de instalação não virou mudança');
}

{
  const c = parseReleaseBody(`### Segurança

- (auth) fecha o vazamento de sessão

### Correções

- (dhcp) duas reservas com o mesmo IP

### Novidades

- (web) tela nova`);
  eq(c.map((x) => x.type), ['security', 'fix', 'feat'], 'as três seções que a tela pinta');
}

{
  // Linha sem escopo continua sendo uma mudança.
  const c = parseReleaseBody('### Correções\n\n- corrige o que não tinha escopo');
  eq(c.length, 1, 'linha sem escopo é aceita');
  eq(c[0].scope, '', 'e fica sem rótulo');
}

{
  // Texto antes de qualquer cabeçalho é ignorado: é o parágrafo do "comparado
  // com", que não é mudança nenhuma.
  const c = parseReleaseBody('Comparado com v1 — 3 commits.\n\n- isto não é uma mudança');
  eq(c.length, 0, 'linha solta antes da primeira seção é ignorada');
}

{
  // Seção desconhecida não pode sumir: ela mudou o produto.
  const c = parseReleaseBody('### Alguma Seção Nova\n\n- algo aconteceu');
  eq(c.length, 1, 'seção desconhecida ainda produz mudança');
  eq(c[0].type, 'chore', 'e cai no tipo neutro');
}

{
  const r = parseReleases([{
    tag: 'v1.0.110', name: 'LinkGuard FW v1.0.110',
    published_at: '2026-08-18T00:19:29Z',
    html_url: 'https://github.com/x/y/releases/tag/v1.0.110',
    body: '### Correções\n\n- (web) algo', prerelease: false,
  }]);
  eq(r[0].version, '1.0.110', 'o "v" sai da versão (a tela já escreve o dela)');
  eq(r[0].date, '2026-08-18', 'a data vem do published_at');
  check(r[0].hasContent, 'release com mudança tem conteúdo');
}

{
  // Release sem nada reconhecível FICA na lista. Sumir com uma versão faria o
  // admin concluir que ela não existiu.
  const r = parseReleases([{
    tag: 'v1.0.50', name: '', published_at: '2026-01-02T00:00:00Z',
    html_url: 'u', body: 'nota escrita à mão, sem seções', prerelease: false,
  }]);
  eq(r.length, 1, 'a release continua na lista');
  check(!r[0].hasContent, 'marcada como sem conteúdo, para a tela ligar no GitHub');
}

{
  eq(isoDate(''), '', 'data ausente não quebra');
  eq(versionOf('sem-v'), 'sem-v', 'tag fora do padrão passa inteira');
  eq(parseReleaseBody('').length, 0, 'corpo vazio não quebra');
}

console.log(`${n} asserções passaram.`);
