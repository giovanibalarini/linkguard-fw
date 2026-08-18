// Gera src/i18n/strings.generated.ts a partir de src/i18n/strings.yaml.
//
// POR QUE ISTO EXISTE. Antes, cada texto da interface morava cravado no JSX, e
// as traduções num dicionário TS escrito à mão — então acrescentar uma frase
// era trabalho manual em dois lugares, e esquecer o inglês não quebrava nada.
// O resultado: 3 de 70 telas traduzidas (issue #105).
//
// Agora o YAML é a fonte única. Quem escreve tela nova acrescenta a chave lá, e
// só lá. Este script transforma o YAML no dicionário que a aplicação consome.
//
// POR QUE GERAR EM VEZ DE IMPORTAR O YAML DIRETO. O arquivo gerado é commitado,
// então a mudança de texto aparece no diff da PR como texto — revisável por
// quem fala os dois idiomas, sem ter de rodar o build para saber o que mudou. E
// o bundle final não carrega parser de YAML nenhum: js-yaml é devDependency.
//
// A VALIDAÇÃO É O PONTO. Uma chave sem tradução em algum idioma aborta com
// código 1, e isso roda no CI. É o que impede a situação de hoje de voltar:
// texto novo que nasce só em português e ninguém percebe.

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
// js-yaml é CommonJS; createRequire evita depender de interop de default export.
const yaml = createRequire(import.meta.url)('js-yaml');

const aqui = dirname(fileURLToPath(import.meta.url));
// Um arquivo POR ÁREA, e não um só. O motivo é prático: quando várias pessoas
// (ou vários agentes) traduzem áreas diferentes ao mesmo tempo, um único
// strings.yaml vira um conflito de merge garantido em cada PR. Com um fragmento
// por área, cada uma só toca o seu.
//
// Uma chave definida em dois arquivos é ERRO, não "o último ganha": duas áreas
// disputando o mesmo id significa que uma delas vai mudar o texto da outra sem
// saber.
const DIR = join(aqui, '..', 'src', 'i18n', 'strings');
const SAIDA = join(aqui, '..', 'src', 'i18n', 'strings.generated.ts');

const IDIOMAS = ['pt', 'en'];

const arquivos = readdirSync(DIR).filter((f) => f.endsWith('.yaml')).sort();
if (arquivos.length === 0) {
  console.error(`${DIR}: nenhum .yaml encontrado`);
  process.exit(1);
}

const doc = {};
const origem = {};   // chave -> arquivo que a definiu, para acusar duplicata
const duplicadas = [];
for (const nome of arquivos) {
  const parcial = yaml.load(readFileSync(join(DIR, nome), 'utf8'));
  if (!parcial || typeof parcial !== 'object') {
    console.error(`${nome}: vazio ou não é um mapa de chaves`);
    process.exit(1);
  }
  for (const [k, v] of Object.entries(parcial)) {
    if (k in doc) duplicadas.push(`${k}: definida em ${origem[k]} e em ${nome}`);
    doc[k] = v;
    origem[k] = nome;
  }
}
if (duplicadas.length > 0) {
  console.error(`\nChaves duplicadas entre arquivos:\n`);
  for (const d of duplicadas) console.error(`  - ${d}`);
  console.error('\nCada chave pertence a uma área só.\n');
  process.exit(1);
}

const problemas = [];
const dicts = Object.fromEntries(IDIOMAS.map((l) => [l, {}]));

for (const [chave, valor] of Object.entries(doc)) {
  if (valor === null || typeof valor !== 'object' || Array.isArray(valor)) {
    problemas.push(`${chave}: esperava um mapa com ${IDIOMAS.join(' e ')}, veio ${Array.isArray(valor) ? 'uma lista' : typeof valor}`);
    continue;
  }
  for (const lang of IDIOMAS) {
    const texto = valor[lang];
    if (typeof texto !== 'string' || texto.trim() === '') {
      problemas.push(`${chave}: falta a tradução "${lang}"`);
      continue;
    }
    dicts[lang][chave] = texto;
  }
  // Uma chave com placeholder {x} em um idioma e não no outro é um bug que só
  // aparece em runtime, no idioma menos usado — e aparece como "{n}" cru na
  // tela do usuário. Barato de pegar aqui.
  const marcadores = (t) => (t.match(/\{[a-zA-Z0-9_]+\}/g) ?? []).sort().join(',');
  const [a, b] = IDIOMAS.map((l) => marcadores(String(valor[l] ?? '')));
  if (a !== b) {
    problemas.push(`${chave}: os marcadores não batem entre os idiomas (${IDIOMAS[0]}: ${a || 'nenhum'} | ${IDIOMAS[1]}: ${b || 'nenhum'})`);
  }
}

if (problemas.length > 0) {
  console.error(`\n${DIR}: ${problemas.length} problema(s)\n`);
  for (const p of problemas) console.error(`  - ${p}`);
  console.error('\nCorrija o YAML: toda chave precisa de texto nos dois idiomas.\n');
  process.exit(1);
}

const total = Object.keys(doc).length;
const corpo = `// GERADO POR scripts/gen-i18n.mjs — NÃO EDITE À MÃO.
//
// A fonte são os YAML em src/i18n/strings/. Para mudar ou acrescentar texto,
// edite o fragmento da sua área e rode \`npm run i18n:gen\` (o build já roda).
//
// Este arquivo é commitado de propósito: assim a mudança de texto aparece no
// diff da PR, revisável por quem fala os dois idiomas.

export type Lang = 'pt' | 'en';
export type Dict = Record<string, string>;

${IDIOMAS.map((l) => `export const ${l}: Dict = ${JSON.stringify(dicts[l], null, 2)};`).join('\n\n')}

export const dicts: Record<Lang, Dict> = { ${IDIOMAS.join(', ')} };
`;

writeFileSync(SAIDA, corpo);
console.log(`i18n: ${total} chaves × ${IDIOMAS.length} idiomas, de ${arquivos.length} arquivo(s) -> src/i18n/strings.generated.ts`);
