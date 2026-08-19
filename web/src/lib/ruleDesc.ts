// A descrição de uma regra, traduzida (issue #109).
//
// O backend manda `desc: { key, vars }` — o QUE a regra faz e com que valores —
// e as palavras são escolhidas aqui. A frase pronta em português continua
// chegando em `description`, e é ela que aparece quando o backend não sabe
// descrever a linha: melhor a expressão nft crua do que um palpite errado, que
// é a mesma disciplina do describeRule no Go.
//
// Só lógica, sem React: a montagem da condição tem regra própria e merece
// asserção.

export interface RuleDesc {
  key: string;
  vars?: Record<string, string>;
}

type T = (key: string, vars?: Record<string, string | number>) => string;

/**
 * describeRule devolve a descrição no idioma ativo.
 *
 * `fallback` é a frase pronta do backend (o campo `description`). Ela é usada
 * quando não há chave — e NÃO é um defeito: é o caso "não sei descrever esta
 * linha", em que o produto mostra a expressão nft em vez de inventar.
 */
export function describeRule(desc: RuleDesc | undefined, fallback: string, t: T): string {
  if (!desc || !desc.key) return fallback;
  const cond = desc.vars?.cond;
  if (cond === undefined) return t(desc.key, desc.vars);
  return t(desc.key, { ...desc.vars, cond: formatCond(cond, t) });
}

/**
 * formatCond traduz as ETIQUETAS da condição e mantém os valores.
 *
 * O backend manda "saddr=10.0.0.0/8|proto=TCP:22": rótulo estável de um lado,
 * valor já formatado do outro. O valor (endereço, porta, protocolo, nome de
 * interface) nunca se traduz — é o que o admin digitou ou o que o kernel usa.
 *
 * Um rótulo que esta tabela não conheça é impresso como veio, com o valor. O
 * mesmo princípio do resto: preferir mostrar algo bruto a esconder.
 */
export function formatCond(cond: string, t: T): string {
  return cond
    .split('|')
    .filter(Boolean)
    .map((par) => {
      const i = par.indexOf('=');
      if (i < 0) return par;
      const rotulo = par.slice(0, i);
      const valor = par.slice(i + 1);
      const chave = `desc.cond.${rotulo}`;
      const texto = t(chave, { v: valor });
      // t() devolve a própria chave quando ela não existe: nesse caso mostramos
      // o par cru em vez de "desc.cond.xyz" na tela do operador.
      return texto === chave ? `${rotulo} ${valor}` : texto;
    })
    .join(', ');
}
