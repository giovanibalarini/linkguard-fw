// Asserções de `resolutionMark.ts` — quem fechou a janela de confirmação.
//
// Por que este arquivo existe: a conta que ele cobre decide se o operador VÊ ou
// NÃO VÊ o aviso de que a alteração dele foi revertida pelo prazo. Ela erra em
// silêncio e compilando, e o jeito de errar não aparece em nenhuma tela de
// desenvolvimento — só numa máquina em que a chamada de confirmar falhou e a
// janela venceu depois. É exatamente o caso que ninguém reproduz por acaso.
//
// Mesmo formato de `series.check.ts`, `grid.check.ts`, `widgets.check.ts` e
// `groupRules.check.ts`: um programa comum, sem runner e sem dependência nova
// (spec §4.3 — num appliance de segurança, uma biblioteca de teste é superfície
// de cadeia de suprimentos por conveniência), executável pelo node que já está
// instalado e que sai com código ≠ 0 na falha.
//
// Como rodar (a partir de `web/`):
//
//     node --experimental-strip-types src/lib/resolutionMark.check.ts

import { claim, consume, release } from './resolutionMark.ts';
import type { ResolutionMark } from './resolutionMark.ts';

let falhas = 0;
let total = 0;
let grupoAtual = '';

function grupo(nome: string) {
  grupoAtual = nome;
}

function assert(cond: boolean, msg: string) {
  total++;
  if (cond) return;
  falhas++;
  console.error(`  FALHOU [${grupoAtual}] ${msg}`);
}

/** A marca nasce vazia, como o `useRef('')` da tela. */
function novaMarca(): ResolutionMark {
  return { current: '' };
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('sem ninguém ter pedido nada');
{
  const m = novaMarca();
  assert(consume(m, 'w1') === false, 'uma janela que sumiu sozinha NÃO foi resolvida por nós');
  assert(m.current === '', 'e a marca continua vazia');
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('confirmar deu certo');
{
  const m = novaMarca();
  claim(m, 'w1');
  assert(m.current === 'w1', 'a marca guarda o id da janela que estamos fechando');
  assert(consume(m, 'w1') === true, 'quando ela sumir, fomos nós — nada de anunciar reversão automática');
  assert(m.current === '', 'e a marca é gasta no caminho');
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('a marca vale por um fechamento só');
{
  const m = novaMarca();
  claim(m, 'w1');
  assert(consume(m, 'w1') === true, 'o primeiro fechamento é nosso');
  // O servidor pode reusar o id, e uma marca não gasta faria a janela SEGUINTE
  // — que ninguém pediu para fechar — sumir calada.
  assert(consume(m, 'w1') === false, 'o segundo já não é: a marca não sobrevive ao uso');
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('confirmar FALHOU — o defeito que este módulo fecha');
{
  const m = novaMarca();
  claim(m, 'w1');
  // 500, 409, timeout: a chamada não resolveu nada e a janela w1 continua
  // correndo na máquina.
  release(m, 'w1');
  assert(m.current === '', 'uma chamada que falhou não deixa marca para trás');
  assert(
    consume(m, 'w1') === false,
    'quando o prazo vencer e o watchdog reverter, o aviso TEM que sair — era ele que era engolido',
  );
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('reverter FALHOU e depois deu certo');
{
  const m = novaMarca();
  claim(m, 'w1');
  release(m, 'w1');
  // O operador aperta "Reverter agora" de novo, e desta vez o servidor aceita.
  claim(m, 'w1');
  assert(consume(m, 'w1') === true, 'a segunda tentativa, essa sim, resolveu a janela');
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('erro atrasado de outra janela');
{
  const m = novaMarca();
  claim(m, 'w2');
  // Uma falha que chega tarde, referente à janela w1 que já foi embora, não
  // pode apagar a marca da tentativa que está em curso agora.
  release(m, 'w1');
  assert(m.current === 'w2', 'release só desfaz a marca da SUA janela');
  assert(consume(m, 'w2') === true, 'e w2 continua sendo nossa');
}

// ─────────────────────────────────────────────────────────────────────────────
grupo('outra janela fechou enquanto a nossa corria');
{
  const m = novaMarca();
  claim(m, 'w2');
  // Outro admin reverteu a janela dele (w3) do outro lado. Para nós isso é uma
  // janela que sumiu sem a gente ter pedido: o aviso tem que sair.
  assert(consume(m, 'w3') === false, 'a janela de outro admin não é a nossa');
  assert(m.current === 'w2', 'e a nossa marca sobrevive intacta');
}

// ─────────────────────────────────────────────────────────────────────────────
if (falhas > 0) {
  console.error(`\n${falhas} de ${total} asserções falharam.`);
  process.exit(1);
}
console.log(`${total} asserções passaram.`);
