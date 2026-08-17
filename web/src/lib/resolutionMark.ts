/**
 * A marca de "esta janela de confirmação fomos NÓS que fechamos".
 *
 * Ela existe por causa de UMA mensagem, e é a mensagem mais importante que a
 * tela de grupos tem:
 *
 *   "O prazo acabou sem confirmação: a alteração foi revertida e os grupos e as
 *    regras voltaram ao estado anterior."
 *
 * O painel não tem como perguntar ao servidor QUEM fechou a janela — ele só vê,
 * no poll seguinte, que o pendente sumiu. A regra é: se sumiu e a gente tinha
 * acabado de pedir para fechar, foi a gente, e anunciar uma reversão automática
 * seria mentira; se sumiu sem a gente ter pedido, foi o relógio, e o operador
 * PRECISA saber que a alteração dele foi desfeita.
 *
 * O erro que essas três funções fecham: a marca era posta antes da chamada e
 * não era desfeita quando a chamada FALHAVA. Uma tentativa de confirmar que
 * volta 500 (ou 409, ou timeout) não resolveu janela nenhuma — a mesma janela
 * continua correndo. Com a marca presa ali, o vencimento dela caía no ramo
 * "fomos nós" e sumia em silêncio, engolindo o aviso. O operador ficava
 * olhando uma tela que não dizia nada sobre a alteração que o firewall acabou
 * de desfazer.
 *
 * `release` é o lado seguro: na dúvida, avisar. Anunciar uma reversão que não
 * houve custa um susto e uma releitura; não anunciar a que houve custa o
 * operador acreditando numa regra de firewall que não está mais lá.
 *
 * O tipo é o de um `useRef<string>` de propósito: a marca tem que ser lida e
 * escrita fora do ciclo de renderização do React (o poll de 3 s a consulta), e
 * um estado atrasaria a leitura em uma renderização.
 */

export interface ResolutionMark {
  current: string;
}

/** claim marca a janela `id` como a que NÓS estamos fechando agora. */
export function claim(mark: ResolutionMark, id: string): void {
  mark.current = id;
}

/**
 * release desfaz a marca de `id` — a chamada falhou e a janela continua de pé.
 *
 * Ela só desfaz a marca DAQUELA janela: um erro atrasado, de uma janela que já
 * não é a marcada, não pode apagar a marca de uma tentativa em curso.
 */
export function release(mark: ResolutionMark, id: string): void {
  if (mark.current === id) mark.current = '';
}

/**
 * consume responde "fomos nós que fechamos a janela `id`?" e gasta a marca.
 *
 * Gastar é parte da resposta: a marca vale por um fechamento só. Deixá-la ali
 * faria a PRÓXIMA janela com o mesmo id (o servidor pode reusá-lo) ser tomada
 * por resolvida sem ninguém ter pedido nada.
 */
export function consume(mark: ResolutionMark, id: string): boolean {
  if (mark.current !== id) return false;
  mark.current = '';
  return true;
}
