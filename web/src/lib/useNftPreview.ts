import { useEffect, useState } from 'react';
import { tStatic } from '../i18n';
import client from '../api/client';

/**
 * useNftPreview pede ao backend a linha nft que a regra/grupo em edição vai
 * gerar.
 *
 * Por que uma ida ao servidor para mostrar uma linha de texto: porque a linha
 * tem que ser a MESMA que vai para o kernel. Antes ela era remontada aqui em
 * TypeScript, espelhando a ordem dos campos do Go, e nada verificava que as
 * duas versões continuavam iguais. A divergência seria assintomática — nenhum
 * teste falharia, nenhum log registraria, nenhum apply daria erro — e a tela
 * afirmaria que a regra faz X enquanto o firewall recebe Y. Num painel em que
 * uma regra errada corta o SSH do operador, isso é o oposto do que o produto
 * promete.
 *
 * O debounce existe porque o preview acompanha a digitação: sem ele seria uma
 * requisição por tecla. 250 ms é o suficiente para não piscar e curto o
 * bastante para a linha parecer instantânea.
 *
 * Campo inválido devolve 400 com o motivo, e o motivo é o que a tela mostra no
 * lugar da linha — enquanto o operador ainda está digitando, é mais útil do que
 * uma linha vazia.
 */
export function useNftPreview(endpoint: string, body: unknown, enabled = true) {
  const [rendered, setRendered] = useState('');
  const [erro, setErro] = useState('');
  const chave = JSON.stringify(body);

  useEffect(() => {
    if (!enabled) return;
    let cancelado = false;
    const t = setTimeout(() => {
      client
        .post<{ rendered: string }>(endpoint, JSON.parse(chave))
        .then(({ data }) => {
          if (cancelado) return;
          setRendered(data.rendered);
          setErro('');
        })
        .catch((e) => {
          if (cancelado) return;
          const ax = e as { response?: { data?: { error?: string } } };
          setRendered('');
          setErro(ax?.response?.data?.error || tStatic('fw.preview.failed'));
        });
    }, 250);
    return () => {
      cancelado = true;
      clearTimeout(t);
    };
  }, [endpoint, chave, enabled]);

  return { rendered, erro };
}
