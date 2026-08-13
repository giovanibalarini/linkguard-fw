import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import client from '../../api/client';

/**
 * A moldura comum dos widgets que desenham o próprio conteúdo.
 *
 * Ela existe para uma coisa só: o widget ocupa exatamente a célula que o
 * operador lhe deu na grade, e o que não couber ROLA DENTRO dele. Sem
 * `min-h-0` + `overflow-auto` aqui, um widget com muitos itens estica a célula
 * e desalinha a grade inteira — que é o defeito clássico de grade em CSS.
 *
 * Alguns widgets ("Primeiros passos", "O que você quer fazer", "Saúde do
 * sistema") reusam componentes que já trazem o próprio cartão, e por isso não
 * passam por aqui.
 */
export default function WidgetCard({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="card flex h-full min-h-0 flex-col">
      <div className="mb-3 flex shrink-0 items-center justify-between gap-2">
        <h2 className="truncate text-sm font-semibold text-white">{title}</h2>
        {action}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
    </div>
  );
}

/**
 * A frase que um widget mostra quando não tem o que mostrar.
 *
 * A distinção é a regra do projeto, e ela é o produto: **`—` é não medido,
 * zero é medido e deu zero**. "Nenhum alerta aberto" é uma medição e se
 * escreve; "não consegui ler os alertas" é outra coisa, e se escreve
 * diferente. O que nunca se faz é preencher com estimativa.
 */
export function WidgetNote({ children }: { children: ReactNode }) {
  return <p className="py-2 text-sm text-gray-500">{children}</p>;
}

export type LoadState = 'loading' | 'ok' | 'error';

/**
 * Busca uma URL e revisita de tempos em tempos.
 *
 * Cada widget busca o SEU dado: widget que não está no painel não pede nada, e
 * widget que o usuário não pode ver não chega a ser montado — então ninguém
 * gasta requisição (nem toma 403) por um widget que não está na tela.
 */
export function usePolled<T>(url: string, intervalMs = 15000): { data: T | null; state: LoadState } {
  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LoadState>('loading');
  const dataRef = useRef<T | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await client.get<T>(url);
        if (!alive) return;
        dataRef.current = res.data;
        setData(res.data);
        setState('ok');
      } catch {
        if (!alive) return;
        // Mantém o último dado bom na tela e marca o estado: apagar tudo a cada
        // falha de rede faria o painel piscar em branco sem motivo.
        setState(dataRef.current === null ? 'error' : 'ok');
      }
    };
    load();
    const t = setInterval(load, intervalMs);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [url, intervalMs]);

  return { data, state };
}
