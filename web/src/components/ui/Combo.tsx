/**
 * Um seletor com busca — a peça que troca "digite o CIDR" por "escolha o
 * aparelho".
 *
 * Ele existe como componente próprio, e não como um <select> nativo, por três
 * coisas que o nativo não faz e que são justamente o ponto aqui: buscar
 * digitando, agrupar por seção com cabeçalho, e mostrar uma segunda linha de
 * apoio (o endereço, embaixo do nome). Sem as três, a lista de 40 aparelhos de
 * uma rede real vira uma rolagem inútil.
 *
 * Deliberadamente NÃO é genérico além do necessário: recebe itens já prontos
 * para desenhar. Quem sabe traduzir host, reserva e link WAN em item é
 * lib/netTargets, que é código puro e tem asserção — e é lá que essa decisão
 * deve continuar morando.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, ChevronDown, X } from 'lucide-react';
import { useI18n } from '../../i18n';

export interface ComboItem {
  id: string;
  label: string;
  /** Linha de apoio: o endereço, a porta, o que ajuda a confirmar a escolha. */
  hint?: string;
  /** Cabeçalho da seção a que este item pertence. */
  group?: string;
  /** Ponto verde à esquerda — usado para "está na rede agora". */
  dot?: boolean;
}

interface Props {
  items: ComboItem[];
  /** id do item escolhido, ou '' para nenhum. */
  value: string;
  onPick: (item: ComboItem | null) => void;
  placeholder?: string;
  /** Texto da opção que limpa a escolha. Ausente = não oferece limpar. */
  emptyLabel?: string;
  /** Busca livre: quando presente, o que for digitado pode virar valor. */
  onFreeText?: (texto: string) => void;
  freeTextHint?: string;
  disabled?: boolean;
}

export default function Combo({
  items, value, onPick, placeholder,
  emptyLabel, onFreeText, freeTextHint, disabled,
}: Props) {
  const { t } = useI18n();
  const textoBusca = placeholder ?? t('shell.combo.search');
  const [aberto, setAberto] = useState(false);
  const [busca, setBusca] = useState('');
  const caixa = useRef<HTMLDivElement>(null);

  const escolhido = useMemo(() => items.find((i) => i.id === value) || null, [items, value]);

  // Fecha ao clicar fora. Sem isto, abrir dois seletores na mesma tela deixa os
  // dois abertos, um por cima do outro.
  useEffect(() => {
    if (!aberto) return;
    const fora = (e: MouseEvent) => {
      if (caixa.current && !caixa.current.contains(e.target as Node)) setAberto(false);
    };
    document.addEventListener('mousedown', fora);
    return () => document.removeEventListener('mousedown', fora);
  }, [aberto]);

  const filtrados = useMemo(() => {
    const q = busca.trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (!q) return items;
    const fold = (s: string) => (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    return items.filter((i) => fold(i.label).includes(q) || fold(i.hint || '').includes(q));
  }, [items, busca]);

  // O texto digitado só vira opção quando não casa com nada conhecido: oferecer
  // "usar 192.168.3.47" com o aparelho desse IP logo acima seria convidar o
  // admin a escolher a versão pior da mesma coisa.
  const podeLivre = !!onFreeText && busca.trim().length > 0 && filtrados.length === 0;

  const escolher = (i: ComboItem | null) => {
    onPick(i);
    setAberto(false);
    setBusca('');
  };

  return (
    <div className="relative" ref={caixa}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setAberto((a) => !a)}
        className="input w-full flex items-center gap-2 text-left disabled:opacity-50"
      >
        <span className="flex-1 min-w-0 truncate">
          {escolhido ? (
            <>
              <span className="text-gray-200">{escolhido.label}</span>
              {escolhido.hint && <span className="text-gray-500 text-xs ml-2 font-mono">{escolhido.hint}</span>}
            </>
          ) : (
            <span className="text-gray-500">{emptyLabel || textoBusca}</span>
          )}
        </span>
        {escolhido && emptyLabel && (
          <X
            className="w-3.5 h-3.5 text-gray-500 hover:text-gray-300 shrink-0"
            onClick={(e) => { e.stopPropagation(); escolher(null); }}
          />
        )}
        <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" />
      </button>

      {aberto && (
        <div className="absolute z-50 mt-1 w-full card p-0 max-h-80 overflow-y-auto">
          <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-2 flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-gray-500 shrink-0" />
            <input
              autoFocus
              className="bg-transparent outline-none text-sm text-gray-200 w-full"
              placeholder={textoBusca}
              value={busca}
              onChange={(e) => setBusca(e.target.value)}
            />
          </div>

          {emptyLabel && (
            <button
              type="button"
              onClick={() => escolher(null)}
              className="w-full text-left px-3 py-2 text-sm text-gray-400 hover:bg-gray-800"
            >
              {emptyLabel}
            </button>
          )}

          {filtrados.map((i, idx) => {
            const novoGrupo = i.group && (idx === 0 || filtrados[idx - 1].group !== i.group);
            return (
              <div key={i.id}>
                {novoGrupo && (
                  <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wide text-gray-600">{i.group}</div>
                )}
                <button
                  type="button"
                  onClick={() => escolher(i)}
                  className={`w-full text-left px-3 py-2 hover:bg-gray-800 flex items-center gap-2 ${
                    i.id === value ? 'bg-gray-800/60' : ''
                  }`}
                >
                  {i.dot !== undefined && (
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${i.dot ? 'bg-green-400' : 'bg-gray-700'}`} />
                  )}
                  <span className="flex-1 min-w-0">
                    <span className="block text-sm text-gray-200 truncate">{i.label}</span>
                    {i.hint && <span className="block text-xs text-gray-500 font-mono truncate">{i.hint}</span>}
                  </span>
                </button>
              </div>
            );
          })}

          {podeLivre && (
            <button
              type="button"
              onClick={() => { onFreeText!(busca.trim()); setAberto(false); setBusca(''); }}
              className="w-full text-left px-3 py-2 text-sm text-blue-400 hover:bg-gray-800 border-t border-gray-800"
            >
              {t('shell.combo.useFreeText', { text: busca.trim() })}
              {freeTextHint && <span className="text-gray-500 text-xs ml-2">{freeTextHint}</span>}
            </button>
          )}

          {filtrados.length === 0 && !podeLivre && (
            <p className="px-3 py-4 text-center text-sm text-gray-600">{t('shell.combo.noMatch')}</p>
          )}
        </div>
      )}
    </div>
  );
}
