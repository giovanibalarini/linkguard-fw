import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { dicts } from './strings.generated';
import type { Lang } from './strings.generated';

/**
 * A camada de i18n. As strings NÃO moram aqui: elas moram em
 * `src/i18n/strings.yaml`, com pt e en lado a lado, e `scripts/gen-i18n.mjs`
 * as transforma em `strings.generated.ts` no build.
 *
 * A inversão é o ponto da issue #105. Antes, o texto nascia cravado no JSX e a
 * tradução era um dicionário à parte que alguém tinha de lembrar de atualizar —
 * e ninguém lembrava: a cobertura tinha parado em 3 de 70 telas. Agora o texto
 * nasce no YAML, nos dois idiomas de uma vez, e uma chave sem tradução quebra o
 * build em vez de virar uma tela meio traduzida em produção.
 *
 * t(key) devolve a string do idioma ativo, caindo no português e depois na
 * própria chave. t(key, {n: 3}) troca os marcadores {n}.
 */
export type { Lang } from './strings.generated';

const STORAGE_KEY = 'lg_lang';


interface I18nValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  // t(key) devolve a string do idioma ativo; t(key, {n: 3}) troca {n} por 3.
  // A interpolação existe porque boa parte do texto do Firewall tem número e
  // nome no meio ("3 regras", "grupo X") — sem ela, cada um viraria três
  // pedaços concatenados no JSX, que é onde a ordem das palavras de um idioma
  // não cabe na do outro.
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nValue | undefined>(undefined);

function readStored(): Lang {
  return localStorage.getItem(STORAGE_KEY) === 'en' ? 'en' : 'pt';
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(readStored);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, lang);
    document.documentElement.lang = lang === 'en' ? 'en' : 'pt-BR';
  }, [lang]);

  const setLang = useCallback((l: Lang) => setLangState(l), []);
  const t = useCallback((key: string, vars?: Record<string, string | number>) => {
    let out = dicts[lang][key] ?? dicts.pt[key] ?? key;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        out = out.split('{' + k + '}').join(String(v));
      }
    }
    return out;
  }, [lang]);

  return <I18nContext.Provider value={{ lang, setLang, t }}>{children}</I18nContext.Provider>;
}

// tStatic traduz FORA de um componente React.
//
// Existe por causa do ErrorBoundary, que é class component e não pode chamar
// hook — e ele é justamente a tela que aparece quando o resto quebrou, então
// deixá-la só em português seria o pior lugar para economizar. Também serve a
// qualquer módulo que precise de uma frase sem estar dentro da árvore.
//
// Lê o idioma do localStorage em vez do contexto: sem contexto disponível, essa
// é a mesma fonte que o provider usa para inicializar, então as duas concordam.
// A troca de idioma em tempo real NÃO chega aqui, e para o ErrorBoundary isso é
// irrelevante — ele é remontado a cada erro.
export function tStatic(key: string, vars?: Record<string, string | number>): string {
  const lang = readStored();
  let out = dicts[lang][key] ?? dicts.pt[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      out = out.split('{' + k + '}').join(String(v));
    }
  }
  return out;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('useI18n must be used within I18nProvider');
  return ctx;
}
