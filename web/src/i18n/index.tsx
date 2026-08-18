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

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('useI18n must be used within I18nProvider');
  return ctx;
}
