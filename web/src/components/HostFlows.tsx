import { useCallback, useEffect, useState } from 'react';
import { Loader2, Info, AlertTriangle } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';

/** Uma conversa observada, como o backend a devolve. */
interface Conversa {
  origem: string;
  destino: string;
  nome: string;
  porta: number;
  pacotes: number;
  bytes: number;
}

/** A resposta de /api/hosts/traffic/flows. */
interface RespostaFluxos {
  ligado: boolean;
  host: string;
  janela_minutos: number;
  conversas: Conversa[];
  total_conversas: number;
  total_bytes: number;
  cheio: boolean;
  teto: number;
  nomes_ligados: boolean;
}

interface ConfigFluxos {
  ligado: boolean;
  janela_minutos: number;
  teto: number;
}

interface RespostaConfig {
  config: ConfigFluxos;
  janela_minima: number;
  janela_maxima: number;
  teto_minimo: number;
  teto_maximo: number;
}

/** As duas rotas do registro de conversa, num lugar so. */
const ROTA = '/api/hosts/traffic/flows';
const ROTA_CONFIG = ROTA + '/config';

interface Props {
  /** Endereço do aparelho. A medição é IPv4: sem IP não há o que consultar. */
  ip: string;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
}

/**
 * HostFlows mostra COM QUEM um aparelho da LAN falou (issue #115).
 *
 * O QUE ELA E, E POR QUE O ROTULO IMPORTA. Isto nao e um registro de fluxo: e
 * uma janela ROLANTE E CURTA mantida na memoria do kernel, que some no
 * reinicio. Chamar de "registro" faria o admin ler uma ausencia como "nao
 * aconteceu", quando pode ser "aconteceu e ja expirou" ou "aconteceu e nao
 * coube no teto". Por isso o cabecalho declara a janela e o rodape declara as
 * quatro coisas que a medicao nao sabe -- nenhum dos dois e enfeite.
 *
 * DESLIGADO NAO E LISTA VAZIA. O backend devolve ligado=false justamente para
 * esta tela poder distinguir "este aparelho nao falou com ninguem" de "a caixa
 * nao esta olhando". Sao diagnosticos opostos, e mostrar o primeiro no lugar do
 * segundo e a definicao de mentir na tela.
 *
 * O CONTROLE DE LIGAR E DESLIGAR MORA AQUI, e nao numa pagina de
 * configuracoes, porque e aqui que a decisao faz sentido: quem abre esta tela e
 * a encontra desligada precisa ler, no mesmo lugar, o que ligar significa para
 * a privacidade de quem usa a rede. Ele aparece so para quem administra a caixa
 * (system.write) -- ver as rotas em internal/api/server.go para a razao de a
 * permissao de OLHAR nao ser a mesma de LIGAR.
 */
export default function HostFlows({ ip }: Props) {
  const { t } = useI18n();
  const { can } = useAuth();
  const podeConfigurar = can('system.write');

  const [dados, setDados] = useState<RespostaFluxos | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [erro, setErro] = useState(false);

  const [limites, setLimites] = useState<RespostaConfig | null>(null);
  const [janela, setJanela] = useState(60);
  const [teto, setTeto] = useState(8192);
  const [salvando, setSalvando] = useState(false);
  const [erroConfig, setErroConfig] = useState('');

  const carregar = useCallback(async () => {
    setCarregando(true); setErro(false);
    try {
      const { data } = await client.get<RespostaFluxos>(ROTA, { params: { ip } });
      setDados(data);
    } catch {
      // Erro NAO vira lista vazia: ver o comentario do topo.
      setErro(true); setDados(null);
    } finally {
      setCarregando(false);
    }
  }, [ip]);

  const carregarConfig = useCallback(async () => {
    if (!podeConfigurar) return;
    try {
      const { data } = await client.get<RespostaConfig>(ROTA_CONFIG);
      setLimites(data);
      setJanela(data.config.janela_minutos);
      setTeto(data.config.teto);
    } catch {
      setLimites(null);
    }
  }, [podeConfigurar]);

  useEffect(() => { carregar(); }, [carregar]);
  useEffect(() => { carregarConfig(); }, [carregarConfig]);

  const salvar = async (ligado: boolean) => {
    setSalvando(true);
    setErroConfig('');
    try {
      await client.put(ROTA_CONFIG, { ligado, janela_minutos: janela, teto });
      await carregarConfig();
      await carregar();
    } catch {
      setErroConfig(t('svc.fluxos.config.saveError'));
    } finally {
      setSalvando(false);
    }
  };

  const janelaMin = limites?.janela_minima ?? 5;
  const janelaMax = limites?.janela_maxima ?? 1440;
  const tetoMin = limites?.teto_minimo ?? 1024;
  const tetoMax = limites?.teto_maximo ?? 32768;
  const desligado = dados !== null && !dados.ligado;

  // O painel de configuracao aparece para quem administra a caixa. Ele fica
  // visivel tambem com o registro LIGADO, porque desligar (e apagar) tem de ser
  // tao facil quanto ligar -- um registro de quem-falou-com-quem que so se liga
  // e uma armadilha para quem instalou o produto.
  const painelDeConfig = podeConfigurar && limites !== null && (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 space-y-3">
      <p className="text-white text-sm font-semibold">{t('svc.fluxos.config.title')}</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block text-xs text-gray-400">
          {t('svc.fluxos.config.window')}
          <input
            type="number"
            className="input w-full mt-1"
            min={janelaMin}
            max={janelaMax}
            value={janela}
            onChange={(e) => setJanela(Number(e.target.value))}
          />
          <span className="block mt-1 text-gray-600">
            {t('svc.fluxos.config.windowHint', { min: janelaMin, max: janelaMax })}
          </span>
        </label>
        <label className="block text-xs text-gray-400">
          {t('svc.fluxos.config.ceiling')}
          <input
            type="number"
            className="input w-full mt-1"
            min={tetoMin}
            max={tetoMax}
            value={teto}
            onChange={(e) => setTeto(Number(e.target.value))}
          />
          <span className="block mt-1 text-gray-600">
            {t('svc.fluxos.config.ceilingHint', { min: tetoMin, max: tetoMax })}
          </span>
        </label>
      </div>
      <p className="flex items-start gap-2 text-amber-300 text-xs">
        <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
        <span>{t('svc.fluxos.config.resetWarning')}</span>
      </p>
      {erroConfig && <p className="text-red-400 text-xs">{erroConfig}</p>}
      <div className="flex gap-2">
        <button className="btn-primary text-sm" disabled={salvando} onClick={() => salvar(true)}>
          {t('svc.fluxos.config.enable')}
        </button>
        {limites.config.ligado && (
          <button className="btn-secondary text-sm" disabled={salvando} onClick={() => salvar(false)}>
            {t('svc.fluxos.config.disable')}
          </button>
        )}
      </div>
    </div>
  );

  if (carregando) {
    return (
      <p className="flex items-center gap-2 text-gray-500 text-sm py-3">
        <Loader2 className="w-4 h-4 animate-spin" /> {t('svc.fluxos.loading')}
      </p>
    );
  }

  // Falha de leitura NAO e "nao falou com ninguem". Ver o comentario do topo.
  if (erro) {
    return (
      <p className="flex items-start gap-2 rounded-lg bg-red-500/10 border border-red-500/20 px-3 py-2 text-red-300 text-sm">
        <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
        <span>{t('svc.fluxos.error')}</span>
      </p>
    );
  }

  if (desligado) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
          <p className="text-white text-sm font-semibold">{t('svc.fluxos.off.title')}</p>
          <p className="text-gray-400 text-sm mt-2">{t('svc.fluxos.off.body')}</p>
          {!podeConfigurar && (
            <p className="text-gray-500 text-xs mt-2">{t('svc.fluxos.off.noPermission')}</p>
          )}
        </div>
        {painelDeConfig}
      </div>
    );
  }

  if (!dados) return null;

  return (
    <div className="space-y-4">
      <div>
        <p className="text-white text-sm font-semibold">{t('svc.fluxos.title')}</p>
        <p className="text-gray-500 text-xs mt-1">
          {t('svc.fluxos.window', { min: dados.janela_minutos })}
        </p>
      </div>

      {dados.cheio && (
        <p className="flex items-start gap-2 rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-amber-300 text-xs">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{t('svc.fluxos.full', { teto: dados.teto })}</span>
        </p>
      )}

      {!dados.nomes_ligados && (
        <p className="flex items-start gap-2 text-gray-500 text-xs">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{t('svc.fluxos.names.off')}</span>
        </p>
      )}

      {dados.conversas.length === 0 ? (
        <p className="text-gray-600 text-sm py-2">{t('svc.fluxos.empty')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="py-2 pr-3 font-medium">{t('svc.fluxos.col.destination')}</th>
                <th className="py-2 pr-3 font-medium">{t('svc.fluxos.col.port')}</th>
                <th className="py-2 font-medium text-right">{t('svc.fluxos.col.volume')}</th>
              </tr>
            </thead>
            <tbody>
              {dados.conversas.map((c) => (
                <tr key={`${c.origem}-${c.destino}-${c.porta}`} className="border-b border-gray-900">
                  <td className="py-2 pr-3">
                    {/* Nome vazio significa "o mapa nao conhece este endereco".
                        A tela mostra o endereco cru em vez de inventar um nome
                        -- ver hostflows.batizar. */}
                    {c.nome ? (
                      <>
                        <span className="text-white">{c.nome}</span>
                        <span className="block text-gray-600 text-xs font-mono">{c.destino}</span>
                      </>
                    ) : (
                      <span className="text-gray-300 font-mono">{c.destino}</span>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-gray-400 font-mono">{c.porta}</td>
                  <td className="py-2 text-right text-gray-300">{fmtBytes(c.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {/* O corte e DECLARADO. Sem esta linha, uma lista truncada passa por
              lista completa e o admin conclui que o aparelho nao falou com o
              resto -- ver hostflows.agregar. */}
          <p className="text-gray-600 text-xs mt-2">
            {t('svc.fluxos.count', { shown: dados.conversas.length, total: dados.total_conversas })}
          </p>
        </div>
      )}

      <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
        <p className="text-gray-400 text-xs font-semibold">{t('svc.fluxos.limits.title')}</p>
        <ul className="text-gray-500 text-xs mt-1 space-y-1 list-disc list-inside">
          <li>{t('svc.fluxos.limits.duration')}</li>
          <li>{t('svc.fluxos.limits.wan')}</li>
          <li>{t('svc.fluxos.limits.family')}</li>
          <li>{t('svc.fluxos.limits.reboot')}</li>
        </ul>
      </div>

      {painelDeConfig}
    </div>
  );
}
