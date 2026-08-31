import type { InterfaceRate } from './interfaceRates';
import type { IfaceView } from '../types';

// O estado que o desenho do jack precisa saber. Fica aqui, e não dentro do
// componente, porque é a única parte disto que tem como estar errada — o SVG
// não tem o que testar, a leitura dos contadores tem.
export interface PortState {
  /** Existe uma porta de verdade atrás desta linha. VLAN e bridge não têm. */
  physical: boolean;
  /** LED de link: o kernel enxerga portadora no fio. */
  link: boolean;
  /**
   * LED de atividade em âmbar: o link está de pé E o contador acusa erro. É
   * de propósito que ele NÃO acende com o link caído — ali o problema já é o
   * link, e dois LEDs vermelhos ao mesmo tempo escondem qual deles importa.
   */
  degraded: boolean;
  /**
   * Passa tráfego agora. TRÊS estados, e o terceiro é a razão de isto ser
   * `boolean | null` em vez de `boolean`:
   *
   *   true  — medido, e há tráfego acima do piso;
   *   false — medido, e a interface está parada;
   *   null  — NÃO MEDIDO. Ainda não há duas amostras de contador, ou a
   *           coleta não respondeu.
   *
   * `false` e `null` levam a leituras opostas — "ninguém está usando" e "não
   * estou olhando" — e é exatamente essa confusão que o alvo por domínio já
   * pagou caro (#123). Um LED apagado por falta de medição afirmaria silêncio
   * na rede que o produto não observou.
   */
  activity: boolean | null;
}

/**
 * ATIVIDADE_MIN é o piso, em bits/s, a partir do qual o LED pisca.
 *
 * Zero não serve como piso: uma interface parada ainda carrega ARP, mDNS e
 * descoberta de vizinho, e um LED que pisca o tempo todo não informa nada —
 * vira enfeite, e enfeite é o que faz o admin parar de olhar para o painel.
 * 16 kbit/s fica acima desse chiado e bem abaixo de qualquer tráfego que uma
 * pessoa tenha gerado de propósito.
 */
export const ATIVIDADE_MIN = 16_000;

/**
 * portState traduz a interface para o que os dois LEDs mostram.
 *
 * Só olha `carrier` e os contadores de ERRO. Descarte (rx_dropped/tx_dropped)
 * ficou de fora porque acontece em operação normal sob carga — um LED âmbar
 * que acende sozinho num link saudável é ruído, e ruído ensina o admin a
 * ignorar o painel.
 *
 * Não existe LED de atividade piscando aqui, e a ausência é deliberada: o
 * /api/interfaces não devolve taxa nenhuma, e um LED que piscasse sem dado
 * atrás estaria afirmando tráfego que este produto não mediu.
 */
export function portState(iface: IfaceView, rate?: InterfaceRate | null): PortState {
  const physical = iface.kind === 'physical';
  if (!physical) {
    return { physical: false, link: false, degraded: false, activity: null };
  }
  const link = iface.live.carrier;
  const errors = (iface.live.rx_errors ?? 0) > 0 || (iface.live.tx_errors ?? 0) > 0;
  return { physical: true, link, degraded: link && errors, activity: atividade(rate) };
}

// `undefined` é o chamador que não mede (as listas, que não coletam taxa);
// `null` é a coleta que ainda não tem duas amostras. Os dois viram null: não
// medido é não medido, e nenhum dos dois autoriza dizer "parada".
function atividade(rate?: InterfaceRate | null): boolean | null {
  if (rate == null) return null;
  return rate.rx + rate.tx >= ATIVIDADE_MIN;
}

/**
 * portIsAbnormal é o critério de "esta porta merece aviso" — link caído ou
 * contador de erro. Existia duplicado em duas partes da tela de interfaces,
 * e as duas cópias discordavam: a visão geral só olhava rx_errors, a lista
 * olhava rx e tx. Uma porta com erro só na transmissão aparecia normal numa
 * aba e com aviso na outra.
 */
export function portIsAbnormal(iface: IfaceView): boolean {
  if (iface.kind !== 'physical') return false;
  return !iface.live.carrier || (iface.live.rx_errors ?? 0) > 0 || (iface.live.tx_errors ?? 0) > 0;
}
