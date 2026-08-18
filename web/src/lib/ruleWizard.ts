// O assistente por intenção (issue #79).
//
// O PROBLEMA. Para criar uma regra de bloqueio comum — o equivalente a uma linha
// na FORWARD do iptables — era preciso, nesta ordem: entender o que é um
// "grupo", criar um (nome, escopo, "e o que sobrar", condição de entrada), e só
// então adicionar a regra dentro dele. A abstração que o produto inventou estava
// exposta como a PRIMEIRA coisa a aprender, e ela não tem equivalente no modelo
// mental de quem já usou iptables, pfSense ou OPNsense.
//
// O que esta peça faz é traduzir uma INTENÇÃO em campos de regra. O grupo
// continua existindo (é assim que a regra chega ao kernel — regra órfã não é
// renderizada, o defeito C-2), mas vira detalhe de implementação.
//
// Só lógica, sem I/O e sem React: é o que permite afirmar sobre a tradução com
// asserção, em vez de clicar na tela.

import type { Target } from './netTargets';
import type { Service } from './services';

export type Intent = 'bloquear' | 'liberar' | 'porta' | 'avancada';

/** Os campos de regra que o assistente preenche. Espelha RuleModalState. */
export interface RuleFields {
  action: 'accept' | 'drop' | 'reject';
  iif: string;
  oif: string;
  saddr: string;
  daddr: string;
  proto: string;
  dport: string;
  description: string;
}

export const CAMPOS_VAZIOS: RuleFields = {
  action: 'drop', iif: '', oif: '', saddr: '', daddr: '', proto: '', dport: '', description: '',
};

/** ehEndereco distingue um IP/CIDR de um nome de interface. */
export function ehEndereco(v: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v);
}

/**
 * buildRule traduz a intenção nos campos da regra.
 *
 * As três intenções guiadas cobrem o que um admin doméstico ou de escritório
 * pequeno pede de verdade. A quarta ("avancada") não passa por aqui: ela abre o
 * formulário inteiro, e forçá-la a nascer de uma tradução limitaria justamente
 * quem já sabe o que quer.
 */
export function buildRule(intent: Intent, alvo: Target | null, servico: Service | null): RuleFields {
  const f: RuleFields = { ...CAMPOS_VAZIOS };
  if (!alvo) return f;

  const campoDoAlvo = (destino: boolean) => {
    if (!ehEndereco(alvo.value)) {
      // Link WAN: o alvo é uma INTERFACE, e a regra fala dela por onde o
      // tráfego entra ou sai, não por endereço.
      if (destino) f.oif = alvo.value;
      else f.iif = alvo.value;
      return;
    }
    if (destino) f.daddr = alvo.value;
    else f.saddr = alvo.value;
  };

  if (intent === 'bloquear') {
    // drop, e não reject: bloquear um aparelho da própria rede é uma decisão
    // administrativa, e avisá-lo de que foi bloqueado só ensina a contornar.
    // Além disso o reject gasta banda de saída para cada pacote descartado.
    f.action = 'drop';
    campoDoAlvo(false);
    f.description = `bloqueio · ${alvo.label}`;
    return f;
  }

  if (intent === 'liberar') {
    f.action = 'accept';
    campoDoAlvo(false);
    if (servico) {
      f.proto = servico.proto;
      f.dport = servico.port;
    }
    f.description = `liberação · ${alvo.label}${servico ? ` · ${servico.name}` : ''}`;
    return f;
  }

  if (intent === 'porta') {
    // "Abrir para a internet" é o alvo RECEBENDO: ele é o destino.
    f.action = 'accept';
    campoDoAlvo(true);
    if (servico) {
      f.proto = servico.proto;
      f.dport = servico.port;
    }
    f.description = `porta aberta · ${servico ? servico.name : ''} → ${alvo.label}`.trim();
    return f;
  }

  return f;
}

/** precisaDeServico diz se a intenção exige escolher um serviço. */
export function precisaDeServico(intent: Intent): boolean {
  return intent === 'liberar' || intent === 'porta';
}

/** rotuloDoAlvo é a pergunta do passo do alvo, que muda com a intenção. */
export function rotuloDoAlvo(intent: Intent): string {
  return intent === 'porta' ? 'Qual aparelho recebe?' : 'Qual aparelho?';
}

/**
 * descreverRegra devolve a frase em português do que a regra vai fazer.
 *
 * Ela existe porque a linha nft não é legível para o público deste produto, e
 * porque uma pré-visualização que só mostra `ip saddr 192.168.3.47 counter drop`
 * devolve ao admin exatamente o problema que o assistente veio resolver.
 */
export function descreverRegra(intent: Intent, alvo: Target | null, servico: Service | null): string {
  if (!alvo) return 'Escolha um aparelho para ver o que vai acontecer.';
  const nome = alvo.label;

  if (intent === 'bloquear') {
    return `${nome} para de sair para a internet e de alcançar outras redes. O resto da rede continua igual.`;
  }
  if (intent === 'liberar') {
    if (!servico) return `${nome} — agora escolha o serviço que ele pode usar.`;
    return `${nome} passa a poder usar ${servico.name} (${servico.what}).`;
  }
  if (intent === 'porta') {
    if (!servico) return `Quem vier da internet vai alcançar ${nome} — escolha o serviço.`;
    return `Quem vier da internet passa a alcançar ${servico.name} em ${nome}.`;
  }
  return 'Modo avançado: todos os campos ficam disponíveis.';
}
