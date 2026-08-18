/**
 * O assistente por intenção (issue #79).
 *
 * Ele é o caminho de entrada que faltava: criar uma regra de bloqueio exigia
 * primeiro entender o conceito de "grupo" — criar um, nomear, escolher escopo e
 * "e o que sobrar" — e só então adicionar a regra dentro. A abstração que o
 * produto inventou estava exposta como a primeira coisa a aprender.
 *
 * Aqui a pergunta é o que o admin quer fazer. Os campos da regra saem disso, e
 * a tradução mora em lib/ruleWizard, que é pura e tem 30 asserções.
 *
 * O grupo continua existindo — é assim que a regra chega ao kernel; regra órfã
 * não é renderizada (defeito C-2) — mas o assistente nunca o menciona.
 */

import { useMemo, useState } from 'react';
import { Ban, Check, Globe, SlidersHorizontal } from 'lucide-react';
import Combo, { type ComboItem } from '../ui/Combo';
import { useNetTargets } from '../../lib/useNetTargets';
import { KIND_LABEL, type Target } from '../../lib/netTargets';
import { SERVICES, type Service } from '../../lib/services';
import {
  buildRule, descreverRegra, precisaDeServico, rotuloDoAlvo, type Intent,
} from '../../lib/ruleWizard';
import type { RuleModalState } from './groupMeta';

const INTENCOES: Array<{ id: Intent; titulo: string; ajuda: string; Icon: typeof Ban; cor: string }> = [
  { id: 'bloquear', titulo: 'Bloquear um aparelho', ajuda: 'Ele para de sair para a internet', Icon: Ban, cor: 'text-red-400' },
  { id: 'liberar', titulo: 'Liberar um serviço', ajuda: 'Abrir uma exceção para alguém', Icon: Check, cor: 'text-green-400' },
  { id: 'porta', titulo: 'Abrir para a internet', ajuda: 'Alguém de fora alcança um serviço daqui', Icon: Globe, cor: 'text-blue-400' },
  { id: 'avancada', titulo: 'Regra avançada', ajuda: 'Todos os campos', Icon: SlidersHorizontal, cor: 'text-gray-400' },
];

interface Props {
  /** Aplica os campos traduzidos no estado do modal de regra. */
  onAplicar: (campos: Partial<RuleModalState>) => void;
  /** Chamado quando o admin escolhe "Regra avançada". */
  onAvancado: () => void;
}

export default function RuleWizard({ onAplicar, onAvancado }: Props) {
  const { targets } = useNetTargets();
  const [intent, setIntent] = useState<Intent>('bloquear');
  const [alvo, setAlvo] = useState<Target | null>(null);
  const [servico, setServico] = useState<Service | null>(null);

  const itensDeRede: ComboItem[] = useMemo(
    () => targets.map((t) => ({
      id: t.id, label: t.label, hint: t.hint, group: KIND_LABEL[t.kind],
      ...(t.kind === 'host' ? { dot: !!t.online } : {}),
    })),
    [targets],
  );

  const itensDeServico: ComboItem[] = useMemo(
    () => SERVICES.map((s) => ({
      id: `${s.port}/${s.proto}`,
      label: `${s.name} — ${s.what}`,
      hint: `${s.port}/${s.proto}`,
    })),
    [],
  );

  const escolherIntencao = (id: Intent) => {
    setIntent(id);
    if (id === 'avancada') { onAvancado(); return; }
    if (!precisaDeServico(id)) setServico(null);
  };

  const aplicar = () => {
    if (!alvo) return;
    onAplicar(buildRule(intent, alvo, servico));
  };

  const pronto = !!alvo && (!precisaDeServico(intent) || !!servico);

  return (
    <div className="space-y-5">
      <div>
        <h3 className="text-white font-semibold text-sm">O que você quer fazer?</h3>
        <p className="text-gray-500 text-xs mt-0.5">
          Sem escolher grupo, sem escopo, sem decorar porta.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {INTENCOES.map(({ id, titulo, ajuda, Icon, cor }) => (
          <button
            key={id}
            type="button"
            onClick={() => escolherIntencao(id)}
            aria-pressed={intent === id}
            className={`flex items-start gap-3 rounded-lg border p-4 text-left transition ${
              intent === id ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
            }`}
          >
            <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${cor}`} />
            <span>
              <span className="block text-sm text-white font-medium">{titulo}</span>
              <span className="block text-xs text-gray-500">{ajuda}</span>
            </span>
          </button>
        ))}
      </div>

      {intent !== 'avancada' && (
        <>
          <div>
            <label className="label mb-1.5 block">{rotuloDoAlvo(intent)}</label>
            <Combo
              items={itensDeRede}
              value={alvo?.id ?? ''}
              onPick={(i) => setAlvo(i ? targets.find((t) => t.id === i.id) ?? null : null)}
              placeholder="Buscar por nome ou endereço…"
              emptyLabel="Escolher aparelho"
            />
          </div>

          {precisaDeServico(intent) && (
            <div>
              <label className="label mb-1.5 block">Qual serviço?</label>
              <Combo
                items={itensDeServico}
                value={servico ? `${servico.port}/${servico.proto}` : ''}
                onPick={(i) => setServico(
                  i ? SERVICES.find((s) => `${s.port}/${s.proto}` === i.id) ?? null : null,
                )}
                placeholder="Buscar “remoto”, “arquivos”, ou a porta…"
                emptyLabel="Escolher serviço"
              />
            </div>
          )}

          {/* A frase em português vem ANTES da linha nft, e é a maior das duas:
              o público deste produto lê a frase; a linha existe para quem quer
              conferir. Inverter a ordem devolveria ao admin exatamente o
              problema que o assistente veio resolver. */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
            <p className="text-xs uppercase tracking-wide text-gray-600 mb-2">O que vai acontecer</p>
            <p className="text-sm text-gray-200">{descreverRegra(intent, alvo, servico)}</p>
          </div>

          <button
            type="button"
            className="btn-primary w-full disabled:opacity-40"
            disabled={!pronto}
            onClick={aplicar}
          >
            Continuar
          </button>
        </>
      )}
    </div>
  );
}
