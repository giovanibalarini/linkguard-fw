export type DomainCapability = 'barrar' | 'direcionar';
export type DomainStage = 'ensaio' | 'ativo';

export interface DomainTargetForm {
  domain: string;
  capability: DomainCapability;
  link_id: string;
  note: string;
}

export interface DomainTargetView {
  id: string;
  domain: string;
  capability: DomainCapability;
  stage: DomainStage;
  effective_stage: DomainStage;
  link_id: string;
  link_name: string;
  link_status?: string;
  mark: number;
  note: string;
  suspended: boolean;
  suspension_reason?: string;
  created_at: string;
  updated_at: string;
  no_kernel: number | null;
  no_index: number;
  at_limit: boolean;
  limit: number;
  overflows: number;
  rejected: number;
  rejected_own: number;
  no_refcount_slot: number;
  routed_ipv6_discarded: number;
  last_learned: number;
  rotation: number;
  rotation_truncated: boolean;
}

export interface DomainRuntimeState {
  barrados: number;
  barrados6: number;
  direcionados: number;
  orfaos: number;
  fora_de_lugar: number;
  ilegiveis: number;
  kernel_lido: boolean;
  kernel_erro?: string;
  dry_run: boolean;
  vivo: boolean;
  reinicios: number;
  descartes: number;
  ignoradas: number;
  lotes: number;
  erros_de_lote: number;
  reenvios: number;
  remocoes_desistidas: number;
}

export interface DomainRoutingState {
  ready: boolean;
  generation: number;
  last_reconciled_at: string;
  last_error?: string;
  blocking_group_present: boolean;
  blocking_group_enabled: boolean;
  routing_ipv6_supported: boolean;
  runtime: DomainRuntimeState;
  targets: DomainTargetView[];
}

export type DomainFormError =
  | 'invalid_domain'
  | 'invalid_capability'
  | 'link_required'
  | 'unknown_link'
  | 'block_with_link'
  | 'invalid_note';

export const emptyDomainTargetForm = (): DomainTargetForm => ({
  domain: '', capability: 'barrar', link_id: '', note: '',
});

/** Mesma gramática conservadora do backend: nome ASCII, pelo menos 2 labels. */
export function normalizeDomainTarget(raw: string): string | null {
  let value = raw.trim().toLowerCase();
  if (value.endsWith('.')) value = value.slice(0, -1);
  if (value.length < 3 || value.length > 253) return null;
  const labels = value.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return null;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }
  return value;
}

export function validateDomainTargetForm(form: DomainTargetForm, knownLinks: Set<string>): DomainFormError | null {
  if (!normalizeDomainTarget(form.domain)) return 'invalid_domain';
  if (form.capability !== 'barrar' && form.capability !== 'direcionar') return 'invalid_capability';
  const linkID = form.link_id.trim();
  if (form.capability === 'direcionar') {
    if (!linkID) return 'link_required';
    if (!knownLinks.has(linkID)) return 'unknown_link';
  } else if (linkID) {
    return 'block_with_link';
  }
  const note = form.note.trim();
  if (Array.from(note).length > 500 || /[\u0000-\u001f\u007f-\u009f]/u.test(note)) return 'invalid_note';
  return null;
}

export type DomainTargetPhase = 'trial' | 'active' | 'suspended';

export function targetPhase(target: DomainTargetView): DomainTargetPhase {
  if (target.suspended) return 'suspended';
  if (target.stage === 'ativo' && target.effective_stage === 'ativo') return 'active';
  return 'trial';
}
