import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import {
  normalizeDomainTarget,
  targetPhase,
  validateDomainTargetForm,
  type DomainTargetView,
} from './domainTargets.ts';

let n = 0;
const check = (condition: unknown, message: string) => { assert.ok(condition, message); n++; };
const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

check(normalizeDomainTarget(' Video.Example.COM. ') === 'video.example.com', 'normaliza caixa/espaço/ponto raiz');
for (const invalid of ['localhost', '.example.com', '-api.example.com', 'api-.example.com', 'a..example.com', 'café.example.com']) {
  check(normalizeDomainTarget(invalid) === null, `recusa domínio inválido: ${invalid}`);
}

const validBlock = { domain: 'ads.example.com', capability: 'barrar' as const, link_id: '', note: '' };
const validRoute = { domain: 'video.example.com', capability: 'direcionar' as const, link_id: 'wan-2', note: '' };
check(validateDomainTargetForm(validBlock, new Set(['wan-2'])) === null, 'bloqueio válido');
check(validateDomainTargetForm(validRoute, new Set(['wan-2'])) === null, 'direcionamento válido');
check(validateDomainTargetForm({ ...validRoute, link_id: 'missing' }, new Set(['wan-2'])) === 'unknown_link', 'link precisa existir');
check(validateDomainTargetForm({ ...validBlock, link_id: 'wan-2' }, new Set(['wan-2'])) === 'block_with_link', 'bloqueio não esconde link');
check(validateDomainTargetForm({ ...validBlock, note: 'linha\nnova' }, new Set()) === 'invalid_note', 'observação recusa controles');

const baseTarget = {
  id: 'd', domain: 'video.example.com', capability: 'direcionar', stage: 'ensaio', effective_stage: 'ensaio',
  link_id: 'wan-2', link_name: 'WAN 2', link_status: 'online', mark: 200, note: '', suspended: false,
  suspension_reason: '', created_at: '', updated_at: '', no_kernel: 0, no_index: 0, at_limit: false,
  limit: 64, overflows: 0, rejected: 0, rejected_own: 0, no_refcount_slot: 0,
  routed_ipv6_discarded: 0, last_learned: 0, rotation: 0, rotation_truncated: false,
} satisfies DomainTargetView;
check(targetPhase(baseTarget) === 'trial', 'ensaio aparece como ensaio');
check(targetPhase({ ...baseTarget, stage: 'ativo', effective_stage: 'ativo' }) === 'active', 'ativo efetivo aparece ativo');
check(targetPhase({ ...baseTarget, stage: 'ativo', suspended: true, suspension_reason: 'link_offline' }) === 'suspended', 'suspensão não se disfarça de ensaio comum');

const component = read('../components/DomainTargets.tsx');
const linksPage = read('../pages/Links.tsx');
const strings = read('../i18n/strings/links.yaml');

for (const endpoint of [
  "client.get<DomainRoutingState>('/api/domain-targets')",
  "client.post<DomainRoutingState>('/api/domain-targets'",
  "client.put<DomainRoutingState>(`/api/domain-targets/${editing.id}`",
  "client.delete<DomainRoutingState>(`/api/domain-targets/${deleteTarget.id}`",
  "client.post<DomainRoutingState>(`/api/domain-targets/${promotionTarget.id}/stage`",
]) {
  check(component.includes(endpoint), `UI precisa usar ${endpoint}`);
}

const saveSection = component.slice(component.indexOf('const saveTarget'), component.indexOf('const requestPromotion'));
check(!/\bstage\s*:/.test(saveSection), 'create/update não podem promover por campo stage');
check(component.includes('promotionTarget'), 'promoção precisa de confirmação explícita');
check(component.includes('canEdit &&'), 'mutações precisam respeitar links.write');
check(linksPage.includes("<DomainTargets links={links} canEdit={can('links.write')}"), 'Links injeta RBAC existente na UI de domínio');

for (const field of [
  'effective_stage', 'suspension_reason', 'no_kernel', 'no_index', 'rotation',
  'routed_ipv6_discarded', 'kernel_lido', 'kernel_erro', 'routing_ipv6_supported',
]) {
  check(component.includes(field), `estado observável precisa renderizar ${field}`);
}

// O ZERO SEM MEDIÇÃO NÃO PODE SER LIDO COMO ZERO MEDIDO. Rotação e último
// aprendizado vêm os dois do dnstap; com o coletor desligado eles são zero por
// construção, e imprimir "0" ali afirma que ninguém acessou o nome — a
// conclusão oposta da verdadeira, e a que faz o admin promover um domínio
// achando que ele é inofensivo.
check(component.includes('runtime?.observando === true'), 'a tela precisa distinguir observando de não sei');
check(component.includes('runtime?.observando === false'), 'coletor desligado precisa de tratamento próprio, separado de nil');
check(component.includes("t('links.domains.notMeasured')"), 'rotação e último acesso precisam dizer "sem medição" quando não há medição');
check(component.includes("t('links.domains.notObservingHelp')"), 'a tela precisa dizer o que fazer quando o coletor está desligado');
for (const key of ['links.domains.observing', 'links.domains.notObserving', 'links.domains.observingUnknown',
  'links.domains.notObservingHelp', 'links.domains.notMeasured']) {
  check(strings.includes(`${key}:`), `dicionário precisa definir ${key}`);
}
// `vivo` é o ALIMENTADOR, e chamá-lo de dnstap era a mesma confusão por outro
// caminho: a tela dizia "dnstap ativo" numa caixa com o dnstap desligado.
const aliveLine = strings.slice(strings.indexOf('links.domains.runtimeAlive:'), strings.indexOf('links.domains.observing:'));
check(!aliveLine.includes('dnstap'), 'o rótulo de `vivo` não pode se chamar dnstap: `vivo` é o alimentador');

for (const term of ['CDN', 'DoH', 'DoT', 'VPN', 'IP fixo', 'IPv6']) {
  check(strings.includes(term), `caveat honesto precisa mencionar ${term}`);
}
for (const key of [
  'links.domains.caveat.cdn', 'links.domains.caveat.encryptedDns', 'links.domains.caveat.vpn',
  'links.domains.caveat.fixedIp', 'links.domains.caveat.ipv6',
]) {
  check(component.includes(key), `componente precisa renderizar ${key}`);
  check(strings.includes(`${key}:`), `dicionário precisa definir ${key}`);
}

console.log(`domainTargets.check: ${n} asserções OK`);
