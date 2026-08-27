import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDownCircle, ArrowUpCircle, Ban, Loader2,
  Pencil, Plus, RefreshCw, Route, Trash2,
} from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import { errMsg } from '../lib/apiError';
import {
  emptyDomainTargetForm, normalizeDomainTarget, targetPhase, validateDomainTargetForm,
  type DomainFormError, type DomainRoutingState, type DomainStage,
  type DomainTargetForm, type DomainTargetView,
} from '../lib/domainTargets';
import type { WanLink } from '../types';
import IconButton from './ui/IconButton';
import Modal from './ui/Modal';
import Panel from './ui/Panel';
import Tag, { type TagVariant } from './ui/Tag';

interface Props {
  links: WanLink[];
  canEdit: boolean;
}

const reasonKeys: Record<string, string> = {
  boot_pending: 'links.domains.reason.boot',
  blocking_group_missing: 'links.domains.reason.blockMissing',
  blocking_group_disabled: 'links.domains.reason.blockDisabled',
  link_missing: 'links.domains.reason.linkMissing',
  link_disabled: 'links.domains.reason.linkDisabled',
  link_unconfigured: 'links.domains.reason.linkUnconfigured',
  link_offline: 'links.domains.reason.linkOffline',
  link_not_ready: 'links.domains.reason.linkNotReady',
  invalid_intent: 'links.domains.reason.invalidIntent',
};

const validationKeys: Record<DomainFormError, string> = {
  invalid_domain: 'links.domains.validation.domain',
  invalid_capability: 'links.domains.validation.capability',
  link_required: 'links.domains.validation.linkRequired',
  unknown_link: 'links.domains.validation.linkUnknown',
  block_with_link: 'links.domains.validation.blockLink',
  invalid_note: 'links.domains.validation.note',
};

function phaseTag(target: DomainTargetView): { variant: TagVariant; key: string } {
  switch (targetPhase(target)) {
    case 'active': return { variant: 'ok', key: 'links.domains.phase.active' };
    case 'suspended': return { variant: 'crit', key: 'links.domains.phase.suspended' };
    default: return { variant: 'warn', key: 'links.domains.phase.trial' };
  }
}

function unixTime(value: number): string {
  if (!value) return '—';
  return new Date(value * 1000).toLocaleString();
}

export default function DomainTargets({ links, canEdit }: Props) {
  const { t } = useI18n();
  const [state, setState] = useState<DomainRoutingState | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [editing, setEditing] = useState<DomainTargetView | null>(null);
  const [form, setForm] = useState<DomainTargetForm | null>(null);
  const [promotionTarget, setPromotionTarget] = useState<DomainTargetView | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DomainTargetView | null>(null);

  const linkIDs = useMemo(() => new Set(links.map((link) => link.id)), [links]);

  const load = useCallback(async (initial = false) => {
    if (initial) setLoading(true);
    try {
      const { data } = await client.get<DomainRoutingState>('/api/domain-targets');
      setState(data);
      setError('');
    } catch (e) {
      setError(errMsg(e));
    } finally {
      if (initial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(true);
    const timer = setInterval(() => void load(false), 15000);
    return () => clearInterval(timer);
  }, [load]);

  const openCreate = () => {
    setEditing(null);
    setForm(emptyDomainTargetForm());
    setFormError('');
  };

  const openEdit = (target: DomainTargetView) => {
    setEditing(target);
    setForm({
      domain: target.domain,
      capability: target.capability,
      link_id: target.link_id,
      note: target.note,
    });
    setFormError('');
  };

  const saveTarget = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form) return;
    const validation = validateDomainTargetForm(form, linkIDs);
    if (validation) {
      setFormError(t(validationKeys[validation]));
      return;
    }
    const payload = {
      domain: normalizeDomainTarget(form.domain)!,
      capability: form.capability,
      link_id: form.capability === 'direcionar' ? form.link_id.trim() : '',
      note: form.note.trim(),
    };
    setBusy(true);
    setFormError('');
    try {
      const response = editing
        ? await client.put<DomainRoutingState>(`/api/domain-targets/${editing.id}`, payload)
        : await client.post<DomainRoutingState>('/api/domain-targets', payload);
      setState(response.data);
      setForm(null);
      setEditing(null);
    } catch (e) {
      setFormError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const requestPromotion = (target: DomainTargetView) => {
    setPromotionTarget(target);
    setError('');
  };

  const applyStage = async () => {
    if (!promotionTarget) return;
    const stage: DomainStage = promotionTarget.stage === 'ensaio' ? 'ativo' : 'ensaio';
    setBusy(true);
    try {
      const response = await client.post<DomainRoutingState>(`/api/domain-targets/${promotionTarget.id}/stage`, { stage });
      setState(response.data);
      setPromotionTarget(null);
    } catch (e) {
      setError(errMsg(e));
      setPromotionTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const removeTarget = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    try {
      const response = await client.delete<DomainRoutingState>(`/api/domain-targets/${deleteTarget.id}`);
      setState(response.data);
      setDeleteTarget(null);
    } catch (e) {
      setError(errMsg(e));
      setDeleteTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const runtime = state?.runtime;

  return (
    <>
      <Panel
        title={(
          <span className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-violet-400" />
            <span className="text-white font-semibold">{t('links.domains.title')}</span>
          </span>
        )}
        action={(
          <div className="flex items-center gap-2">
            <button onClick={() => void load(false)} className="btn-secondary text-xs flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5" /> {t('links.domains.refresh')}
            </button>
            {canEdit && (
              <button onClick={openCreate} className="btn-primary text-xs flex items-center gap-1.5">
                <Plus className="w-3.5 h-3.5" /> {t('links.domains.add')}
              </button>
            )}
          </div>
        )}
        className="mb-1"
      >
        <p className="text-gray-500 text-xs">{t('links.domains.subtitle')}</p>

        <div className="mt-3 flex flex-wrap gap-2">
          <Tag variant={state?.ready ? 'ok' : 'warn'} dot>
            {state?.ready ? t('links.domains.ready') : t('links.domains.notReady')}
          </Tag>
          <Tag variant={runtime?.vivo ? 'ok' : 'crit'}>
            {runtime?.vivo ? t('links.domains.runtimeAlive') : t('links.domains.runtimeDown')}
          </Tag>
          <Tag variant={runtime?.kernel_lido ? 'ok' : 'warn'}>
            {runtime?.kernel_lido ? t('links.domains.kernelRead') : t('links.domains.kernelUnknown')}
          </Tag>
          <Tag variant={state?.routing_ipv6_supported ? 'ok' : 'warn'}>
            {state?.routing_ipv6_supported
              ? t('links.domains.routingIpv6Supported')
              : t('links.domains.routingIpv6Unsupported')}
          </Tag>
          {runtime?.dry_run && <Tag variant="neutral">{t('links.domains.dryRun')}</Tag>}
          {!canEdit && <Tag variant="idle">{t('links.domains.readOnly')}</Tag>}
        </div>

        {(error || state?.last_error || runtime?.kernel_erro) && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error || state?.last_error || runtime?.kernel_erro}</span>
          </div>
        )}

        <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-100/80">
          <p className="font-medium text-amber-300">{t('links.domains.caveat.title')}</p>
          <ul className="mt-2 list-disc space-y-1 pl-4">
            <li>{t('links.domains.caveat.cdn')}</li>
            <li>{t('links.domains.caveat.encryptedDns')}</li>
            <li>{t('links.domains.caveat.vpn')}</li>
            <li>{t('links.domains.caveat.fixedIp')}</li>
            <li>{t('links.domains.caveat.ipv6')}</li>
          </ul>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-500 animate-pulse">{t('links.loading')}</div>
        ) : (state?.targets?.length ?? 0) === 0 ? (
          <div className="py-8 text-center text-sm text-gray-500">{t('links.domains.empty')}</div>
        ) : (
          <ul className="mt-4 space-y-3">
            {state!.targets.map((target) => {
              const phase = phaseTag(target);
              const mismatch = runtime?.kernel_lido && target.no_kernel !== null && target.no_kernel !== target.no_index;
              return (
                <li key={target.id} className="rounded-xl border border-gray-800 bg-gray-950/35 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        {target.capability === 'barrar'
                          ? <Ban className="w-4 h-4 text-red-400" />
                          : <Route className="w-4 h-4 text-blue-400" />}
                        <span className="font-mono text-sm text-white break-all">{target.domain}</span>
                        <Tag variant={phase.variant}>{t(phase.key)}</Tag>
                        <Tag variant="idle">
                          {target.capability === 'barrar' ? t('links.domains.cap.block') : t('links.domains.cap.route')}
                        </Tag>
                      </div>
                      {target.suspended && (
                        <p className="mt-2 text-xs text-red-300">
                          {t(reasonKeys[target.suspension_reason || ''] || 'links.domains.reason.unknown')}
                        </p>
                      )}
                      {target.note && <p className="mt-1 text-xs text-gray-500">{target.note}</p>}
                    </div>
                    {canEdit && (
                      <div className="flex shrink-0 items-center gap-1">
                        <button onClick={() => requestPromotion(target)}
                          className="btn-secondary text-xs flex items-center gap-1.5">
                          {target.stage === 'ensaio'
                            ? <ArrowUpCircle className="w-3.5 h-3.5" />
                            : <ArrowDownCircle className="w-3.5 h-3.5" />}
                          {target.stage === 'ensaio' ? t('links.domains.action.promote') : t('links.domains.action.demote')}
                        </button>
                        <IconButton icon={Pencil} onClick={() => openEdit(target)} label={t('links.domains.action.edit')} />
                        <IconButton icon={Trash2} onClick={() => setDeleteTarget(target)}
                          label={t('links.domains.action.delete')} variant="danger" />
                      </div>
                    )}
                  </div>

                  <dl className="mt-3 grid grid-cols-2 gap-x-5 gap-y-2 text-xs sm:grid-cols-3 lg:grid-cols-6">
                    <Metric label={t('links.domains.metric.intent')} value={target.stage} />
                    <Metric label={t('links.domains.metric.effective')} value={target.effective_stage} />
                    {target.capability === 'direcionar' && (
                      <Metric label={t('links.domains.metric.link')}
                        value={`${target.link_name || target.link_id || '—'} · ${target.link_status || '—'} · mark ${target.mark || '—'}`} />
                    )}
                    <Metric label={t('links.domains.metric.index')} value={String(target.no_index)} />
                    <Metric label={t('links.domains.metric.kernel')}
                      value={target.no_kernel === null ? '?' : String(target.no_kernel)} warn={Boolean(mismatch)} />
                    <Metric label={t('links.domains.metric.rotation')}
                      value={`${target.rotation}${target.rotation_truncated ? '+' : ''}`} warn={target.rotation_truncated} />
                    <Metric label={t('links.domains.metric.lastLearned')} value={unixTime(target.last_learned)} />
                    <Metric label={t('links.domains.metric.ipv6Discarded')}
                      value={String(target.routed_ipv6_discarded)} warn={target.routed_ipv6_discarded > 0} />
                  </dl>

                  {(mismatch || target.at_limit || target.overflows > 0 || target.rejected > 0 ||
                    target.rejected_own > 0 || target.no_refcount_slot > 0) && (
                    <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                      {mismatch && <Tag variant="crit">{t('links.domains.warn.mismatch')}</Tag>}
                      {target.at_limit && <Tag variant="warn">{t('links.domains.warn.limit', { limit: target.limit })}</Tag>}
                      {target.overflows > 0 && <Tag variant="warn">{t('links.domains.warn.overflows', { n: target.overflows })}</Tag>}
                      {target.rejected > 0 && <Tag variant="warn">{t('links.domains.warn.rejected', { n: target.rejected })}</Tag>}
                      {target.rejected_own > 0 && <Tag variant="crit">{t('links.domains.warn.rejectedOwn', { n: target.rejected_own })}</Tag>}
                      {target.no_refcount_slot > 0 && <Tag variant="warn">{t('links.domains.warn.refcount', { n: target.no_refcount_slot })}</Tag>}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Modal open={form !== null} onClose={() => setForm(null)}
        title={editing ? t('links.domains.form.editTitle') : t('links.domains.form.createTitle')}
        size="md" className="rounded-xl border border-gray-800 bg-gray-900">
        {form && (
          <form onSubmit={saveTarget} className="p-6 space-y-4">
            <div>
              <label className="label">{t('links.domains.form.domain')}</label>
              <input className="input w-full font-mono" value={form.domain} placeholder="video.example.com"
                onChange={(event) => setForm({ ...form, domain: event.target.value })} autoFocus />
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="label">{t('links.domains.form.capability')}</label>
                <select className="input w-full" value={form.capability}
                  onChange={(event) => setForm({
                    ...form,
                    capability: event.target.value as DomainTargetForm['capability'],
                    link_id: event.target.value === 'barrar' ? '' : form.link_id,
                  })}>
                  <option value="barrar">{t('links.domains.cap.block')}</option>
                  <option value="direcionar">{t('links.domains.cap.route')}</option>
                </select>
              </div>
              {form.capability === 'direcionar' && (
                <div>
                  <label className="label">{t('links.domains.form.link')}</label>
                  <select className="input w-full" value={form.link_id}
                    onChange={(event) => setForm({ ...form, link_id: event.target.value })}>
                    <option value="">{t('links.domains.form.selectLink')}</option>
                    {links.map((link) => (
                      <option key={link.id} value={link.id}>
                        {link.name} · {link.status}{link.enabled ? '' : ` · ${t('links.disabled')}`}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            <div>
              <label className="label">{t('links.domains.form.note')}</label>
              <textarea className="input min-h-20 w-full" maxLength={500} value={form.note}
                onChange={(event) => setForm({ ...form, note: event.target.value })} />
            </div>
            <p className="text-xs text-amber-300/80">{t('links.domains.form.trialHelp')}</p>
            {formError && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {formError}
              </div>
            )}
            <div className="flex gap-3">
              <button type="submit" disabled={busy} className="btn-primary flex-1 disabled:opacity-50">
                {busy ? t('links.btn.saving') : t('links.btn.save')}
              </button>
              <button type="button" onClick={() => setForm(null)} className="btn-secondary flex-1">
                {t('links.btn.cancel')}
              </button>
            </div>
          </form>
        )}
      </Modal>

      <Modal open={promotionTarget !== null} onClose={() => setPromotionTarget(null)}
        title={promotionTarget?.stage === 'ensaio' ? t('links.domains.promote.title') : t('links.domains.demote.title')}
        size="sm" className="rounded-xl border border-gray-800 bg-gray-900">
        {promotionTarget && (
          <div className="p-6 space-y-4">
            <p className="break-all font-mono text-sm text-white">{promotionTarget.domain}</p>
            <p className="text-sm text-gray-400">
              {promotionTarget.stage === 'ensaio' ? t('links.domains.promote.body') : t('links.domains.demote.body')}
            </p>
            {promotionTarget.stage === 'ensaio' && promotionTarget.suspended && (
              <p className="text-xs text-amber-300">{t('links.domains.promote.suspended')}</p>
            )}
            <div className="flex gap-3">
              <button onClick={() => void applyStage()} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">
                {busy ? <Loader2 className="mx-auto h-4 w-4 animate-spin" /> : t('links.domains.promote.confirm')}
              </button>
              <button onClick={() => setPromotionTarget(null)} className="btn-secondary flex-1">
                {t('links.btn.cancel')}
              </button>
            </div>
          </div>
        )}
      </Modal>

      <Modal open={deleteTarget !== null} onClose={() => setDeleteTarget(null)}
        title={t('links.domains.delete.title')} size="sm"
        className="rounded-xl border border-gray-800 bg-gray-900">
        {deleteTarget && (
          <div className="p-6 space-y-4">
            <p className="text-sm text-gray-400">{t('links.domains.delete.body', { domain: deleteTarget.domain })}</p>
            <div className="flex gap-3">
              <button onClick={() => void removeTarget()} disabled={busy} className="btn-danger flex-1 disabled:opacity-50">
                {t('links.domains.delete.confirm')}
              </button>
              <button onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
                {t('links.btn.cancel')}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

function Metric({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-gray-600">{label}</dt>
      <dd className={`mt-0.5 truncate font-mono ${warn ? 'text-amber-300' : 'text-gray-300'}`}>{value}</dd>
    </div>
  );
}
