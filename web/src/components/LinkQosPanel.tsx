import { useEffect, useId, useMemo, useReducer, useState } from 'react';
import { Activity, AlertTriangle, Check, Gauge, Loader2 } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import {
  buildQosUpdate,
  createQosEditorState,
  qosDraftFrom,
  qosEditorReducer,
  sameQosDraft,
} from '../lib/qos';
import type { QosComparison, QosGetResponse, QosMeasurement, QosState, QosUpdateRequest, WanLink } from '../types';
import Panel from './ui/Panel';

interface Props {
  link: WanLink;
  canEdit: boolean;
  onUpdated?: (linkID: string, value: QosUpdateRequest) => void;
}

const TEST_TIMEOUT_MS = 35_000;

interface ErrorNotice {
  fallbackKey: string;
  message?: string;
}

function draftFromLink(link: WanLink) {
  return qosDraftFrom({
    enabled: link.qos_enabled,
    upload_mbps: link.qos_upload_mbps,
    download_mbps: link.qos_download_mbps,
    interactive: link.qos_interactive,
  });
}

/** Per-WAN CAKE editor and before/after latency measurement. */
export default function LinkQosPanel({ link, canEdit, onUpdated }: Props) {
  const { t } = useI18n();
  const initialDraft = useMemo(() => draftFromLink(link), [link]);
  const [editor, dispatchEditor] = useReducer(qosEditorReducer, initialDraft, createQosEditorState);
  const { draft, savedDraft, comparison } = editor;
  const [observed, setObserved] = useState<QosState | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<ErrorNotice | null>(null);
  const [successKey, setSuccessKey] = useState('');
  const fieldID = useId();
  const uploadValidationID = `${fieldID}-upload-validation`;
  const downloadValidationID = `${fieldID}-download-validation`;
  const testHintID = `${fieldID}-test-hint`;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    client.get<QosGetResponse>(`/api/links/${link.id}/qos`)
      .then(({ data }) => {
        if (!active) return;
        const next = qosDraftFrom(data.desired);
        dispatchEditor({ type: 'loaded', draft: next });
        setObserved(data.observed);
      })
      .catch((e) => {
        if (active) setError(errorNotice(e, 'links.qos.error.load'));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [link.id]);

  useEffect(() => {
    if (!successKey) return;
    const timer = setTimeout(() => setSuccessKey(''), 4000);
    return () => clearTimeout(timer);
  }, [successKey]);

  const update = useMemo(() => buildQosUpdate(draft), [draft]);
  const dirty = !sameQosDraft(draft, savedDraft);
  const busy = loading || saving || testing;
  const validationError = update.ok ? null : update.error;
  const uploadInvalid = validationError?.startsWith('upload_') ?? false;
  const downloadInvalid = validationError?.startsWith('download_') ?? false;
  const renderedError = error?.message || (error ? t(error.fallbackKey) : '');

  const changeDraft = (next: typeof draft) => {
    dispatchEditor({ type: 'draft-changed', draft: next });
  };

  const save = async () => {
    if (!update.ok) return;
    setSaving(true);
    setError(null);
    setSuccessKey('');
    try {
      const { data } = await client.put<QosState>(`/api/links/${link.id}/qos`, update.value);
      const persisted = qosDraftFrom(update.value);
      dispatchEditor({ type: 'saved', draft: persisted });
      setObserved(data);
      setSuccessKey('links.qos.success.saved');
      onUpdated?.(link.id, update.value);
    } catch (e) {
      setError(errorNotice(e, 'links.qos.error.save'));
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    dispatchEditor({ type: 'test-started' });
    setTesting(true);
    setError(null);
    setSuccessKey('');
    try {
      const { data } = await client.post<QosComparison>(
        `/api/links/${link.id}/qos/test`,
        undefined,
        { timeout: TEST_TIMEOUT_MS },
      );
      dispatchEditor({ type: 'test-succeeded', comparison: data });
    } catch (e) {
      setError(errorNotice(e, 'links.qos.error.test'));
    } finally {
      setTesting(false);
    }
  };

  const status = statusView(loading, link.enabled, savedDraft.enabled, observed);
  const testDisabled = busy || dirty || !savedDraft.enabled || !link.enabled || !canEdit;
  const testHint = !canEdit
    ? t('links.qos.noPermission')
    : !link.enabled
      ? t('links.qos.test.linkDisabled')
      : dirty
        ? t('links.qos.test.saveFirst')
        : !savedDraft.enabled
          ? t('links.qos.test.enableFirst')
          : t('links.qos.test.hint');

  return (
    <Panel
      title={
        <h2 className="flex min-w-0 items-center gap-2">
          <Gauge className="h-5 w-5 shrink-0 text-cyan-400" />
          <span className="truncate text-white font-semibold">
            {t('links.qos.title', { name: link.name })}
          </span>
          <span className="hidden sm:inline text-gray-600 font-mono text-xs">{link.interface}</span>
        </h2>
      }
      action={
        <span
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] ${status.className}`}
        >
          {t(status.key)}{status.mode ? ` · ${status.mode}` : ''}
        </span>
      }
      className="mb-1"
    >
      <p className="text-gray-500 text-xs mb-4">{t('links.qos.subtitle')}</p>

      {renderedError && (
        <div role="alert" className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {renderedError}
        </div>
      )}
      {successKey && (
        <div role="status" aria-live="polite" aria-atomic="true" className="mb-3 flex items-start gap-2 rounded-lg border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-400">
          <Check className="w-4 h-4 mt-0.5 shrink-0" /> {t(successKey)}
        </div>
      )}

      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <label className="inline-flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => changeDraft({ ...draft, enabled: e.target.checked })}
              disabled={!canEdit || busy}
              className="h-4 w-4 accent-cyan-500 disabled:opacity-40"
            />
            {t('links.qos.enable')}
          </label>
          <label className="inline-flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={draft.interactive}
              onChange={(e) => changeDraft({ ...draft, interactive: e.target.checked })}
              disabled={!canEdit || busy || !draft.enabled}
              className="h-4 w-4 accent-cyan-500 disabled:opacity-40"
            />
            <span>
              {t('links.qos.interactive')}
              <span className="ml-1 text-[11px] text-gray-600">{t('links.qos.interactiveHint')}</span>
            </span>
          </label>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="text-gray-400 text-xs">{t('links.qos.upload')}</span>
            <input
              type="number"
              min={1}
              max={1_000_000}
              step={1}
              inputMode="numeric"
              value={draft.uploadMbps}
              onChange={(e) => changeDraft({ ...draft, uploadMbps: e.target.value })}
              disabled={!canEdit || busy || !draft.enabled}
              aria-invalid={uploadInvalid}
              aria-describedby={uploadInvalid ? uploadValidationID : undefined}
              placeholder="50"
              className="input mt-1 w-full font-mono disabled:opacity-40"
            />
          </label>
          <label className="block">
            <span className="text-gray-400 text-xs">{t('links.qos.download')}</span>
            <input
              type="number"
              min={1}
              max={1_000_000}
              step={1}
              inputMode="numeric"
              value={draft.downloadMbps}
              onChange={(e) => changeDraft({ ...draft, downloadMbps: e.target.value })}
              disabled={!canEdit || busy || !draft.enabled}
              aria-invalid={downloadInvalid}
              aria-describedby={downloadInvalid ? downloadValidationID : undefined}
              placeholder="300"
              className="input mt-1 w-full font-mono disabled:opacity-40"
            />
          </label>
        </div>

        <div className="flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-xs text-amber-200/90">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{t('links.qos.bandwidthWarning')}</span>
        </div>

        {!update.ok && (
          <p
            id={uploadInvalid ? uploadValidationID : downloadValidationID}
            role="alert"
            className="text-xs text-red-400"
          >
            {t(`links.qos.validation.${update.error}`)}
          </p>
        )}

        {canEdit ? (
          <button
            type="button"
            onClick={save}
            disabled={busy || !dirty || !update.ok}
            className="btn-primary inline-flex items-center gap-2 text-sm disabled:opacity-40"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            {saving ? t('links.qos.saving') : t('links.qos.save')}
          </button>
        ) : (
          <p className="text-xs text-gray-600">{t('links.qos.noPermission')}</p>
        )}

        <div className="border-t border-gray-800 pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="inline-flex items-center gap-2 text-sm font-medium text-white">
                <Activity className="h-4 w-4 text-cyan-400" />
                {t('links.qos.test.title')}
              </h3>
              <p id={testHintID} className="mt-1 text-[11px] text-gray-600">{testHint}</p>
            </div>
            {canEdit && (
              <button
                type="button"
                onClick={test}
                disabled={testDisabled}
                aria-describedby={testHintID}
                className="btn-secondary inline-flex items-center gap-2 text-xs disabled:opacity-40"
              >
                {testing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Activity className="h-3.5 w-3.5" />}
                {testing ? t('links.qos.test.running') : t('links.qos.test.run')}
              </button>
            )}
          </div>

          {comparison && (
            <div role="status" aria-live="polite" aria-atomic="true">
              <MeasurementComparison value={comparison} />
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}

function MeasurementComparison({ value }: { value: QosComparison }) {
  const { t } = useI18n();
  return (
    <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
      <MeasurementCard title={t('links.qos.test.before')} value={value.before} />
      <MeasurementCard title={t('links.qos.test.after')} value={value.after} />
    </div>
  );
}

function MeasurementCard({ title, value }: { title: string; value: QosMeasurement }) {
  const { t } = useI18n();
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
      <p className="mb-2 text-xs font-medium text-gray-300">{title}</p>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        <Metric label={t('links.qos.test.min')} value={`${value.min_ms.toFixed(1)} ms`} />
        <Metric label={t('links.qos.test.avg')} value={`${value.avg_ms.toFixed(1)} ms`} />
        <Metric label={t('links.qos.test.max')} value={`${value.max_ms.toFixed(1)} ms`} />
        <Metric label={t('links.qos.test.loss')} value={`${value.loss_pct.toFixed(1)}%`} />
      </dl>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-gray-600">{label}</dt>
      <dd className="font-mono text-gray-300">{value}</dd>
    </div>
  );
}

function statusView(loading: boolean, linkEnabled: boolean, desiredEnabled: boolean, observed: QosState | null) {
  if (loading) {
    return { key: 'links.qos.status.loading', className: 'border-gray-700 bg-gray-800 text-gray-400', mode: '' };
  }
  if (!observed) {
    return { key: 'links.qos.status.unknown', className: 'border-gray-700 bg-gray-800 text-gray-400', mode: '' };
  }
  if (observed.dry_run) {
    return { key: 'links.qos.status.dryRun', className: 'border-blue-500/30 bg-blue-500/10 text-blue-300', mode: observed.mode };
  }
  if (!linkEnabled && desiredEnabled) {
    return { key: 'links.qos.status.linkDisabled', className: 'border-amber-500/30 bg-amber-500/10 text-amber-300', mode: '' };
  }
  if (desiredEnabled && observed.enabled) {
    return { key: 'links.qos.status.active', className: 'border-green-500/30 bg-green-500/10 text-green-400', mode: observed.mode };
  }
  if (desiredEnabled) {
    return { key: 'links.qos.status.pending', className: 'border-amber-500/30 bg-amber-500/10 text-amber-300', mode: '' };
  }
  return { key: 'links.qos.status.inactive', className: 'border-gray-700 bg-gray-800 text-gray-400', mode: '' };
}

function errorNotice(e: unknown, fallbackKey: string): ErrorNotice {
  const ax = e as { response?: { data?: { error?: string } } };
  const message = ax?.response?.data?.error?.trim();
  return message ? { fallbackKey, message } : { fallbackKey };
}
