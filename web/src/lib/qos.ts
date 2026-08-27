import type { QosComparison, QosConfig, QosUpdateRequest } from '../types';

export const QOS_MIN_MBPS = 1;
export const QOS_MAX_MBPS = 1_000_000;

export interface QosDraft {
  enabled: boolean;
  uploadMbps: string;
  downloadMbps: string;
  interactive: boolean;
}

export interface QosEditorState {
  draft: QosDraft;
  savedDraft: QosDraft;
  comparison: QosComparison | null;
}

export type QosEditorAction =
  | { type: 'draft-changed'; draft: QosDraft }
  | { type: 'loaded'; draft: QosDraft }
  | { type: 'saved'; draft: QosDraft }
  | { type: 'test-started' }
  | { type: 'test-succeeded'; comparison: QosComparison };

export type QosDraftError =
  | 'upload_required'
  | 'upload_integer'
  | 'upload_range'
  | 'download_required'
  | 'download_integer'
  | 'download_range';

export type QosUpdateResult =
  | { ok: true; value: QosUpdateRequest }
  | { ok: false; error: QosDraftError };

type QosDraftSource = Pick<QosConfig, 'enabled' | 'upload_mbps' | 'download_mbps' | 'interactive'>;

export function qosDraftFrom(source: QosDraftSource): QosDraft {
  return {
    enabled: source.enabled,
    uploadMbps: source.upload_mbps > 0 ? String(source.upload_mbps) : '',
    downloadMbps: source.download_mbps > 0 ? String(source.download_mbps) : '',
    interactive: source.interactive,
  };
}

export function sameQosDraft(a: QosDraft, b: QosDraft): boolean {
  return a.enabled === b.enabled &&
    a.uploadMbps === b.uploadMbps &&
    a.downloadMbps === b.downloadMbps &&
    a.interactive === b.interactive;
}

export function createQosEditorState(draft: QosDraft): QosEditorState {
  return {
    draft,
    savedDraft: draft,
    comparison: null,
  };
}

/**
 * Keeps form and measurement transitions atomic. In particular, a refreshed
 * persisted baseline must not overwrite controls the operator has edited.
 */
export function qosEditorReducer(state: QosEditorState, action: QosEditorAction): QosEditorState {
  switch (action.type) {
    case 'draft-changed':
      return { ...state, draft: action.draft, comparison: null };
    case 'loaded': {
      const dirty = !sameQosDraft(state.draft, state.savedDraft);
      return {
        draft: dirty ? state.draft : action.draft,
        savedDraft: action.draft,
        comparison: null,
      };
    }
    case 'saved':
      return { draft: action.draft, savedDraft: action.draft, comparison: null };
    case 'test-started':
      return { ...state, comparison: null };
    case 'test-succeeded':
      return { ...state, comparison: action.comparison };
  }
}

function parseBandwidth(
  direction: 'upload' | 'download',
  raw: string,
  required: boolean,
): { ok: true; value: number } | { ok: false; error: QosDraftError } {
  const text = raw.trim();
  if (text === '') {
    return required
      ? { ok: false, error: `${direction}_required` }
      : { ok: true, value: 0 };
  }

  const value = Number(text);
  if (!Number.isInteger(value)) {
    return { ok: false, error: `${direction}_integer` };
  }
  if ((!required && value === 0)) {
    return { ok: true, value: 0 };
  }
  if (value < QOS_MIN_MBPS || value > QOS_MAX_MBPS) {
    return { ok: false, error: `${direction}_range` };
  }
  return { ok: true, value };
}

export function buildQosUpdate(draft: QosDraft): QosUpdateResult {
  const upload = parseBandwidth('upload', draft.uploadMbps, draft.enabled);
  if (!upload.ok) return upload;

  const download = parseBandwidth('download', draft.downloadMbps, draft.enabled);
  if (!download.ok) return download;

  return {
    ok: true,
    value: {
      enabled: draft.enabled,
      upload_mbps: upload.value,
      download_mbps: download.value,
      interactive: draft.interactive,
    },
  };
}
