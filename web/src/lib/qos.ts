import type { QosConfig, QosUpdateRequest } from '../types';

export const QOS_MIN_MBPS = 1;
export const QOS_MAX_MBPS = 1_000_000;

export interface QosDraft {
  enabled: boolean;
  uploadMbps: string;
  downloadMbps: string;
  interactive: boolean;
}

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
