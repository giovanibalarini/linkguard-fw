import assert from 'node:assert/strict';
import {
  benchmarkResultIsComplete,
  buildQosUpdate,
  createQosEditorState,
  qosDraftFrom,
  qosEditorReducer,
} from './qos.ts';
import type { QosComparison } from '../types/index.ts';

let checks = 0;
const check = (condition: unknown, message: string) => {
  assert.ok(condition, message);
  checks++;
};

// Regression: refreshing the API response must not reset a persisted QoS
// configuration to empty inputs or lose the interactive-priority preference.
{
  const draft = qosDraftFrom({
    enabled: true,
    upload_mbps: 75,
    download_mbps: 400,
    interactive: true,
  });
  assert.deepEqual(draft, {
    enabled: true,
    uploadMbps: '75',
    downloadMbps: '400',
    interactive: true,
  });
  checks++;
}

// Regression: the UI payload must contain integers under the exact API field
// names; otherwise the Go decoder rejects it or silently receives zero values.
{
  const result = buildQosUpdate({
    enabled: true,
    uploadMbps: '75',
    downloadMbps: '400',
    interactive: true,
  });
  assert.deepEqual(result, {
    ok: true,
    value: {
      enabled: true,
      upload_mbps: 75,
      download_mbps: 400,
      interactive: true,
    },
  });
  checks++;
}

// Disabled QoS may legitimately persist zero bandwidth. This is the additive
// migration default and must remain savable from the UI.
{
  const result = buildQosUpdate({
    enabled: false,
    uploadMbps: '',
    downloadMbps: '',
    interactive: false,
  });
  assert.deepEqual(result, {
    ok: true,
    value: {
      enabled: false,
      upload_mbps: 0,
      download_mbps: 0,
      interactive: false,
    },
  });
  checks++;
}

// These inputs would either defeat the control or fail backend validation.
// Keep each error code stable so the component can translate it precisely.
{
  check(
    JSON.stringify(buildQosUpdate({ enabled: true, uploadMbps: '', downloadMbps: '100', interactive: false })) ===
      JSON.stringify({ ok: false, error: 'upload_required' }),
    'enabled QoS requires upload bandwidth',
  );
  check(
    JSON.stringify(buildQosUpdate({ enabled: true, uploadMbps: '10.5', downloadMbps: '100', interactive: false })) ===
      JSON.stringify({ ok: false, error: 'upload_integer' }),
    'upload bandwidth must be an integer',
  );
  check(
    JSON.stringify(buildQosUpdate({ enabled: true, uploadMbps: '10', downloadMbps: '1000001', interactive: false })) ===
      JSON.stringify({ ok: false, error: 'download_range' }),
    'download bandwidth must stay inside the backend range',
  );
}

// A backend or compatibility bug must not let the UI present an incomplete
// result as valid. CPU and both throughput sources are evidence, not optional
// decoration; missing any of them keeps the result explicitly limited.
{
  const complete: QosComparison = {
    baseline: benchmarkPhase(),
    configured: benchmarkPhase(),
    conditions: {
      server: 'iperf.operator.lan', port: 5201, duration_sec: 5,
      load_cap_mbps: 500, upload_offered_mbps: 55, download_offered_mbps: 330,
    },
    valid: true,
    restored: true,
    limitations: [],
  };
  check(benchmarkResultIsComplete(complete), 'complete raw metrics may be labelled complete');
  const missingCPU: QosComparison = {
    ...complete,
    configured: {
      ...complete.configured,
      upload: { ...complete.configured.upload, cpu_percent: null, valid: false, limitations: ['cpu_unavailable'] },
      valid: false,
      limitations: ['cpu_unavailable'],
    },
    valid: false,
    limitations: ['cpu_unavailable'],
  };
  check(!benchmarkResultIsComplete(missingCPU), 'missing CPU keeps benchmark limited');
  check(!benchmarkResultIsComplete({ ...complete, valid: false }), 'backend invalid verdict is never upgraded by the UI');
}

function benchmarkPhase() {
  const direction = {
    offered_mbps: 55,
    latency: { min_ms: 10, avg_ms: 20, max_ms: 30, loss_pct: 0 },
    throughput_mbps: 50,
    interface_mbps: 49,
    cpu_percent: 35,
    valid: true,
    limitations: [],
  };
  return { upload: direction, download: { ...direction, offered_mbps: 330 }, valid: true, limitations: [] };
}

// A refresh may finish while the operator has an unsaved draft (for example,
// after an i18n context update). The persisted baseline can advance, but the
// in-progress form values must not be replaced silently.
{
  const initial = qosDraftFrom({
    enabled: true,
    upload_mbps: 50,
    download_mbps: 300,
    interactive: false,
  });
  const refreshed = qosDraftFrom({
    enabled: true,
    upload_mbps: 60,
    download_mbps: 400,
    interactive: true,
  });
  const dirtyDraft = { ...initial, uploadMbps: '45' };

  let state = createQosEditorState(initial);
  state = qosEditorReducer(state, { type: 'draft-changed', draft: dirtyDraft });
  state = qosEditorReducer(state, { type: 'loaded', draft: refreshed });

  assert.deepEqual(state.draft, dirtyDraft, 'refresh preserves unsaved controls');
  assert.deepEqual(state.savedDraft, refreshed, 'refresh still records the latest persisted baseline');
  checks += 2;
}

console.log(`qos.check: ${checks} assertions OK`);
