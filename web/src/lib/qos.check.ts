import assert from 'node:assert/strict';
import { buildQosUpdate, createQosEditorState, qosDraftFrom, qosEditorReducer } from './qos.ts';
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

// Component-state regressions: the production reducer must be the single
// owner of draft and measurement transitions. A missing invalidation here
// would let an old successful comparison survive a rerun failure or an edit.
{
  const persisted = qosDraftFrom({
    enabled: true,
    upload_mbps: 50,
    download_mbps: 300,
    interactive: false,
  });
  const comparison: QosComparison = {
    before: { min_ms: 20, avg_ms: 25, max_ms: 30, loss_pct: 0 },
    after: { min_ms: 10, avg_ms: 12, max_ms: 15, loss_pct: 0 },
  };

  let state = createQosEditorState(persisted);
  state = qosEditorReducer(state, { type: 'test-succeeded', comparison });
  assert.deepEqual(state.comparison, comparison, 'a completed test publishes its own comparison');

  state = qosEditorReducer(state, { type: 'test-started' });
  assert.equal(
    state.comparison,
    null,
    'starting a rerun clears the previous comparison before a possible failure',
  );

  state = qosEditorReducer(state, { type: 'test-succeeded', comparison });
  const edited = { ...state.draft, uploadMbps: '45' };
  state = qosEditorReducer(state, { type: 'draft-changed', draft: edited });
  assert.equal(state.comparison, null, 'editing controls invalidates the measured comparison');
  checks += 3;
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
