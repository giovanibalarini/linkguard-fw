import assert from 'node:assert/strict';
import { buildQosUpdate, qosDraftFrom } from './qos.ts';

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

console.log(`qos.check: ${checks} assertions OK`);
