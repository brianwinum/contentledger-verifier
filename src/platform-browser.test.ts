// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { runBrowserVerification } from './platform-browser-job';
import { BROWSER_INPUT_LIMIT, browserFailure, parseBrowserResult, type BrowserRequest } from './platform-browser-protocol';

function workerFixture() {
  let request: BrowserRequest;
  let terminated = 0;
  const worker = {
    onmessage: null as Worker['onmessage'], onerror: null as Worker['onerror'], onmessageerror: null as Worker['onmessageerror'],
    postMessage(value: unknown) { request = value as BrowserRequest; },
    terminate() { terminated += 1; },
  };
  const emit = (value: unknown) => worker.onmessage?.call(worker as unknown as Worker, new MessageEvent('message', { data: value }));
  return { worker, emit, request: () => request, terminated: () => terminated };
}
const file = () => new File(['test package'], 'test.zip', { type: 'application/zip' });

test('browser worker boundary rejects incomplete success claims, malformed, mismatched, and oversized results', () => {
  const request = { fileName: 'test.zip', checkedAt: '2026-09-19T12:00:00Z', expectations: {} };
  const r = browserFailure(request.fileName, {}, request.checkedAt, 'browser_verifier_incomplete', 'Not implemented.');
  assert.equal(parseBrowserResult(r, request), r);
  for (const change of [
    { outcome: 'passed', layers: [{ layer: 'container', status: 'valid', code: 'zip_profile_valid', message: 'Checked.', details: {} }] },
    { outcome: 'passed_with_limitations', layers: [{ layer: 'container', status: 'valid', code: 'zip_profile_valid', message: 'Checked.', details: {} }] },
    { verifierVersion: '3.0.0' }, { appVersion: 'unknown' }, { fileName: 'other.zip' }, { checkedAt: '2026-01-01T00:00:00Z' },
    { expectations: { did: 'did:webvh:unexpected.example' } }, { code: '../private-path' }, { code: 'browser_verifier_incomplete\n' }, { packageSha256: `${'a'.repeat(64)}\n` }, { message: 'x'.repeat(16385) },
    { layers: [{ layer: 'container', status: 'valid', code: 'zip_profile_valid', message: 'Checked.', details: { huge: 'x'.repeat(16385) } }] },
    { layers: [{ layer: 'signatures', status: 'valid', code: 'signatures_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'signing_authorization', status: 'valid', code: 'embedded_jws_signatures_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'signature_integrity', status: 'valid', code: 'authenticated_signatures_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'website_identity', status: 'valid', code: 'did_webvh_logs_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'transparency', status: 'valid', code: 'transparency_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'scope', status: 'valid', code: 'scope_world_complete', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'manifests', status: 'valid', code: 'cryptographic_authenticity_valid', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'external_anchor', status: 'matched', code: 'external_witness_verified', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'timestamps', status: 'structural_only', code: 'timestamp_structure', message: 'Checked.', details: {} }] },
    { layers: [{ layer: 'container', status: 'valid', code: 'unimplemented_claim', message: 'Checked.', details: {} }] },
    { outcome: 'failed' },
    { layers: [{ layer: 'evidence', status: 'invalid', code: 'zip_crc', message: 'Invalid.', details: {} }] },
  ]) assert.throws(() => parseBrowserResult({ ...r, ...change }, request));
});

test('worker boundary permits implemented partial stages but rejects an incomplete overall success claim', () => {
  const request = { fileName: 'test.zip', checkedAt: '2026-09-19T12:00:00Z', expectations: {} };
  const r = browserFailure(request.fileName, {}, request.checkedAt, 'browser_verifier_incomplete', 'Not fully verified.');
  r.layers = [['graph_references', 'graph_references_valid'], ['manifests', 'manifest_semantics_valid'], ['scope_declaration', 'scope_declaration_valid'], ['signature_integrity', 'embedded_jws_signatures_valid'], ['website_identity', 'carried_did_webvh_logs_valid'], ['signing_authorization', 'carried_history_authorization_valid'], ['checkpoint_identity', 'checkpoint_identity_bindings_valid'], ['transparency', 'carried_transparency_proofs_valid']].map(([layer, code]) => ({ layer, code, status: 'valid', message: 'Implemented carried-history and proof checks only; no complete verification.', details: {} }));
  assert.equal(parseBrowserResult(r, request), r);
  assert.throws(() => parseBrowserResult({ ...r, outcome: 'passed_with_limitations' }, request));
});

test('worker allows only exact supporting-artifact structural, retained and absent claims', () => {
  const request = { fileName: 'test.zip', checkedAt: '2026-09-19T12:00:00Z', expectations: {} };
  const r = browserFailure(request.fileName, {}, request.checkedAt, 'browser_verifier_incomplete', 'Not fully verified.');
  const claims = [
    ['timestamps', 'structural_only', 'ots_structural_only'], ['timestamps', 'not_present', 'timestamps_absent'],
    ['archive_references', 'retained_only', 'archive_references_retained'], ['archive_references', 'not_present', 'archive_references_absent'],
  ];
  for (const [layer, status, code] of claims) {
    r.layers = [{ layer, status, code, message: 'Structure or retained metadata only.', details: {} }];
    assert.equal(parseBrowserResult(r, request), r);
    for (const altered of [{ layer: 'scope' }, { layer: 'external_anchor' }, { code: 'trusted_time_verified' }, { status: 'valid' }, { status: 'matched' }]) {
      assert.throws(() => parseBrowserResult({ ...r, layers: [{ ...r.layers[0], ...altered }] }, request));
    }
    assert.throws(() => parseBrowserResult({ ...r, outcome: 'passed_with_limitations' }, request));
  }
});

test('browser verification terminates its worker after a validated incomplete result', async () => {
  const fixture = workerFixture();
  const job = runBrowserVerification(file(), { bundleSha256: 'a'.repeat(64) }, { createWorker: () => fixture.worker });
  const req = fixture.request();
  fixture.emit(browserFailure(req.fileName, req.expectations, req.checkedAt, 'browser_verifier_incomplete', 'Full verification is not available.'));
  assert.equal((await job.promise).outcome, 'could_not_check');
  assert.equal(fixture.terminated(), 1);
  assert.equal(fixture.worker.onmessage, null);
});

test('browser cancellation terminates work and suppresses late results', async () => {
  const fixture = workerFixture();
  const job = runBrowserVerification(file(), {}, { createWorker: () => fixture.worker });
  const lateMessage = fixture.worker.onmessage!;
  const req = fixture.request();
  job.cancel();
  lateMessage.call(fixture.worker as unknown as Worker, new MessageEvent('message', { data: browserFailure(req.fileName, {}, req.checkedAt, 'late_result', 'Too late.') }));
  assert.equal((await job.promise).outcome, 'cancelled');
  assert.equal(fixture.terminated(), 1);
});

test('browser worker errors, invalid output, constructor failure, and timeout never claim success', async () => {
  for (const mode of ['crash', 'messageerror', 'malformed', 'timeout']) {
    const fixture = workerFixture();
    const job = runBrowserVerification(file(), {}, { createWorker: () => fixture.worker, timeoutMs: 5 });
    if (mode === 'crash') fixture.worker.onerror?.call(fixture.worker as unknown as Worker, {} as ErrorEvent);
    if (mode === 'messageerror') fixture.worker.onmessageerror?.call(fixture.worker as unknown as Worker, new MessageEvent('messageerror'));
    if (mode === 'malformed') fixture.emit({ outcome: 'passed' });
    const result = await job.promise;
    assert.equal(result.outcome, 'could_not_check');
    assert.equal(result.packageSha256, null);
    assert.equal(fixture.terminated(), 1);
    if (mode === 'timeout') assert.equal(result.code, 'browser_timeout');
  }
  const failed = runBrowserVerification(file(), {}, { createWorker: () => { throw new Error('No worker.'); } });
  assert.equal((await failed.promise).code, 'browser_worker_unavailable');
});

test('browser size limit is enforced before creating a worker or reading input', async () => {
  let called = false;
  const oversized = { name: 'oversized.zip', size: BROWSER_INPUT_LIMIT + 1 } as File;
  const job = runBrowserVerification(oversized, {}, { createWorker: () => { called = true; throw new Error('Should not start.'); } });
  assert.equal((await job.promise).code, 'browser_input_limit');
  assert.equal(called, false);
});
