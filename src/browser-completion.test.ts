// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertBrowserCompletion } from './browser-completion';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';
import type { CheckLayer, CheckResult, Expectations } from './model';
import { runBrowserVerification } from './platform-browser-job';
import { browserFailure, parseBrowserResult, type BrowserRequest } from './platform-browser-protocol';

const hash = 'a'.repeat(64);
const otherHash = 'b'.repeat(64);
const did = 'did:webvh:QmSyntheticHistory:example.com';
const uuid = '00000000-0000-4000-8000-000000000001';
const checkedAt = '2026-09-19T12:00:00Z';
const layer = (name: string, status: string, code: string, details: unknown = {}): CheckLayer => ({ layer: name, status, code, details, message: 'Synthetic envelope claim; this fixture contains no evidence bytes.' });

// Self-contained protocol fixtures: UI tests run before package generation.
// Acceptance here validates only an envelope, never the underlying evidence.
function completed(): CheckResult {
  return {
    schemaVersion: 1, checkedAt, appVersion: BROWSER_APP_VERSION, verifierVersion: BROWSER_VERIFIER_VERSION,
    fileName: 'synthetic.zip', packageSha256: hash, outcome: 'passed_with_limitations', code: 'browser_profile_checks_complete',
    message: 'The synthetic required offline stages completed, with limitations.', expectations: {},
    layers: [
      layer('container', 'valid', 'zip_profile_valid', { entries: 32, sha256: hash }),
      layer('inventory', 'valid', 'inventory_valid', { entries: 30 }),
      layer('bundle_graph', 'valid', 'bundle_profile_valid'),
      layer('graph_references', 'valid', 'graph_references_valid'),
      layer('website_identity', 'valid', 'carried_did_webvh_logs_valid', { receipts: 1, versions: 2 }),
      layer('manifests', 'valid', 'manifest_semantics_valid', { count: 1 }),
      layer('scope_declaration', 'valid', 'scope_declaration_valid'),
      layer('signature_integrity', 'valid', 'embedded_jws_signatures_valid', { recordSignatures: 1, checkpointSignatures: 1, unsupportedRecordSignatures: 0 }),
      layer('signing_authorization', 'valid', 'carried_history_authorization_valid', { records: 1 }),
      layer('checkpoint_identity', 'valid', 'checkpoint_identity_bindings_valid', { checkpoints: 1 }),
      layer('transparency', 'valid', 'carried_transparency_proofs_valid', { checkpoints: 1, leafInventories: 0, inclusionProofs: 1, unanchoredProofs: 0 }),
      layer('timestamps', 'structural_only', 'ots_structural_only', { proofs: 1, unsupportedProofs: 0 }),
      layer('archive_references', 'retained_only', 'archive_references_retained', { references: 2 }),
      layer('content_digests', 'not_checked', 'content_digests_not_recomputed'),
      layer('scope', 'valid', 'scope_graph_complete', { kind: 'record', records: 1, checkpoints: 1 }),
      layer('external_anchor', 'self_contained_only', 'no_external_expectation', { expectations: 0 }),
      layer('capability', 'valid', 'browser_profile_checks_complete'),
    ],
  };
}
function stage(result: CheckResult, name: string): CheckLayer { return result.layers.find(value => value.layer === name)!; }
function details(result: CheckResult, name: string): Record<string, unknown> { return stage(result, name).details as Record<string, unknown>; }
function setStage(result: CheckResult, name: string, status: string, code: string, data?: unknown): void {
  Object.assign(stage(result, name), { status, code }, data === undefined ? {} : { details: data });
}
function request(result: CheckResult) { return { fileName: result.fileName, checkedAt: result.checkedAt, expectations: { ...result.expectations } }; }
function accepts(result: CheckResult): void {
  assert.doesNotThrow(() => assertBrowserCompletion(result));
  assert.equal(parseBrowserResult(result, request(result)), result);
}
function rejects(result: CheckResult, label?: string): void {
  assert.throws(() => assertBrowserCompletion(result), label);
  assert.throws(() => parseBrowserResult(result, request(result)), label);
}
function mutate(action: (result: CheckResult) => void, label?: string): void { const value = completed(); action(value); rejects(value, label); }
function withoutArtifacts(result: CheckResult): void {
  setStage(result, 'timestamps', 'not_present', 'timestamps_absent', { proofs: 0, unsupportedProofs: 0 });
  setStage(result, 'archive_references', 'not_present', 'archive_references_absent', { references: 0 });
}
function manifestOnly(): CheckResult {
  const result = completed();
  setStage(result, 'website_identity', 'not_present', 'did_webvh_logs_absent', { receipts: 0, versions: 0 });
  setStage(result, 'signature_integrity', 'not_present', 'embedded_jws_signatures_absent', { recordSignatures: 0, checkpointSignatures: 0, unsupportedRecordSignatures: 0 });
  setStage(result, 'signing_authorization', 'not_present', 'record_signatures_absent', { records: 0 });
  setStage(result, 'checkpoint_identity', 'not_present', 'checkpoint_signatures_absent', { checkpoints: 0 });
  setStage(result, 'transparency', 'not_present', 'transparency_absent', { checkpoints: 0, leafInventories: 0, inclusionProofs: 0, unanchoredProofs: 0 });
  details(result, 'scope').checkpoints = 0;
  withoutArtifacts(result);
  return result;
}
function bulk(): CheckResult {
  const result = completed();
  Object.assign(details(result, 'scope'), { kind: 'checkpoint', records: 3, checkpoints: 2 });
  details(result, 'manifests').count = 3;
  Object.assign(details(result, 'signature_integrity'), { recordSignatures: 0, checkpointSignatures: 2 });
  setStage(result, 'signing_authorization', 'not_present', 'record_signatures_absent', { records: 0 });
  details(result, 'checkpoint_identity').checkpoints = 2;
  Object.assign(details(result, 'transparency'), { checkpoints: 2, leafInventories: 2, inclusionProofs: 0 });
  return result;
}
function withExpectations(result: CheckResult, values: Expectations): CheckResult {
  result.expectations = { ...values };
  const count = Object.values(values).filter(value => value !== undefined).length;
  setStage(result, 'external_anchor', count ? 'matched' : 'self_contained_only', count ? 'expectations_matched' : 'no_external_expectation', { expectations: count });
  return result;
}

test('completion accepts the exact 17-stage signed-record envelope with limited supporting artifacts', () => {
  const result = completed();
  assert.equal(result.layers.length, 17);
  accepts(result);
  result.layers.reverse();
  accepts(result); // Stage identity, not presentation order, controls completeness.
});

test('completion accepts bulk checkpoint, site, and URL-history envelopes', () => {
  accepts(bulk());
  const site = bulk();
  details(site, 'scope').kind = 'site';
  details(site, 'signature_integrity').recordSignatures = 2;
  setStage(site, 'signing_authorization', 'valid', 'carried_history_authorization_valid', { records: 2 });
  accepts(site);
  const history = completed();
  Object.assign(details(history, 'scope'), { kind: 'url-history', records: 3 });
  details(history, 'manifests').count = 3;
  // Frozen PHP requires a nonempty terminal proof set, not a proof per record.
  accepts(history);
});

test('completion accepts manifest-only envelopes with accurately absent signature and identity stages', () => {
  accepts(manifestOnly());
  const result = manifestOnly();
  setStage(result, 'timestamps', 'structural_only', 'ots_structural_only', { proofs: 1, unsupportedProofs: 0 });
  setStage(result, 'archive_references', 'retained_only', 'archive_references_retained', { references: 1 });
  accepts(result);
});

test('an unused carried identity cannot be hidden by an optional DID comparison', () => {
  const result = manifestOnly();
  setStage(result, 'website_identity', 'valid', 'carried_did_webvh_logs_valid', { receipts: 1, versions: 1 });
  // The complete PHP/browser pipeline rejects identity_graph_orphan before
  // comparisons: a receipt must authorize a record or bind a checkpoint.
  rejects(withExpectations(result, { did }));
});

test('zero, individual, and all five optional matches have exact counts without upgrading limitations', () => {
  accepts(withExpectations(completed(), { did: undefined }));
  for (const values of [{ bundleSha256: hash }, { manifestSha256: otherHash }, { checkpointSha256: otherHash }, { did }, { recordUuid: uuid },
    { bundleSha256: hash, manifestSha256: otherHash, checkpointSha256: otherHash, did, recordUuid: uuid }]) accepts(withExpectations(completed(), values));
});

test('each missing, duplicated, replaced, or extra stage prevents completion', () => {
  for (let index = 0; index < 17; index++) {
    mutate(result => { result.layers.splice(index, 1); }, `missing ${index}`);
    mutate(result => { result.layers[index] = structuredClone(result.layers[(index + 1) % 17]); }, `duplicate ${index}`);
    mutate(result => { result.layers[index].layer = 'unrecognized_stage'; }, `replaced ${index}`);
  }
  mutate(result => { result.layers.push(layer('extra', 'not_checked', 'not_checked')); });
});

test('every unsupported, invalid, or wrong-code stage blocks a successful envelope', () => {
  for (let index = 0; index < 17; index++) {
    mutate(result => { result.layers[index].status = 'unsupported'; }, `unsupported ${index}`);
    mutate(result => { result.layers[index].status = 'invalid'; }, `invalid ${index}`);
    mutate(result => { result.layers[index].code = 'forged_stage_code'; }, `code ${index}`);
    if (completed().layers[index].status === 'valid') mutate(result => { result.layers[index].status = 'not_checked'; }, `unchecked required ${index}`);
  }
});

test('retained content digests, structural timestamps, and archive metadata cannot be promoted to stronger claims', () => {
  for (const name of ['timestamps', 'archive_references', 'content_digests']) {
    for (const status of ['valid', 'matched', 'indeterminate']) mutate(result => { stage(result, name).status = status; });
  }
  mutate(result => { stage(result, 'content_digests').code = 'content_digests_recomputed'; });
  mutate(result => { stage(result, 'timestamps').code = 'trusted_time_verified'; });
  mutate(result => { stage(result, 'archive_references').code = 'archive_availability_verified'; });
});

const countFields: [string, string][] = [
  ['container', 'entries'], ['inventory', 'entries'], ['scope', 'records'], ['scope', 'checkpoints'], ['manifests', 'count'],
  ['signature_integrity', 'recordSignatures'], ['signature_integrity', 'checkpointSignatures'], ['signature_integrity', 'unsupportedRecordSignatures'],
  ['signing_authorization', 'records'], ['checkpoint_identity', 'checkpoints'], ['website_identity', 'receipts'], ['website_identity', 'versions'],
  ['transparency', 'checkpoints'], ['transparency', 'unanchoredProofs'], ['transparency', 'leafInventories'], ['transparency', 'inclusionProofs'],
  ['timestamps', 'proofs'], ['timestamps', 'unsupportedProofs'], ['archive_references', 'references'], ['external_anchor', 'expectations'],
];

test('every required numeric count must exist as a bounded nonnegative safe integer', () => {
  for (const [name, field] of countFields) {
    for (const value of [undefined, null, '1', true, [], {}, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      mutate(result => { details(result, name)[field] = value; }, `${name}.${field}=${String(value)}`);
    }
  }
  for (const name of new Set(countFields.map(([name]) => name))) {
    for (const value of [undefined, null, [], 'details']) mutate(result => { stage(result, name).details = value; });
  }
});

test('count mismatches cannot conceal missing inventory, manifests, signatures, authorization, or identity versions', () => {
  for (const [name, field, value] of [
    ['container', 'entries', 31], ['inventory', 'entries', 31], ['scope', 'records', 2], ['manifests', 'count', 0],
    ['signature_integrity', 'recordSignatures', 2], ['signature_integrity', 'checkpointSignatures', 0],
    ['signature_integrity', 'unsupportedRecordSignatures', 1], ['signing_authorization', 'records', 0],
    ['checkpoint_identity', 'checkpoints', 0], ['website_identity', 'versions', 0], ['website_identity', 'versions', 129],
    ['transparency', 'checkpoints', 0], ['transparency', 'unanchoredProofs', 1], ['timestamps', 'unsupportedProofs', 1],
  ] as const) mutate(result => { details(result, name)[field] = value; }, `${name}.${field}`);
  mutate(result => { setStage(result, 'website_identity', 'not_present', 'did_webvh_logs_absent', { receipts: 0, versions: 0 }); });
  mutate(result => { Object.assign(details(result, 'scope'), { records: 0 }); details(result, 'manifests').count = 0; });
});

test('the count of required receipts cannot exceed the signatures and checkpoints that consume them', () => {
  // Each signature/checkpoint consumes one receipt. Reuse is allowed, but the
  // complete verifier rejects all unused receipts as identity_graph_orphan.
  mutate(result => { Object.assign(details(result, 'website_identity'), { receipts: 3, versions: 3 }); });
  const atBound = completed();
  Object.assign(details(atBound, 'website_identity'), { receipts: 2, versions: 2 });
  accepts(atBound);
});

test('scope topology counts reject bulk inventories in record scope and absent required bulk evidence', () => {
  mutate(result => { details(result, 'scope').kind = 'unknown'; });
  mutate(result => { details(result, 'transparency').leafInventories = 1; });
  mutate(result => { details(result, 'transparency').inclusionProofs = 0; });
  mutate(result => { details(result, 'transparency').inclusionProofs = 2; });
  for (const change of [
    (result: CheckResult) => { details(result, 'transparency').leafInventories = 0; },
    (result: CheckResult) => { details(result, 'transparency').leafInventories = 3; },
    (result: CheckResult) => { details(result, 'transparency').inclusionProofs = 1; },
    (result: CheckResult) => { details(result, 'signature_integrity').recordSignatures = 1; setStage(result, 'signing_authorization', 'valid', 'carried_history_authorization_valid', { records: 1 }); },
  ]) { const result = bulk(); change(result); rejects(result); }
  const noCheckpoint = manifestOnly();
  details(noCheckpoint, 'scope').kind = 'site';
  rejects(noCheckpoint);
});

test('present and absent statuses must agree with exact supporting-artifact and signature counts', () => {
  mutate(result => { details(result, 'timestamps').proofs = 0; });
  mutate(result => { details(result, 'archive_references').references = 0; });
  for (const name of ['website_identity', 'signature_integrity', 'signing_authorization', 'checkpoint_identity', 'transparency', 'timestamps', 'archive_references']) {
    const value = manifestOnly();
    stage(value, name).status = 'valid';
    rejects(value);
  }
  for (const name of ['signature_integrity', 'signing_authorization', 'checkpoint_identity', 'website_identity', 'transparency']) mutate(result => { stage(result, name).status = 'not_present'; });
});

test('fingerprints are exact lowercase 64-character digests and bind the container and bundle comparison', () => {
  for (const fingerprint of [null, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), `${hash}\n`, `${hash}\r\n`, 'z'.repeat(64)]) {
    mutate(result => { result.packageSha256 = fingerprint; details(result, 'container').sha256 = fingerprint; });
  }
  mutate(result => { details(result, 'container').sha256 = otherHash; });
  mutate(result => { withExpectations(result, { bundleSha256: otherHash }); });
});

test('expectation counts, matched statuses, and request echo cannot disagree', () => {
  mutate(result => { details(result, 'external_anchor').expectations = 1; });
  mutate(result => { withExpectations(result, { did }); details(result, 'external_anchor').expectations = 0; });
  mutate(result => { withExpectations(result, { did }); stage(result, 'external_anchor').status = 'self_contained_only'; });
  mutate(result => { stage(result, 'external_anchor').status = 'matched'; });
  const value = withExpectations(completed(), { did });
  assert.throws(() => parseBrowserResult(value, { ...request(value), expectations: {} }));
  assert.throws(() => parseBrowserResult(value, { ...request(value), expectations: { did: `${did}:different` } }));
});

test('DID and checkpoint matches require the corresponding verified evidence to be present', () => {
  rejects(withExpectations(manifestOnly(), { did }));
  rejects(withExpectations(manifestOnly(), { checkpointSha256: otherHash }));
  accepts(withExpectations(manifestOnly(), { bundleSha256: hash, manifestSha256: otherHash, recordUuid: uuid }));
});

test('bare passed, cancelled, failed, and incomplete outcomes never carry a successful completion envelope', () => {
  for (const outcome of ['passed', 'cancelled', 'failed', 'could_not_check'] as const) mutate(result => { result.outcome = outcome; });
  for (const code of ['browser_verifier_incomplete', 'browser_profile_unsupported', 'forged_completion']) mutate(result => { result.code = code; });
  mutate(result => { result.outcome = 'could_not_check'; result.code = 'browser_verifier_incomplete'; });
  mutate(result => { result.outcome = 'could_not_check'; stage(result, 'capability').status = 'unsupported'; });
});

test('ordinary incomplete, invalid, and clean cancellation responses remain supported without a completion claim', () => {
  const input = { fileName: 'synthetic.zip', checkedAt, expectations: {} };
  const incomplete = browserFailure(input.fileName, {}, checkedAt, 'browser_crypto_unavailable', 'Required local cryptography is unavailable.');
  incomplete.layers.push(layer('capability', 'unsupported', 'browser_crypto_unavailable'));
  assert.equal(parseBrowserResult(incomplete, input), incomplete);
  const invalid = browserFailure(input.fileName, {}, checkedAt, 'expected_bundle', 'The independent comparison did not match.');
  invalid.outcome = 'failed';
  invalid.layers.push(layer('evidence', 'invalid', 'expected_bundle'));
  assert.equal(parseBrowserResult(invalid, input), invalid);
  const cancelled = browserFailure(input.fileName, {}, checkedAt, 'cancel_requested', 'Cancelled.', true);
  assert.equal(parseBrowserResult(cancelled, input), cancelled);
});

test('request identity and protocol bounds still apply to otherwise complete envelopes', () => {
  for (const change of [{ appVersion: 'wrong' }, { verifierVersion: 'wrong' }, { fileName: 'other.zip' }, { checkedAt: '2020-01-01T00:00:00Z' }]) {
    const result = completed();
    assert.throws(() => parseBrowserResult({ ...result, ...change }, request(result)));
  }
  const value = completed();
  stage(value, 'bundle_graph').details = { excessive: 'x'.repeat(16385) };
  assert.throws(() => parseBrowserResult(value, request(value)));
});

function workerFixture() {
  let pendingRequest!: BrowserRequest;
  let terminations = 0;
  const worker = {
    onmessage: null as Worker['onmessage'], onerror: null as Worker['onerror'], onmessageerror: null as Worker['onmessageerror'],
    postMessage(value: unknown) { pendingRequest = value as BrowserRequest; },
    terminate() { terminations++; },
  };
  return {
    worker, terminations: () => terminations,
    completion() {
      const result = withExpectations(completed(), pendingRequest.expectations);
      result.fileName = pendingRequest.fileName;
      result.checkedAt = pendingRequest.checkedAt;
      return result;
    },
  };
}

test('a complete limited-pass worker response is delivered once and terminates the worker', async () => {
  const fixture = workerFixture();
  const job = runBrowserVerification(new File(['synthetic'], 'user-selected.zip'), { bundleSha256: hash }, { createWorker: () => fixture.worker });
  const response = fixture.completion();
  fixture.worker.onmessage!.call(fixture.worker as unknown as Worker, new MessageEvent('message', { data: response }));
  const result = await job.promise;
  assert.equal(result, response);
  assert.equal(result.outcome, 'passed_with_limitations');
  assert.equal(result.code, 'browser_profile_checks_complete');
  assert.equal(fixture.terminations(), 1);
  assert.equal(fixture.worker.onmessage, null);
  assert.equal(fixture.worker.onerror, null);
  assert.equal(fixture.worker.onmessageerror, null);
});

test('cancellation suppresses a queued complete limited-pass response and remains cancelled', async () => {
  const fixture = workerFixture();
  const job = runBrowserVerification(new File(['synthetic'], 'user-selected.zip'), {}, { createWorker: () => fixture.worker });
  const lateCompletion = fixture.completion();
  const queuedHandler = fixture.worker.onmessage!;
  job.cancel();
  queuedHandler.call(fixture.worker as unknown as Worker, new MessageEvent('message', { data: lateCompletion }));
  const result = await job.promise;
  assert.equal(result.outcome, 'cancelled');
  assert.equal(result.packageSha256, null);
  assert.deepEqual(result.layers, []);
  assert.equal(fixture.terminations(), 1);
  assert.equal(fixture.worker.onmessage, null);
});
