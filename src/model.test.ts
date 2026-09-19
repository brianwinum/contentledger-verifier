import test from 'node:test';
import assert from 'node:assert/strict';
import { cancellationView, layerView, outcomeView, parseCheckResult, parseSelectedPackage, safeText, validateExpectations, type CheckResult } from './model';

const result: CheckResult = { schemaVersion: 1, checkedAt: '2026-09-18T12:00:00Z', appVersion: '0.1.0', fileName: 'test.zip', packageSha256: 'a'.repeat(64), outcome: 'passed_with_limitations', code: 'verified', message: 'Checked.', verifierVersion: '3.0.0', layers: [{ layer: 'container', status: 'valid', code: 'valid', message: 'Checked.', details: {} }], expectations: {} };

test('success summaries always retain the offline limitations', () => {
  for (const outcome of ['passed', 'passed_with_limitations'] as const) {
    assert.match(outcomeView(outcome).title, /offline checks.*limitations apply/);
    assert.equal(outcomeView(outcome).tone, 'limited');
    assert.doesNotMatch(outcomeView(outcome).title, /authentic|ownership|trusted/i);
  }
});

test('failed evidence and unavailable verification have distinct conclusions', () => {
  assert.equal(outcomeView('failed').tone, 'negative');
  assert.equal(outcomeView('could_not_check').tone, 'neutral');
  assert.notEqual(outcomeView('failed').title, outcomeView('could_not_check').title);
  assert.match(outcomeView('cancelled').description, /No completed/);
});

test('cancellation suppresses late success but preserves failures and cleanup warnings', () => {
  assert.equal(cancellationView(result, false), result);
  for (const outcome of ['passed', 'passed_with_limitations'] as const) {
    const cancelled = cancellationView({ ...result, outcome }, true);
    assert.equal(cancelled.outcome, 'cancelled');
    assert.equal(cancelled.packageSha256, null);
    assert.deepEqual(cancelled.layers, []);
  }
  for (const outcome of ['failed', 'could_not_check', 'cancelled'] as const) {
    const failure: CheckResult = { ...result, outcome, code: outcome === 'could_not_check' ? 'temporary_cleanup' : 'verification_stopped', message: 'Private temporary files could not be removed.' };
    assert.equal(cancellationView(failure, true), failure);
    assert.equal(cancellationView(failure, true).message, failure.message);
  }
});

test('missing and structural evidence cannot become a cryptographic pass', () => {
  for (const status of ['not_present', 'structural_only', 'retained_only', 'not_checked', 'indeterminate', 'unsupported', 'unknown']) {
    assert.notEqual(layerView(status).tone, 'positive');
    assert.notEqual(layerView(status).label, 'Passed');
  }
  assert.equal(layerView('structural_only').label, 'Structure only');
  assert.equal(layerView('retained_only').label, 'Metadata only');
});

test('bridge result rejects missing checks, unknown status, inconsistent success and invalid digests', () => {
  assert.equal(parseCheckResult(result), result);
  for (const change of [{ schemaVersion: 2 }, { layers: [] }, { packageSha256: 'short' }, { expectations: null }, { outcome: 'authentic' }, { layers: [{ ...result.layers[0], status: 'invalid' }] }, { layers: [{ ...result.layers[0], status: 'unsupported' }] }, { layers: [{ ...result.layers[0], status: 'probably_valid' }] }]) {
    assert.throws(() => parseCheckResult({ ...result, ...change }));
  }
  assert.equal(parseCheckResult({ ...result, outcome: 'could_not_check', layers: [], packageSha256: null }).outcome, 'could_not_check');
});

test('package metadata rejects non-finite, fractional, and negative sizes', () => {
  for (const size of [NaN, Infinity, -1, 0.5]) assert.throws(() => parseSelectedPackage({ id: 'x', name: 'x.zip', size }));
  assert.equal(parseSelectedPackage({ id: 'x', name: 'x.zip', size: 0 }).size, 0);
});

test('untrusted text removes hidden direction and control characters, without interpreting markup', () => {
  assert.equal(safeText('report\u202Egpj.exe\u2066'), 'report�gpj.exe�');
  assert.equal(safeText('<script>alert(1)</script>'), '<script>alert(1)</script>');
  assert.equal(safeText('line\nnext\u0000'), 'line\nnext�');
});

test('expectations are normalized individually and refuse malformed values', () => {
  assert.deepEqual(validateExpectations({ bundleSha256: ` ${'A'.repeat(64)} `, manifestSha256: '' }).values, { bundleSha256: 'a'.repeat(64) });
  assert.equal(validateExpectations({ bundleSha256: 'g'.repeat(64) }).field, 'bundleSha256');
  assert.equal(validateExpectations({ did: 'https://example.org' }).field, 'did');
  assert.equal(validateExpectations({ did: 'did:webvh:abc\u202E:example.org' }).field, 'did');
  assert.equal(validateExpectations({ recordUuid: 'invalid' }).field, 'recordUuid');
  assert.equal(validateExpectations({ recordUuid: '12345678-1234-1234-1234-123456789abc' }).field, 'recordUuid');
  assert.equal(validateExpectations({ did: 'did:webvh:abc:example.org', recordUuid: '12345678-1234-4234-9234-123456789abc' }).error, null);
});
