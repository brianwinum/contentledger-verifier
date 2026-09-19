// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { browserReport, reportDownload, reportFileName } from './browser-report';
import type { CheckResult } from './model';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';

function result(): CheckResult {
  return { schemaVersion: 1, checkedAt: '2026-09-18T20:15:42Z', appVersion: BROWSER_APP_VERSION, verifierVersion: BROWSER_VERIFIER_VERSION, fileName: 'C:\\Private\\customer.zip', packageSha256: `cad30fdaa57f${'a'.repeat(52)}`, outcome: 'could_not_check', code: 'browser_verifier_incomplete', message: 'No successful verification is claimed.', expectations: { did: 'did:webvh:private.example', bundleSha256: 'b'.repeat(64) }, layers: [{ layer: 'container', status: 'valid', code: 'zip_profile_valid', message: 'Private source filename appears here.', details: { secret: 'private-details' } }] };
}

test('browser report naming matches native digest/check-time names and normalizes UTC', () => {
  const r = result();
  const expected = 'contentledger-check-summary-cad30fdaa57f-20260918T201542Z.json';
  assert.equal(reportFileName(r), expected);
  for (const checkedAt of ['2026-09-18T16:15:42-04:00', '2026-09-19T00:15:42+04:00', '2026-09-18T20:15:42.123Z']) assert.equal(reportFileName({ ...r, checkedAt }), expected);
  assert.notEqual(reportFileName({ ...r, packageSha256: 'b'.repeat(64) }), expected);
  assert.notEqual(reportFileName({ ...r, checkedAt: '2026-09-18T20:15:43Z' }), expected);
});

test('browser report naming rejects malformed fingerprints and timestamps without using user text', () => {
  for (const packageSha256 of [null, '', '../secret.json', 'A'.repeat(64), 'a'.repeat(12), `${'a'.repeat(64)}\n`]) {
    assert.equal(reportFileName({ ...result(), packageSha256 }), 'contentledger-check-summary-no-fingerprint-20260918T201542Z.json');
  }
  for (const checkedAt of ['not a timestamp', '2026-02-30T12:00:00Z', '2026-09-18', '2026-09-18T24:00:00Z', '2026-09-18T20:15:42+24:00', '2026-09-18T20:15:42', '2026-09-18T20:15:42Z\n']) {
    assert.equal(reportFileName({ ...result(), packageSha256: null, checkedAt }), 'contentledger-check-summary-no-fingerprint-time-unknown.json');
  }
});

test('browser reports preserve the native redacted contract and limitation caveats', () => {
  const r = result();
  const report = browserReport(r);
  const json = JSON.stringify(report);
  for (const secret of [r.fileName, r.expectations.did!, r.expectations.bundleSha256!, 'Private source filename', 'private-details']) assert.ok(!json.includes(secret));
  assert.deepEqual(report.expectationsSupplied, { bundleSha256: true, checkpointSha256: false, manifestSha256: false, did: true, recordUuid: false });
  assert.deepEqual(report.checks, [{ layer: 'container', status: 'valid', code: 'zip_profile_valid' }]);
  assert.equal(report.kind, 'contentledger-local-check-summary');
  assert.equal(report.outcome, 'could_not_check');
  assert.match(report.notice, /not a signed attestation/);
  assert.match(report.expectationSemantics, /does not establish a relationship/);
  assert.match(report.limitations.join(' '), /Bitcoin consensus/);
  assert.match(report.limitations.join(' '), /Browser development build; cross-browser release qualification and independent security review remain open/);
});

test('browser download snapshots its filename and JSON from the same result', () => {
  const r = result();
  const download = reportDownload(r);
  r.packageSha256 = 'f'.repeat(64);
  r.outcome = 'failed';
  r.layers[0].code = 'changed';
  const saved = JSON.parse(download.json);
  assert.match(download.name, /cad30fdaa57f-20260918T201542Z/);
  assert.match(saved.packageSha256, /^cad30fdaa57f/);
  assert.equal(saved.outcome, 'could_not_check');
  assert.equal(saved.checks[0].code, 'zip_profile_valid');
});
