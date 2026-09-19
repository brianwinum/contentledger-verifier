// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import type { Expectations } from '../model';
import { verifyComparisons } from './comparisons';
import { VerifierError } from './errors';
import type { RecordReference } from './graph';
import type { VerifiedIdentityReceipt } from './identity';

const packageHash = 'a'.repeat(64);
const manifestA = 'b'.repeat(64);
const manifestB = 'c'.repeat(64);
const checkpoint = 'd'.repeat(64);
const absentHash = 'e'.repeat(64);
const uuidA = '00000000-0000-4000-8000-000000000001';
const uuidB = '00000000-0000-4000-8000-000000000002';
const absentUuid = '00000000-0000-4000-8000-000000000003';
const didA = 'did:webvh:QmSyntheticHistoryOne:example.com';
const didB = 'did:webvh:QmSyntheticHistoryTwo:example.net';
const absentDid = 'did:webvh:QmSyntheticHistoryThree:example.org';
function record(uuid: string, hash: string): RecordReference {
  return { archiveReferencePath: null, entryId: `urn:uuid:${uuid}`, inclusionProofPaths: [], manifestPath: `records/${uuid}/manifest.json`, manifestSha256: hash, signaturePath: null, timestampPaths: [] };
}
// These unit fixtures exercise membership only. Receipt verification is the
// caller's prerequisite; no cryptographic authenticity is inferred here.
function receipt(did: string): VerifiedIdentityReceipt {
  return {
    did, activeKeyId: `${did}#key`, document: {}, eventHeadHash: absentHash, json: '{}', keys: {}, log_json: '', sha256: absentHash, versions: [],
    identity: { did, assertionMethod: `${did}#key`, entryCount: 1, logBytes: 0, logSha256: absentHash,
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, publicUrl: 'https://example.com/.well-known/did.jsonl',
      siteUrl: 'https://example.com/', stateSha256: absentHash, versionId: '1-synthetic', versionTime: '2026-01-01T00:00:00Z' },
  };
}
const records = [record(uuidA, manifestA), record(uuidB, manifestB)];
const receipts = [receipt(didA), receipt(didB)];
const compare = (expectations: Expectations) => verifyComparisons(expectations, records, checkpoint, receipts, packageHash);
function fails(action: () => unknown, code: string): void {
  assert.throws(action, error => error instanceof VerifierError && error.kind === 'invalid' && error.code === code);
}

test('no comparisons report self-contained evidence, without implying independent trust', () => {
  assert.deepEqual(verifyComparisons({}, [], null, [], packageHash), {
    layer: 'external_anchor', status: 'self_contained_only', code: 'no_external_expectation',
    message: 'No external expectation was supplied; this result does not establish a live DID, current site state, Bitcoin consensus, completeness, or authorship.',
    details: { expectations: 0 },
  });
  assert.deepEqual(compare({ bundleSha256: undefined, did: undefined }).details, { expectations: 0 });
});

test('each independently supplied comparison contributes one count and exposes no values', () => {
  for (const expectation of [{ bundleSha256: packageHash }, { recordUuid: uuidA }, { manifestSha256: manifestB }, { checkpointSha256: checkpoint }, { did: didB }]) {
    assert.deepEqual(compare(expectation), {
      layer: 'external_anchor', status: 'matched', code: 'expectations_matched',
      message: 'Every supplied external expectation matches the selected self-contained evidence.', details: { expectations: 1 },
    });
  }
});

test('all five successful comparisons count fields, not matching records or receipts', () => {
  const expectations = { bundleSha256: packageHash, recordUuid: uuidA, manifestSha256: manifestB, checkpointSha256: checkpoint, did: didB };
  const layer = verifyComparisons(expectations, [...records, ...records], checkpoint, [...receipts, ...receipts], packageHash);
  assert.equal(layer.status, 'matched');
  assert.deepEqual(layer.details, { expectations: 5 });
  for (const value of Object.values(expectations)) assert.ok(!JSON.stringify(layer).includes(value));
});

test('each absent external expectation fails with its frozen PHP error code', () => {
  const cases: [Expectations, string][] = [
    [{ bundleSha256: absentHash }, 'expected_bundle'], [{ recordUuid: absentUuid }, 'expected_record'],
    [{ manifestSha256: absentHash }, 'expected_manifest'], [{ checkpointSha256: absentHash }, 'expected_checkpoint'],
    [{ did: absentDid }, 'expected_did'],
  ];
  for (const [expectations, code] of cases) fails(() => compare(expectations), code);
});

test('mismatches preserve bundle, record, manifest, checkpoint, DID failure precedence', () => {
  const expectations: Expectations = { did: absentDid, checkpointSha256: absentHash, manifestSha256: absentHash, recordUuid: absentUuid, bundleSha256: absentHash };
  const ordered: [keyof Expectations, string][] = [
    ['bundleSha256', 'expected_bundle'], ['recordUuid', 'expected_record'], ['manifestSha256', 'expected_manifest'],
    ['checkpointSha256', 'expected_checkpoint'], ['did', 'expected_did'],
  ];
  for (const [field, code] of ordered) {
    fails(() => compare(expectations), code);
    delete expectations[field];
  }
});

test('record and manifest membership may match different records and do not authenticate a manifest profile', () => {
  // No manifest semantic result is an input: PHP compares checked graph hashes,
  // even if one manifest profile was unsupported. Overall gating is separate.
  const layer = compare({ recordUuid: uuidA, manifestSha256: manifestB });
  assert.equal(layer.status, 'matched');
  assert.deepEqual(layer.details, { expectations: 2 });
});

test('checkpoint expectation must match the terminal target, not an unrelated digest', () => {
  fails(() => verifyComparisons({ checkpointSha256: checkpoint }, records, null, receipts, packageHash), 'expected_checkpoint');
  fails(() => verifyComparisons({ checkpointSha256: manifestA }, records, checkpoint, receipts, packageHash), 'expected_checkpoint');
  assert.equal(verifyComparisons({}, records, null, receipts, packageHash).status, 'self_contained_only');
});

test('DID comparison accepts any verified carried receipt, but not an absent receipt', () => {
  assert.equal(compare({ did: didA }).status, 'matched');
  assert.equal(compare({ did: didB }).status, 'matched');
  fails(() => verifyComparisons({ did: didA }, records, checkpoint, [], packageHash), 'expected_did');
  fails(() => verifyComparisons({ did: didA }, [], null, [receipt(didB)], packageHash), 'expected_did');
});

test('comparison is a read-only, synchronous operation over validated input', () => {
  const expectations = Object.freeze({ bundleSha256: packageHash, recordUuid: uuidA, manifestSha256: manifestB, checkpointSha256: checkpoint, did: didB });
  const frozenRecords = Object.freeze(records.map(value => Object.freeze({ ...value })));
  const frozenReceipts = Object.freeze(receipts.map(value => Object.freeze({ ...value })));
  const before = JSON.stringify({ expectations, frozenRecords, frozenReceipts });
  assert.equal(verifyComparisons(expectations, frozenRecords, checkpoint, frozenReceipts, packageHash).status, 'matched');
  assert.equal(JSON.stringify({ expectations, frozenRecords, frozenReceipts }), before);
});
