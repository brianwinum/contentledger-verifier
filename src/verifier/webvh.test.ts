// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fixtureCanonical, fixtureEntries } from '../../tests/browser-test-support';
import { isWebvhUtcSecond, MAX_WEBVH_JSONL_BYTES, MAX_WEBVH_LINE_BYTES, verifyWebvh, type WebvhState } from './webvh';
import { base58Encode, decodeProofValue, sha256Multihash } from './webvh-codec';

interface Entry {
  parameters: Record<string, unknown>;
  proof: Record<string, unknown>[];
  state: WebvhState;
  versionId: string;
  versionTime: string;
}
const fixture = readFileSync(new URL('../../../qa/fixtures/did-webvh-production-profile-v1/valid-root-continuous-ratchet.jsonl', import.meta.url));
const log = fixture.toString('utf8').trimEnd().split('\n').map(line => JSON.parse(line) as Entry);
const did = log[0].state.id;
const asOf = '2026-08-23T00:00:00Z';
const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const jsonl = (entries: Entry[]): Uint8Array => bytes(entries.map(fixtureCanonical).join('\n') + '\n');
function mutate(change: (entry: Entry, index: number) => void): Uint8Array {
  const entries: Entry[] = structuredClone(log);
  entries.forEach(change);
  return jsonl(entries);
}
async function rejects(raw: Uint8Array, code: string, status: 'invalid' | 'unsupported' | 'malformed' = 'invalid', count = 3): Promise<void> {
  const result = await verifyWebvh(did, raw, asOf);
  assert.equal(result.status, status); assert.equal(result.code, code); assert.equal(result.entryCount, count);
  assert.deepEqual(result.versions, []); assert.deepEqual(result.resolvedStates, []); assert.deepEqual(result.versionIds, []);
}

test('WebVH resolves complete continuous and assertion-rotation histories with exact public fields', async () => {
  for (const filename of ['valid-root-continuous-ratchet.jsonl', 'valid-path-assertion-rotation-ratchet.jsonl']) {
    const raw = readFileSync(new URL(`../../../qa/fixtures/did-webvh-production-profile-v1/${filename}`, import.meta.url));
    const expected = JSON.parse(raw.toString('utf8').split('\n')[0]).state.id as string;
    const result = await verifyWebvh(expected, raw, asOf);
    assert.equal(result.status, 'valid'); assert.equal(result.code, 'ok'); assert.equal(result.entryCount, 3);
    assert.equal(new Set(result.versions.map(version => version.currentUpdateKey)).size, 3);
    assert.equal(new Set(result.versions.map(version => version.committedSuccessorHash)).size, 3);
    assert.deepEqual(result.versionIds, result.versions.map(version => version.versionId));
    assert.deepEqual(result.resolvedStates, result.versions.map(version => version.state));
    for (const version of result.versions) {
      assert.deepEqual(Object.keys(version).sort(), ['assertionKey', 'committedSuccessorHash', 'currentUpdateKey', 'state', 'versionId', 'versionTime']);
      assert.equal(version.state.id, expected);
      assert.equal(version.assertionKey, version.state.verificationMethod[0].publicKeyJwk.x);
    }
  }
});

test('WebVH authenticates the generated package identity log without I/O or receipt authority', async () => {
  const entries = fixtureEntries(readFileSync(new URL('../../tests/fixtures/record.zip', import.meta.url)));
  const bundle = JSON.parse(entries.get('bundle.json')!.toString('utf8'));
  const identity = bundle.identityLogs[0];
  const result = await verifyWebvh(identity.did, entries.get(identity.logPath)!, '9999-12-31T23:59:59Z');
  assert.equal(result.status, 'valid'); assert.equal(result.code, 'ok');
  assert.equal(result.versionIds.at(-1), identity.versionId);
  assert.equal(result.versions.at(-1)?.versionTime, identity.versionTime);
});

test('WebVH framing caps reject before exposing any partial history', async () => {
  for (const [raw, code] of [
    [new Uint8Array(), 'jsonl_empty'], [new Uint8Array(MAX_WEBVH_JSONL_BYTES + 1), 'jsonl_size'],
    [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), fixture]), 'jsonl_bom'], [Buffer.concat([Buffer.from([0]), fixture]), 'jsonl_nul'],
    [bytes(fixture.toString().replaceAll('\n', '\r\n')), 'jsonl_line_endings'], [fixture.subarray(0, -1), 'jsonl_final_lf'],
    [bytes('\n'), 'jsonl_blank_line'], [bytes('x'.repeat(MAX_WEBVH_LINE_BYTES + 1) + '\n'), 'jsonl_line_size'], [bytes('{}\n'.repeat(129)), 'jsonl_entry_count'],
  ] as const) await rejects(raw, code, 'malformed', 0);
});

test('WebVH rejects noncanonical, malformed, nonobject, and number-bearing entry JSON', async () => {
  await rejects(bytes(' ' + fixture.toString()), 'noncanonical_json');
  await rejects(bytes('[]\n'), 'entry_shape', 'invalid', 1);
  await rejects(bytes('{}\n'), 'entry_members', 'invalid', 1);
  await rejects(bytes('{"number":0}\n'), 'json_number_unsupported', 'unsupported', 1);
});

test('WebVH caller and version dates are exact whole UTC seconds with real calendar days', async () => {
  for (const value of ['0000-01-01T00:00:00Z', '2026-02-29T00:00:00Z', '2026-08-23T00:00:60Z', '2026-08-23T00:00:00+00:00', '2026-08-23T00:00:00.0Z', `${asOf}\n`]) {
    assert.equal(isWebvhUtcSecond(value), false);
    const result = await verifyWebvh(did, fixture, value);
    assert.equal(result.status, 'malformed'); assert.equal(result.code, 'as_of_invalid'); assert.equal(result.entryCount, 0);
  }
  assert.equal(isWebvhUtcSecond('0001-01-01T00:00:00Z'), true);
  assert.equal(isWebvhUtcSecond('2024-02-29T23:59:59Z'), true);
  await rejects(mutate((entry, index) => { if (index === 0) entry.versionTime = '2026-02-30T00:00:00Z'; }), 'version_time');
  await rejects(mutate((entry, index) => { if (index === 1) entry.versionTime = log[0].versionTime; }), 'version_time_order');
  assert.equal((await verifyWebvh(did, fixture, '2026-08-22T19:59:59Z')).code, 'version_time_future');
});

test('WebVH expected DID limits and unsupported features remain distinct outcomes', async () => {
  const scid = did.split(':')[2];
  for (const [expected, code, status] of [
    ['', 'did_size', 'invalid'], ['x'.repeat(2049), 'did_size', 'invalid'], [`${did}\n`, 'did_feature_unsupported', 'unsupported'],
    [`${did}%20`, 'did_feature_unsupported', 'unsupported'], [`did:web:${scid}:example.test`, 'did_syntax', 'invalid'],
    [`did:webvh:x:example.test`, 'scid_encoding', 'invalid'], [`did:webvh:${scid}:127.0.0.1`, 'did_feature_unsupported', 'unsupported'],
    [`did:webvh:${scid}:0x7f.1`, 'did_feature_unsupported', 'unsupported'], [`did:webvh:${scid}:xn--example.test`, 'did_feature_unsupported', 'unsupported'],
    [`did:webvh:${scid}:localhost`, 'did_domain', 'invalid'], [`did:webvh:${scid}:Example.test`, 'did_domain', 'invalid'],
    [`${did}:UPPER`, 'did_feature_unsupported', 'unsupported'], [`${did}:..`, 'did_path', 'invalid'], [`${did}:`, 'did_path', 'invalid'],
  ] as const) {
    const result = await verifyWebvh(expected, fixture, asOf);
    assert.equal(result.status, status, expected); assert.equal(result.code, code, expected); assert.equal(result.entryCount, 0);
  }
});

test('WebVH version IDs and genesis parameter shapes preserve exact failure precedence', async () => {
  await rejects(mutate((entry, index) => { if (index === 0) entry.versionId += '\n'; }), 'version_id');
  await rejects(mutate((entry, index) => { if (index === 0) entry.versionId = entry.versionId.replace(/^1-/, '2-'); }), 'version_id');
  for (const [change, code, status] of [
    [(parameters: Record<string, unknown>) => { delete parameters.method; }, 'method_missing', 'invalid'],
    [(parameters: Record<string, unknown>) => { parameters.method = false; }, 'method_shape', 'invalid'],
    [(parameters: Record<string, unknown>) => { parameters.method = 'did:webvh:2.0'; }, 'method_unsupported', 'unsupported'],
    [(parameters: Record<string, unknown>) => { parameters.unrecognized = false; }, 'feature_unsupported', 'unsupported'],
    [(parameters: Record<string, unknown>) => { delete parameters.scid; }, 'scid_missing', 'invalid'],
    [(parameters: Record<string, unknown>) => { delete parameters.portable; }, 'portable_missing', 'invalid'],
    [(parameters: Record<string, unknown>) => { parameters.portable = false; }, 'portable_required', 'invalid'],
    [(parameters: Record<string, unknown>) => { parameters.updateKeys = []; }, 'update_key_count', 'invalid'],
    [(parameters: Record<string, unknown>) => { parameters.nextKeyHashes = []; }, 'next_key_hash_count', 'invalid'],
  ] as const) await rejects(mutate((entry, index) => { if (index === 0) change(entry.parameters); }), code, status);
});

test('WebVH state projection rejects unsupported state members and crossed key references', async () => {
  for (const [change, code, status] of [
    [(state: WebvhState) => Object.assign(state, { service: [] }), 'feature_unsupported', 'unsupported'],
    [(state: WebvhState) => { state['@context'] = []; }, 'state_context', 'invalid'],
    [(state: WebvhState) => { state.id += ':other'; }, 'state_id', 'invalid'],
    [(state: WebvhState) => { state.verificationMethod = []; }, 'assertion_method_count', 'invalid'],
    [(state: WebvhState) => { state.verificationMethod[0].controller += ':other'; }, 'assertion_method_shape', 'invalid'],
    [(state: WebvhState) => Object.assign(state.verificationMethod[0].publicKeyJwk, { d: 'forbidden' }), 'assertion_key_encoding', 'invalid'],
    [(state: WebvhState) => { state.verificationMethod[0].id += 'other'; }, 'assertion_reference', 'invalid'],
    [(state: WebvhState) => { state.assertionMethod = []; }, 'assertion_reference', 'invalid'],
  ] as const) await rejects(mutate((entry, index) => { if (index === 0) change(entry.state); }), code, status);
});

test('WebVH genesis SCID and subsequent entry hash mismatches are rejected', async () => {
  await rejects(mutate((entry, index) => { if (index === 0) entry.versionTime = '2026-08-22T19:59:59Z'; }), 'scid_hash_mismatch');
  const altered = await sha256Multihash(bytes('a different hash'));
  await rejects(mutate((entry, index) => { if (index === 1) entry.versionId = `2-${altered}`; }), 'entry_hash_mismatch');
});

test('WebVH proof profile failures remain bounded and discard earlier authenticated versions', async () => {
  for (const [change, code, status] of [
    [(proof: Record<string, unknown>) => { delete proof.type; }, 'proof_members', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.type = 'Other'; }, 'proof_type', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.cryptosuite = 'other'; }, 'proof_cryptosuite', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.proofPurpose = 'authentication'; }, 'proof_purpose', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.created = '2026-08-22T20:00:01Z'; }, 'proof_created', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.verificationMethod = false; }, 'proof_unauthorized', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.proofValue = false; }, 'proof_value_encoding', 'invalid'],
    [(proof: Record<string, unknown>) => { proof.extra = false; }, 'feature_unsupported', 'unsupported'],
  ] as const) await rejects(mutate((entry, index) => { if (index === 2) change(entry.proof[0]); }), code, status);
  await rejects(mutate((entry, index) => { if (index === 2) entry.proof = []; }), 'proof_count');
  await rejects(mutate((entry, index) => { if (index === 2) {
    const signature = decodeProofValue(entry.proof[0].proofValue as string); signature[0] ^= 1;
    entry.proof[0].proofValue = `z${base58Encode(signature)}`;
  } }), 'proof_signature');
});

test('WebVH history snapshots mutable Buffer evidence before its first asynchronous operation', async () => {
  const raw = Buffer.from(fixture);
  const pending = verifyWebvh(did, raw, asOf);
  raw.fill(0);
  assert.equal((await pending).status, 'valid');
});

test('WebVH runtime crypto absence propagates as capability failure, never corrupted evidence', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    await assert.rejects(verifyWebvh(did, fixture, asOf), { kind: 'unsupported' });
  } finally { if (original) Object.defineProperty(globalThis, 'crypto', original); }
});

test('WebVH mid-check native digest failure stays indeterminate in both codec and proof hashing', async () => {
  const subtle = globalThis.crypto.subtle;
  const nativeDigest = subtle.digest.bind(subtle);
  const original = Object.getOwnPropertyDescriptor(subtle, 'digest');
  for (const target of ['z', '{"created"']) {
    let injected = false;
    try {
      Object.defineProperty(subtle, 'digest', { configurable: true, value: async (algorithm: AlgorithmIdentifier, data: BufferSource) => {
        const value = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
        if (!injected && new TextDecoder().decode(value).startsWith(target)) {
          injected = true;
          throw new DOMException('Test-only digest operation failure.', 'OperationError');
        }
        return nativeDigest(algorithm, data);
      } });
      await assert.rejects(verifyWebvh(did, fixture, asOf), { code: 'browser_crypto_failed', kind: 'unsupported' });
      assert.equal(injected, true, `Expected ${target} hashing branch to execute.`);
    } finally {
      if (original) Object.defineProperty(subtle, 'digest', original);
      else delete (subtle as Partial<SubtleCrypto>).digest;
    }
  }
});
