// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { decodeCanonical, encodeCanonical } from './canonical';
import { verifyBrowserPackage } from './engine';
import { VerifierError } from './errors';
import { parseCompactJws } from './jws';
import { inspectOpenTimestamp } from './opentimestamps';
import { canonicalize, decodeNumberFree, WebvhError } from './webvh-codec';
import { StrictZip } from './zip';

const encoder = new TextEncoder();
const hash = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
}
function mutate(input: Uint8Array, next: () => number, flips: number): Uint8Array {
  const output = new Uint8Array(input);
  const changed = new Set<number>();
  while (changed.size < flips) changed.add(next() % (input.length * 8));
  for (const bit of changed) output[bit >>> 3] ^= 1 << (bit & 7);
  return output;
}
function typedFailure(action: () => unknown): void {
  assert.throws(action, error => error instanceof VerifierError && ['invalid', 'input', 'unsupported'].includes(error.kind));
}

// Independent fixed 100-byte ZIP: one empty file "a", no CRC implementation or
// generated fixture dependency. It is a valid container, not an evidence bundle.
function tinyZip(): Uint8Array {
  const bytes = new Uint8Array(100);
  const view = new DataView(bytes.buffer);
  const u16 = (offset: number, value: number) => view.setUint16(offset, value, true);
  const u32 = (offset: number, value: number) => view.setUint32(offset, value, true);
  u32(0, 0x04034b50); u16(4, 10); u16(12, 33); u16(26, 1); bytes[30] = 97;
  u32(31, 0x02014b50); u16(35, 0x0314); u16(37, 10); u16(45, 33); u16(59, 1);
  u32(69, 0x81a40000); bytes[77] = 97;
  u32(78, 0x06054b50); u16(86, 1); u16(88, 1); u32(90, 47); u32(94, 31);
  return bytes;
}

test('every single-bit mutation and truncation of the tiny exact ZIP fails with a typed diagnostic', () => {
  const source = tinyZip();
  assert.deepEqual(StrictZip.parse(source).paths(), ['a']);
  for (let position = 0; position < source.length; position++) {
    typedFailure(() => StrictZip.parse(source.subarray(0, position)));
    for (let bit = 0; bit < 8; bit++) {
      const mutation = source.slice();
      mutation[position] ^= 1 << bit;
      typedFailure(() => StrictZip.parse(mutation));
    }
  }
  assert.deepEqual(StrictZip.parse(source).read('a'), new Uint8Array());
});

test('seeded short arbitrary and mutated containers never become evidence-verification success', async () => {
  const next = random(0xc01ed8);
  const metadata = { fileName: 'synthetic-mutation.zip', checkedAt: '2026-09-19T00:00:00Z' };
  const source = tinyZip();
  const corpus = [source, ...Array.from({ length: 96 }, () => mutate(source, next, 1 + next() % 6)),
    ...Array.from({ length: 96 }, () => Uint8Array.from({ length: next() % 257 }, () => next() & 255))];
  for (const bytes of corpus) {
    // Some coordinated mutations can still be valid ZIPs. None has the required
    // evidence inventory/profile, so parser acceptance must not become a pass.
    const result = await verifyBrowserPackage(bytes, {}, metadata);
    assert.ok(result.outcome === 'failed' || result.outcome === 'could_not_check');
    assert.notEqual(result.code, 'browser_profile_checks_complete');
    assert.notEqual(result.code, 'browser_runtime_diagnostic');
    assert.equal(result.packageSha256, hash(bytes));
    assert.ok(result.layers.length <= 3);
    assert.ok(result.message.length < 1024);
    assert.ok(result.layers.every(layer => layer.status !== 'matched'));
  }
});

test('seeded canonical JSON mutations either fail closed or round-trip to the exact accepted bytes', () => {
  const next = random(0x59cc823);
  let accepted = 0, rejected = 0;
  for (let iteration = 0; iteration < 192; iteration++) {
    const value = { a: [next() % 10000, Boolean(next() & 1), null], text: `value-${next()}-é-😀`, z: { key: String(next()) } };
    const source = encoder.encode(encodeCanonical(value));
    assert.equal(encodeCanonical(decodeCanonical(source)), new TextDecoder().decode(source));
    // Whitespace is always a deliberate profile violation, even valid JSON.
    typedFailure(() => decodeCanonical(new Uint8Array([...source, 32])));
    for (const mutation of [mutate(source, next, 1), mutate(source, next, 3)]) {
      try {
        const decoded = decodeCanonical(mutation);
        assert.deepEqual(encoder.encode(encodeCanonical(decoded)), mutation);
        accepted++;
      } catch (error) {
        assert.ok(error instanceof VerifierError, 'No native parser/stack exception may escape this bounded corpus.');
        rejected++;
      }
    }
  }
  assert.ok(accepted > 0 && rejected > 0, 'The deterministic corpus must exercise both parser paths.');
});

test('seeded number-free JSON mutations preserve the codec boundary and never pollute prototypes', () => {
  const next = random(0x82da20);
  let accepted = 0, rejected = 0;
  for (let iteration = 0; iteration < 192; iteration++) {
    const source = encoder.encode(canonicalize({ a: [true, false, null, {}], text: `v${next()}-é`, z: { ['__proto__']: String(next()) } }));
    for (const mutation of [source, mutate(source, next, 1 + next() % 3)]) {
      try {
        const normalized = canonicalize(decodeNumberFree(mutation));
        assert.equal(canonicalize(decodeNumberFree(normalized)), normalized);
        accepted++;
      } catch (error) {
        assert.ok(error instanceof WebvhError, 'This corpus has no PHP-specific leading-NUL property assignment.');
        rejected++;
      }
    }
  }
  assert.ok(accepted >= 192 && rejected > 0);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('short seeded JWS gibberish cannot bypass the exact compact envelope', () => {
  const next = random(0x3e0992);
  for (let iteration = 0; iteration < 384; iteration++) {
    const bytes = Uint8Array.from({ length: next() % 512 }, () => next() & 255);
    typedFailure(() => parseCompactJws(bytes));
  }
});

test('seeded detached-proof mutations have typed failures or bounded structural-only results', async () => {
  const digest = 'a'.repeat(64);
  const source = Buffer.concat([
    Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex'),
    Buffer.from([1, 8]), Buffer.from(digest, 'hex'),
    Buffer.from('000588960d73d719010101', 'hex'), // Bitcoin height 1; no trusted-time authority.
  ]);
  const next = random(0x75ee2);
  let accepted = 0, rejected = 0;
  for (let iteration = 0; iteration < 192; iteration++) {
    const bytes = mutate(source, next, 1 + next() % 3);
    try {
      const result = await inspectOpenTimestamp(bytes, digest);
      assert.equal(result.fileDigest, digest);
      assert.equal(result.proofSha256, hash(bytes));
      assert.ok(result.pending.length + result.bitcoin.length + result.unknownCount <= 1);
      assert.deepEqual(Object.keys(result).sort(), ['bitcoin', 'fileDigest', 'pending', 'proofSha256', 'unknownCount']);
      accepted++;
    } catch (error) {
      assert.ok(error instanceof VerifierError, 'No unclassified binary-parser exception may escape.');
      assert.ok(error.kind === 'invalid' || error.kind === 'unsupported');
      rejected++;
    }
  }
  assert.ok(accepted > 0 && rejected > 0);
});
