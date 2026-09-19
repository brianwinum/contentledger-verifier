// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEd25519Verifier, verifyEd25519 } from './ed25519';
import { ED25519_SMALL_ORDER_Y, ED25519_VECTORS, ed25519VectorBytes as bytes } from './ed25519-vectors';
import { VerifierError } from './errors';

const subtle = globalThis.crypto.subtle;
const first = ED25519_VECTORS[0];
const sample = () => [bytes(first.signature), bytes(first.message), bytes(first.publicKey)] as const;
type Backend = Parameters<typeof createEd25519Verifier>[0];
function backend(overrides: Record<string, unknown> = {}): Backend {
  return { importKey: subtle.importKey.bind(subtle), verify: subtle.verify.bind(subtle), ...overrides } as Backend;
}
function failure(code: string): (failure: unknown) => boolean {
  return (value) => value instanceof VerifierError && value.code === code && value.kind === 'unsupported'
    && !value.message.includes('private runtime detail');
}

for (const vector of ED25519_VECTORS) {
  test(`qualified Ed25519 agrees with ${vector.name}`, async () => {
    assert.equal(await verifyEd25519(bytes(vector.signature), bytes(vector.message), bytes(vector.publicKey)), vector.valid);
  });
}

test('Ed25519 rejects changed messages, signature bytes and another valid public key', async () => {
  const [signature, message, publicKey] = sample();
  assert.equal(await verifyEd25519(signature, new Uint8Array([0]), publicKey), false);
  assert.equal(await verifyEd25519(signature, message, bytes(ED25519_VECTORS[1].publicKey)), false);
  signature[0] ^= 1;
  assert.equal(await verifyEd25519(signature, message, publicKey), false);
});

test('Ed25519 enforces exact key and signature lengths before native operations', async () => {
  const verify = createEd25519Verifier(undefined);
  const [signature, message, publicKey] = sample();
  for (const length of [0, 31, 33]) assert.equal(await verify(signature, message, new Uint8Array(length)), false);
  for (const length of [0, 32, 63, 65]) assert.equal(await verify(new Uint8Array(length), message, publicKey), false);
});

test('Ed25519 rejects all small-order encodings, sign bits and noncanonical y in A and R', async () => {
  // No native backend is present. These failures must be decided by byte guards.
  const verify = createEd25519Verifier(undefined);
  const [signature, message, publicKey] = sample();
  const values = [...ED25519_SMALL_ORDER_Y, 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + '7f', 'ff'.repeat(31) + '7f'];
  for (const value of values) {
    for (const sign of [0, 128]) {
      const point = bytes(value);
      point[31] = (point[31] & 127) | sign;
      assert.equal(await verify(signature, message, point), false, `A ${value} ${sign}`);
      const altered = new Uint8Array(signature);
      altered.set(point);
      assert.equal(await verify(altered, message, publicKey), false, `R ${value} ${sign}`);
    }
  }
});

test('Ed25519 rejects S equal to or greater than L, including S+L malleability', async () => {
  const verify = createEd25519Verifier(undefined);
  const [signature, message, publicKey] = sample();
  const order = bytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
  const added = new Uint8Array(signature.subarray(32));
  let carry = 0;
  for (let i = 0; i < 32; i += 1) {
    const total = added[i] + order[i] + carry;
    added[i] = total & 255;
    carry = total >>> 8;
  }
  for (const scalar of [order, added, new Uint8Array(32).fill(255)]) {
    const altered = new Uint8Array(signature);
    altered.set(scalar, 32);
    assert.equal(await verify(altered, message, publicKey), false);
  }
});

test('Ed25519 reports unsupported when native operations are absent', async () => {
  await assert.rejects(createEd25519Verifier(undefined)(...sample()), failure('browser_ed25519_unavailable'));
  await assert.rejects(createEd25519Verifier({} as Backend)(...sample()), failure('browser_ed25519_unavailable'));
});

test('Ed25519 reports algorithm NotSupportedError as unavailable', async () => {
  const verify = createEd25519Verifier(backend({ importKey: async () => { throw new DOMException('private runtime detail', 'NotSupportedError'); } }));
  await assert.rejects(verify(...sample()), failure('browser_ed25519_unavailable'));
});

test('Ed25519 rejects a backend which always accepts or always rejects', async () => {
  for (const value of [true, false]) {
    await assert.rejects(createEd25519Verifier(backend({ verify: async () => value }))(...sample()), failure('browser_ed25519_unqualified'));
  }
});

test('Ed25519 qualification detects wrong cofactor behavior in either direction', async () => {
  for (const vectorIndex of [5, 6]) {
    const vector = ED25519_VECTORS[vectorIndex];
    const native = subtle.verify.bind(subtle);
    const verify = createEd25519Verifier(backend({ verify: async (...args: Parameters<SubtleCrypto['verify']>) => {
      const signature = new Uint8Array(args[2] as ArrayBuffer);
      if (signature[0] === bytes(vector.signature)[0]) return !vector.valid;
      return native(...args);
    } }));
    await assert.rejects(verify(...sample()), failure('browser_ed25519_unqualified'));
  }
});

test('Ed25519 qualification exceptions are unsupported and redacted', async () => {
  const verify = createEd25519Verifier(backend({ verify: async () => { throw new Error('private runtime detail'); } }));
  await assert.rejects(verify(...sample()), failure('browser_ed25519_unqualified'));
});

test('Ed25519 shares one in-flight qualification and caches a failed qualification', async () => {
  let imports = 0;
  const verify = createEd25519Verifier(backend({ importKey: async () => { imports += 1; throw new Error('private runtime detail'); } }));
  await Promise.all([assert.rejects(verify(...sample()), failure('browser_ed25519_unqualified')), assert.rejects(verify(...sample()), failure('browser_ed25519_unqualified'))]);
  await assert.rejects(verify(...sample()), failure('browser_ed25519_unqualified'));
  assert.equal(imports, 1);
});

test('Ed25519 successful qualification is cached without caching evidence decisions', async () => {
  let calls = 0;
  const native = subtle.verify.bind(subtle);
  const verify = createEd25519Verifier(backend({ verify: async (...args: Parameters<SubtleCrypto['verify']>) => { calls += 1; return native(...args); } }));
  assert.equal(await verify(...sample()), true);
  const initialCalls = calls;
  assert.ok(initialCalls > 1);
  assert.equal(await verify(...sample()), true);
  assert.equal(calls, initialCalls + 1);
  const [signature, , publicKey] = sample();
  assert.equal(await verify(signature, new Uint8Array([0]), publicKey), false);
  assert.equal(calls, initialCalls + 2);
});

test('Ed25519 runtime import or verification exceptions cannot become invalid evidence', async () => {
  for (const operation of ['importKey', 'verify'] as const) {
    let broken = false;
    const native = subtle[operation].bind(subtle) as (...args: unknown[]) => Promise<unknown>;
    const verify = createEd25519Verifier(backend({ [operation]: async (...args: unknown[]) => {
      if (broken) throw new Error('private runtime detail');
      return native(...args);
    } }));
    assert.equal(await verify(...sample()), true);
    broken = true;
    await assert.rejects(verify(...sample()), failure('browser_ed25519_runtime'));
  }
});

test('Ed25519 rejects a non-boolean native result rather than accepting truthy data', async () => {
  let broken = false;
  const native = subtle.verify.bind(subtle);
  const verify = createEd25519Verifier(backend({ verify: async (...args: Parameters<SubtleCrypto['verify']>) => broken ? 'true' : native(...args) }));
  assert.equal(await verify(...sample()), true);
  broken = true;
  await assert.rejects(verify(...sample()), failure('browser_ed25519_runtime'));
});

test('Ed25519 snapshots Buffer inputs before awaiting runtime qualification', async () => {
  const vector = ED25519_VECTORS[1];
  const signature = Buffer.from(vector.signature, 'hex');
  const message = Buffer.from(vector.message, 'hex');
  const publicKey = Buffer.from(vector.publicKey, 'hex');
  const verify = createEd25519Verifier(backend());
  const result = verify(signature, message, publicKey);
  signature.fill(0); message.fill(0); publicKey.fill(0);
  assert.equal(await result, true);
});
