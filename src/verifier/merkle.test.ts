// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inclusionPath, inclusionSides, MAX_LEAVES, merkleRoot, nodeHash, prefixRoots, validateLeaf, verifyConsistency } from './merkle';
import { VerifierError } from './errors';

const hash = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
const node = (left: string, right: string): string => hash(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
const hashes = (count: number): string[] => Array.from({ length: count }, (_, i) => hash(Buffer.concat([Buffer.from([0]), Buffer.from(`leaf ${i}`)])));
const uuid = '12345678-1234-4123-8123-123456789abc';
const manifest = 'a'.repeat(64);
const leaf = () => ({ entryId: `urn:uuid:${uuid}`, manifestDigest: { algorithm: 'sha-256', value: manifest } });
const leafJson = `{"entryId":"urn:uuid:${uuid}","manifestDigest":{"algorithm":"sha-256","value":"${manifest}"}}`;
const invalid = (code: string) => (error: unknown): boolean => error instanceof VerifierError && error.code === code && error.kind === 'invalid';

// Independent synchronous Node/OpenSSL oracle and RFC6962 recursive proof
// construction. No production tree/proof helper is used to construct expected
// roots, proof hashes, or cryptographic checks.
function root(leaves: readonly string[]): string {
  if (leaves.length === 1) return leaves[0];
  const split = 2 ** Math.floor(Math.log2(leaves.length - 1));
  return node(root(leaves.slice(0, split)), root(leaves.slice(split)));
}
function proof(oldCount: number, leaves: readonly string[], complete = true): string[] {
  if (oldCount === leaves.length) return complete ? [] : [root(leaves)];
  const split = 2 ** Math.floor(Math.log2(leaves.length - 1));
  return oldCount <= split
    ? [...proof(oldCount, leaves.slice(0, split), complete), root(leaves.slice(split))]
    : [...proof(oldCount - split, leaves.slice(split), false), root(leaves.slice(0, split))];
}

test('Merkle leaf hash has exact canonical JSON and the leaf domain separator', async () => {
  const expected = hash(Buffer.concat([Buffer.from([0]), Buffer.from(leafJson)]));
  assert.deepEqual(await validateLeaf(leaf()), { hash: expected, uuid, manifest });
  assert.notEqual(expected, hash(leafJson));
  assert.notEqual(expected, hash(Buffer.concat([Buffer.from([1]), Buffer.from(leafJson)])));
  assert.deepEqual(await validateLeaf({ manifestDigest: { value: manifest, algorithm: 'sha-256' }, entryId: `urn:uuid:${uuid}` }), { hash: expected, uuid, manifest });
});

test('Merkle leaf validation refuses malformed profiles and UUIDs', async () => {
  for (const value of [null, true, [], {}, { ...leaf(), extra: true }, { ...leaf(), entryId: uuid }, { ...leaf(), entryId: leaf().entryId + '\n' }, { ...leaf(), entryId: leaf().entryId.replace('-4123-', '-6123-') }]) {
    await assert.rejects(validateLeaf(value), invalid('leaf_profile'));
  }
});

test('Merkle leaf validation refuses wrong or inexact digest profiles', async () => {
  for (const value of [null, [], {}, { algorithm: 'sha256', value: manifest }, { algorithm: 'sha-256', value: manifest.toUpperCase() },
    { algorithm: 'sha-256', value: manifest + '\n' }, { algorithm: 'sha-256', value: manifest, extra: null }]) {
    await assert.rejects(validateLeaf({ ...leaf(), manifestDigest: value }), invalid('leaf_digest'));
  }
});

test('Merkle node hashing uses binary hashes, order and a different domain separator', async () => {
  const [left, right] = hashes(2);
  assert.equal(await nodeHash(left, right), node(left, right));
  assert.notEqual(await nodeHash(left, right), await nodeHash(right, left));
  assert.notEqual(await nodeHash(left, right), hash(left + right));
  assert.equal(await nodeHash(left.toUpperCase(), right), node(left, right));
  assert.equal(await nodeHash('', ''), hash(Buffer.from([1])));
  for (const value of ['0', 'gg', left + '\n', ' ']) assert.equal(await nodeHash(value, right), '');
});

test('Merkle roots match independent RFC6962 trees across powers of two and odd sizes', async () => {
  const leaves = hashes(65);
  for (let count = 1; count <= leaves.length; count += 1) assert.equal(await merkleRoot(leaves.slice(0, count)), root(leaves.slice(0, count)), `size ${count}`);
  const three = leaves.slice(0, 3);
  assert.equal(await merkleRoot(three), node(node(three[0], three[1]), three[2]));
  assert.notEqual(await merkleRoot(three), node(node(three[0], three[1]), node(three[2], three[2])));
});

test('Merkle root input must be a nonempty bounded list of exact lowercase hashes', async () => {
  await assert.rejects(merkleRoot([]), invalid('leaf_inventory_count'));
  await assert.rejects(merkleRoot(new Array(MAX_LEAVES + 1).fill(manifest)), invalid('leaf_inventory_count'));
  for (const value of ['', manifest.toUpperCase(), manifest + '\n', 'g'.repeat(64)]) await assert.rejects(merkleRoot([value]), invalid('leaf_inventory_hash'));
  await assert.rejects(merkleRoot(new Array(1)), invalid('leaf_inventory_hash'));
});

test('Merkle roots and prefix computation accept the exact 10000-leaf upper boundary', async () => {
  const leaves = new Array(MAX_LEAVES).fill(hash('bounded maximum')) as string[];
  const expected = root(leaves);
  assert.equal(await merkleRoot(leaves), expected);
  const prefixes = await prefixRoots(leaves, [1, 8192, MAX_LEAVES]);
  assert.equal(prefixes.get(1), leaves[0]);
  assert.equal(prefixes.get(8192), root(leaves.slice(0, 8192)));
  assert.equal(prefixes.get(MAX_LEAVES), expected);
  for (const index of [0, 8191, 8192, MAX_LEAVES - 1]) assert.ok(inclusionSides(index, 0, MAX_LEAVES).length <= 14);
});

test('Merkle prefix frontier produces only requested roots in ascending count order', async () => {
  const leaves = hashes(65);
  const requested = [65, 17, 3, 2, 1, 8, 32, 3, 0, -1, 100];
  const actual = await prefixRoots(leaves, requested);
  const expectedCounts = [1, 2, 3, 8, 17, 32, 65];
  assert.deepEqual([...actual.keys()], expectedCounts);
  for (const count of expectedCounts) assert.equal(actual.get(count), root(leaves.slice(0, count)));
  assert.deepEqual(await prefixRoots([], [0, 1]), new Map());
  assert.deepEqual(await prefixRoots(leaves, []), new Map());
  await assert.rejects(prefixRoots(['invalid'], []), invalid('leaf_inventory_hash'));
  await assert.rejects(prefixRoots(new Array(MAX_LEAVES + 1).fill(manifest), []), invalid('leaf_inventory_count'));
});

test('Merkle inclusion paths reconstruct every leaf in odd and even trees with exact topology', async () => {
  for (const count of [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33]) {
    const leaves = hashes(count);
    for (let index = 0; index < count; index += 1) {
      const path = await inclusionPath(index, 0, count, leaves);
      assert.deepEqual(path.map(step => step.side), inclusionSides(index, 0, count));
      let reconstructed = leaves[index];
      for (const step of path) reconstructed = step.side === 'left' ? node(step.hash, reconstructed) : node(reconstructed, step.hash);
      assert.equal(reconstructed, root(leaves), `${index}/${count}`);
    }
  }
  assert.deepEqual(inclusionSides(0, 0, 3), ['right', 'right']);
  assert.deepEqual(inclusionSides(1, 0, 3), ['left', 'right']);
  assert.deepEqual(inclusionSides(2, 0, 3), ['left']);
});

test('Merkle inclusion paths preserve absolute indexes for a subtree range', async () => {
  const leaves = hashes(12);
  for (let index = 4; index < 11; index += 1) {
    const path = await inclusionPath(index, 4, 7, leaves);
    assert.deepEqual(path.map(step => step.side), inclusionSides(index - 4, 0, 7));
    let current = leaves[index];
    for (const step of path) current = step.side === 'left' ? node(step.hash, current) : node(current, step.hash);
    assert.equal(current, root(leaves.slice(4, 11)));
  }
});

test('Merkle inclusion caching bounds 1000 paths to one tree worth of native hashing', async context => {
  const leaves = hashes(1000);
  const expected = root(leaves);
  const native = crypto.subtle.digest.bind(crypto.subtle);
  let operations = 0;
  context.mock.method(crypto.subtle, 'digest', (...args: Parameters<SubtleCrypto['digest']>) => { operations += 1; return native(...args); });
  for (let index = 0; index < leaves.length; index += 1) {
    const path = await inclusionPath(index, 0, leaves.length, leaves);
    let current = leaves[index];
    for (const step of path) current = step.side === 'left' ? node(step.hash, current) : node(current, step.hash);
    assert.equal(current, expected);
  }
  // Every internal subtree except the whole root is needed exactly once.
  assert.equal(operations, leaves.length - 2);
  const afterFirstPass = operations;
  for (let index = 0; index < leaves.length; index += 1) await inclusionPath(index, 0, leaves.length, leaves);
  assert.equal(operations, afterFirstPass);
});

test('Merkle inclusion cache invalidates on mutation, range change and different array identity', async context => {
  const leaves = hashes(16);
  const native = crypto.subtle.digest.bind(crypto.subtle);
  let operations = 0;
  context.mock.method(crypto.subtle, 'digest', (...args: Parameters<SubtleCrypto['digest']>) => { operations += 1; return native(...args); });
  const initial = await inclusionPath(0, 0, 16, leaves);
  let before = operations;
  assert.deepEqual(await inclusionPath(0, 0, 16, leaves), initial);
  assert.equal(operations, before);
  leaves[15] = manifest;
  const changed = await inclusionPath(0, 0, 16, leaves);
  assert.ok(operations > before);
  assert.notDeepEqual(changed, initial);
  let current = leaves[0];
  for (const step of changed) current = step.side === 'left' ? node(step.hash, current) : node(current, step.hash);
  assert.equal(current, root(leaves));
  before = operations;
  assert.deepEqual(await inclusionPath(0, 0, 16, [...leaves]), changed);
  assert.ok(operations > before, 'Equal contents in a different array must not use a global content cache.');
  await inclusionPath(8, 8, 8, leaves);
  before = operations;
  assert.deepEqual(await inclusionPath(0, 0, 16, leaves), changed);
  assert.ok(operations > before, 'Changing a range replaces its former subtree cache.');
  leaves[5] = 'invalid';
  await assert.rejects(inclusionPath(0, 0, 16, leaves), invalid('leaf_inventory_hash'));
});

test('Merkle inclusion cache shares in-flight subtrees and preserves snapshots across mutation', async context => {
  const leaves = hashes(32);
  const native = crypto.subtle.digest.bind(crypto.subtle);
  let operations = 0;
  context.mock.method(crypto.subtle, 'digest', (...args: Parameters<SubtleCrypto['digest']>) => { operations += 1; return native(...args); });
  const jobs = leaves.map((_, index) => inclusionPath(index, 0, leaves.length, leaves));
  const results = await Promise.all(jobs);
  assert.equal(operations, leaves.length - 2);
  const oldPath = results[0];
  const beforeMutation = inclusionPath(0, 0, 32, leaves);
  leaves[31] = manifest;
  const afterMutation = inclusionPath(0, 0, 32, leaves);
  assert.deepEqual(await beforeMutation, oldPath);
  assert.notDeepEqual(await afterMutation, oldPath);
});

test('Merkle inclusion exports reject invalid ranges before recursion', async () => {
  for (const [index, start, length] of [[0, 0, 0], [-1, 0, 2], [2, 0, 2], [0, -1, 2], [0, 0, MAX_LEAVES + 1], [9999, 9999, 2], [1.5, 0, 2], [0, 0, Infinity]]) {
    assert.throws(() => inclusionSides(index, start, length), invalid('inclusion_tree'));
    await assert.rejects(inclusionPath(index, start, length, hashes(3)), invalid('inclusion_tree'));
  }
  await assert.rejects(inclusionPath(2, 0, 3, hashes(2)), invalid('inclusion_tree'));
  await assert.rejects(inclusionPath(0, 0, 2, ['invalid', ...hashes(1)]), invalid('leaf_inventory_hash'));
});

test('Merkle consistency accepts independent append proofs for every prefix through size 33', async () => {
  const leaves = hashes(33);
  for (let newCount = 1; newCount <= leaves.length; newCount += 1) {
    const current = leaves.slice(0, newCount);
    for (let oldCount = 1; oldCount <= newCount; oldCount += 1) {
      assert.equal(await verifyConsistency(oldCount, root(current.slice(0, oldCount)), newCount, root(current), proof(oldCount, current)), true, `${oldCount}->${newCount}`);
    }
  }
});

test('Merkle consistency rejects invalid sizes, roots and overlong or malformed proofs', async () => {
  for (const [oldCount, newCount] of [[0, 1], [-1, 2], [3, 2], [1, MAX_LEAVES + 1], [1.5, 3], [1, NaN]]) {
    assert.equal(await verifyConsistency(oldCount, manifest, newCount, manifest, []), false);
  }
  for (const bad of ['', manifest.toUpperCase(), manifest + '\n']) {
    assert.equal(await verifyConsistency(1, bad, 1, manifest, []), false);
    assert.equal(await verifyConsistency(1, manifest, 1, bad, []), false);
    assert.equal(await verifyConsistency(1, manifest, 2, manifest, [bad]), false);
  }
  assert.equal(await verifyConsistency(1, manifest, 2, manifest, new Array(33).fill(manifest)), false);
  assert.equal(await verifyConsistency(1, manifest, 2, manifest, new Array(1)), false);
});

test('Merkle consistency requires equal roots and empty proof for equal-size checkpoints', async () => {
  const [first, second] = hashes(2);
  assert.equal(await verifyConsistency(4, first, 4, first, []), true);
  assert.equal(await verifyConsistency(4, first, 4, second, []), false);
  assert.equal(await verifyConsistency(4, first, 4, first, [first]), false);
});

test('Merkle consistency rejects truncated, extra, reordered and substituted proof hashes', async () => {
  const leaves = hashes(17);
  for (const oldCount of [1, 2, 3, 5, 8, 9, 15, 16]) {
    const path = proof(oldCount, leaves);
    const verify = (candidate: string[]) => verifyConsistency(oldCount, root(leaves.slice(0, oldCount)), leaves.length, root(leaves), candidate);
    assert.equal(await verify(path.slice(0, -1)), false, `truncated ${oldCount}`);
    assert.equal(await verify([...path, manifest]), false, `extra ${oldCount}`);
    assert.equal(await verify([manifest, ...path.slice(1)]), false, `substituted ${oldCount}`);
    if (path.length > 1) assert.equal(await verify([...path].reverse()), false, `reordered ${oldCount}`);
  }
});

test('Merkle helpers snapshot mutable documents and arrays before native hashing', async () => {
  const document = leaf();
  const leafResult = validateLeaf(document);
  document.entryId = 'changed'; document.manifestDigest.value = 'changed';
  assert.deepEqual(await leafResult, { hash: hash(Buffer.concat([Buffer.from([0]), Buffer.from(leafJson)])), uuid, manifest });
  const original = hashes(7);
  const rootInput = [...original];
  const rootResult = merkleRoot(rootInput); rootInput.fill(manifest);
  assert.equal(await rootResult, root(original));
  const prefixInput = [...original]; const requested = [3, 7];
  const prefixResult = prefixRoots(prefixInput, requested); prefixInput.fill(manifest); requested.fill(1);
  assert.deepEqual([...await prefixResult], [[3, root(original.slice(0, 3))], [7, root(original)]]);
  const pathInput = [...original];
  const pathResult = inclusionPath(3, 0, 7, pathInput); pathInput.fill(manifest);
  assert.deepEqual(await pathResult, await inclusionPath(3, 0, 7, original));
  const path = proof(3, original);
  const consistency = verifyConsistency(3, root(original.slice(0, 3)), 7, root(original), path); path.fill(manifest);
  assert.equal(await consistency, true);
});

test('Merkle native digest failures are unsupported capability failures, not invalid evidence', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle: {
      digest: async () => { throw new DOMException('private digest details', 'OperationError'); },
    } } });
    const capability = (error: unknown): boolean => error instanceof VerifierError && error.kind === 'unsupported'
      && error.code === 'browser_crypto_failed' && !error.message.includes('private digest details');
    await assert.rejects(validateLeaf(leaf()), capability);
    await assert.rejects(merkleRoot(hashes(2)), capability);
    await assert.rejects(prefixRoots(hashes(2), [2]), capability);
    await assert.rejects(inclusionPath(2, 0, 3, hashes(3)), capability);
    const leaves = hashes(3);
    await assert.rejects(verifyConsistency(1, root(leaves.slice(0, 1)), 3, root(leaves), proof(1, leaves)), capability);
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    await assert.rejects(nodeHash(manifest, manifest), error => error instanceof VerifierError && error.kind === 'unsupported' && error.code === 'browser_crypto_unavailable');
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});
