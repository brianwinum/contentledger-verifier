// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fixtureCanonical, fixtureEntries, fixtureZip, refreshInventory } from '../../tests/browser-test-support';
import { verifyBrowserPackage } from './engine';
import { VerifierError } from './errors';
import type { LeafInventoryReference } from './graph';
import type { LeafInventory } from './transparency';
import { inspectInclusionUnanchored, verifyLeafInventorySeries } from './transparency-graph';

const hash = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
const canonical = (value: unknown): Buffer => Buffer.from(fixtureCanonical(value));
const node = (left: string, right: string): string => hash(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
const leafHash = (value: unknown): string => hash(Buffer.concat([Buffer.from([0]), canonical(value)]));
const first = 'a'.repeat(64), second = 'b'.repeat(64), third = 'c'.repeat(64);
const uuid = '12345678-1234-4123-8123-123456789abc';
const manifest = 'd'.repeat(64);
const metadata = { fileName: 'synthetic-transparency.zip', checkedAt: '2026-09-19T00:00:00.000Z' };
const invalid = (code: string) => (error: unknown): boolean => error instanceof VerifierError && error.kind === 'invalid' && error.code === code;
const reference = (checkpointSha256: string): LeafInventoryReference => ({ checkpointSha256, path: `transparency/leaf-inventory/${checkpointSha256}.json` });
const inventory = (hashes: string[]): LeafInventory => ({ hashes, leaves: [], records: Object.create(null) });

function inclusion() {
  const leaf = { entryId: `urn:uuid:${uuid}`, manifestDigest: { algorithm: 'sha-256', value: manifest } };
  const digest = leafHash(leaf);
  return { checkpointSha256: first, format: 'WP ContentLedger Transparency Inclusion Proof', version: '1.0',
    leaf, leafHash: digest, leafIndex: 0, path: [{ hash: second, side: 'right' }, { hash: third, side: 'right' }],
    tree: { algorithm: 'rfc6962-sha256-v1', leafCount: 3, rootHash: node(node(digest, second), third) } };
}

test('leaf inventory series accepts ascending selected checkpoints and immutable extensions', () => {
  const inventories = new Map([[first, inventory([first])], [second, inventory([first, second])], [third, inventory([first, second, third])]]);
  const snapshot = JSON.stringify([...inventories]);
  assert.doesNotThrow(() => verifyLeafInventorySeries([reference(first), reference(second), reference(third)], inventories, [first, second, third]));
  assert.doesNotThrow(() => verifyLeafInventorySeries([reference(first), reference(third)], inventories, [first, second, third]));
  assert.doesNotThrow(() => verifyLeafInventorySeries([], inventories, [first, second, third]));
  assert.equal(JSON.stringify([...inventories]), snapshot);
  for (const value of inventories.values()) assert.equal(Object.getPrototypeOf(value.records), null);
  inventories.set(third, inventory([first, second]));
  assert.doesNotThrow(() => verifyLeafInventorySeries([reference(second), reference(third)], inventories, [first, second, third]));
});

test('leaf inventory series rejects reordering, duplicates, unknown checkpoints and missing inventories', () => {
  const inventories = new Map([[first, inventory([first])], [second, inventory([first, second])]]);
  for (const refs of [[reference(second), reference(first)], [reference(first), reference(first)], [reference(third)]]) {
    assert.throws(() => verifyLeafInventorySeries(refs, inventories, [first, second]), invalid('leaf_inventory_order'));
  }
  assert.throws(() => verifyLeafInventorySeries([reference(second)], new Map(), [first, second]), invalid('leaf_inventory_order'));
});

test('leaf inventory series rejects replacement, reordering and truncation of a prior prefix', () => {
  for (const next of [[first], [second, first], [first, third], [first, third, second]]) {
    const inventories = new Map([[first, inventory([first, second])], [second, inventory(next)]]);
    assert.throws(() => verifyLeafInventorySeries([reference(first), reference(second)], inventories, [first, second]), invalid('leaf_inventory_fork'));
  }
});

test('unanchored inclusion inspection checks math but returns no checkpoint authority', async () => {
  const proof = inclusion();
  assert.equal(await inspectInclusionUnanchored(canonical(proof), first, uuid, new Map([[uuid, manifest]])), undefined);
  // A mathematically self-consistent tree can name any checkpoint hash here.
  // This is intentionally inspection only, without a trusted checkpoint map.
  proof.checkpointSha256 = third;
  proof.path[0].hash = manifest;
  proof.tree.rootHash = node(node(proof.leafHash, manifest), third);
  assert.equal(await inspectInclusionUnanchored(canonical(proof), third, uuid, new Map([[uuid, manifest]])), undefined);
});

test('unanchored inclusion inspection requires exact topology even when altered math matches', async () => {
  const wrongSide = inclusion();
  wrongSide.path[1].side = 'left';
  wrongSide.tree.rootHash = node(third, node(wrongSide.leafHash, second));
  await assert.rejects(inspectInclusionUnanchored(canonical(wrongSide), first, uuid, new Map([[uuid, manifest]])), invalid('inclusion_topology'));
  const extra = inclusion();
  extra.path.push({ hash: manifest, side: 'right' });
  extra.tree.rootHash = node(extra.tree.rootHash, manifest);
  await assert.rejects(inspectInclusionUnanchored(canonical(extra), first, uuid, new Map([[uuid, manifest]])), invalid('inclusion_topology'));
  const wrongRoot = inclusion(); wrongRoot.tree.rootHash = manifest;
  await assert.rejects(inspectInclusionUnanchored(canonical(wrongRoot), first, uuid, new Map([[uuid, manifest]])), invalid('inclusion_topology'));
});

test('unanchored inclusion inspection still rejects bad leaf, graph, count and path bindings', async () => {
  const proof = inclusion();
  await assert.rejects(inspectInclusionUnanchored(canonical(proof), second, uuid, new Map([[uuid, manifest]])), invalid('inclusion_profile'));
  await assert.rejects(inspectInclusionUnanchored(canonical(proof), first, uuid, new Map([[uuid, first]])), invalid('inclusion_leaf'));
  const count = inclusion(); count.tree.leafCount = 10001;
  await assert.rejects(inspectInclusionUnanchored(canonical(count), first, uuid, new Map([[uuid, manifest]])), invalid('inclusion_tree'));
  const path = inclusion(); path.path[0].side = 'up';
  await assert.rejects(inspectInclusionUnanchored(canonical(path), first, uuid, new Map([[uuid, manifest]])), invalid('inclusion_path'));
});

test('engine rejects inventory-consistent invalid inclusion without a valid transparency claim', async () => {
  const entries = fixtureEntries(readFileSync(new URL('../../tests/fixtures/record.zip', import.meta.url)));
  const bundle = JSON.parse(entries.get('bundle.json')!.toString());
  const path = bundle.records[0].inclusionProofPaths[0];
  const proof = JSON.parse(entries.get(path)!.toString());
  proof.path[0].hash = first;
  entries.set(path, canonical(proof)); refreshInventory(entries);
  const result = await verifyBrowserPackage(fixtureZip(entries), {}, metadata);
  assert.equal(result.outcome, 'failed');
  assert.equal(result.code, 'inclusion_checkpoint_binding');
  assert.ok(result.layers.some(layer => layer.layer === 'checkpoint_identity' && layer.status === 'valid'));
  assert.equal(result.layers.some(layer => layer.layer === 'transparency' && layer.status === 'valid'), false);
});

test('engine unsupported-manifest inspection cannot turn an arbitrary root into authenticated transparency', async () => {
  const entries = fixtureEntries(readFileSync(new URL('../../tests/fixtures/record.zip', import.meta.url)));
  const bundle = JSON.parse(entries.get('bundle.json')!.toString());
  const record = bundle.records[0];
  const document = JSON.parse(entries.get(record.manifestPath)!.toString());
  document.manifestVersion = '99.0';
  const documentBytes = canonical(document);
  record.manifestSha256 = hash(documentBytes);
  entries.set(record.manifestPath, documentBytes);
  const path = record.inclusionProofPaths[0];
  const proof = JSON.parse(entries.get(path)!.toString());
  proof.leaf.manifestDigest.value = record.manifestSha256;
  proof.leafHash = leafHash(proof.leaf);
  let root = proof.leafHash;
  for (const step of proof.path) root = step.side === 'left' ? node(step.hash, root) : node(root, step.hash);
  proof.tree.rootHash = root;
  const signedCheckpoint = JSON.parse(entries.get(bundle.checkpoints[0].documentPath)!.toString());
  assert.notEqual(proof.tree.rootHash, signedCheckpoint.tree.rootHash);
  entries.set(path, canonical(proof)); entries.set('bundle.json', canonical(bundle)); refreshInventory(entries);
  const result = await verifyBrowserPackage(fixtureZip(entries), {}, metadata);
  assert.equal(result.outcome, 'could_not_check');
  assert.equal(result.code, 'browser_profile_unsupported');
  assert.ok(result.layers.some(layer => layer.layer === 'manifests' && layer.status === 'unsupported'));
  assert.ok(result.layers.some(layer => layer.layer === 'transparency' && layer.status === 'not_checked' && layer.code === 'transparency_manifest_dependency'));
  assert.equal(result.layers.some(layer => ['signature_integrity', 'signing_authorization', 'transparency'].includes(layer.layer) && layer.status === 'valid'), false);
});

test('engine completion requires scope closure and remains self-contained without external values', async () => {
  const bytes = readFileSync(new URL('../../tests/fixtures/record.zip', import.meta.url));
  const result = await verifyBrowserPackage(bytes, {}, metadata);
  assert.equal(result.outcome, 'passed_with_limitations');
  assert.equal(result.code, 'browser_profile_checks_complete');
  assert.ok(result.layers.some(layer => layer.layer === 'transparency' && layer.status === 'valid'));
  assert.ok(result.layers.some(layer => layer.layer === 'scope' && layer.status === 'valid'));
  assert.ok(result.layers.some(layer => layer.layer === 'external_anchor' && layer.status === 'self_contained_only'));
  for (const name of ['timestamps', 'archive_references']) {
    assert.ok(result.layers.some(layer => layer.layer === name && layer.status === 'not_present'));
  }
});

test('engine mid-transparency hashing failure remains indeterminate and redacted', async context => {
  const native = crypto.subtle.digest.bind(crypto.subtle);
  context.mock.method(crypto.subtle, 'digest', (...args: Parameters<SubtleCrypto['digest']>) => {
    const bytes = ArrayBuffer.isView(args[1]) ? new Uint8Array(args[1].buffer, args[1].byteOffset, args[1].byteLength) : new Uint8Array(args[1]);
    if (bytes[0] === 0) return Promise.reject(new Error('private Merkle runtime failure'));
    return native(...args);
  });
  const result = await verifyBrowserPackage(readFileSync(new URL('../../tests/fixtures/record.zip', import.meta.url)), {}, metadata);
  assert.equal(result.outcome, 'could_not_check');
  assert.equal(result.code, 'browser_crypto_failed');
  assert.ok(result.layers.some(layer => layer.layer === 'checkpoint_identity' && layer.status === 'valid'));
  assert.equal(result.layers.some(layer => layer.layer === 'transparency' && layer.status === 'valid'), false);
  assert.equal(JSON.stringify(result).includes('private Merkle runtime failure'), false);
});
