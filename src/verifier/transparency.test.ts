// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fixtureCanonical } from '../../tests/browser-test-support';
import { createSigningAuthorization, verifyIdentityGraph } from './authorization';
import { decodeCanonicalObject } from './canonical';
import { validateBundleGraph } from './graph';
import { verifyManifest } from './manifest';
import { inclusionPath } from './merkle';
import { verifySignatureIntegrity } from './signature-integrity';
import { MAX_INCLUSION_BYTES, MAX_LEAF_INVENTORY_BYTES, verifyAppendOrder, verifyCheckpointChain, verifyHistoryExtension,
  verifyInclusion, verifyLeafInventory, verifyManifestBoundaries, type CheckpointMap, type ManifestMap, type TransparencyLeaf } from './transparency';
import { StrictZip } from './zip';

const canonical = (value: unknown): Uint8Array => new TextEncoder().encode(fixtureCanonical(value));
const hash = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
const node = (left: string, right: string): string => hash(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
const firstHash = 'a'.repeat(64), secondHash = 'b'.repeat(64);
const sealedAt = '2026-01-01T00:00:00Z';

async function fixture(name = 'site') {
  const zip = StrictZip.parse(readFileSync(new URL(`../../tests/fixtures/${name}.zip`, import.meta.url)));
  const graph = validateBundleGraph(decodeCanonicalObject(zip.read('bundle.json')));
  const receipts = await verifyIdentityGraph(zip, graph);
  const manifests = await Promise.all(graph.records.map(item => verifyManifest(zip.read(item.manifestPath), item.entryId.slice(9), item.manifestSha256)));
  const auth = createSigningAuthorization(receipts);
  await verifySignatureIntegrity(zip, graph, manifests, auth); auth.finish();
  return { zip, graph, checkpoints: auth.verifiedCheckpoints(), manifests: new Map(manifests.map(manifest => [manifest.uuid, manifest])) };
}

/** Trusted-data semantic fixture, not a claim that these synthetic checkpoints
 * have signed bytes. The separate all-scope test authenticates real signatures. */
async function oddChain() {
  const original = (await fixture()).checkpoints.values().next().value!;
  const leaves: TransparencyLeaf[] = [];
  const leafDocuments: { entryId: string; manifestDigest: { algorithm: string; value: string } }[] = [];
  const manifests: ManifestMap = new Map();
  for (let index = 1; index <= 5; index++) {
    const uuid = `${String(index).padStart(8, '0')}-1234-4123-8123-123456789abc`;
    const manifestHash = hash(uuid);
    const document = { entryId: `urn:uuid:${uuid}`, manifestDigest: { algorithm: 'sha-256', value: manifestHash } };
    leafDocuments.push(document);
    leaves.push({ uuid, manifest: manifestHash, hash: hash(Buffer.concat([Buffer.from([0]), canonical(document)])) });
    manifests.set(uuid, { uuid, sha256: manifestHash, canonicalUrl: `https://example.test/${index}`, previous: null, sealedAt, version: '2.0' });
  }
  const hashes = leaves.map(leaf => leaf.hash);
  const firstRoot = node(hashes[0], hashes[1]);
  const middleRoot = node(hashes[2], hashes[3]);
  const lastRoot = node(node(firstRoot, middleRoot), hashes[4]);
  const first = structuredClone(original), second = structuredClone(original);
  first.sha256 = firstHash; second.sha256 = secondHash;
  first.document.tree = { ...first.document.tree, leafCount: 2, rootHash: firstRoot };
  second.document.tree = { ...second.document.tree, leafCount: 5, rootHash: lastRoot };
  first.document.predecessor = null;
  second.document.predecessor = { checkpointSha256: firstHash, leafCount: 2, rootHash: firstRoot, consistencyProof: [middleRoot, hashes[4]] };
  first.document.recordedThrough.manifestSealedAt = sealedAt;
  second.document.recordedThrough.manifestSealedAt = sealedAt;
  const checkpoints: CheckpointMap = new Map([[firstHash, first], [secondHash, second]]);
  const inventory = { checkpointSha256: secondHash, format: 'WP ContentLedger Transparency Leaf Inventory', version: '1.0',
    leaves: leaves.map((leaf, index) => ({ leaf: leafDocuments[index], leafHash: leaf.hash, leafIndex: index })) };
  return { checkpoints, manifests, leaves, hashes, leafDocuments, inventory };
}

test('transparency validates authenticated generated checkpoint graphs, inventories, inclusions, and boundaries', async () => {
  for (const name of ['record', 'url-history', 'checkpoint', 'site', 'site-chain']) {
    const { zip, graph, checkpoints, manifests } = await fixture(name);
    const inventories = new Map();
    for (const item of graph.leafInventories) inventories.set(item.checkpointSha256, await verifyLeafInventory(zip.read(item.path), item.checkpointSha256, checkpoints, manifests));
    const target = graph.checkpoints.at(-1)?.checkpointSha256;
    if (target) {
      const inventory = inventories.get(target);
      const order = await verifyCheckpointChain(checkpoints, target, inventory?.hashes ?? []);
      assert.deepEqual(order, graph.checkpoints.map(item => item.checkpointSha256));
      if (inventory) { verifyAppendOrder(order, checkpoints, inventory.leaves); verifyManifestBoundaries(order, checkpoints, inventory.leaves, manifests); }
    }
    for (const record of graph.records) for (const path of record.inclusionProofPaths) {
      const checkpoint = path.slice(path.lastIndexOf('/') + 1, -5);
      const result = await verifyInclusion(zip.read(path), checkpoint, record.entryId.slice(9), checkpoints, manifests, inventories.get(checkpoint)?.hashes ?? []);
      assert.equal(result.checkpointSha256, checkpoint);
    }
  }
});

test('transparency accepts an independent odd-size five-leaf root, prefix chain, and every exact inclusion position', async () => {
  const { checkpoints, manifests, leaves, hashes, leafDocuments, inventory } = await oddChain();
  const result = await verifyLeafInventory(canonical(inventory), secondHash, checkpoints, manifests);
  assert.deepEqual(result.hashes, hashes); assert.deepEqual(result.leaves, leaves);
  assert.equal(Object.getPrototypeOf(result.records), null);
  assert.equal(result.records[leaves[4].uuid], 4);
  assert.deepEqual(await verifyCheckpointChain(checkpoints, secondHash, hashes), [firstHash, secondHash]);
  assert.deepEqual(await verifyCheckpointChain(checkpoints, secondHash), [firstHash, secondHash]);
  verifyAppendOrder([firstHash, secondHash], checkpoints, leaves);
  verifyManifestBoundaries([firstHash, secondHash], checkpoints, leaves, manifests);
  for (let index = 0; index < leaves.length; index++) {
    const proof = { checkpointSha256: secondHash, format: 'WP ContentLedger Transparency Inclusion Proof', version: '1.0',
      leaf: leafDocuments[index], leafHash: hashes[index], leafIndex: index, path: await inclusionPath(index, 0, 5, hashes),
      tree: { algorithm: 'rfc6962-sha256-v1', leafCount: 5, rootHash: checkpoints.get(secondHash)!.document.tree.rootHash } };
    await verifyInclusion(canonical(proof), secondHash, leaves[index].uuid, checkpoints, manifests, hashes);
    await verifyInclusion(canonical(proof), secondHash, leaves[index].uuid, checkpoints, manifests);
  }
});

test('checkpoint chain rejects absent targets, crossed maps, cycles, missing predecessors, and unrelated checkpoints', async () => {
  const { checkpoints } = await oddChain();
  await assert.rejects(verifyCheckpointChain(new Map(), secondHash), { code: 'checkpoint_chain_target' });
  await assert.rejects(verifyCheckpointChain(checkpoints, 'c'.repeat(64)), { code: 'checkpoint_chain_target' });
  const crossed = structuredClone(checkpoints); crossed.get(secondHash)!.sha256 = firstHash;
  await assert.rejects(verifyCheckpointChain(crossed, secondHash), { code: 'checkpoint_map' });
  const cycle = structuredClone(checkpoints); cycle.get(firstHash)!.document.predecessor = structuredClone(cycle.get(secondHash)!.document.predecessor);
  cycle.get(firstHash)!.document.predecessor!.checkpointSha256 = secondHash;
  await assert.rejects(verifyCheckpointChain(cycle, secondHash), { code: 'checkpoint_chain_cycle' });
  const missing = structuredClone(checkpoints); missing.delete(firstHash);
  await assert.rejects(verifyCheckpointChain(missing, secondHash), { code: 'checkpoint_predecessor_missing' });
  const extra = structuredClone(checkpoints); const clone = structuredClone(extra.get(firstHash)!); clone.sha256 = 'c'.repeat(64); extra.set(clone.sha256, clone);
  await assert.rejects(verifyCheckpointChain(extra, secondHash), { code: 'checkpoint_chain_extras' });
});

test('checkpoint chain enforces prefix roots, exact consistency, full inventory count, and monotonic time', async () => {
  const { checkpoints, hashes } = await oddChain();
  const wrongRoot = structuredClone(checkpoints); wrongRoot.get(firstHash)!.document.tree.rootHash = 'c'.repeat(64);
  await assert.rejects(verifyCheckpointChain(wrongRoot, secondHash, hashes), { code: 'checkpoint_leaf_root' });
  const consistency = structuredClone(checkpoints); consistency.get(secondHash)!.document.predecessor!.consistencyProof.reverse();
  await assert.rejects(verifyCheckpointChain(consistency, secondHash), { code: 'checkpoint_consistency' });
  await assert.rejects(verifyCheckpointChain(checkpoints, secondHash, [...hashes, 'c'.repeat(64)]), { code: 'checkpoint_leaf_inventory_count' });
  const time = structuredClone(checkpoints); time.get(secondHash)!.document.recordedThrough.manifestSealedAt = '2025-01-01T00:00:00Z';
  await assert.rejects(verifyCheckpointChain(time, secondHash), { code: 'checkpoint_boundary_rollback' });
});

test('checkpoint identity history must extend exact log bytes under the same DID and routes', async () => {
  const { checkpoints } = await oddChain();
  const prior = checkpoints.get(firstHash)!.receipt;
  const successor = structuredClone(prior);
  successor.log_json += 'additional exact bytes\n';
  assert.doesNotThrow(() => verifyHistoryExtension(prior, successor));
  assert.doesNotThrow(() => verifyHistoryExtension(prior, prior));
  for (const field of ['did', 'siteUrl', 'publicUrl'] as const) {
    const wrong = structuredClone(successor); wrong.identity[field] += 'other';
    assert.throws(() => verifyHistoryExtension(prior, wrong), { code: 'checkpoint_identity_fork' });
  }
  for (const log of ['', prior.log_json.slice(0, -1), ' ' + prior.log_json]) assert.throws(() => verifyHistoryExtension(prior, { ...successor, log_json: log }), { code: 'checkpoint_identity_fork' });
  const fork = structuredClone(checkpoints); fork.get(secondHash)!.receipt.log_json = 'fork\n';
  await assert.rejects(verifyCheckpointChain(fork, secondHash), { code: 'checkpoint_identity_fork' });
});

test('leaf inventory rejects bounds, noncontiguous items, duplicate records, crossed manifests, and altered roots', async () => {
  const { checkpoints, manifests, inventory } = await oddChain();
  await assert.rejects(verifyLeafInventory(new Uint8Array(), secondHash, checkpoints, manifests), { code: 'leaf_inventory_size' });
  await assert.rejects(verifyLeafInventory(new Uint8Array(MAX_LEAF_INVENTORY_BYTES + 1), secondHash, checkpoints, manifests), { code: 'leaf_inventory_size' });
  await assert.rejects(verifyLeafInventory(canonical({ ...inventory, version: '2.0' }), secondHash, checkpoints, manifests), { code: 'leaf_inventory_profile' });
  await assert.rejects(verifyLeafInventory(canonical({ ...inventory, leaves: inventory.leaves.slice(1) }), secondHash, checkpoints, manifests), { code: 'leaf_inventory_checkpoint' });
  const index = structuredClone(inventory); index.leaves[0].leafIndex = 1;
  await assert.rejects(verifyLeafInventory(canonical(index), secondHash, checkpoints, manifests), { code: 'leaf_inventory_item' });
  const duplicate = structuredClone(inventory); duplicate.leaves[1] = { ...duplicate.leaves[0], leafIndex: 1 };
  await assert.rejects(verifyLeafInventory(canonical(duplicate), secondHash, checkpoints, manifests), { code: 'leaf_inventory_binding' });
  await assert.rejects(verifyLeafInventory(canonical(inventory), secondHash, checkpoints, new Map()), { code: 'leaf_inventory_manifest' });
  const root = structuredClone(checkpoints); root.get(secondHash)!.document.tree.rootHash = 'c'.repeat(64);
  await assert.rejects(verifyLeafInventory(canonical(inventory), secondHash, root, manifests), { code: 'leaf_inventory_root' });
});

test('inclusion rejects bounds, crossed leaf/manifest, wrong topology, inventory path, and root bindings', async () => {
  const { checkpoints, manifests, leaves, hashes, leafDocuments } = await oddChain();
  const proof = { checkpointSha256: secondHash, format: 'WP ContentLedger Transparency Inclusion Proof', version: '1.0',
    leaf: leafDocuments[4], leafHash: hashes[4], leafIndex: 4, path: await inclusionPath(4, 0, 5, hashes),
    tree: { algorithm: 'rfc6962-sha256-v1', leafCount: 5, rootHash: checkpoints.get(secondHash)!.document.tree.rootHash } };
  const check = (value: unknown, inventory: string[] = hashes) => verifyInclusion(canonical(value), secondHash, leaves[4].uuid, checkpoints, manifests, inventory);
  await assert.rejects(verifyInclusion(new Uint8Array(), secondHash, leaves[4].uuid, checkpoints, manifests), { code: 'inclusion_size' });
  await assert.rejects(verifyInclusion(new Uint8Array(MAX_INCLUSION_BYTES + 1), secondHash, leaves[4].uuid, checkpoints, manifests), { code: 'inclusion_size' });
  await assert.rejects(check({ ...proof, version: '2.0' }), { code: 'inclusion_profile' });
  await assert.rejects(check({ ...proof, leafHash: hashes[0] }), { code: 'inclusion_leaf' });
  await assert.rejects(verifyInclusion(canonical(proof), secondHash, leaves[4].uuid, checkpoints, new Map()), { code: 'inclusion_manifest' });
  await assert.rejects(check({ ...proof, leafIndex: 5 }), { code: 'inclusion_tree' });
  await assert.rejects(check({ ...proof, path: [{ ...proof.path[0], side: 'other' }] }), { code: 'inclusion_path' });
  await assert.rejects(check({ ...proof, path: [{ ...proof.path[0], side: 'right' }] }), { code: 'inclusion_topology' });
  await assert.rejects(check(proof, hashes.slice(1)), { code: 'inclusion_inventory_leaf' });
  await assert.rejects(check({ ...proof, path: [{ ...proof.path[0], hash: 'c'.repeat(64) }] }), { code: 'inclusion_inventory_path' });
  await assert.rejects(check({ ...proof, path: [{ ...proof.path[0], hash: 'c'.repeat(64) }] }, []), { code: 'inclusion_checkpoint_binding' });
});

test('append order is strict only within each checkpoint delta, with monotonic prefix bounds', async () => {
  const { checkpoints, leaves } = await oddChain();
  const unordered = structuredClone(leaves); [unordered[3], unordered[4]] = [unordered[4], unordered[3]];
  assert.throws(() => verifyAppendOrder([firstHash, secondHash], checkpoints, unordered), { code: 'leaf_append_order' });
  const duplicate = structuredClone(leaves); duplicate[4].uuid = duplicate[3].uuid;
  assert.throws(() => verifyAppendOrder([firstHash, secondHash], checkpoints, duplicate), { code: 'leaf_append_order' });
  assert.throws(() => verifyAppendOrder([secondHash, firstHash], checkpoints, leaves), { code: 'leaf_append_boundary' });
  const across = [...leaves.slice(3), ...leaves.slice(0, 3)];
  assert.doesNotThrow(() => verifyAppendOrder([firstHash, secondHash], checkpoints, across));
});

test('manifest boundary uses PHP timestamp ordering, UUID tie-breaking, and exact retained spelling', async () => {
  const { checkpoints, leaves, manifests } = await oddChain();
  const last = checkpoints.get(secondHash)!;
  const check = () => verifyManifestBoundaries([secondHash], new Map([[secondHash, last]]), leaves, manifests);
  const low = leaves[0].uuid, high = leaves[4].uuid;
  for (const manifest of manifests.values()) manifest.sealedAt = '1969-12-31T23:59:59.500000Z';
  manifests.get(high)!.sealedAt = '1969-12-31T23:59:59.1Z';
  last.document.recordedThrough.manifestSealedAt = '1969-12-31T23:59:59.1Z';
  assert.doesNotThrow(check); // PHP compares -1.1 > -1.5 after U.u conversion.
  for (const manifest of manifests.values()) manifest.sealedAt = sealedAt;
  manifests.get(low)!.sealedAt = '2026-01-01T00:00:00+00:00';
  last.document.recordedThrough.manifestSealedAt = sealedAt;
  assert.doesNotThrow(check); // Higher UUID wins equal instants, retaining its Z.
  manifests.get(high)!.sealedAt = '2026-01-01T00:00:00+00:00';
  assert.throws(check, { code: 'checkpoint_manifest_boundary' });
  last.document.recordedThrough.manifestSealedAt = '2026-01-01T00:00:00+00:00';
  assert.doesNotThrow(check);
  for (const manifest of manifests.values()) manifest.sealedAt = '2026-01-01T00:00:00.1234561Z';
  manifests.get(high)!.sealedAt = '2026-01-01T00:00:00.1234569Z';
  last.document.recordedThrough.manifestSealedAt = '2026-01-01T00:00:00.1234569Z';
  assert.doesNotThrow(check); // Both truncate to the same six microsecond digits.
});

test('transparency input snapshots remain stable if the source Buffer changes during hashing', async () => {
  const { checkpoints, manifests, inventory } = await oddChain();
  const input = Buffer.from(canonical(inventory));
  const pending = verifyLeafInventory(input, secondHash, checkpoints, manifests);
  input.fill(0);
  assert.equal((await pending).leaves.length, 5);
});

test('transparency crypto backend failures are capability errors rather than invalid evidence', async () => {
  const { checkpoints, manifests, inventory } = await oddChain();
  const subtle = globalThis.crypto.subtle;
  const original = Object.getOwnPropertyDescriptor(subtle, 'digest');
  try {
    Object.defineProperty(subtle, 'digest', { configurable: true, value: async () => { throw new DOMException('Synthetic backend failure.', 'OperationError'); } });
    await assert.rejects(verifyLeafInventory(canonical(inventory), secondHash, checkpoints, manifests), { kind: 'unsupported', code: 'browser_crypto_failed' });
  } finally {
    if (original) Object.defineProperty(subtle, 'digest', original);
    else delete (subtle as Partial<SubtleCrypto>).digest;
  }
});
