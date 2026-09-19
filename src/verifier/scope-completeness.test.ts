// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createSigningAuthorization, verifyIdentityGraph } from './authorization';
import { decodeCanonicalObject } from './canonical';
import { validateBundleGraph, type RecordReference } from './graph';
import { verifyManifest, type VerifiedManifest } from './manifest';
import { validateScopeDeclaration, type BundleScope } from './scope';
import { verifyScopeCompleteness } from './scope-completeness';
import { verifySignatureIntegrity } from './signature-integrity';
import { verifyLeafInventory, type LeafInventory } from './transparency';
import { StrictZip } from './zip';

const target = 'd'.repeat(64), earlier = 'e'.repeat(64);
const url = 'https://example.test/article';
const uuids = ['00000001-1234-4123-8123-123456789abc', '00000002-1234-4123-8123-123456789abc', '00000003-1234-4123-8123-123456789abc'];
function record(index = 0, overrides: Partial<RecordReference> = {}): RecordReference {
  return { archiveReferencePath: null, entryId: `urn:uuid:${uuids[index]}`, inclusionProofPaths: [], manifestPath: `records/${uuids[index]}/manifest.json`,
    manifestSha256: String.fromCharCode(97 + index).repeat(64), signaturePath: null, timestampPaths: [], ...overrides };
}
function manifest(index = 0, previous: string | null = null): Omit<VerifiedManifest, 'document'> {
  return { canonicalUrl: url, previous, sealedAt: '2026-01-01T00:00:00Z', sha256: record(index).manifestSha256, uuid: uuids[index], version: '2.0' };
}
function proof(index = 0, digest = target): string { return `records/${uuids[index]}/inclusion/${digest}.json`; }
const recordScope: BundleScope = { kind: 'record', entryId: record().entryId };
const urlScope: BundleScope = { kind: 'url-history', url };
function inventory(indices: number[] = [0]): LeafInventory {
  const leaves = indices.map(index => ({ uuid: uuids[index], manifest: record(index).manifestSha256, hash: 'f'.repeat(64) }));
  return { leaves, hashes: leaves.map(leaf => leaf.hash), records: Object.fromEntries(leaves.map((leaf, index) => [leaf.uuid, index])) };
}
const bulkScope = (kind: 'checkpoint' | 'site'): BundleScope => ({ kind, checkpointSha256: target });

test('scope completeness accepts all authenticated generated scope fixtures', async () => {
  for (const name of ['record', 'url-history', 'checkpoint', 'site', 'site-chain']) {
    const zip = StrictZip.parse(readFileSync(new URL(`../../tests/fixtures/${name}.zip`, import.meta.url)));
    const bundle = decodeCanonicalObject(zip.read('bundle.json'));
    const graph = validateBundleGraph(bundle), scope = validateScopeDeclaration(bundle.scope);
    const receipts = await verifyIdentityGraph(zip, graph);
    const manifests = await Promise.all(graph.records.map(item => verifyManifest(zip.read(item.manifestPath), item.entryId.slice(9), item.manifestSha256)));
    const auth = createSigningAuthorization(receipts);
    await verifySignatureIntegrity(zip, graph, manifests, auth); auth.finish();
    const checkpoints = auth.verifiedCheckpoints();
    const byUuid = new Map(manifests.map(item => [item.uuid, item]));
    const inventories = new Map<string, LeafInventory>();
    for (const item of graph.leafInventories) inventories.set(item.checkpointSha256, await verifyLeafInventory(zip.read(item.path), item.checkpointSha256, checkpoints, byUuid));
    const selected = scope.kind === 'checkpoint' || scope.kind === 'site' ? scope.checkpointSha256 : graph.checkpoints.at(-1)?.checkpointSha256 ?? null;
    assert.doesNotThrow(() => verifyScopeCompleteness(scope, graph.records, manifests, selected, inventories), name);
  }
});

test('record scope allows no checkpoint or exactly one terminal inclusion for exactly its declared record', () => {
  assert.doesNotThrow(() => verifyScopeCompleteness(recordScope, [record()], [manifest()], null, new Map()));
  assert.doesNotThrow(() => verifyScopeCompleteness(recordScope, [record(0, { inclusionProofPaths: [proof()] })], [manifest()], target, new Map()));
  assert.throws(() => verifyScopeCompleteness(recordScope, [], [], null, new Map()), { code: 'scope_record' });
  assert.throws(() => verifyScopeCompleteness(recordScope, [record(), record(1)], [manifest(), manifest(1)], null, new Map()), { code: 'scope_record' });
  assert.throws(() => verifyScopeCompleteness(recordScope, [record(1)], [manifest(1)], null, new Map()), { code: 'scope_record' });
  // No signature requirement is invented for an otherwise valid record scope.
  assert.doesNotThrow(() => verifyScopeCompleteness(recordScope, [record()], [], null, new Map(), true));
});

test('record and URL-history reject bulk inventories before proof or manifest errors', () => {
  for (const scope of [recordScope, urlScope]) for (const degraded of [false, true]) {
    assert.throws(() => verifyScopeCompleteness(scope, [], [], target, new Map([[target, inventory()]]), degraded), { code: 'scope_leaf_inventory' });
    assert.throws(() => verifyScopeCompleteness(scope, [record(0, { inclusionProofPaths: [proof(0, earlier)] })], [], target, new Map([[earlier, inventory()]]), degraded), { code: 'scope_leaf_inventory' });
  }
});

test('record and URL-history inclusions target the exact terminal checkpoint and close any carried chain', () => {
  for (const scope of [recordScope, urlScope]) for (const degraded of [false, true]) {
    assert.throws(() => verifyScopeCompleteness(scope, [record(0, { inclusionProofPaths: [proof()] })], [manifest()], null, new Map(), degraded), { code: 'scope_inclusion_target' });
    assert.throws(() => verifyScopeCompleteness(scope, [record(0, { inclusionProofPaths: [proof(0, earlier)] })], [manifest()], target, new Map(), degraded), { code: 'scope_inclusion_target' });
    assert.throws(() => verifyScopeCompleteness(scope, [record()], [manifest()], target, new Map(), degraded), { code: 'scope_checkpoint_closure' });
  }
  assert.throws(() => verifyScopeCompleteness(recordScope, [record(0, { inclusionProofPaths: [proof(), proof()] })], [manifest()], target, new Map()), { code: 'scope_checkpoint_closure' });
  assert.throws(() => verifyScopeCompleteness(recordScope, [record(1, { inclusionProofPaths: [proof(1, earlier)] })], [manifest(1)], target, new Map()), { code: 'scope_inclusion_target' });
});

test('URL-history requires a nonempty single canonical URL and one complete unbranched manifest chain', () => {
  const records = [record(), record(1), record(2)];
  const manifests = [manifest(), manifest(1, record().manifestSha256), manifest(2, record(1).manifestSha256)];
  assert.doesNotThrow(() => verifyScopeCompleteness(urlScope, records, manifests, null, new Map()));
  assert.throws(() => verifyScopeCompleteness(urlScope, [], [], null, new Map()), { code: 'scope_url_empty' });
  assert.throws(() => verifyScopeCompleteness(urlScope, [], [], target, new Map()), { code: 'scope_checkpoint_closure' });
  const different = structuredClone(manifests); different[1].canonicalUrl += '/other';
  assert.throws(() => verifyScopeCompleteness(urlScope, records, different, null, new Map()), { code: 'scope_url_binding' });
  const branch = [manifest(), manifest(1, record().manifestSha256), manifest(2, record().manifestSha256)];
  assert.throws(() => verifyScopeCompleteness(urlScope, records, branch, null, new Map()), { code: 'scope_url_branch' });
  assert.throws(() => verifyScopeCompleteness(urlScope, records, [manifest(), manifest(1), manifest(2)], null, new Map()), { code: 'scope_url_chain' });
  assert.throws(() => verifyScopeCompleteness(urlScope, records, [manifest(), manifest(1, earlier), manifest(2, record(1).manifestSha256)], null, new Map()), { code: 'scope_url_chain' });
  const disconnected = [manifest(), manifest(1, record(2).manifestSha256), manifest(2, record(1).manifestSha256)];
  assert.throws(() => verifyScopeCompleteness(urlScope, records, disconnected, null, new Map()), { code: 'scope_url_disconnected' });
});

test('URL-history uses the reference terminal proof-set rule, not a new proof-per-record requirement', () => {
  const records = [record(0, { inclusionProofPaths: [proof()] }), record(1)];
  const manifests = [manifest(), manifest(1, record().manifestSha256)];
  assert.doesNotThrow(() => verifyScopeCompleteness(urlScope, records, manifests, target, new Map()));
  records[1].inclusionProofPaths.push(proof(1));
  assert.doesNotThrow(() => verifyScopeCompleteness(urlScope, records, manifests, target, new Map()));
});

test('unsupported manifest semantics skip only URL chain interpretation, never closure or known URL binding', () => {
  const records = [record(), record(1)];
  assert.doesNotThrow(() => verifyScopeCompleteness(urlScope, records, [], null, new Map(), true));
  assert.doesNotThrow(() => verifyScopeCompleteness(urlScope, records, [manifest(1, earlier)], null, new Map(), true));
  assert.throws(() => verifyScopeCompleteness(urlScope, records, [manifest(1, earlier)], null, new Map()), { code: 'scope_url_chain' });
  assert.throws(() => verifyScopeCompleteness(urlScope, records, [{ ...manifest(), canonicalUrl: url + '/other' }], null, new Map(), true), { code: 'scope_url_binding' });
  assert.throws(() => verifyScopeCompleteness(urlScope, records, [], target, new Map(), true), { code: 'scope_checkpoint_closure' });
});

test('bulk scopes require the selected exact inventory and identical sorted record UUID sets', () => {
  const records = [record(), record(1)], manifests = [manifest(), manifest(1)];
  for (const kind of ['checkpoint', 'site'] as const) {
    const scope = bulkScope(kind);
    assert.doesNotThrow(() => verifyScopeCompleteness(scope, records, manifests, target, new Map([[target, inventory([1, 0])]])));
    assert.throws(() => verifyScopeCompleteness(scope, records, manifests, null, new Map([[target, inventory([0, 1])]])), { code: 'scope_checkpoint_inventory' });
    assert.throws(() => verifyScopeCompleteness(scope, records, manifests, earlier, new Map([[earlier, inventory([0, 1])]])), { code: 'scope_checkpoint_inventory' });
    assert.throws(() => verifyScopeCompleteness(scope, records, manifests, target, new Map([[earlier, inventory([0, 1])]])), { code: 'scope_checkpoint_inventory' });
    for (const indices of [[0], [0, 2], [0, 1, 2]]) {
      assert.throws(() => verifyScopeCompleteness(scope, records, manifests, target, new Map([[target, inventory(indices)]])), { code: 'scope_leaf_records' });
    }
    assert.throws(() => verifyScopeCompleteness(scope, [record(), record()], manifests, target, new Map([[target, inventory()]])), { code: 'scope_leaf_records' });
  }
});

test('bulk scopes prohibit per-record inclusion proofs, and checkpoint scope keeps manifest-only records', () => {
  const inventories = new Map([[target, inventory()]]);
  for (const kind of ['checkpoint', 'site'] as const) for (const degraded of [false, true]) {
    assert.throws(() => verifyScopeCompleteness(bulkScope(kind), [record(0, { inclusionProofPaths: [proof()] })], [manifest()], target, inventories, degraded), { code: 'scope_record_inclusion' });
  }
  for (const overrides of [{ archiveReferencePath: `records/${uuids[0]}/archive-references.json` }, { signaturePath: `records/${uuids[0]}/signature.jws` }, { timestampPaths: [`records/${uuids[0]}/timestamps/${target}.ots`] }]) {
    const records = [record(0, overrides)];
    for (const degraded of [false, true]) {
      assert.throws(() => verifyScopeCompleteness(bulkScope('checkpoint'), records, [manifest()], target, inventories, degraded), { code: 'scope_checkpoint_record_artifact' });
      assert.doesNotThrow(() => verifyScopeCompleteness(bulkScope('site'), records, [manifest()], target, inventories, degraded));
    }
  }
  assert.throws(() => verifyScopeCompleteness(bulkScope('checkpoint'), [record(0, { inclusionProofPaths: [proof()], signaturePath: 'record-signature' })], [manifest()], target, inventories), { code: 'scope_record_inclusion' });
});

test('scope completeness never mutates caller record arrays, manifest links, or inventory ordering', () => {
  const records = [record(1), record()], manifests = [manifest(1), manifest()];
  const inventories = new Map([[target, inventory([0, 1])]]);
  const before = structuredClone({ records, manifests, inventories });
  verifyScopeCompleteness(bulkScope('site'), records, manifests, target, inventories);
  assert.deepEqual({ records, manifests, inventories }, before);
});
