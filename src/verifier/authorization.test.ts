// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fixtureCanonical, fixtureEntries, fixtureZip } from '../../tests/browser-test-support';
import { createSigningAuthorization, receiptForKey, verifyIdentityGraph } from './authorization';
import { MAX_CHECKPOINT_BYTES, readCheckpointDocument, type CheckpointDocument } from './checkpoint-document';
import { decodeCanonicalObject } from './canonical';
import { validateBundleGraph } from './graph';
import { CHECKPOINT_JWS_TYPE, verifyExactJws, verifyRecordJws } from './jws';
import { verifyManifest } from './manifest';
import { verifySignatureIntegrity } from './signature-integrity';
import { StrictZip } from './zip';

const encoder = new TextEncoder();
const canonical = (value: unknown): Uint8Array => encoder.encode(fixtureCanonical(value));
function fixture(name = 'checkpoint') {
  const bytes = readFileSync(new URL(`../../tests/fixtures/${name}.zip`, import.meta.url));
  const zip = StrictZip.parse(bytes);
  const graph = validateBundleGraph(decodeCanonicalObject(zip.read('bundle.json')));
  return { bytes, zip, graph };
}
async function checkpoint() {
  const { zip, graph } = fixture();
  const receipts = await verifyIdentityGraph(zip, graph);
  const item = graph.checkpoints[0];
  const bytes = zip.read(item.documentPath);
  const signature = await verifyExactJws(zip.read(item.jwsPath), bytes, CHECKPOINT_JWS_TYPE);
  return { zip, graph, receipts, item, bytes, signature };
}
async function record() {
  const { zip, graph } = fixture('record');
  const receipts = await verifyIdentityGraph(zip, graph);
  const item = graph.records.find(item => item.signaturePath !== null)!;
  const manifest = await verifyManifest(zip.read(item.manifestPath), item.entryId.slice(9), item.manifestSha256);
  const signature = await verifyRecordJws(zip.read(item.signaturePath!), manifest);
  return { zip, graph, receipts, signature };
}

test('authorization hooks authenticate all supported signatures in every generated bundle scope', async () => {
  for (const name of ['record', 'url-history', 'checkpoint', 'site']) {
    const { zip, graph } = fixture(name);
    const receipts = await verifyIdentityGraph(zip, graph);
    const manifests = await Promise.all(graph.records.map(item => verifyManifest(zip.read(item.manifestPath), item.entryId.slice(9), item.manifestSha256)));
    const hooks = createSigningAuthorization(receipts);
    const signatures = await verifySignatureIntegrity(zip, graph, manifests, hooks);
    const authorization = hooks.finish();
    assert.equal(signatures.recordSignatures, authorization.recordSignatures, name);
    assert.equal(signatures.checkpointSignatures, authorization.checkpointSignatures, name);
    assert.equal(authorization.usedReceipts, receipts.length, name);
    assert.equal(signatures.unsupportedRecordSignatures, 0, name);
  }
});

test('receipt selection prefers the longest matching DID and key, retaining graph order for ties', async () => {
  const { receipts, signature } = await record();
  const first = receipts[0];
  const second = { ...first, sha256: 'b'.repeat(64) };
  const longest = { ...first, versions: [...first.versions, first.versions[0]], sha256: 'c'.repeat(64) };
  assert.equal(receiptForKey([first, second], signature.issuer, signature.kid), first);
  assert.equal(receiptForKey([second, first], signature.issuer, signature.kid), second);
  assert.equal(receiptForKey([first, longest, second], signature.issuer, signature.kid), longest);
  assert.equal(receiptForKey([{ ...longest, did: 'other' }, first], signature.issuer, signature.kid), first);
  assert.equal(receiptForKey([{ ...longest, keys: {} }, first], signature.issuer, signature.kid), first);
  assert.equal(receiptForKey([first], `${signature.issuer}:other`, signature.kid), undefined);
  assert.equal(receiptForKey([first], signature.issuer, `${signature.kid}-other`), undefined);
});

test('record authorization rejects missing receipts and out-of-interval claimed signing times', async () => {
  const { receipts, signature } = await record();
  assert.throws(() => createSigningAuthorization([]).record(signature), { code: 'record_identity_receipt_missing' });
  assert.throws(() => createSigningAuthorization(receipts).record({ ...signature, kid: `${signature.kid}-other` }), { code: 'record_identity_receipt_missing' });
  assert.throws(() => createSigningAuthorization(receipts).record({ ...signature, issuedAt: '0001-01-01T00:00:00Z' }), { code: 'record_authorization' });
  assert.throws(() => createSigningAuthorization(receipts).record({ ...signature, issuedAt: '2026-01-01T00:00:00.0Z' }), { code: 'record_authorization' });
  const hooks = createSigningAuthorization(receipts);
  hooks.record(signature);
  assert.deepEqual(hooks.finish(), { recordSignatures: 1, checkpointSignatures: 0, usedReceipts: 1 });
});

test('record authorization uses the selected longest receipt rather than a shorter permissive history', async () => {
  const { receipts, signature } = await record();
  const original = receipts[0];
  const longer = structuredClone(original);
  longer.versions.push(longer.versions[0]);
  longer.keys[signature.kid].until = signature.issuedAt;
  assert.throws(() => createSigningAuthorization([original, longer]).record(signature), { code: 'record_authorization' });
});

test('checkpoint authorization requires exactly one matching identity receipt', async () => {
  const { receipts, bytes, item, signature } = await checkpoint();
  assert.throws(() => createSigningAuthorization([]).checkpoint(bytes, signature, item), { code: 'checkpoint_receipt_missing' });
  assert.throws(() => createSigningAuthorization([...receipts, receipts[0]]).checkpoint(bytes, signature, item), { code: 'checkpoint_receipt_missing' });
  const wrong = receipts.map(receipt => ({ ...receipt, eventHeadHash: 'a'.repeat(64) }));
  assert.throws(() => createSigningAuthorization(wrong).checkpoint(bytes, signature, item), { code: 'checkpoint_receipt_binding' });
});

test('checkpoint authorization binds exact JWS key and signed predecessor/receipt graph values', async () => {
  const { receipts, bytes, item, signature } = await checkpoint();
  assert.throws(() => createSigningAuthorization(receipts).checkpoint(bytes, { ...signature, kid: signature.kid + '-other' }, item), { code: 'jws_kid_binding' });
  assert.throws(() => createSigningAuthorization(receipts).checkpoint(bytes, { ...signature, jwk: { ...signature.jwk, x: 'A'.repeat(43) } }, item), { code: 'jws_jwk_binding' });
  assert.throws(() => createSigningAuthorization(receipts).checkpoint(bytes, signature, { ...item, identityReceiptSha256: 'a'.repeat(64) }), { code: 'checkpoint_graph_binding' });
  assert.throws(() => createSigningAuthorization(receipts).checkpoint(bytes, signature, { ...item, predecessorCheckpointSha256: 'a'.repeat(64) }), { code: 'checkpoint_graph_binding' });
  const hooks = createSigningAuthorization(receipts);
  hooks.checkpoint(bytes, signature, item);
  assert.deepEqual(hooks.finish(), { recordSignatures: 0, checkpointSignatures: 1, usedReceipts: 1 });
});

test('unused identity receipts cannot silently acquire an authorization claim', async () => {
  const { receipts, signature } = await record();
  assert.throws(() => createSigningAuthorization(receipts).finish(), { code: 'identity_graph_orphan' });
  const unrelated = { ...receipts[0], did: receipts[0].did + ':other', sha256: 'a'.repeat(64) };
  const hooks = createSigningAuthorization([...receipts, unrelated]);
  hooks.record(signature);
  assert.throws(() => hooks.finish(), { code: 'identity_graph_orphan' });
});

test('identity graph authorization compares every exact receipt declaration and carried log', async () => {
  const { bytes, zip, graph } = fixture('record');
  for (const field of ['did', 'assertionMethod', 'logSha256', 'receiptSha256', 'versionId', 'versionTime'] as const) {
    const changed = structuredClone(graph);
    changed.identities[0][field] += 'other';
    await assert.rejects(verifyIdentityGraph(zip, changed), { code: 'identity_graph_log' }, field);
  }
  const entries = fixtureEntries(bytes);
  entries.set(graph.identities[0].logPath, Buffer.from('different log bytes'));
  await assert.rejects(verifyIdentityGraph(StrictZip.parse(fixtureZip(entries)), graph), { code: 'identity_graph_log' });
});

test('checkpoint document validation enforces exact profile, identity, boundary, scope, and tree declarations', async () => {
  const { bytes } = await checkpoint();
  const original = readCheckpointDocument(bytes);
  assert.throws(() => readCheckpointDocument(new Uint8Array()), { code: 'checkpoint_size' });
  assert.throws(() => readCheckpointDocument(new Uint8Array(MAX_CHECKPOINT_BYTES + 1)), { code: 'checkpoint_size' });
  for (const [change, code] of [
    [(doc: CheckpointDocument) => Object.assign(doc, { version: '3.0' }), 'checkpoint_profile'],
    [(doc: CheckpointDocument) => Object.assign(doc, { extra: true }), 'checkpoint_profile'],
    [(doc: CheckpointDocument) => { doc.identity.entryCount = 0; }, 'checkpoint_identity'],
    [(doc: CheckpointDocument) => { doc.identity.logSha256 += '\n'; }, 'checkpoint_identity'],
    [(doc: CheckpointDocument) => { doc.identity.publicKeyJwk.x += '='; }, 'checkpoint_identity'],
    [(doc: CheckpointDocument) => { doc.identity.versionTime = '2026-02-30T00:00:00Z'; }, 'checkpoint_identity'],
    [(doc: CheckpointDocument) => { doc.recordedThrough.identityEventRecordedAt = '0001-01-01T00:00:00Z'; }, 'checkpoint_boundary'],
    [(doc: CheckpointDocument) => { doc.recordedThrough.manifestSealedAt = '2026-01-01T00:00:00.0Z'; }, 'checkpoint_boundary'],
    [(doc: CheckpointDocument) => Object.assign(doc.scope, { selection: 'some-manifests' }), 'checkpoint_scope'],
    [(doc: CheckpointDocument) => { doc.tree.leafCount = 0; }, 'checkpoint_tree'],
    [(doc: CheckpointDocument) => { doc.tree.leafCount = 10001; }, 'checkpoint_tree'],
    [(doc: CheckpointDocument) => { doc.tree.rootHash = 'A'.repeat(64); }, 'checkpoint_tree'],
  ] as const) {
    const changed = structuredClone(original); change(changed);
    assert.throws(() => readCheckpointDocument(canonical(changed)), { code });
  }
});

test('checkpoint predecessor declarations reject malformed and oversized consistency proof lists', async () => {
  const { bytes } = await checkpoint();
  const original = readCheckpointDocument(bytes);
  original.tree.leafCount = 2;
  original.predecessor = { checkpointSha256: 'a'.repeat(64), consistencyProof: [], leafCount: 1, rootHash: 'b'.repeat(64) };
  assert.doesNotThrow(() => readCheckpointDocument(canonical(original)));
  for (const [change, code] of [
    [(doc: CheckpointDocument) => { doc.predecessor!.leafCount = 3; }, 'checkpoint_predecessor'],
    [(doc: CheckpointDocument) => { doc.predecessor!.checkpointSha256 += '\n'; }, 'checkpoint_predecessor'],
    [(doc: CheckpointDocument) => { doc.predecessor!.consistencyProof = Array(33).fill('a'.repeat(64)); }, 'checkpoint_predecessor'],
    [(doc: CheckpointDocument) => { doc.predecessor!.consistencyProof = ['not-a-hash']; }, 'checkpoint_consistency_hash'],
    [(doc: CheckpointDocument) => { doc.predecessor!.leafCount = 2; doc.predecessor!.consistencyProof = ['a'.repeat(64)]; }, 'checkpoint_equal_consistency'],
  ] as const) {
    const changed = structuredClone(original); change(changed);
    assert.throws(() => readCheckpointDocument(canonical(changed)), { code });
  }
});
