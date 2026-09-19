// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { validateBundleGraph, verifyGraphReferences } from './graph';
import { StrictZip } from './zip';
import { VerifierError } from './errors';
import { fixtureZip, sha256, type FixtureEntries } from '../../tests/browser-test-support';

const uuid = '12345678-1234-4123-8123-123456789abc';
const checkpointHash = 'a'.repeat(64);
const artifactHash = 'b'.repeat(64);
const manifest = Buffer.from('{"example":"manifest bytes"}');
const log = Buffer.from('example identity log\n');
const receipt = Buffer.from('{"example":"identity receipt bytes"}');
const logHash = sha256(log);
const receiptHash = sha256(receipt);
type MutableBundle = Record<string, unknown> & {
  records: Record<string, unknown>[];
  checkpoints: Record<string, unknown>[];
  identityLogs: Record<string, unknown>[];
  leafInventories: Record<string, unknown>[];
};

function bundle(): MutableBundle {
  return {
    format: 'WP ContentLedger Evidence Bundle', version: '3.0', profile: 'contentledger-evidence-bundle-native-webvh-v1',
    scope: { kind: 'record', entryId: `urn:uuid:${uuid}` },
    records: [{
      archiveReferencePath: null, entryId: `urn:uuid:${uuid}`, inclusionProofPaths: [],
      manifestPath: `records/${uuid}/manifest.json`, manifestSha256: sha256(manifest), signaturePath: null, timestampPaths: [],
    }],
    checkpoints: [{
      archiveReferencePath: null, checkpointSha256: checkpointHash,
      documentPath: `transparency/checkpoints/${checkpointHash}/checkpoint.json`, identityReceiptSha256: receiptHash,
      jwsPath: `transparency/checkpoints/${checkpointHash}/checkpoint.jws`, predecessorCheckpointSha256: null, timestampPaths: [],
    }],
    identityLogs: [{
      archiveReferencePath: null, assertionMethod: 'did:webvh:example#key', did: 'did:webvh:example',
      logPath: `identity/logs/${logHash}.jsonl`, logSha256: logHash,
      receiptPath: `identity/checkpoints/${receiptHash}.json`, receiptSha256: receiptHash,
      timestampPaths: [], versionId: '1-example', versionTime: '2026-09-19T00:00:00Z',
    }],
    leafInventories: [{ checkpointSha256: checkpointHash, path: `transparency/leaf-inventory/${checkpointHash}.json` }],
  };
}

function entries(): FixtureEntries {
  // These functions test graph references in isolation; full inventory/profile
  // validation is performed by the engine before calling them.
  return new Map([
    [`records/${uuid}/manifest.json`, manifest],
    [`identity/logs/${logHash}.jsonl`, log],
    [`identity/checkpoints/${receiptHash}.json`, receipt],
    [`transparency/checkpoints/${checkpointHash}/checkpoint.json`, Buffer.from('not yet authenticated')],
    [`transparency/checkpoints/${checkpointHash}/checkpoint.jws`, Buffer.from('not yet authenticated')],
    [`transparency/leaf-inventory/${checkpointHash}.json`, Buffer.from('not yet authenticated')],
  ]);
}

function fails(code: string): (error: unknown) => boolean {
  return error => error instanceof VerifierError && error.code === code && error.kind === 'invalid';
}

test('graph declarations preserve all four item types without authenticating their contents', async () => {
  const graph = validateBundleGraph(bundle());
  assert.equal(graph.records.length, 1);
  assert.equal(graph.identities.length, 1);
  assert.equal(graph.checkpoints.length, 1);
  assert.equal(graph.leafInventories.length, 1);
  await verifyGraphReferences(StrictZip.parse(fixtureZip(entries())), graph);
});

test('record exact fields, UUIDs, digest shapes, and byte-length limits reject malformed declarations', () => {
  for (const change of [
    { extra: true }, { entryId: `urn:uuid:${uuid}\n` }, { entryId: 'urn:uuid:12345678-1234-6123-8123-123456789abc' },
    { manifestSha256: `${'a'.repeat(64)}\n` }, { archiveReferencePath: '' }, { signaturePath: 'é'.repeat(121) },
    { timestampPaths: null }, { timestampPaths: Array.from({ length: 10001 }, () => 'x') },
  ]) {
    const value = bundle(); Object.assign(value.records[0], change);
    assert.throws(() => validateBundleGraph(value), fails('bundle_record_item'));
  }
});

test('record paths are confined to the exact UUID namespace', () => {
  for (const field of ['manifestPath', 'signaturePath', 'archiveReferencePath']) {
    const value = bundle(); value.records[0][field] = 'records/wrong/manifest.json';
    assert.throws(() => validateBundleGraph(value), fails('bundle_record_path'));
  }
  for (const field of ['timestampPaths', 'inclusionProofPaths']) {
    const value = bundle(); value.records[0][field] = [`records/${uuid}/timestamps/${artifactHash}.ots\n`];
    assert.throws(() => validateBundleGraph(value), fails('bundle_artifact_path'));
  }
});

test('supporting paths must be unique and bytewise ordered', () => {
  const high = `records/${uuid}/timestamps/${'f'.repeat(64)}.ots`;
  const low = `records/${uuid}/timestamps/${'a'.repeat(64)}.ots`;
  for (const list of [[high, low], [low, low]]) {
    const value = bundle(); value.records[0].timestampPaths = list;
    assert.throws(() => validateBundleGraph(value), fails('bundle_record_item'));
  }
  const value = bundle(); value.records[0].timestampPaths = [low, high];
  assert.doesNotThrow(() => validateBundleGraph(value));
});

test('record declarations reject duplicate and descending UUID order', () => {
  const value = bundle(); value.records.push({ ...value.records[0] });
  assert.throws(() => validateBundleGraph(value), fails('bundle_record_order'));
  value.records.unshift({ ...value.records[0], entryId: `urn:uuid:${uuid.replace('12345678', '22345678')}`, manifestPath: `records/${uuid.replace('12345678', '22345678')}/manifest.json` });
  assert.throws(() => validateBundleGraph(value), fails('bundle_record_order'));
});

test('checkpoint declarations enforce unique hashes, exact fields, and content-addressed namespaces', () => {
  for (const change of [{ checkpointSha256: null }, { identityReceiptSha256: `${receiptHash}\n` }, { predecessorCheckpointSha256: 'wrong' }, { timestampPaths: [''] }]) {
    const value = bundle(); Object.assign(value.checkpoints[0], change);
    assert.throws(() => validateBundleGraph(value), fails('bundle_checkpoint_item'));
  }
  const duplicate = bundle(); duplicate.checkpoints.push({ ...duplicate.checkpoints[0] });
  assert.throws(() => validateBundleGraph(duplicate), fails('bundle_checkpoint_item'));
  for (const field of ['documentPath', 'jwsPath', 'archiveReferencePath']) {
    const value = bundle(); value.checkpoints[0][field] = 'wrong';
    assert.throws(() => validateBundleGraph(value), fails('bundle_checkpoint_path'));
  }
  const artifact = bundle(); artifact.checkpoints[0].timestampPaths = [`records/${uuid}/timestamps/${artifactHash}.ots`];
  assert.throws(() => validateBundleGraph(artifact), fails('bundle_artifact_path'));
});

test('identity declarations use the frozen prefix-level DID and assertion checks, not authentication', () => {
  const allowed = bundle(); allowed.identityLogs[0].versionId = '';
  assert.doesNotThrow(() => validateBundleGraph(allowed));
  for (const change of [{ did: 'did:web:example.com' }, { assertionMethod: 'did:webvh:elsewhere#key' }, { versionId: 1 }, { receiptSha256: `${receiptHash}\n` }, { logSha256: false }]) {
    const value = bundle(); Object.assign(value.identityLogs[0], change);
    assert.throws(() => validateBundleGraph(value), fails('bundle_identity_item'));
  }
  const duplicate = bundle(); duplicate.identityLogs.push({ ...duplicate.identityLogs[0] });
  assert.throws(() => validateBundleGraph(duplicate), fails('bundle_identity_item'));
});

test('identity version times match the strict UTC calendar grammar including leap years', () => {
  for (const time of ['2024-02-29T23:59:59.123456789Z', '2000-02-29T00:00:00+00:00', '0000-02-29T00:00:00Z']) {
    const value = bundle(); value.identityLogs[0].versionTime = time;
    assert.doesNotThrow(() => validateBundleGraph(value));
  }
  for (const time of ['2026-02-29T00:00:00Z', '1900-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:60Z', '2026-01-01T00:00:00-00:00', '2026-01-01T00:00:00Z\n']) {
    const value = bundle(); value.identityLogs[0].versionTime = time;
    assert.throws(() => validateBundleGraph(value), fails('bundle_identity_item'));
  }
});

test('identity version times preserve PHP fractional overflow and date rollover behavior', () => {
  for (const time of [`2026-09-19T00:00:00.${'0'.repeat(1000)}Z`, `2026-09-19T23:59:59.${'9'.repeat(17)}+00:00`]) {
    const value = bundle(); value.identityLogs[0].versionTime = time;
    assert.doesNotThrow(() => validateBundleGraph(value));
  }
  for (const time of [`2026-09-19T00:00:00.${'1'.repeat(1000)}Z`, `2026-09-19T23:59:59.${'9'.repeat(16)}+00:00`]) {
    const value = bundle(); value.identityLogs[0].versionTime = time;
    assert.throws(() => validateBundleGraph(value), fails('bundle_identity_item'));
  }
});

test('identity log order and exact content-addressed paths reject substitutions', () => {
  const order = bundle(); order.identityLogs.push({ ...order.identityLogs[0], receiptSha256: artifactHash, receiptPath: `identity/checkpoints/${artifactHash}.json` });
  assert.throws(() => validateBundleGraph(order), fails('bundle_identity_order'));
  for (const field of ['logPath', 'receiptPath', 'archiveReferencePath']) {
    const value = bundle(); value.identityLogs[0][field] = 'wrong';
    assert.throws(() => validateBundleGraph(value), fails('bundle_identity_path'));
  }
  const value = bundle(); value.identityLogs[0].timestampPaths = [`identity/checkpoints/${receiptHash}/timestamps/${artifactHash}.ots\n`];
  assert.throws(() => validateBundleGraph(value), fails('bundle_artifact_path'));
});

test('leaf-inventory references require the exact hash-addressed path and shape', () => {
  for (const change of [{ path: 'wrong' }, { checkpointSha256: `${checkpointHash}\n` }, { extra: true }]) {
    const value = bundle(); Object.assign(value.leafInventories[0], change);
    assert.throws(() => validateBundleGraph(value), fails('bundle_leaf_reference'));
  }
});

test('each direct graph file must exist, including all optional supporting files', async () => {
  const value = bundle();
  value.records[0].signaturePath = `records/${uuid}/signature.jws`;
  value.records[0].archiveReferencePath = `records/${uuid}/archive-references.json`;
  value.records[0].inclusionProofPaths = [`records/${uuid}/inclusion/${checkpointHash}.json`];
  value.records[0].timestampPaths = [`records/${uuid}/timestamps/${artifactHash}.ots`];
  value.checkpoints[0].archiveReferencePath = `transparency/checkpoints/${checkpointHash}/archive-references.json`;
  value.checkpoints[0].timestampPaths = [`transparency/checkpoints/${checkpointHash}/timestamps/${artifactHash}.ots`];
  value.identityLogs[0].archiveReferencePath = `identity/checkpoints/${receiptHash}/archive-references.json`;
  value.identityLogs[0].timestampPaths = [`identity/checkpoints/${receiptHash}/timestamps/${artifactHash}.ots`];
  const graph = validateBundleGraph(value);
  const files = entries();
  const optional = [graph.records[0].signaturePath!, graph.records[0].archiveReferencePath!, ...graph.records[0].inclusionProofPaths, ...graph.records[0].timestampPaths, graph.checkpoints[0].archiveReferencePath!, ...graph.checkpoints[0].timestampPaths, graph.identities[0].archiveReferencePath!, ...graph.identities[0].timestampPaths];
  for (const path of optional) files.set(path, Buffer.from('unverified optional bytes'));
  await verifyGraphReferences(StrictZip.parse(fixtureZip(files)), graph);
  for (const path of files.keys()) {
    const missing = new Map(files); missing.delete(path);
    await assert.rejects(verifyGraphReferences(StrictZip.parse(fixtureZip(missing)), graph), fails('zip_entry_missing'));
  }
});

test('identity and manifest graph hashes bind the exact bytes, independently of inventory hashes', async () => {
  const graph = validateBundleGraph(bundle());
  for (const [path, code] of [[graph.identities[0].logPath, 'identity_graph_digest'], [graph.identities[0].receiptPath, 'identity_graph_digest'], [graph.records[0].manifestPath, 'manifest_graph_digest']]) {
    const files = entries(); files.set(path, Buffer.from('substituted bytes'));
    await assert.rejects(verifyGraphReferences(StrictZip.parse(fixtureZip(files)), graph), fails(code));
  }
});

test('byte-reference closure rejects undeclared files without claiming semantic scope closure', async () => {
  const files = entries(); files.set(`records/${uuid}/signature.jws`, Buffer.from('unreferenced'));
  await assert.rejects(verifyGraphReferences(StrictZip.parse(fixtureZip(files)), validateBundleGraph(bundle())), fails('bundle_orphan_entry'));
});

test('graph references still enforce role limits before materializing supporting file bytes', async () => {
  const files = entries(); files.set(`transparency/checkpoints/${checkpointHash}/checkpoint.jws`, Buffer.alloc(131073));
  await assert.rejects(verifyGraphReferences(StrictZip.parse(fixtureZip(files)), validateBundleGraph(bundle())), fails('zip_entry_limit'));
});
