// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fixtureEntries, fixtureZip } from '../../tests/browser-test-support';
import { decodeCanonicalObject } from './canonical';
import { verifyBrowserPackage } from './engine';
import { validateBundleGraph } from './graph';
import { verifyManifest } from './manifest';
import { verifySignatureIntegrity } from './signature-integrity';
import { StrictZip } from './zip';
import { parseBrowserResult } from '../platform-browser-protocol';

const fixture = (name: string) => readFileSync(new URL(`../../tests/fixtures/${name}.zip`, import.meta.url));
const readGraph = (bytes: Uint8Array) => {
  const zip = StrictZip.parse(bytes);
  return { zip, graph: validateBundleGraph(decodeCanonicalObject(zip.read('bundle.json'))) };
};
const metadata = { fileName: 'synthetic-signature.zip', checkedAt: '2026-09-19T00:00:00.000Z' };

test('signature integration checks records and checkpoints but not identity authorization', async () => {
  for (const name of ['record', 'url-history', 'checkpoint', 'site']) {
    const { zip, graph } = readGraph(fixture(name));
    const manifests = await Promise.all(graph.records.map(item => verifyManifest(zip.read(item.manifestPath), item.entryId.slice(9), item.manifestSha256)));
    assert.deepEqual(await verifySignatureIntegrity(zip, graph, manifests), {
      recordSignatures: graph.records.filter(item => item.signaturePath !== null).length,
      checkpointSignatures: graph.checkpoints.length, unsupportedRecordSignatures: 0,
    });
  }
});

test('unknown manifest dependencies inspect compact bytes without claiming record signature verification', async () => {
  const { zip, graph } = readGraph(fixture('invalid-signature'));
  graph.checkpoints = [];
  const result = await verifySignatureIntegrity(zip, graph, []);
  assert.equal(result.recordSignatures, 0);
  assert.equal(result.unsupportedRecordSignatures, 1);
  const entries = fixtureEntries(fixture('record'));
  entries.set(graph.records[0].signaturePath!, Buffer.from('not a compact signature'));
  await assert.rejects(verifySignatureIntegrity(StrictZip.parse(fixtureZip(entries)), graph, []), { code: 'jws_compact' });
});

test('checkpoint JWS binds exact document bytes, not merely a valid signature over other bytes', async () => {
  const bytes = fixture('checkpoint');
  const { graph } = readGraph(bytes);
  const entries = fixtureEntries(bytes);
  const path = graph.checkpoints[0].documentPath;
  entries.set(path, Buffer.concat([entries.get(path)!, Buffer.from('\n')]));
  await assert.rejects(verifySignatureIntegrity(StrictZip.parse(fixtureZip(entries)), graph, []), { code: 'jws_payload_binding' });
});

test('checkpoint graph digest must bind the signed document even when the JWS is mathematically valid', async () => {
  const { zip, graph } = readGraph(fixture('checkpoint'));
  graph.checkpoints[0].checkpointSha256 = '0'.repeat(64);
  await assert.rejects(verifySignatureIntegrity(zip, graph, []), { code: 'checkpoint_graph_binding' });
});

test('missing or unqualified native crypto never labels a package corrupt or successful', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  const original = globalThis.crypto;
  try {
    for (const mode of ['missing', 'permissive', 'crash']) {
      const subtle = {
        digest: original.subtle.digest.bind(original.subtle),
        importKey: mode === 'missing' ? undefined : async () => ({}),
        verify: async () => { if (mode === 'crash') throw new Error('private runtime details'); return true; },
      };
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle } });
      const result = await verifyBrowserPackage(fixture('record'), {}, metadata);
      assert.equal(result.outcome, 'could_not_check');
      assert.equal(result.code, mode === 'missing' ? 'browser_ed25519_unavailable' : 'browser_ed25519_unqualified');
      assert.match(result.packageSha256!, /^[a-f0-9]{64}$/);
      assert.equal(result.layers.some(layer => layer.status === 'invalid' || layer.layer === 'signature_integrity' && layer.status === 'valid'), false);
      assert.equal(JSON.stringify(result).includes('private runtime details'), false);
      assert.equal(parseBrowserResult(result, { ...metadata, expectations: {} }), result);
    }
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor);
  }
});
