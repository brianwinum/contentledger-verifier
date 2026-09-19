// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyBrowserPackage } from '../src/verifier/engine';

interface FixtureExpectation {
  file: string;
  bytes: number;
  sha256: string;
  outcome: 'passed_with_limitations' | 'failed';
  code: string;
}

const manifest = JSON.parse(readFileSync(new URL('./corpus-manifest.json', import.meta.url), 'utf8')) as {
  schemaVersion: number;
  kind: string;
  fixtures: FixtureExpectation[];
};

test('the checked-in public corpus has a fixed shape', () => {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.kind, 'contentledger-public-conformance-corpus');
  assert.equal(manifest.fixtures.length, 13);
  assert.equal(new Set(manifest.fixtures.map(item => item.file)).size, manifest.fixtures.length);
  assert.ok(manifest.fixtures.some(item => item.outcome === 'passed_with_limitations'));
  assert.ok(manifest.fixtures.some(item => item.outcome === 'failed'));
});

for (const fixture of manifest.fixtures) {
  test(`public conformance fixture: ${fixture.file}`, async () => {
    const bytes = readFileSync(new URL(`./fixtures/${fixture.file}`, import.meta.url));
    assert.equal(bytes.byteLength, fixture.bytes);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), fixture.sha256);
    const result = await verifyBrowserPackage(bytes, {}, { fileName: fixture.file, checkedAt: '2026-09-19T00:00:00.000Z' });
    assert.equal(result.packageSha256, fixture.sha256);
    assert.equal(result.outcome, fixture.outcome);
    assert.equal(result.code, fixture.code);
    assert.equal(result.layers.at(-1)?.code, fixture.code);
  });
}
