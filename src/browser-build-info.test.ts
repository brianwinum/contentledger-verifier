// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { BROWSER_BUILD_INFO, parseBrowserBuildInfo } from './browser-build-info';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';
import { browserReport, reportFileName } from './browser-report';
import type { CheckResult } from './model';

function metadata() {
  return {
    schemaVersion: 1,
    kind: 'contentledger-browser-build',
    appVersion: BROWSER_APP_VERSION,
    verifierVersion: BROWSER_VERIFIER_VERSION,
    sourceSha256: 'a'.repeat(64),
    sourceFileCount: 123,
    dependencyLockSha256: 'b'.repeat(64),
    toolchain: { node: '24.13.0', vite: '8.0.3', typescript: '7.0.2' },
    releaseStatus: 'development-unpublished',
    sourceRevision: null,
  };
}

function result(): CheckResult {
  return {
    schemaVersion: 1, checkedAt: '2026-09-19T16:19:20Z',
    appVersion: BROWSER_APP_VERSION, verifierVersion: BROWSER_VERIFIER_VERSION,
    fileName: 'C:\\Private\\customer-evidence.zip', packageSha256: 'c'.repeat(64),
    outcome: 'could_not_check', code: 'browser_crypto_unavailable',
    message: 'No completed verification result is available.',
    expectations: { did: 'did:webvh:private.example', manifestSha256: 'd'.repeat(64) },
    layers: [{ layer: 'capability', status: 'unsupported', code: 'browser_crypto_unavailable', message: 'private-layer-message', details: { privateValue: 'private-layer-details' } }],
  };
}

test('build metadata is unavailable outside a compiled production browser build', () => {
  assert.equal(BROWSER_BUILD_INFO, null);
  assert.equal(browserReport(result()).checkerBuild, null);
});

test('build metadata accepts only the exact bounded current-development schema', () => {
  assert.deepEqual(parseBrowserBuildInfo(metadata()), metadata());
  const preview = { ...metadata(), releaseStatus: 'development-preview', sourceRevision: 'c'.repeat(40) };
  assert.deepEqual(parseBrowserBuildInfo(preview), preview);
  for (const value of [undefined, null, false, 1, 'build', [], [metadata()], new Date()]) {
    assert.equal(parseBrowserBuildInfo(value), null);
  }
  for (const key of Object.keys(metadata())) {
    const missing: Record<string, unknown> = metadata();
    delete missing[key];
    assert.equal(parseBrowserBuildInfo(missing), null, `missing ${key}`);
  }
  for (const extra of ['filename', 'buildTime', 'gitBranch', 'sourceFiles', 'machine', 'url']) {
    assert.equal(parseBrowserBuildInfo({ ...metadata(), [extra]: 'private-value' }), null, extra);
  }
  for (const [key, value] of [
    ['schemaVersion', '1'], ['schemaVersion', 2], ['kind', 'signed-release'],
    ['appVersion', '0.1.3'], ['verifierVersion', '3.0.0'],
    ['releaseStatus', 'released'], ['releaseStatus', 'development-preview'], ['sourceRevision', 'a'.repeat(40)],
  ] as const) {
    assert.equal(parseBrowserBuildInfo({ ...metadata(), [key]: value }), null, key);
  }
  for (const sourceRevision of ['', 'a'.repeat(39), 'a'.repeat(41), 'A'.repeat(40), `${'a'.repeat(40)}\n`, '../private']) {
    assert.equal(parseBrowserBuildInfo({ ...metadata(), releaseStatus: 'development-preview', sourceRevision }), null, sourceRevision);
  }
  assert.equal(parseBrowserBuildInfo(Object.create(metadata())), null, 'inherited fields are not metadata');
});

test('source and dependency identities require exact lowercase SHA-256 values', () => {
  for (const key of ['sourceSha256', 'dependencyLockSha256']) {
    for (const value of [null, 123, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), `${'a'.repeat(64)}\n`, ` ${'a'.repeat(64)}`, '../private-file']) {
      assert.equal(parseBrowserBuildInfo({ ...metadata(), [key]: value }), null, `${key}: ${String(value)}`);
    }
  }
  for (const sourceFileCount of [1, 1000]) assert.equal(parseBrowserBuildInfo({ ...metadata(), sourceFileCount })?.sourceFileCount, sourceFileCount);
  for (const sourceFileCount of [undefined, null, '123', 0, -1, 1.1, 1001, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(parseBrowserBuildInfo({ ...metadata(), sourceFileCount }), null);
  }
});

test('toolchain data contains only three bounded public version strings', () => {
  for (const toolchain of [null, [], {}, { node: '24.13.0', vite: '8.0.3' }, { ...metadata().toolchain, cwd: 'C:\\Private' }, Object.create(metadata().toolchain)]) {
    assert.equal(parseBrowserBuildInfo({ ...metadata(), toolchain }), null);
  }
  for (const key of ['node', 'vite', 'typescript'] as const) {
    for (const value of [null, 24, '', 'v24.13.0', '24', '24.13', '24.13.0\n', '24.13.0\r', '24.13.0\u0000', '24.13.0 private', '24.13.0/path', '24.13.0_under', '24.13.0-'.concat('a'.repeat(81))]) {
      assert.equal(parseBrowserBuildInfo({ ...metadata(), toolchain: { ...metadata().toolchain, [key]: value } }), null, `${key}: ${String(value)}`);
    }
    const valid = { ...metadata(), toolchain: { ...metadata().toolchain, [key]: '24.13.0-beta.1+build.2' } };
    assert.deepEqual(parseBrowserBuildInfo(valid), valid);
  }
});

test('accepted metadata is a copied, deeply frozen public snapshot', () => {
  const source = metadata();
  const parsed = parseBrowserBuildInfo(source);
  assert.ok(parsed);
  assert.notEqual(parsed, source);
  assert.notEqual(parsed.toolchain, source.toolchain);
  assert.ok(Object.isFrozen(parsed));
  assert.ok(Object.isFrozen(parsed.toolchain));
  source.sourceSha256 = 'e'.repeat(64);
  source.toolchain.node = '99.0.0';
  assert.equal(parsed.sourceSha256, 'a'.repeat(64));
  assert.equal(parsed.toolchain.node, '24.13.0');
  assert.throws(() => { (parsed as { sourceFileCount: number }).sourceFileCount = 9; }, TypeError);
  assert.throws(() => { (parsed.toolchain as { node: string }).node = '99.0.0'; }, TypeError);

  // Non-enumerable/inherited hooks cannot influence the copied serialization.
  const withHooks = Object.assign(Object.create({ privatePath: 'private-inherited-path' }), metadata());
  Object.defineProperty(withHooks, 'toJSON', { value: () => ({ privatePath: 'private-serialization-hook' }) });
  const copied = parseBrowserBuildInfo(withHooks);
  assert.deepEqual(copied, metadata());
  assert.doesNotMatch(JSON.stringify(copied), /private-/);
});

test('saved report build identity requires matching checker and verifier versions', () => {
  const r = result();
  const build = metadata();
  assert.deepEqual(browserReport(r, build).checkerBuild, build);
  for (const changed of [
    { ...r, appVersion: '0.8.0-dev' },
    { ...r, verifierVersion: 'browser-0.8.0-dev' },
    { ...r, appVersion: '0.1.3', verifierVersion: '3.0.0' },
  ]) assert.equal(browserReport(changed, build).checkerBuild, null);
  for (const value of [null, undefined, { ...build, appVersion: '0.8.0-dev' }, { ...build, sourceSha256: 'invalid' }, { ...build, fileName: r.fileName }]) {
    assert.equal(browserReport(r, value).checkerBuild, null);
  }
});

test('build identity cannot change a result, its package digest or its download name', () => {
  const r = result();
  const before = structuredClone(r);
  const report = browserReport(r, metadata());
  assert.deepEqual(r, before);
  assert.equal(report.outcome, r.outcome);
  assert.equal(report.code, r.code);
  assert.equal(report.packageSha256, r.packageSha256);
  assert.notEqual(report.packageSha256, report.checkerBuild?.sourceSha256);
  assert.notEqual(report.packageSha256, report.checkerBuild?.dependencyLockSha256);
  assert.equal(reportFileName(r), 'contentledger-check-summary-cccccccccccc-20260919T161920Z.json');
  assert.match(report.checkerBuildNotice, /not a signed release/);
  assert.match(report.checkerBuildNotice, /Null means no matching production-build identity/);
});

test('reports retain redaction and an independent frozen build snapshot', () => {
  const r = result(), build = metadata();
  const report = browserReport(r, build);
  const saved = JSON.stringify(report);
  for (const secret of [r.fileName, r.expectations.did!, r.expectations.manifestSha256!, 'private-layer-message', 'private-layer-details']) {
    assert.ok(!saved.includes(secret), secret);
  }
  assert.deepEqual(report.expectationsSupplied, { bundleSha256: false, checkpointSha256: false, manifestSha256: true, did: true, recordUuid: false });
  assert.deepEqual(report.checks, [{ layer: 'capability', status: 'unsupported', code: 'browser_crypto_unavailable' }]);
  build.sourceSha256 = 'f'.repeat(64);
  build.toolchain.vite = '99.0.0';
  assert.equal(JSON.stringify(report), saved);
  assert.ok(Object.isFrozen(report.checkerBuild));
  assert.ok(Object.isFrozen(report.checkerBuild?.toolchain));
});
