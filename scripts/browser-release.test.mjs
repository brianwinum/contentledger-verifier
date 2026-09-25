// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import {
  assertPlainTree, assetPath, collectBrowserAssets, compareBrowserAssets, createReleaseManifest,
  MANIFEST_NAME, MAX_ASSET_BYTES, MAX_ASSET_FILES, MAX_TOTAL_ASSET_BYTES, stableJson,
  validateAssetInventory, validateReleaseManifest, verifyBrowserArtifact,
} from './browser-release-lib.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const provenance = () => ({
  schemaVersion: 1, kind: 'contentledger-browser-build', appVersion: '1.0.0', verifierVersion: 'browser-1.0.0',
  sourceSha256: 'a'.repeat(64), sourceFileCount: 44, dependencyLockSha256: 'b'.repeat(64),
  toolchain: { node: '24.0.0', vite: '8.3.0', typescript: '7.0.2' }, releaseStatus: 'local-unpublished', sourceRevision: null,
});
const productionProvenance = () => ({ ...provenance(), releaseStatus: 'production', sourceRevision: 'c'.repeat(40) });
function temporary(context) {
  const parent = realpathSync(tmpdir()), path = mkdtempSync(join(parent, 'contentledger-browser-release-test-'));
  context.after(() => {
    // Delete only this exclusively created test directory; never a caller path.
    if (dirname(path) !== parent || !basename(path).startsWith('contentledger-browser-release-test-') || realpathSync(path) !== path || lstatSync(path).isSymbolicLink()) throw new Error('Unsafe test cleanup target.');
    rmSync(path, { recursive: true });
  });
  return path;
}
function output(parent, name = 'app') {
  const path = join(parent, name); mkdirSync(path); mkdirSync(join(path, 'assets'));
  writeFileSync(join(path, 'index.html'), '<!doctype html><title>Synthetic inventory fixture only</title>');
  writeFileSync(join(path, 'assets/index-A1.js'), 'export const synthetic=true;\n');
  writeFileSync(join(path, 'assets/index-A1.css'), 'body{color:#111}\n');
  return path;
}
function artifact(parent) {
  const directory = join(parent, 'artifact'); mkdirSync(directory);
  const app = output(directory), assets = collectBrowserAssets(app);
  const manifest = createReleaseManifest(provenance(), assets, assets);
  writeFileSync(join(directory, MANIFEST_NAME), stableJson(manifest));
  return { directory, app, assets, manifest };
}
function pin(path, bytes = 1) { return { path, bytes, sha256: 'a'.repeat(64) }; }
const minimum = () => [pin('assets/a.css'), pin('assets/a.js'), pin('index.html')];

test('asset inventory uses sorted exact relative paths, byte lengths and raw-byte SHA-256', context => {
  const root = temporary(context), directory = output(root);
  const assets = collectBrowserAssets(directory);
  assert.deepEqual(assets.map(asset => asset.path), ['assets/index-A1.css', 'assets/index-A1.js', 'index.html']);
  for (const asset of assets) {
    const bytes = readFileSync(join(directory, asset.path));
    assert.equal(asset.bytes, bytes.length); assert.equal(asset.sha256, sha(bytes));
  }
  assert.doesNotThrow(() => compareBrowserAssets(assets, assets.map(({ path, bytes, sha256 }) => ({ sha256, bytes, path }))));
});

test('strict asset paths reject escapes, platform aliases and unreviewed source/runtime files', () => {
  for (const name of ['', '../index.html', '/index.html', 'C:/index.html', 'assets\\a.js', 'assets/../index.html', 'assets//a.js', 'assets/a.js\n', 'index.html\n',
    'assets/con.js', 'assets/NUL.css', 'assets/a.js.map', 'package.json', 'browser-release-manifest.json', 'src/a.ts', 'assets/.hidden.js', 'assets/a.php', 'assets/a.exe', 'assets/a.zip', 'assets/é.js']) assert.throws(() => assetPath('.', name), undefined, name);
  assert.equal(assetPath('.', 'assets/index-A_1.js'), resolve('assets/index-A_1.js'));
});

test('malformed inventories reject wrong shapes, order, duplicates, aliases, hashes and missing roles', () => {
  for (const invalid of [null, {}, [], [pin('index.html')], [...minimum()].reverse(), [...minimum(), pin('index.html')],
    [pin('assets/A.css'), pin('assets/a.css'), pin('assets/a.js'), pin('index.html')],
    minimum().map((asset, index) => index === 0 ? { ...asset, extra: true } : asset),
    minimum().map((asset, index) => index === 0 ? { ...asset, sha256: 'A'.repeat(64) } : asset),
    minimum().map((asset, index) => index === 0 ? { ...asset, sha256: 'a'.repeat(64) + '\n' } : asset),
    [pin('assets/a.js'), pin('assets/b.js'), pin('index.html')]]) assert.throws(() => validateAssetInventory(invalid));
});

test('inventory numeric and aggregate bounds reject impossible data without large allocations', () => {
  for (const bytes of [-1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', MAX_ASSET_BYTES + 1]) {
    const assets = minimum(); assets[0].bytes = bytes; assert.throws(() => validateAssetInventory(assets));
  }
  const total = minimum(); total[0].bytes = total[1].bytes = MAX_ASSET_BYTES;
  assert.throws(() => validateAssetInventory(total));
  total[2].bytes = 0; assert.equal(total.reduce((sum, item) => sum + item.bytes, 0), MAX_TOTAL_ASSET_BYTES);
  assert.doesNotThrow(() => validateAssetInventory(total));
  const many = Array.from({ length: MAX_ASSET_FILES + 1 }, (_, index) => pin(`assets/a${index.toString().padStart(3, '0')}.js`));
  assert.throws(() => validateAssetInventory(many));
});

test('repeated-build comparison rejects changed bytes, names, missing and additional outputs', () => {
  const assets = minimum();
  for (const change of [
    value => { value[0].sha256 = 'b'.repeat(64); }, value => { value[0].bytes++; },
    value => { value[0].path = 'assets/changed.css'; }, value => { value.splice(0, 1); },
    value => { value.splice(2, 0, pin('assets/b.js')); },
  ]) { const second = structuredClone(assets); change(second); assert.throws(() => compareBrowserAssets(assets, second)); assert.throws(() => createReleaseManifest(provenance(), assets, second)); }
});

test('manifest serialization is deterministic and omits host paths, clocks, identities and Git assumptions', () => {
  const assets = minimum(), first = createReleaseManifest(provenance(), assets, assets), second = createReleaseManifest(provenance(), structuredClone(assets), structuredClone(assets));
  assert.equal(stableJson(first), stableJson(second));
  assert.equal(first.repeatedBuildsIdentical, true);
  assert.equal(first.status, 'local-unpublished');
  assert.equal(first.provenance.sourceRevision, null);
  assert.equal(first.assetSetSha256, sha(stableJson(assets)));
  assert.match(first.limitations.join(' '), /Unsigned local integrity record/);
  assert.match(first.limitations.join(' '), /do not authenticate installed dependency bytes/);
  assert.doesNotMatch(stableJson(first), /C:\\|\/Users\/|\/home\/|createdAt|timestamp|username|hostname/);
  assets[0].bytes = 99;
  assert.equal(first.assets[0].bytes, 1, 'Manifest owns an inventory snapshot.');
});

test('revision-bound production releases retain their exact deployment identity', () => {
  const value = createReleaseManifest(productionProvenance(), minimum(), minimum());
  assert.equal(value.status, 'production');
  assert.equal(value.provenance.releaseStatus, 'production');
  assert.equal(value.provenance.sourceRevision, 'c'.repeat(40));
  assert.deepEqual(validateReleaseManifest(value), value);
});

test('manifest refuses unbounded, extra, forged-release or malformed provenance fields', () => {
  for (const change of [
    value => { value.sourceFileCount = 0; }, value => { value.sourceFileCount = 1001; }, value => { value.sourceSha256 += '\n'; },
    value => { value.sourceRevision = 'invented'; }, value => { value.releaseStatus = 'published'; }, value => { value.absolutePath = 'private'; },
    value => { value.releaseStatus = 'production'; },
    value => { value.releaseStatus = 'production'; value.sourceRevision = 'C'.repeat(40); },
    value => { value.appVersion += '\n'; value.verifierVersion += '\n'; }, value => { value.toolchain.node = '24.0.0\n'; },
    value => { value.toolchain.node = 'v24.0.0'; }, value => { value.toolchain.vite = 'file:/private'; }, value => { value.toolchain.extra = '1.0.0'; },
  ]) { const value = provenance(); change(value); assert.throws(() => createReleaseManifest(value, minimum(), minimum())); }
  for (const change of [
    value => { value.repeatedBuildsIdentical = false; }, value => { value.checks.productionBuilds = 1; },
    value => { value.status = 'published'; }, value => { value.assetRoot = '../app'; }, value => { value.assetSetSha256 = 'f'.repeat(64); },
    value => { value.status = 'production'; },
    value => { value.limitations = []; }, value => { value.extra = true; },
  ]) { const value = createReleaseManifest(provenance(), minimum(), minimum()); change(value); assert.throws(() => validateReleaseManifest(value)); }
});

test('read-only artifact verification detects changed, missing and additional files', context => {
  const root = temporary(context), fixture = artifact(root);
  const original = readFileSync(join(fixture.app, 'assets/index-A1.js'));
  assert.equal(verifyBrowserArtifact(fixture.directory).assetSetSha256, fixture.manifest.assetSetSha256);
  writeFileSync(join(fixture.app, 'assets/index-A1.js'), 'changed bytes');
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
  writeFileSync(join(fixture.app, 'assets/index-A1.js'), original);
  renameSync(join(fixture.app, 'assets/index-A1.js'), join(root, 'held.js'));
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
  renameSync(join(root, 'held.js'), join(fixture.app, 'assets/index-A1.js'));
  writeFileSync(join(fixture.app, 'assets/extra.js'), 'extra');
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
});

test('artifact verification rejects extra top-level entries and noncanonical or altered manifests', context => {
  const root = temporary(context), fixture = artifact(root), path = join(fixture.directory, MANIFEST_NAME);
  const original = readFileSync(path);
  writeFileSync(path, JSON.stringify(fixture.manifest));
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
  writeFileSync(path, '{"schemaVersion":1,"schemaVersion":1}\n');
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
  writeFileSync(path, original);
  writeFileSync(join(fixture.directory, 'unexpected.txt'), 'extra');
  assert.throws(() => verifyBrowserArtifact(fixture.directory));
});

test('nested directories and stale source maps fail instead of being omitted from inventories', context => {
  const root = temporary(context), directory = output(root);
  mkdirSync(join(directory, 'assets/nested'));
  assert.throws(() => collectBrowserAssets(directory));
  const second = output(root, 'second');
  writeFileSync(join(second, 'assets/a.js.map'), '{}');
  assert.throws(() => collectBrowserAssets(second));
});

test('tree preflight refuses nested redirection without following it or altering the target', context => {
  const root = temporary(context), directory = output(root), target = join(root, 'target'); mkdirSync(target);
  writeFileSync(join(target, 'sentinel.txt'), 'unchanged');
  const link = join(directory, 'assets/redirected');
  try { symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { context.skip('This host does not permit a local symlink/junction test.'); return; } throw error; }
  assert.throws(() => assertPlainTree(directory));
  assert.throws(() => collectBrowserAssets(directory));
  assert.equal(readFileSync(join(target, 'sentinel.txt'), 'utf8'), 'unchanged');
});

test('tree preflight bounds traversal depth and entry count', context => {
  const root = temporary(context); let directory = root;
  for (let depth = 0; depth < 10; depth++) { directory = join(directory, 'a'); mkdirSync(directory); }
  assert.throws(() => assertPlainTree(root));
  const small = join(root, 'small'); mkdirSync(small); writeFileSync(join(small, 'one'), ''); writeFileSync(join(small, 'two'), '');
  assert.throws(() => assertPlainTree(small, 1));
  assert.doesNotThrow(() => assertPlainTree(small, 2));
});

test('verification never rewrites the manifest or production files', context => {
  const root = temporary(context), fixture = artifact(root);
  const before = readFileSync(join(fixture.directory, MANIFEST_NAME));
  const assets = collectBrowserAssets(fixture.app);
  verifyBrowserArtifact(fixture.directory); verifyBrowserArtifact(fixture.directory);
  assert.deepEqual(readFileSync(join(fixture.directory, MANIFEST_NAME)), before);
  assert.deepEqual(collectBrowserAssets(fixture.app), assets);
  assert.equal(existsSync(join(fixture.directory, 'source')), false);
});
