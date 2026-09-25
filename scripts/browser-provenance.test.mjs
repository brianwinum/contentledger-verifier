// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertBrowserBuildEnvironment, BROWSER_SOURCE_PATHS, browserDeploymentIdentity, collectBrowserProvenance, collectBrowserSourceInventory } from './browser-provenance.mjs';

const app = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporaryParent = realpathSync(tmpdir());
function temporaryApp(t) {
  const root = mkdtempSync(join(temporaryParent, 'contentledger-provenance-test-'));
  t.after(() => {
    // Only remove this newly created test directory, never a caller path.
    assert.equal(dirname(resolve(root)), temporaryParent);
    assert.ok(basename(root).startsWith('contentledger-provenance-test-'));
    assert.equal(lstatSync(root).isSymbolicLink(), false);
    assert.equal(realpathSync(root), resolve(root));
    rmSync(root, { recursive: true, force: false });
  });
  for (const name of [...BROWSER_SOURCE_PATHS, 'node_modules/vite/package.json', 'node_modules/typescript/package.json']) {
    const target = join(root, name); mkdirSync(dirname(target), { recursive: true }); copyFileSync(join(app, name), target);
  }
  return root;
}
function write(root, name, value) {
  const path = join(root, name); mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value));
}
function editJson(root, name, mutate) {
  const value = JSON.parse(readFileSync(join(root, name), 'utf8')); mutate(value); write(root, name, value);
}
function hash(value) { return createHash('sha256').update(value).digest('hex'); }

test('provenance is deterministic, sorted, exact-byte and contains only bounded public identity', t => {
  const root = temporaryApp(t), inventory = collectBrowserSourceInventory(root), result = collectBrowserProvenance(root);
  assert.deepEqual(collectBrowserProvenance(root), result);
  assert.deepEqual(inventory.map(value => value.path), [...BROWSER_SOURCE_PATHS].sort());
  assert.equal(new Set(inventory.map(value => value.path)).size, inventory.length);
  for (const item of inventory) {
    assert.match(item.path, /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/);
    const bytes = readFileSync(join(root, item.path));
    assert.equal(item.bytes, bytes.length); assert.equal(item.sha256, hash(bytes));
  }
  assert.equal(result.sourceSha256, hash(JSON.stringify({ schemaVersion: 1, files: inventory }) + '\n'));
  assert.equal(result.sourceFileCount, inventory.length);
  assert.equal(result.dependencyLockSha256, hash(readFileSync(join(root, 'package-lock.json'))));
  assert.equal(result.releaseStatus, 'local-unpublished'); assert.equal(result.sourceRevision, null);
  assert.equal(result.verifierVersion, `browser-${result.appVersion}`);
  assert.deepEqual(Object.keys(result.toolchain), ['node', 'vite', 'typescript']);
  assert.equal(result.toolchain.node, process.versions.node);
  assert.doesNotMatch(JSON.stringify(result), /[\\/]|timestamp|builtAt|committed|file:|userName/i);
});
test('reviewed raw source changes affect identity, while non-production paths are excluded', t => {
  const root = temporaryApp(t), original = collectBrowserProvenance(root);
  for (const name of ['src/unrelated.test.ts', 'tests/fixtures/public.zip', 'dist-browser/index.html', 'build-output/local.js', 'scripts/unrelated.mjs']) write(root, name, 'synthetic excluded test data');
  assert.deepEqual(collectBrowserProvenance(root), original);
  write(root, 'src/tokens.css', readFileSync(join(root, 'src/tokens.css'), 'utf8') + '\n/* reviewed byte change */\n');
  const changed = collectBrowserProvenance(root);
  assert.notEqual(changed.sourceSha256, original.sourceSha256);
  assert.equal(changed.dependencyLockSha256, original.dependencyLockSha256);
});
test('new unreviewed or desktop production modules and resource files fail closed', t => {
  const root = temporaryApp(t);
  for (const name of ['src/extra.ts', 'src/extra.css', 'src/extra.js', 'src/extra.json', 'src/new/extra.ts', 'src/platform-desktop.ts']) {
    write(root, name, 'synthetic'); assert.throws(() => collectBrowserProvenance(root), /unreviewed production input/); unlinkSync(join(root, name));
  }
});
test('missing, empty, oversized and aggregate-oversized source inputs are rejected', t => {
  const root = temporaryApp(t), path = join(root, 'src/tokens.css'), original = readFileSync(path);
  unlinkSync(path); assert.throws(() => collectBrowserProvenance(root));
  writeFileSync(path, ''); assert.throws(() => collectBrowserProvenance(root), /bounded regular file/);
  writeFileSync(path, Buffer.alloc(1024 * 1024 + 1, 65)); assert.throws(() => collectBrowserProvenance(root), /bounded regular file/);
  writeFileSync(path, original);
  for (const name of BROWSER_SOURCE_PATHS.filter(name => name.startsWith('src/') && name !== 'src/browser-version.ts').slice(0, 9)) write(root, name, Buffer.alloc(1024 * 1024, 65));
  assert.throws(() => collectBrowserSourceInventory(root), /aggregate bound/);
});
test('environment files, ambient build overrides and production environment dependencies are rejected without values', t => {
  const root = temporaryApp(t);
  for (const name of ['.env', '.env.local', '.env.browser', '.env.production.local']) {
    write(root, name, 'PRIVATE_VALUE=never-print-this');
    assert.throws(() => collectBrowserProvenance(root), error => /do not accept .env/.test(error.message) && !error.message.includes('never-print-this'));
    unlinkSync(join(root, name));
  }
  for (const name of ['VITE_SECRET', 'TAURI_ENV_KEY', 'NODE_OPTIONS', 'NODE_PATH', 'BROWSERSLIST_CONFIG', 'ROLLDOWN_MODE', 'ROLLUP_CACHE', 'BABEL_ENV']) assert.throws(() => assertBrowserBuildEnvironment(root, { [name]: 'never-print-this' }), /ambient build overrides/);
  assert.throws(() => assertBrowserBuildEnvironment(root, { NODE_ENV: 'development' }), /NODE_ENV/);
  assert.doesNotThrow(() => assertBrowserBuildEnvironment(root, {}));
  assert.doesNotThrow(() => assertBrowserBuildEnvironment(root, { NODE_ENV: 'production', UNRELATED_OPERATOR_LABEL: 'ignored' }));
  assert.doesNotThrow(() => assertBrowserBuildEnvironment(root, { CONTENTLEDGER_BROWSER_AUDIT_OUTPUT: 'audit-only' }));
  assert.deepEqual(browserDeploymentIdentity({}), { releaseStatus: 'local-unpublished', sourceRevision: null });
  const production = { CONTENTLEDGER_BROWSER_RELEASE_STATUS: 'production', CONTENTLEDGER_BROWSER_SOURCE_REVISION: 'a'.repeat(40) };
  assert.deepEqual(browserDeploymentIdentity(production), { releaseStatus: 'production', sourceRevision: 'a'.repeat(40) });
  assert.doesNotThrow(() => assertBrowserBuildEnvironment(root, production));
  for (const environment of [
    { CONTENTLEDGER_BROWSER_RELEASE_STATUS: 'production' },
    { CONTENTLEDGER_BROWSER_SOURCE_REVISION: 'a'.repeat(40) },
    { ...production, CONTENTLEDGER_BROWSER_SOURCE_REVISION: 'A'.repeat(40) },
    { ...production, CONTENTLEDGER_BROWSER_SOURCE_REVISION: 'a'.repeat(39) },
    { ...production, CONTENTLEDGER_BROWSER_RELEASE_STATUS: 'released' },
    { ...production, CONTENTLEDGER_BROWSER_PRIVATE_VALUE: 'never-print-this' },
  ]) assert.throws(() => assertBrowserBuildEnvironment(root, environment), /deployment|unreviewed/);
  for (const text of ['export const x = import.meta.env.VITE_VALUE;', "export const x = process['env'];", 'export const x = process.env.VALUE;']) {
    write(root, 'src/browser-worker.ts', text); assert.throws(() => collectBrowserProvenance(root), /environment dependency/);
  }
});
test('browser version declarations must be exact, unique, stable-release and mutually consistent', t => {
  const root = temporaryApp(t);
  for (const text of [
    "export const BROWSER_APP_VERSION = '1.0.0'; export const BROWSER_VERIFIER_VERSION = 'browser-0.9.0';",
    "export const BROWSER_APP_VERSION = '1.0.0-dev'; export const BROWSER_VERIFIER_VERSION = 'browser-1.0.0-dev';",
    "export const BROWSER_APP_VERSION = '01.0.0'; export const BROWSER_VERIFIER_VERSION = 'browser-01.0.0';",
    "export const BROWSER_APP_VERSION = '1.0.0'; export const BROWSER_VERIFIER_VERSION = 'browser-1.0.0'; export const EXTRA = true;",
  ]) { write(root, 'src/browser-version.ts', text); assert.throws(() => collectBrowserProvenance(root), /version constants/); }
});
test('dependency root, pins, lock versions and installed tool package versions must agree', t => {
  for (const mutation of [
    root => editJson(root, 'package.json', value => { value.license = 'MIT'; }),
    root => editJson(root, 'package.json', value => { value.devDependencies.vite = '^8.3.0'; }),
    root => editJson(root, 'package.json', value => { value.version += '\n'; }),
    root => editJson(root, 'package.json', value => { value.devDependencies.vite += '\n'; }),
    root => editJson(root, 'package.json', value => { value.overrides = {}; }),
    root => editJson(root, 'package-lock.json', value => { value.lockfileVersion = 2; }),
    root => editJson(root, 'package-lock.json', value => { value.packages[''].version = '9.9.9'; }),
    root => editJson(root, 'package-lock.json', value => { value.packages[''].devDependencies.typescript = '9.9.9'; }),
    root => editJson(root, 'package-lock.json', value => { value.packages['node_modules/vite'].version = '9.9.9'; }),
    root => editJson(root, 'package-lock.json', value => { value.packages['node_modules/vite'].integrity = 'not-a-digest'; }),
    root => editJson(root, 'package-lock.json', value => { value.packages['node_modules/vite'].integrity += '\n'; }),
    root => editJson(root, 'package-lock.json', value => { value.packages['node_modules/vite'].resolved += '\n'; }),
    root => editJson(root, 'node_modules/typescript/package.json', value => { value.version = '9.9.9'; }),
    root => editJson(root, 'tsconfig.json', value => { value.extends = '../outside.json'; }),
    root => write(root, 'package-lock.json', '{"bad":'),
  ]) { const root = temporaryApp(t); mutation(root); assert.throws(() => collectBrowserProvenance(root)); }
});
test('nested source and installed dependency directory symlinks cannot redirect provenance', t => {
  const root = temporaryApp(t);
  for (const relative of ['src/verifier', 'node_modules/vite']) {
    const target = join(root, relative), retained = join(root, `synthetic-${basename(relative)}`);
    renameSync(target, retained);
    try { symlinkSync(retained, target, process.platform === 'win32' ? 'junction' : 'dir'); }
    catch (error) { renameSync(retained, target); if (error.code === 'EPERM' || error.code === 'EACCES') { t.skip('This platform does not permit test-owned directory links.'); return; } throw error; }
    try { assert.throws(() => collectBrowserProvenance(root), /symlinks|redirected/); }
    finally { unlinkSync(target); renameSync(retained, target); }
  }
  assert.ok(existsSync(join(root, 'src/verifier/engine.ts')));
});
