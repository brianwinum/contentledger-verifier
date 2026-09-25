// SPDX-License-Identifier: GPL-2.0-or-later
// Build-source identity, not a signature, Git claim, dependency-byte
// attestation, or proof that a remotely served application has these bytes.
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const BROWSER_SOURCE_PATHS = Object.freeze([
  'src/site-shell.css', 'src/site-integration.css',
  'src/assets/libre-franklin-latin.woff2', 'src/assets/ibm-plex-mono-latin.woff2', 'src/assets/Libre-Franklin-OFL.txt', 'src/assets/IBM-Plex-Mono-OFL.txt', 'src/assets/favicon.svg',
  'index.html', 'LICENSE', 'package-lock.json', 'package.json', 'scripts/browser-provenance.mjs', 'THIRD-PARTY-NOTICES.md',
  'schemas/content-ledger-evidence-bundle-inventory-v1.schema.json', 'schemas/content-ledger-evidence-bundle-v3.schema.json',
  'schemas/content-ledger-manifest-v1.schema.json', 'schemas/content-ledger-manifest-v2.schema.json',
  'schemas/content-ledger-transparency-checkpoint-v2.schema.json', 'schemas/content-ledger-transparency-inclusion-proof-v1.schema.json',
  'schemas/content-ledger-transparency-leaf-inventory-v1.schema.json',
  'specifications/CONTENTLEDGER-EVIDENCE-BUNDLE-v3.md', 'specifications/CONTENTLEDGER-MANIFEST-v1.md',
  'specifications/CONTENTLEDGER-MANIFEST-v2.md', 'specifications/VERIFY.txt', 'specifications/WEBSITE-IDENTITY.md',
  'src/browser-build-info.ts', 'src/browser-completion.ts', 'src/browser-report.ts', 'src/browser-version.ts', 'src/browser-worker.ts',
  'src/main.ts', 'src/model.ts', 'src/platform-browser-job.ts', 'src/platform-browser-protocol.ts', 'src/platform-browser.ts', 'src/platform.ts', 'src/style.css', 'src/tokens.css',
  'src/verifier/archive-references.ts', 'src/verifier/authorization.ts', 'src/verifier/bytes.ts', 'src/verifier/canonical.ts', 'src/verifier/checkpoint-document.ts',
  'src/verifier/comparisons.ts', 'src/verifier/ed25519-vectors.ts', 'src/verifier/ed25519.ts', 'src/verifier/engine.ts', 'src/verifier/errors.ts', 'src/verifier/graph.ts',
  'src/verifier/identity.ts', 'src/verifier/jws.ts', 'src/verifier/manifest.ts', 'src/verifier/merkle.ts', 'src/verifier/opentimestamps.ts', 'src/verifier/profile.ts',
  'src/verifier/scope-completeness.ts', 'src/verifier/scope.ts', 'src/verifier/signature-integrity.ts', 'src/verifier/supporting-artifacts.ts',
  'src/verifier/transparency-graph.ts', 'src/verifier/transparency.ts', 'src/verifier/webvh-codec.ts', 'src/verifier/webvh.ts', 'src/verifier/zip.ts',
  'tsconfig.json', 'vite.config.ts',
].sort());
const allowed = new Set(BROWSER_SOURCE_PATHS);
const MAX_FILE_BYTES = 1024 * 1024, MAX_TOTAL_BYTES = 8 * 1024 * 1024, MAX_TREE_ENTRIES = 512;
const semver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const exact = (pattern, value) => typeof value === 'string' && pattern.exec(value)?.[0] === value;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw new Error(`Browser provenance: ${message}`); };
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function rootPath(appRoot) {
  if (typeof appRoot !== 'string' || !appRoot) fail('an explicit app directory is required.');
  const root = resolve(appRoot), stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(root) !== root) fail('redirected app directories are not accepted.');
  return root;
}
function pathInRoot(root, relative) {
  if (!/^[A-Za-z0-9@_.-]+(?:\/[A-Za-z0-9@_.-]+)*$/.test(relative) || relative.split('/').some(part => part === '.' || part === '..')) fail('invalid reviewed path.');
  let current = root;
  const parts = relative.split('/');
  for (let index = 0; index < parts.length; index++) {
    current = join(current, parts[index]);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || realpathSync(current) !== current || index < parts.length - 1 && !stat.isDirectory()) fail('redirected source/dependency paths are not accepted.');
  }
  return current;
}
function readBounded(root, relative) {
  const path = pathInRoot(root, relative), before = lstatSync(path);
  if (!before.isFile() || before.size < 1 || before.size > MAX_FILE_BYTES) fail('a reviewed input is not a bounded regular file.');
  const handle = openSync(path, 'r');
  try {
    const opened = fstatSync(handle);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) fail('a reviewed input changed while opening.');
    const bytes = readFileSync(handle), after = fstatSync(handle), named = lstatSync(path);
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || named.isSymbolicLink() || named.dev !== before.dev || named.ino !== before.ino || realpathSync(path) !== path) fail('a reviewed input changed while reading.');
    return bytes;
  } finally { closeSync(handle); }
}
function json(bytes) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail('invalid UTF-8 JSON metadata.'); }
  if (!plain(value)) fail('metadata must be a JSON object.');
  return value;
}
function checkSourceTree(root) {
  let count = 0;
  const walk = (directory, depth) => {
    if (depth > 8) fail('source nesting exceeds its bound.');
    for (const entry of readdirSync(pathInRoot(root, directory), { withFileTypes: true })) {
      if (++count > MAX_TREE_ENTRIES) fail('source entry count exceeds its bound.');
      const name = `${directory}/${entry.name}`;
      if (entry.isSymbolicLink()) fail('source symlinks are not accepted.');
      if (entry.isDirectory()) { walk(name, depth + 1); continue; }
      if (!entry.isFile()) fail('special source files are not accepted.');
      if (name.endsWith('.test.ts')) continue;
      if (!allowed.has(name)) fail(`unreviewed production input: ${name}`);
    }
  };
  walk('src', 0);
}
export function assertBrowserBuildEnvironment(appRoot, environment = process.env) {
  const root = rootPath(appRoot);
  // Reject rather than parse/read potential private .env contents.
  if (readdirSync(root).some(name => /^\.env(?:\.|$)/i.test(name))) fail('production browser builds do not accept .env files.');
  for (const name of Object.keys(environment)) {
    if (/^(?:VITE_|TAURI_ENV_|ROLLDOWN_|ROLLUP_|BROWSERSLIST)/i.test(name)
      || /^(?:NODE_OPTIONS|NODE_PATH|BABEL_ENV)$/i.test(name)) fail('ambient build overrides are not accepted.');
    if (/^CONTENTLEDGER_BROWSER_/i.test(name)
      && name !== 'CONTENTLEDGER_BROWSER_RELEASE_STATUS'
      && name !== 'CONTENTLEDGER_BROWSER_SOURCE_REVISION'
      && name !== 'CONTENTLEDGER_BROWSER_AUDIT_OUTPUT') fail('unreviewed browser deployment metadata is not accepted.');
  }
  if (environment.NODE_ENV !== undefined && environment.NODE_ENV !== 'production') fail('NODE_ENV must be absent or production.');
  browserDeploymentIdentity(environment);
}
export function browserDeploymentIdentity(environment = process.env) {
  const status = environment.CONTENTLEDGER_BROWSER_RELEASE_STATUS;
  const revision = environment.CONTENTLEDGER_BROWSER_SOURCE_REVISION;
  if (status === undefined && revision === undefined) return { releaseStatus: 'local-unpublished', sourceRevision: null };
  if (status !== 'production' || typeof revision !== 'string' || !/^[a-f0-9]{40}$/.test(revision)) {
    fail('deployment status and source revision must be an exact reviewed pair.');
  }
  return { releaseStatus: status, sourceRevision: revision };
}
function snapshot(appRoot) {
  const root = rootPath(appRoot);
  assertBrowserBuildEnvironment(root);
  checkSourceTree(root);
  const contents = new Map(), inventory = [];
  let total = 0;
  for (const path of BROWSER_SOURCE_PATHS) {
    const bytes = readBounded(root, path);
    if ((total += bytes.length) > MAX_TOTAL_BYTES) fail('source bytes exceed the aggregate bound.');
    // Production modules do not currently consume ambient environment values.
    // This conservative tripwire refuses new spellings until explicitly reviewed.
    if (path.startsWith('src/') && /\bimport\s*\.\s*meta\b|\bprocess\s*(?:\.|\[)/.test(bytes.toString('utf8'))) fail('production source has an unreviewed environment dependency.');
    contents.set(path, bytes); inventory.push({ path, bytes: bytes.length, sha256: digest(bytes) });
  }
  return { root, contents, inventory };
}
/** Sorted raw-byte source inventory. Paths are relative POSIX names only. */
export function collectBrowserSourceInventory(appRoot) { return snapshot(appRoot).inventory; }
function dependencyTable(value) {
  if (value === undefined) return '[]';
  if (!plain(value) || Object.values(value).some(version => !exact(semver, version))) fail('dependencies must use exact version pins.');
  return JSON.stringify(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
}
/** Compile-time source identity. Actual emitted-file hashes live outside this
 * object to avoid self-referential output hashes. No Git state is inferred. */
export function collectBrowserProvenance(appRoot) {
  const { root, contents, inventory } = snapshot(appRoot);
  const pkg = json(contents.get('package.json')), lock = json(contents.get('package-lock.json'));
  if (pkg.name !== 'contentledger-public-verifier' || pkg.private !== true || pkg.type !== 'module' || pkg.license !== 'GPL-2.0-or-later' || !exact(semver, pkg.version)
    || pkg.overrides !== undefined || pkg.resolutions !== undefined || pkg.workspaces !== undefined) fail('package metadata is outside the reviewed profile.');
  const lockedRoot = lock.packages?.[''];
  if (lock.lockfileVersion !== 3 || lock.name !== pkg.name || lock.version !== pkg.version || !plain(lock.packages) || Object.keys(lock.packages).length > 2048 || !plain(lockedRoot)
    || lockedRoot.name !== pkg.name || lockedRoot.version !== pkg.version || lockedRoot.license !== pkg.license
    || dependencyTable(pkg.dependencies) !== dependencyTable(lockedRoot.dependencies) || dependencyTable(pkg.devDependencies) !== dependencyTable(lockedRoot.devDependencies)) fail('package and dependency lock disagree.');
  const toolchain = { node: process.versions.node, vite: '', typescript: '' };
  if (!exact(semver, toolchain.node) || Number(toolchain.node.split('.')[0]) < 24) fail('Node 24 or newer is required.');
  for (const name of ['vite', 'typescript']) {
    const pinned = pkg.devDependencies[name], locked = lock.packages[`node_modules/${name}`];
    const installed = json(readBounded(root, `node_modules/${name}/package.json`));
    if (!plain(locked) || locked.version !== pinned || installed.name !== name || installed.version !== pinned
      || !exact(/^sha512-[A-Za-z0-9+/]{86}==$/, locked.integrity)
      || Buffer.from(locked.integrity.slice(7), 'base64').toString('base64') !== locked.integrity.slice(7)
      || locked.resolved !== `https://registry.npmjs.org/${name}/-/${name}-${pinned}.tgz`) fail('installed build-tool versions do not match exact dependency pins.');
    toolchain[name] = installed.version;
  }
  const config = json(contents.get('tsconfig.json'));
  if (config.extends !== undefined || config.references !== undefined) fail('external TypeScript config inputs require review.');
  const versionText = contents.get('src/browser-version.ts').toString('utf8').replace(/\/\/[^\r\n]*/g, '').trim();
  const versions = /^export const BROWSER_APP_VERSION = '((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))';\s*export const BROWSER_VERIFIER_VERSION = '(browser-[^']+)';$/.exec(versionText);
  if (!versions || versions[2] !== `browser-${versions[1]}`) fail('browser version constants are malformed or inconsistent.');
  const deployment = browserDeploymentIdentity(process.env);
  return { schemaVersion: 1, kind: 'contentledger-browser-build', appVersion: versions[1], verifierVersion: versions[2],
    sourceSha256: digest(JSON.stringify({ schemaVersion: 1, files: inventory }) + '\n'), sourceFileCount: inventory.length,
    dependencyLockSha256: digest(contents.get('package-lock.json')), toolchain, ...deployment };
}
