// SPDX-License-Identifier: GPL-2.0-or-later
// Local unsigned artifact integrity only; never publisher authentication.
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readSync, readdirSync, realpathSync } from 'node:fs';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';

export const MANIFEST_NAME = 'browser-release-manifest.json';
export const MAX_ASSET_FILES = 128;
export const MAX_ASSET_BYTES = 16 * 1024 * 1024;
export const MAX_TOTAL_ASSET_BYTES = 32 * 1024 * 1024;
export const RELEASE_LIMITATIONS = [
  'Unsigned local integrity record; not publisher authentication or a signed attestation.',
  'Two matching builds on one recorded toolchain do not prove cross-platform reproducibility.',
  'Source and lockfile fingerprints do not authenticate installed dependency bytes or the toolchain.',
  'Development artifact; browser qualification and independent security review remain open.',
  'Static audits do not replace network observation, offline distribution testing or security review.',
];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.exec(value)?.[0] === value;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const integer = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const fail = message => { throw new Error(message); };

export function assertPlainDirectory(directory) {
  const path = resolve(directory), stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) fail('Refusing redirected or non-directory browser artifact path.');
  return path;
}

export function assertPlainFile(file) {
  const path = resolve(file), stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) fail('Refusing redirected or non-regular browser artifact file.');
  return stat;
}

// Allocate only the already-bounded exact size, not a possibly growing file.
// Identity/metadata checks catch replacement or ordinary concurrent edits; an
// attacker controlling the host/filesystem is outside unsigned integrity trust.
function readExactFile(path, maximum) {
  const before = assertPlainFile(path);
  if (!integer(before.size, maximum)) fail('Browser artifact file exceeds its safe limit.');
  const handle = openSync(path, 'r');
  try {
    const opened = fstatSync(handle);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) fail('Browser artifact changed while opening.');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(handle, bytes, offset, bytes.length - offset, offset);
      if (!count) fail('Browser artifact was truncated while reading.');
      offset += count;
    }
    const after = fstatSync(handle), named = assertPlainFile(path);
    if (readSync(handle, Buffer.alloc(1), 0, 1, bytes.length) !== 0 || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || named.dev !== before.dev || named.ino !== before.ino || named.size !== before.size || named.mtimeMs !== before.mtimeMs) fail('Browser artifact changed while reading.');
    return bytes;
  } finally { closeSync(handle); }
}

/** Scan a bounded existing output tree without following links or reading bytes. */
export function assertPlainTree(directory, maximumEntries = 10000) {
  const root = assertPlainDirectory(directory);
  let count = 0;
  function walk(path, depth) {
    if (depth > 8) fail('Browser output directory nesting exceeds its safe limit.');
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      if (++count > maximumEntries) fail('Browser output tree exceeds its safe entry limit.');
      const child = join(path, entry.name), stat = lstatSync(child);
      if (stat.isSymbolicLink() || realpathSync(child) !== child) fail('Refusing redirected browser output tree.');
      if (stat.isDirectory()) walk(child, depth + 1);
      else if (!stat.isFile()) fail('Browser output tree contains a non-regular entry.');
    }
  }
  walk(root, 0);
  return root;
}

export function assetPath(root, name) {
  if (typeof name !== 'string' || name.length > 240
    || /^(?:index\.html|assets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:css|m?js|png|svg|ico|webp|woff2?))$/.exec(name)?.[0] !== name
    || name.includes('\\') || name.split('/').some(part => part === '.' || part === '..')
    || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(basename(name))) fail('Unsafe or unreviewed browser asset path.');
  const path = resolve(root, name), rel = relative(resolve(root), path);
  if (!rel || isAbsolute(rel) || rel === '..' || rel.startsWith('..' + sep)) fail('Browser asset path escapes its root.');
  return path;
}

export function validateAssetInventory(assets) {
  if (!Array.isArray(assets) || assets.length < 3 || assets.length > MAX_ASSET_FILES) fail('Invalid browser asset inventory count.');
  let previous = '', total = 0;
  const folded = new Set();
  for (const asset of assets) {
    if (!exact(asset, ['path', 'bytes', 'sha256'])) fail('Invalid browser asset inventory shape.');
    assetPath('.', asset.path);
    if (asset.path <= previous || folded.has(asset.path.toLowerCase()) || !integer(asset.bytes, MAX_ASSET_BYTES) || !hash(asset.sha256)) fail('Invalid browser asset ordering, size or digest.');
    previous = asset.path;
    folded.add(asset.path.toLowerCase());
    total += asset.bytes;
    if (total > MAX_TOTAL_ASSET_BYTES) fail('Browser asset aggregate exceeds its safe limit.');
  }
  if (!assets.some(asset => asset.path === 'index.html') || !assets.some(asset => /\.m?js$/.test(asset.path)) || !assets.some(asset => /\.css$/.test(asset.path))) fail('Browser asset inventory omits a required output role.');
  return assets;
}

export function collectBrowserAssets(directory) {
  const root = assertPlainDirectory(directory);
  const names = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name === 'assets') {
      const assets = assertPlainDirectory(join(root, 'assets'));
      for (const child of readdirSync(assets, { withFileTypes: true })) names.push(`assets/${child.name}`);
    } else names.push(entry.name);
  }
  if (names.length > MAX_ASSET_FILES) fail('Browser asset inventory count exceeds its safe limit.');
  let total = 0;
  const files = names.sort().map(name => {
    const path = assetPath(root, name), stat = assertPlainFile(path);
    if (!integer(stat.size, MAX_ASSET_BYTES) || (total += stat.size) > MAX_TOTAL_ASSET_BYTES) fail('Browser asset bytes exceed their safe limit.');
    const bytes = readExactFile(path, MAX_ASSET_BYTES);
    if (bytes.length !== stat.size) fail('Browser asset changed while being read.');
    return { path: name, bytes: bytes.length, sha256: digest(bytes) };
  });
  return validateAssetInventory(files);
}

export function compareBrowserAssets(first, second) {
  validateAssetInventory(first); validateAssetInventory(second);
  if (stableJson(first) !== stableJson(second)) fail('Repeated browser builds differ in exact paths, sizes or SHA-256.');
}

function validateProvenance(value) {
  if (!exact(value, ['schemaVersion', 'kind', 'appVersion', 'verifierVersion', 'sourceSha256', 'sourceFileCount', 'dependencyLockSha256', 'toolchain', 'releaseStatus', 'sourceRevision'])
    || value.schemaVersion !== 1 || value.kind !== 'contentledger-browser-build'
    || value.releaseStatus !== 'development-unpublished' && value.releaseStatus !== 'development-preview'
    || value.releaseStatus === 'development-unpublished' && value.sourceRevision !== null
    || value.releaseStatus === 'development-preview' && (typeof value.sourceRevision !== 'string' || !/^[a-f0-9]{40}$/.test(value.sourceRevision))
    || typeof value.appVersion !== 'string' || /^\d+\.\d+\.\d+-dev$/.exec(value.appVersion)?.[0] !== value.appVersion
    || value.verifierVersion !== `browser-${value.appVersion}` || !hash(value.sourceSha256) || !hash(value.dependencyLockSha256)
    || !integer(value.sourceFileCount, 1000) || value.sourceFileCount < 1 || !exact(value.toolchain, ['node', 'vite', 'typescript'])
    || Object.values(value.toolchain).some(version => typeof version !== 'string' || version.length > 80 || /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.exec(version)?.[0] !== version)) fail('Invalid browser build provenance.');
  return value;
}

/** Stable serialization has no wall clock, absolute path, random run ID or Git inference. */
export function stableJson(value) {
  const ordered = input => Array.isArray(input) ? input.map(ordered) : object(input)
    ? Object.fromEntries(Object.keys(input).sort().map(key => [key, ordered(input[key])])) : input;
  return JSON.stringify(ordered(value), null, 2) + '\n';
}

export function createReleaseManifest(provenance, first, second) {
  validateProvenance(provenance);
  compareBrowserAssets(first, second);
  const assets = first.map(asset => ({ ...asset }));
  return {
    schemaVersion: 1, kind: 'contentledger-browser-local-artifact', status: provenance.releaseStatus, assetRoot: 'app',
    provenance: structuredClone(provenance), assets, assetSetSha256: digest(stableJson(assets)),
    repeatedBuildsIdentical: true, checks: { productionBuilds: 2, matchingSourceSnapshots: 3, productionStaticAudits: 2 },
    limitations: [...RELEASE_LIMITATIONS],
  };
}

export function validateReleaseManifest(manifest) {
  if (!exact(manifest, ['schemaVersion', 'kind', 'status', 'assetRoot', 'provenance', 'assets', 'assetSetSha256', 'repeatedBuildsIdentical', 'checks', 'limitations'])
    || manifest.schemaVersion !== 1 || manifest.kind !== 'contentledger-browser-local-artifact'
    || manifest.status !== 'development-unpublished' && manifest.status !== 'development-preview' || manifest.assetRoot !== 'app'
    || manifest.repeatedBuildsIdentical !== true || !exact(manifest.checks, ['productionBuilds', 'matchingSourceSnapshots', 'productionStaticAudits'])
    || manifest.checks.productionBuilds !== 2 || manifest.checks.matchingSourceSnapshots !== 3 || manifest.checks.productionStaticAudits !== 2
    || JSON.stringify(manifest.limitations) !== JSON.stringify(RELEASE_LIMITATIONS)) fail('Invalid unsigned browser artifact manifest.');
  validateProvenance(manifest.provenance);
  if (manifest.status !== manifest.provenance.releaseStatus) fail('Browser artifact status does not match its build provenance.');
  validateAssetInventory(manifest.assets);
  if (!hash(manifest.assetSetSha256) || manifest.assetSetSha256 !== digest(stableJson(manifest.assets))) fail('Browser manifest asset-set digest mismatch.');
  return manifest;
}

export function verifyBrowserArtifact(directory) {
  const root = assertPlainDirectory(directory);
  if (JSON.stringify(readdirSync(root).sort()) !== JSON.stringify(['app', MANIFEST_NAME].sort())) fail('Browser artifact has missing or additional top-level entries.');
  const path = join(root, MANIFEST_NAME), stat = assertPlainFile(path);
  if (stat.size < 1 || stat.size > 1024 * 1024) fail('Browser artifact manifest exceeds its safe limit.');
  const bytes = readExactFile(path, 1024 * 1024), manifest = validateReleaseManifest(JSON.parse(bytes.toString('utf8')));
  if (!bytes.equals(Buffer.from(stableJson(manifest)))) fail('Browser artifact manifest is not in exact deterministic form.');
  compareBrowserAssets(manifest.assets, collectBrowserAssets(join(root, 'app')));
  return manifest;
}
