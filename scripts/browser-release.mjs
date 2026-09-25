// SPDX-License-Identifier: GPL-2.0-or-later
// Local preparation only. Never publishes, exports source, installs or downloads.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { collectBrowserProvenance } from './browser-provenance.mjs';
import { assertPlainDirectory, assertPlainFile, assertPlainTree, collectBrowserAssets, createReleaseManifest, MANIFEST_NAME, stableJson, verifyBrowserArtifact } from './browser-release-lib.mjs';

const app = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function run(script, args, env = process.env) {
  assertPlainFile(process.execPath);
  assertPlainFile(script);
  const result = spawnSync(process.execPath, [script, ...args], { cwd: app, env, shell: false, windowsHide: true, stdio: 'inherit', timeout: 180000 });
  if (result.error) throw new Error('A local browser release-check process could not complete.');
  if (result.status !== 0) throw new Error('A local browser release-check process failed; no complete artifact is claimed.');
}
function plainChild(parent, name) {
  assertPlainDirectory(parent);
  const child = join(parent, name);
  if (!existsSync(child)) mkdirSync(child);
  return assertPlainDirectory(child);
}
function prepare() {
  assertPlainDirectory(app);
  const parent = plainChild(app, 'build-output'), root = plainChild(parent, 'browser-release');
  assertPlainTree(root);
  // mkdtemp creates an exclusively new bounded descendant. Prior runs are never
  // erased, reused, silently replaced or included in the new asset inventories.
  const runDirectory = mkdtempSync(join(root, 'run-'));
  const artifact = plainChild(runDirectory, 'artifact');
  const first = plainChild(artifact, 'app'), second = plainChild(runDirectory, 'repeat');
  const before = collectBrowserProvenance(app);
  const unchanged = () => { if (stableJson(collectBrowserProvenance(app)) !== stableJson(before)) throw new Error('Browser build inputs changed during repeated preparation. Retained partial outputs are not a completed artifact.'); };
  run(join(app, 'node_modules/typescript/bin/tsc'), ['--noEmit']);
  function build(output) {
    assertPlainTree(root);
    if (readdirSync(output).length) throw new Error('Refusing to build over an existing browser output.');
    run(join(app, 'node_modules/vite/bin/vite.js'), ['build', '--mode', 'browser', '--outDir', output, '--emptyOutDir', 'false']);
    assertPlainTree(output, 256);
    const assets = collectBrowserAssets(output);
    run(join(app, 'scripts/browser-build.test.mjs'), [], { ...process.env, CONTENTLEDGER_BROWSER_AUDIT_OUTPUT: output });
    // Ensure audits did not alter the bytes being recorded.
    if (stableJson(collectBrowserAssets(output)) !== stableJson(assets)) throw new Error('Browser output changed during its static audit.');
    return assets;
  }
  const firstAssets = build(first);
  unchanged();
  const secondAssets = build(second);
  unchanged();
  const manifest = createReleaseManifest(before, firstAssets, secondAssets);
  assertPlainTree(root);
  writeFileSync(join(artifact, MANIFEST_NAME), stableJson(manifest), { flag: 'wx', mode: 0o600 });
  verifyBrowserArtifact(artifact);
  console.log(`Local unsigned browser artifact prepared; ${manifest.status}.`);
  console.log(`Artifact: ${artifact}`);
  console.log(`Asset-set SHA-256: ${manifest.assetSetSha256}`);
  console.log('Two retained builds matched exactly. This is not publisher authentication or release approval.');
}

try {
  const args = process.argv.slice(2);
  if (!args.length) prepare();
  else if (args.length === 2 && args[0] === 'verify') {
    const manifest = verifyBrowserArtifact(resolve(args[1]));
    console.log(`Local artifact integrity matches: ${manifest.assetSetSha256}`);
    console.log('Unsigned manifest; publisher authenticity and independent security review are not established.');
  } else throw new Error('Usage: node scripts/browser-release.mjs [verify <artifact-directory>]');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Local browser artifact preparation failed.');
  process.exitCode = 1;
}
