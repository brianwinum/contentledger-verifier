// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import test from 'node:test';

const root = realpathSync(fileURLToPath(new URL('../', import.meta.url)));
const ignoredRoots = new Set(['node_modules', 'dist-browser', 'build-output', 'playwright-report', 'test-results', '.git']);
const allowedRoots = new Set([
  '.github', '.gitattributes', '.gitignore', 'CONTRIBUTING.md', 'LICENSE', 'README.md', 'SECURITY.md', 'THIRD-PARTY-NOTICES.md',
  'WINDOWS-QUALIFICATION.md',
  'e2e', 'index.html', 'package-lock.json', 'package.json', 'playwright.config.ts', 'schemas', 'scripts', 'specifications', 'src', 'tests',
  'tsconfig.json', 'vite.config.ts', ...ignoredRoots,
]);

function inventory() {
  const files = [];
  let entries = 0;
  let bytes = 0;
  const walk = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (++entries > 1024) throw new Error('Public repository entry bound exceeded.');
      const absolute = join(directory, entry.name);
      const path = relative(root, absolute).replaceAll('\\', '/');
      const top = path.split('/')[0];
      if (directory === root) assert.ok(allowedRoots.has(entry.name), `Unreviewed root entry: ${entry.name}`);
      if (directory === root && ignoredRoots.has(entry.name)) continue;
      const stat = lstatSync(absolute);
      assert.equal(stat.isSymbolicLink(), false, `Symlinks are not accepted: ${path}`);
      if (entry.isDirectory()) walk(absolute);
      else {
        assert.ok(entry.isFile(), `Special files are not accepted: ${path}`);
        bytes += stat.size;
        assert.ok(bytes <= 32 * 1024 * 1024, 'Public repository byte bound exceeded.');
        files.push({ path, absolute, size: stat.size, top });
      }
    }
  };
  walk(root);
  return files;
}

test('the repository contains only the reviewed public browser-verifier boundary', () => {
  const files = inventory();
  assert.ok(files.length > 50);
  assert.deepEqual(files.filter(({ top }) => top === '.github').map(({ path }) => path), ['.github/workflows/public-verifier-pages.yml']);
  for (const { path } of files) {
    assert.doesNotMatch(path, /(?:^|\/)(?:src-tauri|imported-package|private|recovery|vendor)(?:\/|$)/i);
    assert.doesNotMatch(path, /(?:exporter|generator)/i);
    assert.doesNotMatch(path, /(?:^|\/)(?:\.env(?:\..*)?|[^/]+\.(?:php|rs|exe|dll|dylib|so|pem|key|p12|pfx))$/i);
  }
});

test('production source is browser-only, local-only, and independent of parent projects', () => {
  const files = inventory().filter(({ path }) =>
    (/^src\/.*\.(?:ts|css)$/.test(path) && !path.endsWith('.test.ts'))
    || ['index.html', 'package.json', 'tsconfig.json', 'vite.config.ts'].includes(path));
  for (const { path, absolute } of files) {
    const text = readFileSync(absolute, 'utf8');
    assert.doesNotMatch(text, /@tauri|src-tauri|imported-package|platform-desktop|<\?php/i, path);
    assert.doesNotMatch(text, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(|sendBeacon\s*\(/, path);
    assert.doesNotMatch(text, /from\s+['"](?:\.\.\/){2,}/, path);
  }
});

test('tests and audits cannot depend on files in a parent or private QA repository', () => {
  for (const { path, absolute } of inventory().filter(({ path }) => /\.(?:ts|mjs)$/.test(path))) {
    const text = readFileSync(absolute, 'utf8');
    assert.doesNotMatch(text, /new URL\(\s*['"`](?:\.\.\/){3,}/, path);
    assert.doesNotMatch(text, /(?:^|[/'"`])qa\/fixtures\//m, path);
  }
});

test('checked-in evidence packages contain no obvious key material or workstation paths', () => {
  for (const { path, absolute } of inventory().filter(({ path }) => /^tests\/fixtures\/.*\.zip$/.test(path))) {
    const bytes = readFileSync(absolute);
    const text = bytes.toString('latin1');
    assert.doesNotMatch(text, /-----BEGIN (?:OPENSSH |EC |RSA )?PRIVATE KEY-----/i, path);
    assert.doesNotMatch(text, /(?:[A-Z]:\\Users\\|\/Users\/|\/home\/)[^/\\\s]+/i, path);
  }
});

test('public WebVH interoperability fixtures are exact, synthetic, and self-contained', () => {
  const expected = {
    'tests/fixtures/webvh/valid-path-assertion-rotation-ratchet.jsonl': { bytes: 3954, sha256: 'b2f7b8c1df6bbcd2cefb61a1d493c0634c365ff6031c579367f0280548e5d207' },
    'tests/fixtures/webvh/valid-root-continuous-ratchet.jsonl': { bytes: 3787, sha256: '6631a2b6c4f2e898c384f82a90b104763dc6d4e18d72a27d4ba16bb212e4b6eb' },
  };
  const fixtures = inventory().filter(({ path }) => path.startsWith('tests/fixtures/webvh/'));
  assert.deepEqual(fixtures.map(({ path }) => path).sort(), Object.keys(expected).sort());
  for (const { path, absolute, size } of fixtures) {
    const bytes = readFileSync(absolute);
    assert.equal(size, expected[path].bytes, path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected[path].sha256, path);
    assert.doesNotMatch(bytes.toString('utf8'), /-----BEGIN (?:OPENSSH |EC |RSA )?PRIVATE KEY-----|(?:[A-Z]:\\Users\\|\/Users\/|\/home\/)[^/\\\s]+/i, path);
  }
});
