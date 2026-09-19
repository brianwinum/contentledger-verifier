// SPDX-License-Identifier: GPL-2.0-or-later
// Static audits of actual production output, not a substitute for browser
// request capture, offline compatibility testing, or independent security review.
import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Explicit developer test override; never consumed by the browser application.
const output = process.env.CONTENTLEDGER_BROWSER_AUDIT_OUTPUT
  ? resolve(process.env.CONTENTLEDGER_BROWSER_AUDIT_OUTPUT)
  : resolve(dirname(fileURLToPath(import.meta.url)), '../dist-browser');
const sourceDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
let html;
let files;
let scripts;
let workerSources;

function inventory(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    assert.equal(entry.isSymbolicLink(), false, 'Production output must not contain symlinks.');
    const path = join(directory, entry.name);
    return entry.isDirectory() ? inventory(path) : [path];
  });
}

function htmlText(text) {
  return text.replace(/&#(?:x([0-9a-f]+)|(\d+));/gi, (_, hex, decimal) => String.fromCodePoint(parseInt(hex ?? decimal, hex ? 16 : 10)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function attributes(tag) {
  return Object.fromEntries([...tag.matchAll(/([a-z][a-z0-9-]*)\s*=\s*(["'])(.*?)\2/gi)]
    .map(([, name, , value]) => [name.toLowerCase(), htmlText(value)]));
}

function localAsset(reference, owner) {
  assert.match(reference, /^\.\//, `Asset must be relative to the deployment directory: ${reference}`);
  assert.equal(/[?#\\]/.test(reference), false, `Unexpected asset reference: ${reference}`);
  const path = resolve(dirname(owner), reference);
  assert.equal(relative(output, path).startsWith('..'), false, `Asset escaped the output directory: ${reference}`);
  assert.ok(existsSync(path), `Missing generated asset: ${reference}`);
  return path;
}

// Regression tripwires for this application's deliberately small capability
// surface, not a JavaScript data-flow proof or a detector for arbitrary obfuscation.
function assertPrivateSource(source, name) {
  assert.doesNotMatch(source, /\b(?:localStorage|sessionStorage|indexedDB|IDBFactory|openDatabase|CacheStorage|caches|cookieStore|StorageManager|serviceWorker|PushManager)\b/, `${name}: persistent browser storage/background service`);
  assert.doesNotMatch(source, /\bdocument\s*(?:\.\s*cookie\b|\[\s*["']cookie["']\s*\])|\bnavigator\s*\.\s*(?:storage|clipboard|share|geolocation)\b/, `${name}: browser data persistence/sharing`);
  assert.doesNotMatch(source, /\b(?:showSaveFilePicker|showOpenFilePicker|showDirectoryPicker|FileSystemWritableFileStream|FileSystemDirectoryHandle|FileSystemFileHandle|webkitRequestFileSystem|requestFileSystem)\b/, `${name}: filesystem persistence outside explicit report download`);
  assert.doesNotMatch(source, /\bconsole\s*(?:\?\.|\.|\[)/, `${name}: application console output`);
  assert.doesNotMatch(source, /\b(?:BroadcastChannel|SharedWorker)\b|\b(?:window|parent|opener|top)\s*\.\s*(?:postMessage|open)\s*\(/, `${name}: cross-window/background data channel`);
  assert.doesNotMatch(source, /\b(?:location\s*(?:\.\s*(?:href|hash|search)\s*=|\.\s*(?:assign|replace)\s*\()|history\s*\.\s*(?:pushState|replaceState)\s*\()/, `${name}: evidence-bearing navigation/history`);
  assert.doesNotMatch(source, /\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc)\b|\bdocument\s*\.\s*(?:write|writeln)\s*\(/, `${name}: active HTML rendering sink`);
}

function assertPrivateHtml(document) {
  for (const match of document.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*>/gi)) {
    const kind = match[1].toLowerCase(), attrs = attributes(match[0]);
    assert.equal(['iframe', 'object', 'embed', 'base', 'audio', 'video', 'track', 'source', 'foreignobject'].includes(kind), false, `Unreviewed active/resource element: ${kind}`);
    assert.doesNotMatch(match[0], /\b(?:src|href|srcset|ping|action|formaction|srcdoc)\s*=\s*[^"'\s][^\s>]*/i, 'URL-bearing attributes must be explicitly quoted for audit.');
    for (const key of ['srcset', 'ping', 'action', 'formaction', 'srcdoc']) assert.equal(attrs[key], undefined, `Unexpected ${key} data/request surface`);
    if (kind === 'a') {
      assert.match(attrs.href ?? '', /^#[A-Za-z][A-Za-z0-9_-]*$/, 'Static navigation must stay within this page.');
      assert.equal(attrs.target, undefined, 'No automatic cross-window navigation.');
    } else {
      for (const key of ['src', 'href']) if (attrs[key]) localAsset(attrs[key], join(output, 'index.html'));
    }
    if (kind === 'meta') assert.notEqual(attrs['http-equiv']?.toLowerCase(), 'refresh', 'No automatic page redirect.');
    if (kind === 'link') assert.ok(['stylesheet', 'modulepreload', 'icon'].includes(attrs.rel), `Unreviewed link relation: ${attrs.rel}`);
  }
}

// Decode only literal data. Never evaluate generated application/worker code.
function decodeLiteral(value) {
  return value.replace(/\\(?:u\{([0-9a-f]+)\}|u([0-9a-f]{4})|x([0-9a-f]{2})|(\r\n|[\n\r\u2028\u2029])|([\s\S]))/gi,
    (_, point, unicode, byte, continuation, escaped) => {
      if (point || unicode || byte) return String.fromCodePoint(parseInt(point ?? unicode ?? byte, 16));
      if (continuation) return '';
      return ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', 0: '\0' })[escaped] ?? escaped;
    });
}

function decodedEmbeddedSources(source) {
  const candidates = [];
  // Vite currently emits a quoted worker program; older output may carry a
  // base64 worker. Inspect either representation without pinning chunk hashes.
  for (const match of source.matchAll(/(["'`])(?:\\[\s\S]|(?!\1)[^\\])*?\1/g)) {
    const literal = decodeLiteral(match[0].slice(1, -1));
    if (literal.includes('onmessage') && literal.includes('browser_verifier_incomplete')) candidates.push(literal);
    const base64 = literal.replace(/^data:(?:text|application)\/javascript(?:;charset=[^;,]+)?;base64,/, '');
    if (base64.length >= 256 && /^[A-Za-z0-9+/]+={0,2}$/.test(base64) && base64.length % 4 === 0) {
      const decoded = Buffer.from(base64, 'base64').toString('utf8');
      if (decoded.includes('onmessage') && decoded.includes('browser_verifier_incomplete')) candidates.push(decoded);
    }
  }
  return candidates;
}

before(() => {
  assert.ok(existsSync(join(output, 'index.html')), 'Run npm run browser:build before auditing the browser production output.');
  files = inventory(output);
  html = readFileSync(join(output, 'index.html'), 'utf8');
  scripts = files.filter(path => /\.m?js$/.test(path)).map(path => ({ name: relative(output, path), source: readFileSync(path, 'utf8') }));
  assert.ok(scripts.length, 'Browser build contains no JavaScript.');
  workerSources = scripts.flatMap(({ name, source }) => decodedEmbeddedSources(source).map((decoded, index) => ({ name: `${name}:embedded-worker-${index}`, source: decoded })));
  // Also support an emitted standalone worker chunk.
  workerSources.push(...scripts.filter(({ source }) => source.includes('onmessage') && source.includes('browser_verifier_incomplete') && !source.includes('document.getElementById')));
  assert.ok(workerSources.length, 'The emitted verification worker must be found and audited, including an inline/base64 payload.');
});

test('production browser output contains only static web assets, not native runtimes or private sources', () => {
  for (const path of files) {
    const name = relative(output, path);
    assert.match(name, /\.(?:html|css|m?js|png|svg|ico|webp|woff2?)$/i, `Unexpected deployment artifact: ${name}`);
    assert.doesNotMatch(name, /(?:^|[\\/])(?:node_modules|src-tauri|imported-package|tests|resources)(?:[\\/]|$)/i);
  }
  assert.equal(files.some(path => path.endsWith('.map')), false, 'This release does not publish source maps.');
});

test('production output embeds the current bounded source and deployment identity', async () => {
  const { collectBrowserProvenance } = await import('./browser-provenance.mjs');
  const info = collectBrowserProvenance(resolve(sourceDirectory, '..'));
  const main = scripts.map(item => item.source).join('\n');
  for (const value of [info.sourceSha256, info.dependencyLockSha256, info.appVersion, info.verifierVersion, info.releaseStatus]) assert.ok(main.includes(value), `Missing build identity ${value}`);
  if (info.sourceRevision !== null) assert.ok(main.includes(info.sourceRevision), 'Missing deployment source revision');
  assert.ok(html.includes('About this checker build'));
  assert.ok(html.includes('not your evidence package'));
  assert.ok(main.includes('checkerBuild'));
  assert.ok(main.includes('not a signed release or independent proof of the running code'));
  if (info.releaseStatus === 'development-unpublished') assert.equal(info.sourceRevision, null);
  else assert.match(info.sourceRevision, /^[a-f0-9]{40}$/);
});

test('production HTML uses existing relative local assets and no inline runtime code', () => {
  let entryScripts = 0;
  for (const match of html.matchAll(/<(script|link|img|source|iframe|object|embed|base)\b[^>]*>/gi)) {
    const [, kind] = match;
    const attrs = attributes(match[0]);
    assert.equal(['iframe', 'object', 'embed', 'base'].includes(kind.toLowerCase()), false, `Unexpected embedded runtime element: ${kind}`);
    for (const key of ['src', 'href']) if (attrs[key]) localAsset(attrs[key], join(output, 'index.html'));
    assert.equal(attrs.srcset, undefined, 'Audit srcset assets explicitly before introducing them.');
    if (kind.toLowerCase() === 'script') {
      entryScripts++;
      assert.ok(attrs.src, 'Application scripts must be external local files, not inline code.');
      assert.equal(attrs.type, 'module');
    }
  }
  assert.ok(entryScripts > 0);
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) assert.equal(match[1].trim(), '');
  assert.doesNotMatch(html, /\bon[a-z]+\s*=\s*["']/i, 'No inline HTML event handlers.');
});

test('production CSP blocks network connections while permitting the local blob worker', () => {
  const metas = [...html.matchAll(/<meta\b[^>]*>/gi)].map(match => attributes(match[0]));
  const policies = metas.filter(meta => meta['http-equiv']?.toLowerCase() === 'content-security-policy');
  assert.equal(policies.length, 1);
  const entries = policies[0].content.split(';').map(value => value.trim().split(/\s+/)).filter(value => value[0]);
  const policy = new Map(entries.map(([directive, ...values]) => [directive, values]));
  assert.equal(policy.size, entries.length, 'CSP directives must not be duplicated.');
  for (const directive of ['default-src', 'connect-src', 'object-src', 'base-uri', 'form-action']) assert.deepEqual(policy.get(directive), ["'none'"], directive);
  for (const directive of ['script-src', 'style-src', 'font-src']) assert.deepEqual(policy.get(directive), ["'self'"], directive);
  assert.deepEqual(policy.get('worker-src'), ["'self'", 'blob:']);
  assert.deepEqual(policy.get('img-src'), ["'self'", 'data:']);
  assert.doesNotMatch(policies[0].content, /unsafe-inline|unsafe-eval|https?:|\*/i);
  assert.equal(metas.find(meta => meta.name === 'referrer')?.content, 'no-referrer');
});

test('all emitted JavaScript including decoded worker payloads omits native bridges and network APIs', () => {
  for (const { name, source } of [...scripts, ...workerSources]) {
    assert.doesNotMatch(source, /__TAURI(?:_INTERNALS)?__|@tauri-apps\/|plugin:dialog|\bnode:(?:fs|path|crypto|child_process|http|https)\b|<\?php|php_sodium\.dll|contentledger-verify\.php/i, name);
    assert.doesNotMatch(source, /\brequire\s*\(|\bprocess\.(?:env|versions|platform)\b|\b(?:execFile|spawnSync)\s*\(/, name);
    assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|WebTransport|RTCPeerConnection)\b/, `${name}: network API identifier`);
    assert.doesNotMatch(source, /google-analytics|googletagmanager|\bgtag\s*\(|\b(?:Sentry|posthog|mixpanel|amplitude)\s*\./i, `${name}: analytics`);
  }
  const worker = workerSources.map(item => item.source).join('\n');
  assert.match(worker, /crypto\??\.subtle\.digest\(/, 'The actual emitted worker must contain local WebCrypto hashing.');
  assert.match(worker, /browser_profile_checks_complete/, 'The supported-profile completion result must survive the production build.');
  assert.match(worker, /browser_profile_unsupported/, 'Unsupported profiles must retain an incomplete outcome.');
  assert.match(worker, /content_digests_not_recomputed/, 'Retained content digests must not become an independent content check.');
  assert.match(worker, /Incomplete or inconsistent browser completion\./, 'The independent completion-envelope guard must survive the production build.');
});

test('runtime imports and resource assignments cannot reference remote URLs', () => {
  for (const { name, source } of [...scripts, ...workerSources]) {
    // Plain document/specification URLs in diagnostic strings are not runtime
    // requests. Inspect loading expressions and assignments, not every URL word.
    assert.doesNotMatch(source, /\b(?:import|export)[^;\n]*?\bfrom\s*["'`](?:https?:|\/\/)/i, name);
    assert.doesNotMatch(source, /\b(?:import|Worker|SharedWorker|URL)\s*\(\s*["'`](?:https?:|wss?:|\/\/)/i, name);
    assert.doesNotMatch(source, /\b(?:src|href|srcset)\s*[:=]\s*["'`](?:https?:|wss?:|\/\/)/i, name);
    assert.doesNotMatch(source, /\.setAttribute\s*\(\s*["'`](?:src|href|srcset)["'`]\s*,\s*["'`](?:https?:|wss?:|\/\/)/i, name);
    assert.doesNotMatch(source, /sourceMappingURL\s*=/, `${name}: unexpected runtime source map`);
  }
});

test('production scripts and decoded workers omit persistence, logging, active HTML and cross-window channels', () => {
  for (const { name, source } of [...scripts, ...workerSources]) assertPrivateSource(source, name);
  // Source coverage also catches code that a minifier could otherwise remove.
  const shared = ['main.ts', 'model.ts', 'platform-browser.ts', 'platform-browser-job.ts', 'platform-browser-protocol.ts', 'browser-completion.ts', 'browser-worker.ts', 'browser-report.ts', 'browser-build-info.ts'];
  const verifier = inventory(join(sourceDirectory, 'verifier')).filter(path => path.endsWith('.ts') && !path.endsWith('.test.ts'));
  for (const path of [...shared.map(name => join(sourceDirectory, name)), ...verifier]) assertPrivateSource(readFileSync(path, 'utf8'), relative(sourceDirectory, path));
});

test('production HTML has no form submission, beacon, redirect or unreviewed active resource surface', () => {
  assertPrivateHtml(html);
});

test('browser evidence writes are limited to the explicit redacted report download path', () => {
  const adapter = readFileSync(join(sourceDirectory, 'platform-browser.ts'), 'utf8');
  const main = readFileSync(join(sourceDirectory, 'main.ts'), 'utf8');
  const beforeSave = adapter.slice(0, adapter.indexOf('async save('));
  const save = adapter.slice(adapter.indexOf('async save('), adapter.indexOf('async listenForDrops('));
  assert.ok(save.length > 0);
  assert.doesNotMatch(beforeSave, /(?:reportDownload|createObjectURL)\s*\(/, 'Selecting/checking must not trigger a download.');
  assert.equal([...adapter.matchAll(/reportDownload\s*\(/g)].length, 1);
  assert.match(save, /const download = reportDownload\(result\)/);
  assert.match(save, /URL\.createObjectURL\(new Blob\(\[download\.json\]/);
  assert.match(save, /anchor\.download = download\.name/);
  assert.match(save, /finally\s*\{\s*anchor\.remove\(\);\s*setTimeout\(\(\) => URL\.revokeObjectURL\(url\)/);
  assert.equal([...main.matchAll(/platform\.save\s*\(/g)].length, 1);
  assert.match(main, /saveButton\.addEventListener\('click',\s*\(\) => \{ void saveReport\(\); \}\)/);
  assert.equal([...main.matchAll(/void saveReport\s*\(/g)].length, 1, 'Report persistence must have a single explicit user-action entry point.');
});

test('privacy audit tripwires reject representative storage, logging, navigation and markup regressions', () => {
  for (const source of [
    "localStorage.setItem('package', bytes)", "globalThis['sessionStorage'].setItem('result', result)", 'indexedDB.open(name)', 'caches.open(name)',
    "document.cookie='evidence='+value", "document['cookie']=value", "navigator.storage.getDirectory()", "navigator.clipboard.writeText(value)", 'navigator.share(result)',
    'navigator.serviceWorker.register(path)', 'showSaveFilePicker()', 'console.log(bytes)', "console['warn'](result)", 'console?.error(result)',
    "new BroadcastChannel('evidence')", 'new SharedWorker(path)', "parent.postMessage(result,'*')", 'window.open(url)',
    'window.location.href = value', 'location.assign(url)', 'history.replaceState(result, "", url)', 'element.innerHTML = value', 'document.write(value)',
  ]) assert.throws(() => assertPrivateSource(source, 'negative fixture'), undefined, source);
  for (const markup of [
    '<form action="https://example.test/upload">', '<button formaction="/upload">', '<a href="#main" ping="https://example.test/log">',
    '<meta http-equiv="refresh" content="0;url=https://example.test/">', '<a href="https://example.test/">',
    '<iframe srcdoc="markup">', '<video src="https://example.test/video">', '<link rel="preconnect" href="https://example.test/">',
    '<img src=https://example.test/image>',
  ]) assert.throws(() => assertPrivateHtml(markup), undefined, markup);
  assert.doesNotThrow(() => assertPrivateSource('worker.postMessage(request); workerScope.postMessage(result); URL.revokeObjectURL(url);', 'local worker'));
  assert.doesNotThrow(() => assertPrivateHtml('<a href="#main">Local section</a><form id="comparisons">'));
});

test('browser distribution retains third-party Ed25519 vector attribution and license terms', () => {
  const bundled = [...scripts, ...workerSources].map(item => item.source).join('\n');
  for (const notice of ['WPT vector attribution', 'web-platform-tests contributors', 'Redistribution and use in source and binary forms', 'Neither the name of the copyright holder', 'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS']) {
    assert.ok(bundled.includes(notice), `Missing third-party vector notice: ${notice}`);
  }
});

test('worker audit decodes plain, base64, and data-URL literal payloads without execution', () => {
  const program = "self.onmessage=()=>self.postMessage({code:'browser_verifier_incomplete'});";
  const encoded = Buffer.from(program).toString('base64');
  // Pad a valid worker comment so the generic base64 candidate passes the
  // conservative minimum-size filter used for real compiled worker payloads.
  const padded = `${program}/*${'inert '.repeat(40)}*/`;
  const paddedEncoded = Buffer.from(padded).toString('base64');
  assert.deepEqual(decodedEmbeddedSources(`const worker=${JSON.stringify(program)};`), [program]);
  assert.deepEqual(decodedEmbeddedSources(`const worker='${paddedEncoded}';`), [padded]);
  assert.deepEqual(decodedEmbeddedSources(`const worker=\`data:text/javascript;base64,${paddedEncoded}\`;`), [padded]);
  assert.equal(encoded.includes('browser_verifier_incomplete'), false, 'Raw text scanning alone cannot audit a base64 payload.');
});

test('production CSS has no remote font imports or resource URLs', () => {
  for (const path of files.filter(path => path.endsWith('.css'))) {
    const css = readFileSync(path, 'utf8');
    assert.doesNotMatch(css, /@import\b/i, relative(output, path));
    for (const match of css.matchAll(/url\(\s*(["']?)(.*?)\1\s*\)/gi)) {
      const reference = match[2].trim();
      if (reference.startsWith('data:image/')) continue;
      if (reference.startsWith('#')) continue;
      localAsset(reference, path);
    }
  }
});
