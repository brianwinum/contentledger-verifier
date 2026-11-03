// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { encodeCanonical } from './canonical';
import { verifyManifest } from './manifest';

const field = { name: 'service_area', present: true, value: ['Washington', 'Oregon'] };
const product = { sku: 'S-1', regularPrice: '29.95', salePrice: '', currency: 'USD', stockStatus: 'instock',
  attributes: [{ name: 'pa_color', values: ['blue'] }], variations: [
    { id: '12', parentId: '10', sku: 'S-1-B', regularPrice: '29.95', salePrice: '', stockStatus: 'instock', attributes: [{ name: 'pa_color', values: ['blue'] }] },
  ] };
const media = { algorithm: 'sha-256', sha256: 'b'.repeat(64), bytes: 1024, mimeType: 'image/png', scope: 'original-file-bytes', width: 16, height: 16, alt: 'Public diagram' };
function manifest(extra: Record<string, unknown> = {}): Record<string, any> {
  return { $schema: 'https://example.test/?contentledger_schema=manifest-v2.1', manifestVersion: '2.1',
    entryId: 'urn:uuid:12345678-1234-4123-8123-123456789abc', sealedAt: '2026-11-01T00:00:00Z',
    generator: { name: 'WP ContentLedger', version: '0.13.27' },
    evidenceScope: ['canonical-content-integrity', 'publisher-controlled-recording'], limitations: ['Selected public declarations; no ownership claim.'],
    provenance: { evidenceCapturedAt: '2026-11-01T00:00:00Z', recordSource: 'publish', sealedFromPreviouslyCapturedEvidence: false },
    digests: [{ algorithm: 'sha-256', canonicalization: 'wp-contentledger-content-v2', scope: 'canonical-content', value: 'a'.repeat(64) }],
    subject: { type: 'WebPage', canonicalUrl: 'https://example.test/services', postType: 'services', title: 'Services', publisher: { name: 'Example', url: 'https://example.test' },
      coverage: { profile: 'wp-contentledger-coverage-v1', fields: [structuredClone(field)], ...structuredClone(extra) } } };
}
function encoded(doc: unknown) { return new TextEncoder().encode(encodeCanonical(doc)); }
const cases: Array<{ name: string; doc: Record<string, any>; code?: string }> = [];
function vector(name: string, change: (doc: Record<string, any>) => void, code?: string) { const doc = manifest({ product, media }); change(doc); cases.push({ name, doc, code }); }
vector('combined declared coverage', () => {});
vector('absent selected field', d => { d.subject.coverage.fields = [{ name: 'optional', present: false, value: null }]; });
vector('no selected custom fields', d => { d.subject.coverage.fields = []; });
vector('duplicate field', d => d.subject.coverage.fields.push(structuredClone(field)), 'coverage_field');
vector('excluded field pretending absent', d => { d.subject.coverage.fields[0].present = false; }, 'coverage_field');
vector('private field key', d => { d.subject.coverage.fields[0].name = '_internal'; }, 'coverage_field');
vector('unknown object field value', d => { d.subject.coverage.fields[0].value = { secret: 'no' }; }, 'coverage_value');
vector('field depth limit', d => { d.subject.coverage.fields[0].value = [[['x']]]; }, 'coverage_value');
vector('UTF-8 byte limit', d => { d.subject.coverage.fields[0].value = '🧪'.repeat(2049); }, 'coverage_value');
vector('field count limit', d => { d.subject.coverage.fields = Array.from({ length: 101 }, (_, i) => ({ name: `a${i}`, present: true, value: '' })); }, 'coverage_profile');
vector('unsupported profile', d => { d.subject.coverage.profile = 'unknown'; }, 'coverage_profile');
vector('legacy content profile', d => { d.digests[0].canonicalization = 'wp-contentledger-content-v1'; }, 'coverage_digest');
vector('legacy manifest cannot carry coverage', d => { d.manifestVersion = '2.0'; }, 'manifest_subject');
vector('coverage required in 2.1', d => { delete d.subject.coverage; }, 'coverage_shape');
vector('media reference is not a file hash', d => { d.subject.coverage.media.sha256 = 'https://example.test/file.png'; }, 'coverage_media');
vector('media byte limit', d => { d.subject.coverage.media.bytes = 20971521; }, 'coverage_media');
vector('media dimension pair', d => { delete d.subject.coverage.media.width; }, 'coverage_media');
vector('replacement hash accepted as another declaration', d => { d.subject.coverage.media.sha256 = 'c'.repeat(64); });
vector('invalid stored price', d => { d.subject.coverage.product.salePrice = '1e2'; }, 'coverage_product');
vector('negative stock quantity supported', d => { d.subject.coverage.product.stockQuantity = '-1'; });
vector('currency case', d => { d.subject.coverage.product.currency = 'usd'; }, 'coverage_product');
vector('duplicate variation', d => { d.subject.coverage.product.variations.push(structuredClone(product.variations[0])); }, 'coverage_product');
vector('mismatched variation parent', d => { d.subject.coverage.product.variations.push({ ...structuredClone(product.variations[0]), id: '13', parentId: '11' }); }, 'coverage_product');
vector('duplicate attribute', d => { d.subject.coverage.product.attributes.push(structuredClone(product.attributes[0])); }, 'coverage_product');
vector('UTF-8 attribute sort', d => { d.subject.coverage.product.attributes = [{ name: '\uE000', values: [] }, { name: '🧪', values: [] }]; });
vector('oversized overall coverage', d => { d.subject.coverage.fields = Array.from({ length: 17 }, (_, i) => ({ name: `f${String(i).padStart(2, '0')}`, present: true, value: 'a'.repeat(8192) })); }, 'coverage_shape');

for (const c of cases) test(`manifest 2.1: ${c.name}`, async () => {
  if (c.code) await assert.rejects(verifyManifest(encoded(c.doc)), { code: c.code });
  else assert.equal((await verifyManifest(encoded(c.doc))).version, '2.1');
});

// Optional differential qualification against the exact 3.1 PHP source under review.
// No network, WordPress, source files, private keys or Bitcoin services are opened.
test('extended vectors agree with the supplied portable PHP reference', { skip: !process.env.CONTENTLEDGER_MANIFEST_REFERENCE }, async () => {
  const script = "require getenv('CONTENTLEDGER_MANIFEST_REFERENCE'); try { (new \\WPContentLedger\\Portable\\Manifest_Verifier())->verify(stream_get_contents(STDIN)); echo 'valid'; } catch (\\Throwable $e) { echo 'invalid'; }";
  for (const c of cases) {
    const result = spawnSync(process.env.CONTENTLEDGER_PHP_BINARY || 'php', ['-r', script], { input: encoded(c.doc), encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, `${c.name}: ${result.stderr}`);
    assert.equal(result.stdout, c.code ? 'invalid' : 'valid', c.name);
  }
});
