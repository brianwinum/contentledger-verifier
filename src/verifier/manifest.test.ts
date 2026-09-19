// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { fixtureCanonical } from '../../tests/browser-test-support';
import { isHttpsUrl, isManifestDate, isManifestHash, isUuidUrn, MAX_MANIFEST_BYTES, verifyManifest } from './manifest';

const uuid = '12345678-1234-4123-8123-123456789abc';
const date = '2026-09-19T00:00:00Z';
const digest = { algorithm: 'sha-256', canonicalization: 'wp-contentledger-content-v1', scope: 'canonical-content', value: 'a'.repeat(64) };
const subject = { canonicalUrl: 'https://example.test/article', postType: 'post', publisher: { name: 'Publisher', url: 'https://example.test' }, title: 'Article', type: 'WebPage' };

function document(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    $schema: 'https://example.test/schema/manifest-v2.json', digests: [{ ...digest }], entryId: `urn:uuid:${uuid}`,
    evidenceScope: ['canonical-content-integrity', 'publisher-controlled-recording'], generator: { name: 'WP ContentLedger', version: '0.13.12' },
    limitations: ['Publisher-controlled recording.'], manifestVersion: '2.0',
    provenance: { evidenceCapturedAt: date, recordSource: 'publish', sealedFromPreviouslyCapturedEvidence: false },
    sealedAt: date, subject: structuredClone(subject), ...overrides,
  };
}

function v1(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const value = document({ manifestVersion: '1.0', digests: [], provenance: { evidenceCapturedAt: date, legacyImported: true, recordSource: 'legacy' },
    archiveEvidence: { capturedAt: date, discoveryMethod: 'availability-api', provider: { name: 'Internet Archive', url: 'https://archive.org' },
      snapshotUrl: 'https://web.archive.org/web/20260919000000/https://example.test/article', verificationMethod: 'http-resolution', verificationStatus: 'verified', verifiedAt: date }, ...overrides });
  delete value.evidenceScope;
  return value;
}

function bytes(value: unknown): Uint8Array { return new TextEncoder().encode(fixtureCanonical(value)); }
async function rejects(value: unknown, code: string): Promise<void> { await assert.rejects(verifyManifest(bytes(value)), { code }); }

test('manifest v1 and v2 validate exact canonical bytes and expose only bound declarations', async () => {
  for (const value of [v1(), document()]) {
    const input = bytes(value);
    const hash = createHash('sha256').update(input).digest('hex');
    const result = await verifyManifest(input, uuid, hash);
    assert.equal(result.sha256, hash);
    assert.equal(result.uuid, uuid);
    assert.equal(result.version, value.manifestVersion);
    assert.equal(result.canonicalUrl, subject.canonicalUrl);
    assert.equal(result.sealedAt, date);
    assert.equal(result.previous, null);
    assert.equal(fixtureCanonical(result.document), fixtureCanonical(value));
  }
});

test('manifest hashes and entry paths remain exact lowercase bindings', async () => {
  await assert.rejects(verifyManifest(bytes(document()), '', 'b'.repeat(64)), { code: 'manifest_expected_hash' });
  await assert.rejects(verifyManifest(bytes(document()), '', 'A'.repeat(64)), { code: 'manifest_expected_hash' });
  await assert.rejects(verifyManifest(bytes(document()), `${uuid}\n`), { code: 'manifest_entry_path' });
  for (const value of ['a'.repeat(64) + '\n', 'a'.repeat(63), 'A'.repeat(64), 42, null]) assert.equal(isManifestHash(value), false);
  assert.equal(isManifestHash('a'.repeat(64)), true);
  for (const value of [`urn:uuid:${uuid}\n`, `URN:UUID:${uuid}`, `urn:uuid:${uuid.toUpperCase()}`, 'urn:uuid:12345678-1234-6123-8123-123456789abc']) assert.equal(isUuidUrn(value), false);
});

test('manifest decoding and profile markers fail closed without relabeling unsupported as invalid', async () => {
  await assert.rejects(verifyManifest(new Uint8Array()), { code: 'manifest_size' });
  await assert.rejects(verifyManifest(new Uint8Array(MAX_MANIFEST_BYTES + 1)), { code: 'manifest_size' });
  await assert.rejects(verifyManifest(new TextEncoder().encode(JSON.stringify(document(), null, 2))), { code: 'json_noncanonical' });
  await assert.rejects(verifyManifest(bytes(document({ manifestVersion: '3.0' }))), { code: 'manifest_profile', kind: 'unsupported' });
  await rejects(document({ manifestVersion: null }), 'manifest_profile');
  await rejects(document({ extra: false }), 'manifest_shape');
  const missing = document(); delete missing.limitations;
  await rejects(missing, 'manifest_shape');
});

test('v2 scope and provenance use exact types, fields, and order', async () => {
  await rejects(document({ evidenceScope: ['publisher-controlled-recording', 'canonical-content-integrity'] }), 'manifest_scope');
  await rejects(document({ evidenceScope: [] }), 'manifest_scope');
  for (const provenance of [null, [], { evidenceCapturedAt: date, recordSource: 'x', sealedFromPreviouslyCapturedEvidence: 0 }, { evidenceCapturedAt: '2026-02-30T00:00:00Z', recordSource: 'x', sealedFromPreviouslyCapturedEvidence: true }]) {
    await rejects(document({ provenance }), 'manifest_provenance');
  }
});

test('UTC dates validate Gregorian leap years, zero year, fractions, and exact ending', () => {
  for (const value of ['0000-02-29T00:00:00Z', '0099-01-01T00:00:00Z', '2000-02-29T23:59:59.123456789+00:00', date]) assert.equal(isManifestDate(value), true, value);
  for (const value of ['1900-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:60Z', '2026-01-01T00:00:00-00:00', date + '\n', date.toLowerCase(), null, 0]) assert.equal(isManifestDate(value), false, String(value));
});

test('UTC fractions preserve PHP double overflow and midnight rounding without a length cap', () => {
  for (const ending of ['Z', '+00:00']) {
    for (const fraction of ['1'.repeat(309), '0'.repeat(1000), '0'.repeat(1000) + '1']) {
      assert.equal(isManifestDate(`2026-09-19T00:00:00.${fraction}${ending}`), true);
    }
    for (const fraction of ['1'.repeat(310), '9'.repeat(309), '1' + '0'.repeat(999)]) {
      assert.equal(isManifestDate(`2026-09-19T00:00:00.${fraction}${ending}`), false);
    }
    for (const length of [15, 17]) assert.equal(isManifestDate(`2026-09-19T23:59:59.${'9'.repeat(length)}${ending}`), true);
    for (const length of [16, 18, 20, 50, 100, 308]) {
      assert.equal(isManifestDate(`2026-09-19T23:59:59.${'9'.repeat(length)}${ending}`), false);
      assert.equal(isManifestDate(`2026-09-19T23:59:58.${'9'.repeat(length)}${ending}`), true);
    }
  }
});

test('PHP-compatible HTTPS predicates avoid browser normalization or URL fetching', () => {
  for (const value of ['https://example.test', 'https://localhost', 'https://999.999.999.999', 'https://foo-.', 'https://example.test:', 'https://example.test:80abc', 'https://example.test:+80', 'https://example.test:-0', 'https://example.test/"<>\\`{|}^', 'https://%41:pass@example.test', 'https://@example.test', 'https://[::1]', 'https://[::ffff:192.0.2.1]:443']) assert.equal(isHttpsUrl(value), true, value);
  for (const value of ['HTTPS://example.test', 'http://example.test', 'https:///path', 'https://-foo.test', 'https://foo-.test', 'https://foo_bar.test', 'https://.test', 'https://example..test', 'https://example.test:65536', 'https://example.test:000080', 'https://example.test:-1', 'https://example.test:abc', 'https://%ab@example.test', 'https://a@b@example.test', 'https://é.test', 'https://example.test/é', 'https://example.test/a b', 'https://example.test/\n', 'https://[::ffff:192.000.2.1]', 'https://[1:2:3:4:5:6:7:8:9]', 'https://[1:2:3:4:5:6:7:8::]', null]) assert.equal(isHttpsUrl(value), false, String(value));
  assert.equal(isHttpsUrl('https://' + 'a'.repeat(63) + '.test'), true);
  assert.equal(isHttpsUrl('https://' + 'a'.repeat(64) + '.test'), false);
  assert.equal(isHttpsUrl('https://example.test/' + 'a'.repeat(8192 - 21)), true);
  assert.equal(isHttpsUrl('https://example.test/' + 'a'.repeat(8193 - 21)), false);
});

test('generator and limitation bounds count UTF-8 bytes, not UTF-16 units', async () => {
  await verifyManifest(bytes(document({ generator: { name: 'WP ContentLedger', version: 'é'.repeat(32) }, limitations: ['🧪'.repeat(1024)] })));
  await rejects(document({ generator: { name: 'WP ContentLedger', version: 'é'.repeat(33) } }), 'manifest_generator');
  await rejects(document({ limitations: ['🧪'.repeat(1025)] }), 'manifest_limitations');
  for (const limitations of [[], Array(33).fill('x'), [''], [false], false]) await rejects(document({ limitations }), 'manifest_limitations');
});

test('digest declarations preserve PHP acceptance and reject duplicate or malformed scopes', async () => {
  await rejects(document({ digests: [] }), 'manifest_digests');
  await rejects(document({ digests: [digest, digest] }), 'manifest_digest');
  await rejects(document({ digests: [digest, digest, digest] }), 'manifest_digests');
  await rejects(document({ digests: [{ ...digest, value: 'a'.repeat(64) + '\n' }] }), 'manifest_digest');
  await rejects(document({ digests: [{ ...digest, extra: null }] }), 'manifest_digest');
  await rejects(document({ digests: [{ ...digest, scope: 'public-representation' }] }), 'manifest_digest');
  await verifyManifest(bytes(document({ digests: [{ ...digest, scope: 'public-representation', mediaType: '', retrievedAt: date }] })));
  // Optional media fields are only interpreted for the public-representation scope.
  await verifyManifest(bytes(document({ digests: [{ ...digest, mediaType: false, retrievedAt: null }] })));
});

test('PHP isset semantics preserve null optional fields without applying new policy', async () => {
  const result = await verifyManifest(bytes(document({ chain: null, limitations: null, subject: { ...subject, author: null, dateModified: null, datePublished: null, description: null, featuredImage: null, language: null, taxonomies: null } })));
  assert.equal(result.previous, null);
  await verifyManifest(bytes(v1({ limitations: null })));
  const historical = v1(); delete historical.limitations;
  await verifyManifest(bytes(historical));
});

test('manifest predecessor syntax is verified independently of graph closure', async () => {
  const result = await verifyManifest(bytes(document({ chain: { algorithm: 'sha-256', previousManifestDigest: 'b'.repeat(64) } })));
  assert.equal(result.previous, 'b'.repeat(64));
  for (const chain of [false, [], { algorithm: 'sha-256', previousManifestDigest: 'b'.repeat(64), extra: '' }, { algorithm: 'sha-512', previousManifestDigest: 'b'.repeat(64) }]) await rejects(document({ chain }), 'manifest_chain');
});

test('subject metadata and taxonomy declarations retain their exact field boundaries', async () => {
  await verifyManifest(bytes(document({ subject: { ...subject, title: '', taxonomies: { category: [{ name: '', slug: '' }], tags: [] } } })));
  await rejects(document({ subject: { ...subject, extra: 'x' } }), 'manifest_subject');
  await rejects(document({ subject: { ...subject, publisher: { name: 'Publisher', url: 'http://example.test' } } }), 'manifest_subject');
  await rejects(document({ subject: { ...subject, datePublished: '2026-02-30T00:00:00Z' } }), 'manifest_subject_date');
  await rejects(document({ subject: { ...subject, featuredImage: 'http://example.test/image.png' } }), 'manifest_subject_image');
  await rejects(document({ subject: { ...subject, description: false } }), 'manifest_subject_text');
  await rejects(document({ subject: { ...subject, taxonomies: [] } }), 'manifest_taxonomies');
  await rejects(document({ subject: { ...subject, taxonomies: { category: Array(1001).fill({ name: 'x', slug: 'x' }) } } }), 'manifest_taxonomies');
  await rejects(document({ subject: { ...subject, taxonomies: { category: [{ name: 'x', slug: 1 }] } } }), 'manifest_term');
});

test('historical v1 archive and provenance claims validate without claiming preservation', async () => {
  await rejects(v1({ archiveEvidence: null }), 'manifest_archive');
  const archive = v1().archiveEvidence as Record<string, unknown>;
  await rejects(v1({ archiveEvidence: { ...archive, verificationStatus: 'pending' } }), 'manifest_archive');
  await rejects(v1({ archiveEvidence: { ...archive, capturedAt: '2026-09-31T00:00:00Z' } }), 'manifest_archive');
  await rejects(v1({ provenance: { evidenceCapturedAt: date, legacyImported: 1, recordSource: 'legacy' } }), 'manifest_provenance');
});

test('manifest snapshots mutable Buffer input before asynchronous hashing', async () => {
  const input = Buffer.from(bytes(document()));
  const hash = createHash('sha256').update(input).digest('hex');
  const result = verifyManifest(input);
  input.fill(0);
  assert.equal((await result).sha256, hash);
});
