// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { fixtureCanonical } from '../../tests/browser-test-support';
import { MAX_ARCHIVE_REFERENCE_BYTES, validWaybackReference, verifyArchiveReferences, type ArchiveReferenceKind } from './archive-references';

const encoder = new TextEncoder();
const canonical = (value: unknown): Uint8Array => encoder.encode(fixtureCanonical(value));
const subject = 'a'.repeat(64);
const capturedAt = '2026-01-01T00:00:00Z';
const prefix = 'https://web.archive.org/web/20260101000000';
const kind: ArchiveReferenceKind = 'attributable-wayback-capture';
const exactKind: ArchiveReferenceKind = 'exact-byte-wayback-capture';
const url = `${prefix}id_/https://example.test/article`;
function reference(overrides: Record<string, unknown> = {}) {
  return { capturedAt, kind, provider: 'Internet Archive', remoteUrl: url, verifiedAt: '2026-01-01T01:00:00Z', ...overrides };
}
function document(overrides: Record<string, unknown> = {}) {
  return { format: 'WP ContentLedger Archive Reference Set', references: [reference()], subjectSha256: subject, version: '3.0', ...overrides };
}
const check = (value: unknown, expectedKind: ArchiveReferenceKind = kind): number => verifyArchiveReferences(canonical(value), subject, expectedKind);

test('archive references retain both supported kinds without claiming online availability', () => {
  assert.equal(check(document()), 1);
  assert.equal(check(document({ references: [reference({ kind: exactKind })] }), exactKind), 1);
  assert.equal(check(document({ references: [reference({ verifiedAt: '2000-01-01T00:00:00Z' })] })), 1);
  // PHP does not impose new chronology or original-page/subject-URL equality.
  assert.equal(check(document({ references: [reference({ remoteUrl: `${prefix}/https://different.test/retained` })] })), 1);
});

test('archive references enforce set version, exact fields, subject, and 1..250 entries', () => {
  for (const overrides of [{ format: 'other' }, { version: '2.0' }, { extra: true }, { subjectSha256: 'b'.repeat(64) }, { subjectSha256: true },
    { references: null }, { references: [] }, { references: { named: reference() } }, { references: Array(251).fill(reference()) }]) {
    assert.throws(() => check(document(overrides)), { code: 'archive_reference_profile' });
  }
  const refs = Array.from({ length: 250 }, (_, index) => reference({ remoteUrl: `${prefix}/https://example.test/${String(index).padStart(3, '0')}` }));
  assert.equal(check(document({ references: refs })), 250);
  for (const field of ['format', 'references', 'subjectSha256', 'version']) {
    const missing: Record<string, unknown> = document(); delete missing[field];
    assert.throws(() => check(missing), { code: 'archive_reference_profile' });
  }
});

test('archive references apply byte/depth caps and canonical JSON before interpreting metadata', () => {
  assert.throws(() => verifyArchiveReferences(new Uint8Array(MAX_ARCHIVE_REFERENCE_BYTES + 1), subject, kind), { code: 'zip_entry_limit' });
  assert.throws(() => verifyArchiveReferences(new Uint8Array(), subject, kind), { code: 'json_invalid' });
  assert.throws(() => verifyArchiveReferences(encoder.encode(fixtureCanonical(document()) + '\n'), subject, kind), { code: 'json_noncanonical' });
  assert.throws(() => verifyArchiveReferences(encoder.encode('[]'), subject, kind), { code: 'json_object' });
  assert.throws(() => check(document({ references: {} })), { code: 'json_noncanonical' });
  let nested: unknown = false;
  for (let index = 0; index < 16; index++) nested = [nested];
  assert.throws(() => check(document({ nested })), { code: 'json_invalid' });
});

test('archive reference items have exact kind, provider, strings, and members', () => {
  for (const overrides of [{ kind: exactKind }, { kind: true }, { provider: 'Other Archive' }, { provider: null }, { remoteUrl: null }, { capturedAt: null },
    { verifiedAt: false }, { extra: true }, { capturedAt: '2026-02-30T00:00:00Z' }, { verifiedAt: '2026-02-30T00:00:00Z' }]) {
    assert.throws(() => check(document({ references: [reference(overrides)] })), { code: 'archive_reference_item' });
  }
  for (const item of [null, [], 'reference']) assert.throws(() => check(document({ references: [item] })), { code: 'archive_reference_item' });
  for (const field of ['capturedAt', 'kind', 'provider', 'remoteUrl', 'verifiedAt']) {
    const missing: Record<string, unknown> = reference(); delete missing[field];
    assert.throws(() => check(document({ references: [missing] })), { code: 'archive_reference_item' });
  }
});

test('archive capture timestamps are exact whole Z values matching valid Wayback calendar stamps', () => {
  for (const value of ['2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00.0Z', '2026-01-01T00:00:01Z', `${capturedAt}\n`]) {
    assert.equal(validWaybackReference(url, value, kind), false);
    assert.throws(() => check(document({ references: [reference({ capturedAt: value })] })), { code: 'archive_reference_item' });
  }
  for (const stamp of ['20260229000000', '20260431000000', '20260001000000', '20260101240000', '20260101000060']) {
    const changed = url.replace('20260101000000', stamp);
    assert.equal(validWaybackReference(changed, capturedAt, kind), false);
  }
  for (const [stamp, time] of [['20240229235959', '2024-02-29T23:59:59Z'], ['00000101000000', '0000-01-01T00:00:00Z']]) {
    assert.equal(validWaybackReference(url.replace('20260101000000', stamp), time, kind), true);
  }
});

test('archive verifiedAt retains the full JWS UTC profile rather than capture-stamp restrictions', () => {
  for (const verifiedAt of ['2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00.123456789Z', '0000-02-29T00:00:00Z']) {
    assert.equal(check(document({ references: [reference({ verifiedAt })] })), 1);
  }
  for (const verifiedAt of ['2026-01-01T00:00:00+01:00', '2026-01-01', '2026-01-01T00:00:00z', '2026-01-01T00:00:00Z\n']) {
    assert.throws(() => check(document({ references: [reference({ verifiedAt })] })), { code: 'archive_reference_item' });
  }
});

test('archive modifiers preserve attributable grammar and exact-byte id_ requirement', () => {
  for (const modifier of ['', 'id_', 'if_', 'abc', 'ABCDEFGHIJK_', '____________']) {
    assert.equal(validWaybackReference(`${prefix}${modifier}/https://example.test/`, capturedAt, kind), true);
    assert.equal(validWaybackReference(`${prefix}${modifier}/https://example.test/`, capturedAt, exactKind), modifier === 'id_');
  }
  for (const modifier of ['ID_', 'id', 'if_']) assert.throws(() => check(document({ references: [reference({ kind: exactKind, remoteUrl: `${prefix}${modifier}/https://example.test/` })] }), exactKind), { code: 'archive_reference_item' });
  for (const modifier of ['a'.repeat(13), 'id_1', 'id-', '%69d_']) assert.equal(validWaybackReference(`${prefix}${modifier}/https://example.test/`, capturedAt, kind), false);
});

test('archive URL carrier is exact HTTPS web.archive.org with only optional literal :443', () => {
  assert.equal(check(document({ references: [reference({ remoteUrl: url.replace('web.archive.org/', 'web.archive.org:443/') })] })), 1);
  for (const remoteUrl of [url.replace('https:', 'http:'), url.replace('https:', 'HTTPS:'), url.replace('web.archive.org', 'Web.Archive.Org'),
    url.replace('web.archive.org/', 'web.archive.org:0443/'), url.replace('web.archive.org/', 'web.archive.org:80/'), url.replace('web.archive.org', 'web.archive.org.example.test'),
    url.replace('/web/', '/WEB/'), `${url}\n`, `${url} `, `${url}\u007f`, `${url}é`, url.replace('/https://', '/http://')]) {
    assert.throws(() => check(document({ references: [reference({ remoteUrl })] })), { code: 'archive_reference_item' }, remoteUrl);
  }
});

test('archive original targets match permissive PHP parse_url instead of WHATWG normalization', () => {
  for (const original of ['https://example.test', 'https://example.test:', 'https://example.test:443', 'https://example.test:+443', 'https://example.test:12abc',
    'https://example.test:-0', 'https://example.test:1.2', 'https://example.test:1e2', 'https://example.test:abc:', 'https://example.test::',
    'https://[bad]/path', 'https://[::1]/path', 'https://[]/path', 'https://::1/path', 'https://bad_host/path', 'https://example.test\\retained',
    'https://00/path', 'https://example.test/path@retained', 'https://example.test/?x=value', 'https://example.test/%23fragment']) {
    const remoteUrl = `${prefix}id_/${original}`;
    assert.equal(validWaybackReference(remoteUrl, capturedAt, exactKind), true, original);
    assert.equal(check(document({ references: [reference({ kind: exactKind, remoteUrl })] }), exactKind), 1, original);
  }
  for (const original of ['https://', 'https://:', 'https://0', 'https://0:443/path', 'https:///example.test', 'https://?query', 'https://user@example.test',
    'https://user:pass@example.test', 'https://@example.test', 'https://example.test/#', 'https://example.test/#fragment',
    'https://example.test:000443/path', 'https://example.test:65536/path', 'https://example.test:-1/path', 'https://example.test:abc/path']) {
    assert.equal(validWaybackReference(`${prefix}id_/${original}`, capturedAt, exactKind), false, original);
  }
});

test('archive outer URL byte length and strict ascending URL order are enforced', () => {
  const base = `${prefix}/https://example.test/`;
  assert.equal(check(document({ references: [reference({ remoteUrl: base + 'a'.repeat(8192 - base.length) })] })), 1);
  assert.throws(() => check(document({ references: [reference({ remoteUrl: base + 'a'.repeat(8193 - base.length) })] })), { code: 'archive_reference_item' });
  const first = reference({ remoteUrl: `${base}A` }), second = reference({ remoteUrl: `${base}a` });
  assert.equal(check(document({ references: [first, second] })), 2);
  assert.throws(() => check(document({ references: [second, first] })), { code: 'archive_reference_item' });
  assert.throws(() => check(document({ references: [first, first] })), { code: 'archive_reference_item' });
});
