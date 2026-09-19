// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import test from 'node:test';
import { fixtureCanonical } from '../../tests/browser-test-support';
import { base64urlDecode, base64urlEncode, CHECKPOINT_JWS_TYPE, inspectCompactJws, isDidWebvh, isPublicJwk, jwkThumbprint,
  MAX_JWS_BYTES, parseCompactJws, type PublicJwk, verifyExactJws, verifyRecordJws } from './jws';

const encoder = new TextEncoder();
const bytes = (value: string): Uint8Array => encoder.encode(value);
const canonical = (value: unknown): Uint8Array => bytes(fixtureCanonical(value));
// Published RFC 8032 test seed, used only for disposable synthetic signatures.
const key = createPrivateKey({ key: Buffer.from('302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(key).export({ format: 'jwk' }) as PublicJwk;
const jwk: PublicJwk = { crv: 'Ed25519', kty: 'OKP', x: publicKey.x };
const thumbprint = createHash('sha256').update(canonical(jwk)).digest('base64url');
const issuer = `did:webvh:${'z'.repeat(46)}:example.test`;
const kid = `${issuer}#${thumbprint}`;
const manifest = { uuid: '12345678-1234-4123-8123-123456789abc', sha256: 'a'.repeat(64) };
const header = { alg: 'Ed25519', jwk, kid };
const payload = { documentVersion: '2.0' };
const claims = { contentLedgerSignatureVersion: '2.0', entryId: `urn:uuid:${manifest.uuid}`, issuedAt: '2026-09-19T00:00:00Z',
  issuer, manifestDigest: { algorithm: 'sha-256', value: manifest.sha256 }, verificationMethod: kid };

function compact(headerBytes: Uint8Array, payloadBytes: Uint8Array, signature?: Uint8Array): Uint8Array {
  const input = `${Buffer.from(headerBytes).toString('base64url')}.${Buffer.from(payloadBytes).toString('base64url')}`;
  return bytes(`${input}.${Buffer.from(signature ?? sign(null, Buffer.from(input), key)).toString('base64url')}`);
}
function signed(nextPayload: unknown = payload, nextHeader: unknown = header): Uint8Array { return compact(canonical(nextHeader), canonical(nextPayload)); }

test('JWS base64url is exact, unpadded, canonical, and byte preserving', () => {
  for (const value of [new Uint8Array([0]), new Uint8Array([255]), new Uint8Array([1, 2]), Uint8Array.from({ length: 256 }, (_, index) => index)]) {
    assert.deepEqual(base64urlDecode(base64urlEncode(value)), value);
    assert.equal(base64urlEncode(value), Buffer.from(value).toString('base64url'));
  }
  assert.equal(base64urlEncode(new Uint8Array()), '');
  for (const value of ['', 'A', 'AAAAA', 'YQ=', 'YQ==', ' YQ', 'YQ\n', 'YQ\r\n', 'YQ+', 'YQ/', 'YR', 'YWJ', 'éA']) {
    assert.throws(() => base64urlDecode(value), { code: 'base64url' }, value);
  }
});

test('JWS public JWK exact profile and thumbprint match independent SHA-256', async () => {
  assert.equal(isPublicJwk(jwk), true);
  assert.equal(await jwkThumbprint(jwk), thumbprint);
  for (const value of [null, [], {}, { ...jwk, d: 'secret' }, { ...jwk, kty: 'EC' }, { ...jwk, crv: 'Ed448' }, { ...jwk, x: jwk.x + '=' }, { ...jwk, x: 'AA' }, { ...jwk, x: `${jwk.x}\n` }, { ...jwk, x: 1 }]) {
    assert.equal(isPublicJwk(value), false);
    await assert.rejects(jwkThumbprint(value as PublicJwk), { code: 'jwk_profile' });
  }
});

test('JWS DID predicate matches the frozen ASCII grammar and full-string limits', () => {
  assert.equal(isDidWebvh(issuer), true);
  assert.equal(isDidWebvh(`${issuer}:segment_1:~path`), true);
  for (const value of [null, 2, `${issuer}\n`, issuer.replace('did:webvh:', 'did:web:'), issuer.replace('example', 'Example'), issuer.replace('example', 'ex..ample'),
    issuer.replace('z'.repeat(46), 'z'.repeat(45)), issuer.replace('z'.repeat(46), `0${'z'.repeat(45)}`), issuer + '/', issuer + ':', issuer + ':A', issuer + '#key',
    `did:webvh:${'z'.repeat(46)}:x`, `${issuer}:${'x'.repeat(2048)}`]) assert.equal(isDidWebvh(value), false, String(value));
  assert.equal(isDidWebvh(`${issuer}:${'x'.repeat(2048 - issuer.length - 1)}`), true);
});

test('JWS inspection exposes exact payload but makes no signature claim', () => {
  const result = inspectCompactJws(signed(payload, header));
  assert.equal(result.payloadJson, fixtureCanonical(payload));
  assert.deepEqual(result.payloadBytes, canonical(payload));
  assert.equal(result.kid, kid);
  assert.equal(result.jwk.x, jwk.x);
  assert.equal('signatureValid' in result, false);
  assert.equal('signature' in result, false);
  assert.equal('signingInput' in result, false);
  assert.equal(parseCompactJws(signed()).signature.length, 64);
});

test('JWS verifies typed and untyped exact payloads with embedded Ed25519 keys', async () => {
  const plain = await verifyExactJws(signed(), canonical(payload), null, kid, jwk);
  assert.equal(plain.signatureValid, true);
  assert.equal('issuer' in plain, false);
  const typedHeader = { ...header, typ: CHECKPOINT_JWS_TYPE };
  const typed = await verifyExactJws(signed(payload, typedHeader), canonical(payload), CHECKPOINT_JWS_TYPE, kid, jwk);
  assert.equal(typed.signatureValid, true);
  assert.equal(typed.header.typ, CHECKPOINT_JWS_TYPE);
});

test('JWS rejects empty, oversized, NUL, and inexact compact envelopes', () => {
  for (const value of [new Uint8Array(), new Uint8Array(MAX_JWS_BYTES + 1).fill(65), bytes('abc\0.def.ghi')]) assert.throws(() => inspectCompactJws(value), { code: 'jws_size' });
  for (const value of ['one', 'one.two', 'one.two.three.four', '.two.three', 'one..three', 'one.two.']) assert.throws(() => inspectCompactJws(bytes(value)), { code: 'jws_compact' });
  assert.throws(() => inspectCompactJws(new Uint8Array(MAX_JWS_BYTES).fill(65)), { code: 'jws_compact' });
});

test('JWS rejects base64 aliases, trailing newline, and non-ASCII source bytes', () => {
  const good = Buffer.from(signed()).toString('ascii');
  const parts = good.split('.');
  for (const value of [`${good}\n`, `${parts[0]}=.${parts[1]}.${parts[2]}`, `${parts[0]}.${parts[1]}=.${parts[2]}`]) assert.throws(() => inspectCompactJws(bytes(value)), { code: 'base64url' });
  const invalid = Buffer.from(good); invalid[0] = 255;
  assert.throws(() => inspectCompactJws(invalid), { code: 'base64url' });
});

test('JWS signature length is checked before canonical JSON interpretation', () => {
  for (const length of [1, 31, 32, 63, 65]) assert.throws(() => inspectCompactJws(compact(bytes('bad'), bytes('bad'), new Uint8Array(length))), { code: 'jws_signature_size' });
});

test('JWS requires canonical object header and payload bytes', () => {
  const signature = new Uint8Array(64);
  for (const nextHeader of [bytes(JSON.stringify({ kid, jwk, alg: 'Ed25519' })), bytes(fixtureCanonical(header) + '\n')]) {
    // The first header deliberately has non-lexical insertion order.
    assert.throws(() => inspectCompactJws(compact(nextHeader, canonical(payload), signature)), { code: 'json_noncanonical' });
  }
  assert.throws(() => inspectCompactJws(compact(canonical(header), bytes('{"documentVersion":"2.0", "extra":true}'), signature)), { code: 'json_noncanonical' });
  assert.throws(() => inspectCompactJws(compact(canonical(header), bytes('[]'), signature)), { code: 'json_object' });
  assert.throws(() => inspectCompactJws(compact(bytes('[]'), canonical(payload), signature)), { code: 'json_object' });
  assert.throws(() => inspectCompactJws(compact(canonical(header), Uint8Array.of(255), signature)), { code: 'json_invalid' });
});

test('JWS protected headers permit only the frozen Ed25519 profile', () => {
  for (const nextHeader of [{ ...header, alg: 'EdDSA' }, { ...header, alg: 'none' }, { ...header, jwk: { ...jwk, d: 'forbidden' } },
    { ...header, crit: ['x'] }, { ...header, b64: false }, { ...header, jku: 'https://example.test/key' }, { ...header, kid: null }, { ...header, kid: 'x'.repeat(4097) },
    { ...header, kid: 'é'.repeat(2049) }, { ...header, typ: CHECKPOINT_JWS_TYPE }]) assert.throws(() => inspectCompactJws(signed(payload, nextHeader)), { code: 'jws_header' });
  assert.doesNotThrow(() => inspectCompactJws(signed(payload, { ...header, kid: 'é'.repeat(2048) })));
  assert.doesNotThrow(() => inspectCompactJws(signed(payload, { ...header, kid: '' })));
  assert.throws(() => inspectCompactJws(signed(), CHECKPOINT_JWS_TYPE), { code: 'jws_header' });
  assert.throws(() => inspectCompactJws(signed(payload, { ...header, typ: 'other' }), CHECKPOINT_JWS_TYPE), { code: 'jws_header' });
});

test('JWS exact binding rejects different payload bytes, method, and public key before crypto', async () => {
  const input = signed();
  await assert.rejects(verifyExactJws(input, bytes(fixtureCanonical(payload) + '\n'), null), { code: 'jws_payload_binding' });
  await assert.rejects(verifyExactJws(input, canonical({ documentVersion: '3.0' }), null, 'wrong'), { code: 'jws_payload_binding' });
  await assert.rejects(verifyExactJws(input, canonical(payload), null, `${kid}\n`), { code: 'jws_kid_binding' });
  await assert.rejects(verifyExactJws(input, canonical(payload), null, kid, { ...jwk, x: 'A'.repeat(43) }), { code: 'jws_jwk_binding' });
});

test('JWS Ed25519 rejects a same-size corrupted signature and changed signed payload', async () => {
  const original = parseCompactJws(signed());
  const signature = new Uint8Array(original.signature); signature[0] ^= 1;
  await assert.rejects(verifyExactJws(compact(canonical(header), canonical(payload), signature), canonical(payload), null), { code: 'jws_signature_invalid' });
  const changed = { documentVersion: '3.0' };
  await assert.rejects(verifyExactJws(compact(canonical(header), canonical(changed), original.signature), canonical(changed), null), { code: 'jws_signature_invalid' });
});

test('record JWS binds manifest digest, UUID, DID, deterministic key ID, and signing-time claims', async () => {
  const result = await verifyRecordJws(signed(claims), manifest);
  assert.equal(result.signatureValid, true);
  assert.equal(result.issuer, issuer);
  assert.equal(result.issuedAt, claims.issuedAt);
  assert.equal('authorized' in result, false);
});

test('record JWS rejects missing or extra claims and malformed digest objects', async () => {
  for (const claim of Object.keys(claims)) {
    const missing: Record<string, unknown> = { ...claims }; delete missing[claim];
    await assert.rejects(verifyRecordJws(signed(missing), manifest), { code: 'record_jws_claims' });
  }
  await assert.rejects(verifyRecordJws(signed({ ...claims, arbitrary: true }), manifest), { code: 'record_jws_claims' });
  for (const digest of [null, [], ['sha-256', manifest.sha256], { algorithm: 'sha-256' }, { algorithm: 'sha-256', value: manifest.sha256, extra: true }]) {
    await assert.rejects(verifyRecordJws(signed({ ...claims, manifestDigest: digest }), manifest), { code: 'record_jws_binding' });
  }
});

test('record JWS rejects each crossed application binding independently', async () => {
  for (const override of [{ contentLedgerSignatureVersion: '1.0' }, { entryId: 'urn:uuid:12345678-1234-4123-8123-123456789abd' },
    { manifestDigest: { algorithm: 'sha-512', value: manifest.sha256 } }, { manifestDigest: { algorithm: 'sha-256', value: 'b'.repeat(64) } },
    { manifestDigest: { algorithm: 'sha-256', value: null } }, { issuer: `${issuer}\n` }, { issuer: 12 }, { verificationMethod: `${kid}\n` },
    { issuedAt: '2026-02-30T00:00:00Z' }, { issuedAt: '2026-09-19T00:00:00+01:00' }, { issuedAt: `${claims.issuedAt}\n` }]) {
    await assert.rejects(verifyRecordJws(signed({ ...claims, ...override }), manifest), { code: 'record_jws_binding' });
  }
});

test('record JWS checks deterministic issuer thumbprint without claiming key authorization', async () => {
  const wrongKid = `${issuer}#other`;
  await assert.rejects(verifyRecordJws(signed({ ...claims, verificationMethod: wrongKid }, { ...header, kid: wrongKid }), manifest), { code: 'record_jws_controller' });
  const otherIssuer = issuer.replace('example.test', 'another.test');
  const otherKid = `${otherIssuer}#${thumbprint}`;
  assert.equal((await verifyRecordJws(signed({ ...claims, issuer: otherIssuer, verificationMethod: otherKid }, { ...header, kid: otherKid }), manifest)).signatureValid, true);
});

test('JWS verification snapshots Buffer inputs before its first asynchronous operation', async () => {
  const input = Buffer.from(signed(claims));
  const promise = verifyRecordJws(input, manifest);
  input.fill(0);
  assert.equal((await promise).signatureValid, true);
  const exactInput = Buffer.from(signed());
  const expectedPayload = Buffer.from(canonical(payload));
  const exactPromise = verifyExactJws(exactInput, expectedPayload, null);
  exactInput.fill(0); expectedPayload.fill(0);
  assert.equal((await exactPromise).signatureValid, true);
});
