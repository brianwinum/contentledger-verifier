// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  WebvhError, decodeNumberFree, canonicalize, base58Encode, base58Decode,
  sha256Multihash, decodeSha256Multihash, encodeEd25519Multikey, decodeEd25519Multikey,
  updateKeyHash, decodeProofValue, base64urlEncode, decodeEd25519JwkX,
  assertionJwkThumbprint, replaceStrings, assertEd25519PublicKeyEncoding,
} from './webvh-codec';
import { VerifierError } from './errors';

const publicKey = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);
function throws(status: string, code: string, operation: () => unknown): void {
  assert.throws(operation, (error: unknown) => error instanceof WebvhError && error.status === status && error.code === code && error.message === code);
}

test('WebVH number-free JSON preserves empty objects and normalizes permitted whitespace', () => {
  assert.equal(canonicalize(decodeNumberFree(' \n\r\t{ "b" : [true,false,null,{}],"a":"text" } \n')), '{"a":"text","b":[true,false,null,{}]}');
  assert.equal(canonicalize(decodeNumberFree('{}')), '{}');
  assert.equal(canonicalize(decodeNumberFree('[]')), '[]');
  assert.equal(canonicalize(decodeNumberFree('"number 123"')), '"number 123"');
  assert.equal(Object.getPrototypeOf(decodeNumberFree('{}')), null);
});

test('WebVH number-free JSON refuses every numeric token, even malformed numeric prefixes', () => {
  for (const input of ['0', '-0', '1.0', '1e0', '9223372036854775808', '-garbage', '01', '[0]', '{"a":-}']) {
    throws('unsupported', 'json_number_unsupported', () => decodeNumberFree(input));
  }
  for (const number of [0, -0, 0.5, NaN, Infinity, 3n]) throws('unsupported', 'json_number_unsupported', () => canonicalize(number));
});

test('WebVH number-free JSON rejects duplicate decoded names without Unicode normalization', () => {
  for (const input of ['{"a":true,"a":false}', '{"a":true,"\\u0061":false}', '{"0":null,"\\u0030":null}', '{"__proto__":true,"__proto__":false}']) {
    throws('malformed', 'json_duplicate_member', () => decodeNumberFree(input));
  }
  assert.equal(canonicalize(decodeNumberFree('{"é":true,"é":false}')), '{"é":false,"é":true}');
});

test('WebVH numeric property names preserve PHP stdClass decode and integer-key encoding behavior', () => {
  for (const key of ['0', '1', '-1', '9223372036854775807', '-9223372036854775808']) {
    const value = decodeNumberFree(JSON.stringify({ [key]: true })) as Record<string, unknown>;
    assert.equal(value[key], true);
    throws('unsupported', 'json_number_unsupported', () => canonicalize(value));
  }
  for (const key of ['-0', '00', '01', '+1', '1.0', '1e0', '9223372036854775808', '-9223372036854775809']) {
    const json = JSON.stringify({ [key]: true });
    assert.equal(canonicalize(decodeNumberFree(json)), json);
  }
});

test('WebVH canonical JSON sorts UTF-16 units and preserves Unicode, slashes and line separators', () => {
  const input = '{"":"/é\u2028\u2029","😀":"\\uD83D\\uDE00","a":"\\b\\f\\n\\r\\t\\u0000"}';
  assert.equal(canonicalize(decodeNumberFree(input)), '{"a":"\\b\\f\\n\\r\\t\\u0000","😀":"😀","":"/é\u2028\u2029"}');
});

test('WebVH string errors reject bad escapes, controls, surrogate halves and invalid UTF-8', () => {
  for (const input of ['"\\x"', '"\\u123"', '"\\u12x4"', '"\\ud800"', '"\\udfff"', '"\\ud800a"', '"unterminated', '"line\n"', '"end\\']) {
    throws('malformed', 'json_string', () => decodeNumberFree(input));
  }
  for (const input of [Uint8Array.from([34, 0xc0, 0xaf, 34]), Uint8Array.from([34, 0xed, 0xa0, 0x80, 34]), Uint8Array.from([34, 0xff, 34])]) {
    throws('malformed', 'json_string', () => decodeNumberFree(input));
  }
  throws('malformed', 'json_string', () => canonicalize('\ud800'));
  assert.equal(canonicalize(decodeNumberFree('"\\ufeff"')), '"﻿"');
});

test('WebVH syntax errors stay distinct from unsupported numbers and string errors', () => {
  for (const input of ['', ' ', '{}{}', 'true false', '{a:true}', '{"a" true}', '{"a":true,}', '[true,]', '+1', 'TRUE', '\ufeff{}', '\v{}', 'NaN']) {
    throws('malformed', 'json_syntax', () => decodeNumberFree(input));
  }
  throws('malformed', 'json_syntax', () => decodeNumberFree(Uint8Array.from([0xff])));
});

test('WebVH depth bound counts values from one and handles empty containers exactly', () => {
  const allowed = '['.repeat(31) + 'null' + ']'.repeat(31);
  assert.equal(canonicalize(decodeNumberFree(allowed)), allowed);
  throws('malformed', 'json_depth', () => decodeNumberFree('['.repeat(32) + 'null' + ']'.repeat(32)));
  const empty = '['.repeat(31) + '{}' + ']'.repeat(31);
  assert.equal(canonicalize(decodeNumberFree(empty)), empty);
  throws('malformed', 'json_depth', () => decodeNumberFree('['.repeat(31) + '{"a":true}' + ']'.repeat(31)));
  let tooDeep: unknown = null;
  for (let i = 0; i < 32; i += 1) tooDeep = [tooDeep];
  throws('malformed', 'json_depth', () => canonicalize(tooDeep));
});

test('WebVH node bound counts values, not object member names; encoder has no node cap', () => {
  const allowed = '[' + new Array(8191).fill('null').join(',') + ']';
  assert.equal(canonicalize(decodeNumberFree(allowed)), allowed);
  throws('malformed', 'json_nodes', () => decodeNumberFree('[' + new Array(8192).fill('null').join(',') + ']'));
  const object = '{' + Array.from({ length: 8191 }, (_, i) => `"a${i}":null`).join(',') + '}';
  assert.equal(Object.keys(decodeNumberFree(object) as object).length, 8191);
  assert.equal(canonicalize(new Array(8192).fill(null)).length, 40961);
});

test('WebVH canonical encoding rejects internal shapes, sparse lists and cycles', () => {
  for (const value of [undefined, () => true, Symbol('x'), new Date(), new Map(), new Array(1)]) {
    throws('malformed', 'json_internal_shape', () => canonicalize(value));
  }
  const cyclic: unknown[] = [];
  cyclic.push(cyclic);
  throws('malformed', 'json_depth', () => canonicalize(cyclic));
});

test('WebVH objects and recursive replacement cannot pollute Object.prototype', () => {
  const parsed = decodeNumberFree('{"__proto__":{"polluted":true},"constructor":"{SCID}"}') as Record<string, unknown>;
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.equal(canonicalize(parsed), '{"__proto__":{"polluted":true},"constructor":"{SCID}"}');
  const replaced = replaceStrings(parsed, '{SCID}', 'new') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(replaced), null);
  assert.equal(replaced.constructor, 'new');
  assert.equal(parsed.constructor, '{SCID}');
});

test('WebVH preserves PHP runtime rejection of NUL-leading dynamic property names', () => {
  const referenceFailure = (error: unknown): boolean => error instanceof Error && !(error instanceof WebvhError);
  assert.throws(() => decodeNumberFree('{"\\u0000a":true}'), referenceFailure);
  assert.throws(() => replaceStrings({ x: true }, 'x', '\0'), referenceFailure);
  // RHS parsing occurs before the failing dynamic assignment in PHP.
  throws('unsupported', 'json_number_unsupported', () => decodeNumberFree('{"\\u0000a":0}'));
  assert.equal(canonicalize(decodeNumberFree('{"a\\u0000b":true}')), '{"a\\u0000b":true}');
});

test('WebVH replacement covers names and values without mutating input or permitting collisions', () => {
  const source = decodeNumberFree('{"{SCID}":["{SCID}/{SCID}",{"a":"{SCID}"}],"x":null}');
  const original = canonicalize(source);
  assert.equal(canonicalize(replaceStrings(source, '{SCID}', 'abc')), '{"abc":["abc/abc",{"a":"abc"}],"x":null}');
  assert.equal(canonicalize(source), original);
  assert.equal(replaceStrings('ab', '', 'x'), 'ab');
  throws('invalid', 'scid_replacement_collision', () => replaceStrings(decodeNumberFree('{"{SCID}":true,"abc":false}'), '{SCID}', 'abc'));
});

test('WebVH base58 handles empty bytes, leading zeroes and independently known encodings', () => {
  assert.equal(base58Encode(new Uint8Array()), '');
  assert.equal(base58Encode(Uint8Array.from([0, 0, 1])), '112');
  assert.equal(base58Encode(bytes('Hello World')), 'JxF12TrwUP45BMd');
  for (const value of [new Uint8Array(4), Uint8Array.from([0, 0, 255]), publicKey, Uint8Array.from({ length: 64 }, (_, i) => i * 4)]) {
    assert.deepEqual(base58Decode(base58Encode(value)), new Uint8Array(value));
  }
});

test('WebVH base58 decoding is bounded and preserves supplied failure codes', () => {
  for (const encoded of ['', '0', 'O', 'I', 'l', 'abc\n', ' abc', '１', 'a'.repeat(129)]) {
    throws('invalid', 'base58_invalid', () => base58Decode(encoded));
  }
  assert.equal(base58Decode('1'.repeat(128)).length, 128);
  throws('invalid', 'custom_hash_code', () => base58Decode('11', 1, 'custom_hash_code'));
});

test('WebVH SHA-256 multihash binds exact bytes and prefix with no multibase marker', async () => {
  const input = Buffer.from('exact\0bytes');
  const expected = createHash('sha256').update(input).digest();
  const result = await sha256Multihash(input);
  assert.equal(result.length, 46);
  assert.deepEqual(decodeSha256Multihash(result, 'scid_encoding'), new Uint8Array(expected));
  assert.deepEqual(base58Decode(result), Uint8Array.from([0x12, 0x20, ...expected]));
  for (const encoded of ['z' + result, '1' + result, base58Encode(Uint8Array.from([0x13, 0x20, ...expected])), '1'.repeat(34)]) {
    throws('invalid', 'scid_encoding', () => decodeSha256Multihash(encoded, 'scid_encoding'));
  }
});

test('WebVH Multikey and JWK x are canonical encodings of the same screened public key', async () => {
  const multikey = encodeEd25519Multikey(publicKey);
  const x = publicKey.toString('base64url');
  assert.equal(multikey.length, 48);
  assert.ok(multikey.startsWith('z6Mk'));
  assert.deepEqual(decodeEd25519Multikey(multikey), new Uint8Array(publicKey));
  assert.deepEqual(decodeEd25519JwkX(x), new Uint8Array(publicKey));
  assert.equal(base64urlEncode(publicKey), x);
  assert.equal(await updateKeyHash(multikey), await sha256Multihash(bytes(multikey)));
  const jwk = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  assert.equal(await assertionJwkThumbprint(x), createHash('sha256').update(jwk).digest('base64url'));
});

test('WebVH rejects wrong Multikey markers, prefixes, lengths and trailing line breaks', () => {
  const valid = encodeEd25519Multikey(publicKey);
  for (const value of [valid + '\n', valid.slice(1), 'u' + valid.slice(1), valid + '1', 'z' + base58Encode(Uint8Array.from([0xed, 2, ...publicKey])), 'z' + '1'.repeat(47)]) {
    throws('invalid', 'update_key_encoding', () => decodeEd25519Multikey(value));
  }
  throws('invalid', 'assertion_key_encoding', () => encodeEd25519Multikey(publicKey.subarray(1)));
  throws('invalid', 'caller_code', () => decodeEd25519Multikey('bad', 'caller_code'));
});

test('WebVH JWK x refuses padding, unused pad bits, bad alphabet and bad lengths', () => {
  const x = publicKey.toString('base64url');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const padBits = x.slice(0, -1) + alphabet[alphabet.indexOf(x.at(-1)!) + 1];
  for (const value of [x + '=', x + '\n', x.slice(1), x.replace(/./, '+'), padBits, 'A'.repeat(43)]) {
    throws('invalid', 'assertion_key_encoding', () => decodeEd25519JwkX(value));
  }
});

test('WebVH key screening exactly excludes canonical-y bounds and small-order encodings', () => {
  const blocked = ['00'.repeat(32), '01' + '00'.repeat(31),
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'ec' + 'ff'.repeat(30) + '7f', 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + '7f', 'ff'.repeat(31) + '7f'];
  for (const hex of blocked) {
    for (const sign of [0, 128]) {
      const key = Buffer.from(hex, 'hex');
      key[31] = (key[31] & 127) | sign;
      throws('invalid', 'screen', () => assertEd25519PublicKeyEncoding(key, 'screen'));
      throws('invalid', 'assertion_key_encoding', () => decodeEd25519JwkX(key.toString('base64url')));
      throws('invalid', 'update_key_encoding', () => decodeEd25519Multikey('z' + base58Encode(Uint8Array.from([0xed, 1, ...key]))));
    }
  }
});

test('WebVH encoding screen deliberately does not claim curve membership', () => {
  const yTwo = new Uint8Array(32);
  yTwo[0] = 2;
  assert.doesNotThrow(() => assertEd25519PublicKeyEncoding(yTwo, 'screen'));
  assert.deepEqual(decodeEd25519Multikey(encodeEd25519Multikey(yTwo)), yTwo);
});

test('WebVH proofValue decoding checks representation and size, not signature validity', () => {
  for (const signature of [new Uint8Array(64), new Uint8Array(64).fill(255), Uint8Array.from({ length: 64 }, (_, i) => i)]) {
    const value = 'z' + base58Encode(signature);
    assert.deepEqual(decodeProofValue(value), signature);
    throws('invalid', 'proof_value_encoding', () => decodeProofValue(value + '\n'));
  }
  for (const value of ['z' + '1'.repeat(63), 'z' + '1'.repeat(65), 'z' + '1'.repeat(89), 'u' + '1'.repeat(64)]) {
    throws('invalid', 'proof_value_encoding', () => decodeProofValue(value));
  }
});

test('WebVH hash helpers preserve crypto capability errors and snapshot input bytes', async () => {
  const input = Buffer.from('before');
  const result = sha256Multihash(input);
  input.fill(0);
  assert.deepEqual(decodeSha256Multihash(await result, 'hash'), new Uint8Array(createHash('sha256').update('before').digest()));
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    await assert.rejects(sha256Multihash(bytes('x')), error => error instanceof VerifierError && error.kind === 'unsupported' && error.code === 'browser_crypto_unavailable');
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});

test('WebVH native digest rejections remain unsupported capability failures', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { subtle: {
      digest: async () => { throw new DOMException('private native runtime detail', 'OperationError'); },
    } } });
    const expected = (error: unknown): boolean => error instanceof VerifierError && error.kind === 'unsupported'
      && error.code === 'browser_crypto_failed' && !error.message.includes('private native runtime detail');
    await assert.rejects(sha256Multihash(bytes('x')), expected);
    await assert.rejects(updateKeyHash(encodeEd25519Multikey(publicKey)), expected);
    await assert.rejects(assertionJwkThumbprint(publicKey.toString('base64url')), expected);
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});
