// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspectOpenTimestamp, MAX_DEPTH, MAX_MESSAGE_BYTES, MAX_PROOF_BYTES } from './opentimestamps';
import { VerifierError } from './errors';

const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const PENDING = Buffer.from('83dfe30d2ef90c8e', 'hex');
const BITCOIN = Buffer.from('0588960d73d71901', 'hex');
const UNKNOWN = Buffer.from('0102030405060708', 'hex');
const subject = createHash('sha256').update('synthetic subject').digest();
const expected = subject.toString('hex');
const uri = 'https://calendar.example.test/path_1';
const hash = (algorithm: string, value: Uint8Array): Buffer => createHash(algorithm).update(value).digest();
const invalid = (code: string) => (error: unknown): boolean => error instanceof VerifierError && error.kind === 'invalid' && error.code === code;
const unsupported = (code: string) => (error: unknown): boolean => error instanceof VerifierError && error.kind === 'unsupported' && error.code === code;
function variable(value: bigint | number): Buffer {
  let remaining = BigInt(value);
  const bytes: number[] = [];
  while (remaining >= 128n) { bytes.push(Number(remaining & 127n) | 128); remaining >>= 7n; }
  bytes.push(Number(remaining));
  return Buffer.from(bytes);
}
const varbytes = (value: Buffer): Buffer => Buffer.concat([variable(value.length), value]);
const attestation = (tag: Buffer, payload: Buffer): Buffer => Buffer.concat([Buffer.from([0]), tag, varbytes(payload)]);
const pending = (value = uri): Buffer => attestation(PENDING, varbytes(Buffer.from(value)));
const bitcoin = (height: bigint | number = 123456): Buffer => attestation(BITCOIN, variable(height));
const proof = (body: Buffer): Buffer => Buffer.concat([MAGIC, Buffer.from([1, 8]), subject, body]);
const fork = (...branches: Buffer[]): Buffer => Buffer.concat(branches.map((branch, index) => index === branches.length - 1 ? branch : Buffer.concat([Buffer.from([255]), branch])));
const operation = (tag: number, tail: Buffer, argument?: Buffer): Buffer => Buffer.concat([Buffer.from([tag]), ...(argument ? [varbytes(argument)] : []), tail]);

test('OTS pending and Bitcoin attestations retain claims without trusted-time authority', async () => {
  const input = proof(fork(pending(), bitcoin()));
  const result = await inspectOpenTimestamp(input, expected);
  assert.deepEqual(result, { fileDigest: expected, proofSha256: hash('sha256', input).toString('hex'),
    pending: [{ uri, commitment: expected }], bitcoin: [{ height: '123456', commitment: expected }], unknownCount: 0 });
  assert.deepEqual(Object.keys(result).sort(), ['bitcoin', 'fileDigest', 'pending', 'proofSha256', 'unknownCount']);
});

test('OTS supported unary operations apply exact bytes and independent native digests', async () => {
  for (const [tag, transformed] of [[0x02, hash('sha1', subject)], [0x08, hash('sha256', subject)], [0xf2, Buffer.from(subject).reverse()], [0xf3, Buffer.from(expected)]] as const) {
    const result = await inspectOpenTimestamp(proof(operation(tag, pending())), expected);
    assert.equal(result.pending[0].commitment, transformed.toString('hex'), `tag ${tag}`);
  }
});

test('OTS append and prepend support binary arguments and exact operation chains', async () => {
  const argument = Buffer.from([0, 255, 128, 1]);
  for (const tag of [0xf0, 0xf1]) {
    const input = tag === 0xf0 ? Buffer.concat([subject, argument]) : Buffer.concat([argument, subject]);
    const result = await inspectOpenTimestamp(proof(operation(tag, operation(0x08, bitcoin(0)), argument)), expected);
    assert.equal(result.bitcoin[0].commitment, hash('sha256', input).toString('hex'));
    assert.equal(result.bitcoin[0].height, '0');
  }
});

test('OTS fork traversal reports parent attestations before operation children', async () => {
  const childUri = 'https://calendar.example.test/child';
  const input = proof(fork(operation(0x08, pending(childUri)), pending(), operation(0x02, bitcoin(9))));
  const result = await inspectOpenTimestamp(input, expected);
  assert.deepEqual(result.pending, [{ uri, commitment: expected }, { uri: childUri, commitment: hash('sha256', subject).toString('hex') }]);
  assert.deepEqual(result.bitcoin, [{ height: '9', commitment: hash('sha1', subject).toString('hex') }]);
});

test('OTS duplicate attestations remain permitted and unknown attestations stay opaque', async () => {
  const result = await inspectOpenTimestamp(proof(fork(pending(), pending(), attestation(UNKNOWN, Buffer.from([255, 0, 128])), attestation(UNKNOWN, Buffer.alloc(0)))), expected);
  assert.equal(result.pending.length, 2);
  assert.equal(result.unknownCount, 2);
  assert.deepEqual(result.bitcoin, []);
});

test('OTS operation branches must be unique by exact tag and argument', async () => {
  await assert.rejects(inspectOpenTimestamp(proof(fork(operation(0x08, pending()), operation(0x08, bitcoin()))), expected), invalid('ots_duplicate_branch'));
  await assert.rejects(inspectOpenTimestamp(proof(fork(operation(0xf0, pending(), Buffer.from([1])), operation(0xf0, bitcoin(), Buffer.from([1])))), expected), invalid('ots_duplicate_branch'));
  const result = await inspectOpenTimestamp(proof(fork(operation(0xf0, pending(), Buffer.from([1])), operation(0xf0, bitcoin(), Buffer.from([2])))), expected);
  assert.equal(result.pending.length, 1); assert.equal(result.bitcoin.length, 1);
});

test('OTS explicit unsupported cryptographic operations cannot become structural success', async () => {
  for (const [tag, code] of [[0x03, 'ots_ripemd160'], [0x67, 'ots_keccak']] as const) {
    await assert.rejects(inspectOpenTimestamp(proof(operation(tag, pending())), expected), unsupported(code));
    // PHP applies the operation before trying to read its child node.
    await assert.rejects(inspectOpenTimestamp(proof(Buffer.from([tag])), expected), unsupported(code));
  }
  for (const tag of [1, 4, 7, 9, 0xf4, 0xfe]) await assert.rejects(inspectOpenTimestamp(proof(Buffer.from([tag])), expected), invalid('ots_operation'));
});

test('OTS detached header, version, digest algorithm and exact subject are mandatory', async () => {
  const input = proof(pending());
  for (const digest of ['', expected.toUpperCase(), expected + '\n', 'g'.repeat(64)]) await assert.rejects(inspectOpenTimestamp(input, digest), invalid('ots_subject'));
  await assert.rejects(inspectOpenTimestamp(input, '0'.repeat(64)), invalid('ots_digest'));
  const magic = Buffer.from(input); magic[1] ^= 1;
  await assert.rejects(inspectOpenTimestamp(magic, expected), invalid('ots_header'));
  const version = Buffer.from(input); version[MAGIC.length] = 2;
  await assert.rejects(inspectOpenTimestamp(version, expected), invalid('ots_profile'));
  const algorithm = Buffer.from(input); algorithm[MAGIC.length + 1] = 2;
  await assert.rejects(inspectOpenTimestamp(algorithm, expected), invalid('ots_profile'));
  await assert.rejects(inspectOpenTimestamp(Buffer.concat([MAGIC, Buffer.from([2])]), expected), invalid('ots_profile'));
});

test('OTS truncated fields, missing fork branch, nested fork markers and trailing bytes fail closed', async () => {
  const input = proof(pending());
  await assert.rejects(inspectOpenTimestamp(input.subarray(0, 0), expected), invalid('ots_size'));
  for (let length = 1; length < input.length; length += 1) await assert.rejects(inspectOpenTimestamp(input.subarray(0, length), expected), invalid('ots_truncated'));
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.from([255]), pending()])), expected), invalid('ots_truncated'));
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.from([255, 255])), expected), invalid('ots_fork'));
  await assert.rejects(inspectOpenTimestamp(Buffer.concat([input, Buffer.from([0])]), expected), invalid('ots_trailing'));
});

test('OTS recursion depth accepts 255 operations and rejects a 256th', async () => {
  const allowed = proof(Buffer.concat([Buffer.alloc(MAX_DEPTH - 1, 0xf2), bitcoin()]));
  assert.equal((await inspectOpenTimestamp(allowed, expected)).bitcoin.length, 1);
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.alloc(MAX_DEPTH, 0xf2), bitcoin()])), expected), invalid('ots_depth'));
});

test('OTS message and binary argument bounds are enforced before child parsing', async () => {
  const allowedArgument = Buffer.alloc(MAX_MESSAGE_BYTES - subject.length, 42);
  const result = await inspectOpenTimestamp(proof(operation(0xf0, pending(), allowedArgument)), expected);
  assert.equal(result.pending[0].commitment.length, MAX_MESSAGE_BYTES * 2);
  await assert.rejects(inspectOpenTimestamp(proof(operation(0xf0, pending(), Buffer.alloc(allowedArgument.length + 1))), expected), invalid('ots_message_limit'));
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.from([0xf0]), variable(0), pending()])), expected), invalid('ots_varbytes'));
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.from([0xf1]), variable(MAX_MESSAGE_BYTES + 1)])), expected), invalid('ots_varbytes'));
  assert.equal((await inspectOpenTimestamp(proof(Buffer.concat([Buffer.alloc(7, 0xf3), pending()])), expected)).pending[0].commitment.length, MAX_MESSAGE_BYTES * 2);
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.alloc(8, 0xf3), pending()])), expected), invalid('ots_message_limit'));
});

test('OTS proof size and unknown attestation payload limits use exact byte ceilings', async () => {
  await assert.rejects(inspectOpenTimestamp(Buffer.alloc(MAX_PROOF_BYTES + 1), expected), invalid('ots_size'));
  assert.equal((await inspectOpenTimestamp(proof(attestation(UNKNOWN, Buffer.alloc(8192))), expected)).unknownCount, 1);
  await assert.rejects(inspectOpenTimestamp(proof(attestation(UNKNOWN, Buffer.alloc(8193))), expected), invalid('ots_varbytes'));
  // Build an exactly 20,000-byte syntactically valid proof from three unknown
  // attestations; the serialized envelope changes only the final payload size.
  const first = attestation(UNKNOWN, Buffer.alloc(8192));
  const second = attestation(UNKNOWN, Buffer.alloc(8192));
  const overhead = proof(fork(first, second, attestation(UNKNOWN, Buffer.alloc(1024)))).length - 1024;
  const exact = proof(fork(first, second, attestation(UNKNOWN, Buffer.alloc(MAX_PROOF_BYTES - overhead))));
  assert.equal(exact.length, MAX_PROOF_BYTES);
  assert.equal((await inspectOpenTimestamp(exact, expected)).unknownCount, 3);
});

test('OTS pending URI grammar and nested payload boundaries match the frozen profile', async () => {
  for (const value of ['https:///../', 'https://a_b/c-d.1', 'https://' + 'a'.repeat(992)]) {
    assert.equal((await inspectOpenTimestamp(proof(pending(value)), expected)).pending[0].uri, value);
  }
  for (const value of ['', 'http://a', 'https://a:443', 'https://a?b', 'https://a#b', 'https://a%20b', 'https://é', 'https://a\n']) {
    await assert.rejects(inspectOpenTimestamp(proof(pending(value)), expected), invalid('ots_pending_attestation'));
  }
  await assert.rejects(inspectOpenTimestamp(proof(pending('https://' + 'a'.repeat(993))), expected), invalid('ots_varbytes'));
  await assert.rejects(inspectOpenTimestamp(proof(attestation(PENDING, Buffer.concat([varbytes(Buffer.from(uri)), Buffer.from([0])]))), expected), invalid('ots_pending_attestation'));
});

test('OTS Bitcoin heights preserve exact decimal values through signed-64-bit maximum', async () => {
  for (const height of [0n, 127n, 128n, 16384n, 9007199254740991n, 9007199254740992n, 9007199254740993n, 9223372036854775807n]) {
    const result = await inspectOpenTimestamp(proof(bitcoin(height)), expected);
    assert.equal(result.bitcoin[0].height, height.toString());
    assert.equal(typeof result.bitcoin[0].height, 'string');
  }
  await assert.rejects(inspectOpenTimestamp(proof(bitcoin(9223372036854775808n)), expected), invalid('ots_integer'));
  await assert.rejects(inspectOpenTimestamp(proof(attestation(BITCOIN, Buffer.concat([variable(1), Buffer.from([0])]))), expected), invalid('ots_bitcoin_attestation'));
});

test('OTS varints reject nonminimal, unterminated and overflowing encodings in all length contexts', async () => {
  for (const value of [Buffer.from([128, 0]), Buffer.from([129, 0]), Buffer.from([255, 128, 0])]) {
    await assert.rejects(inspectOpenTimestamp(proof(attestation(BITCOIN, value)), expected), invalid('ots_integer_nonminimal'));
  }
  await assert.rejects(inspectOpenTimestamp(proof(attestation(BITCOIN, Buffer.from([128]))), expected), invalid('ots_truncated'));
  for (const value of [Buffer.alloc(9, 128), Buffer.alloc(10, 255), variable(9223372036854775808n)]) {
    await assert.rejects(inspectOpenTimestamp(proof(attestation(BITCOIN, value)), expected), invalid('ots_integer'));
  }
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.from([0]), UNKNOWN, Buffer.from([128, 0])])), expected), invalid('ots_integer_nonminimal'));
  await assert.rejects(inspectOpenTimestamp(proof(Buffer.concat([Buffer.from([0xf0]), variable(9223372036854775807n)])), expected), invalid('ots_varbytes'));
});

test('OTS snapshots mutable Buffer bytes before any operation awaits', async () => {
  const input = proof(operation(0x08, pending()));
  const original = Buffer.from(input);
  const result = inspectOpenTimestamp(input, expected);
  input.fill(0);
  const inspected = await result;
  assert.equal(inspected.proofSha256, hash('sha256', original).toString('hex'));
  assert.equal(inspected.pending[0].commitment, hash('sha256', subject).toString('hex'));
});

test('OTS native SHA1 and SHA256 failures stay unsupported with redacted diagnostics', async context => {
  const native = crypto.subtle.digest.bind(crypto.subtle);
  for (const failed of ['SHA-1', 'SHA-256']) {
    const mock = context.mock.method(crypto.subtle, 'digest', (...args: Parameters<SubtleCrypto['digest']>) => {
      if (args[0] === failed) return Promise.reject(new DOMException('private digest detail', 'NotSupportedError'));
      return native(...args);
    });
    for (const input of [proof(operation(failed === 'SHA-1' ? 0x02 : 0x08, pending())), ...(failed === 'SHA-256' ? [proof(pending())] : [])]) {
      await assert.rejects(inspectOpenTimestamp(input, expected), error => unsupported('browser_crypto_failed')(error) && !(error as Error).message.includes('private digest detail'));
    }
    mock.mock.restore();
  }
});

test('OTS unavailable cryptography cannot yield a structural success', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    await assert.rejects(inspectOpenTimestamp(proof(pending()), expected), unsupported('browser_crypto_unavailable'));
    await assert.rejects(inspectOpenTimestamp(proof(operation(0x02, bitcoin())), expected), unsupported('browser_crypto_unavailable'));
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});
