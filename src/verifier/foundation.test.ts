// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeCanonical, decodeCanonicalObject, encodeCanonical, exactKeys } from './canonical';
import { sha256, utf8 } from './bytes';
import { VerifierError } from './errors';
import { MAX_PACKAGE_BYTES, StrictZip } from './zip';

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const decode = (value: string, depth?: number): unknown => decodeCanonical(bytes(value), depth);
function error(code: string, action: () => unknown, kind = 'invalid'): void {
  assert.throws(action, (failure) => failure instanceof VerifierError && failure.code === code && failure.kind === kind);
}

// Independent, bitwise CRC implementation for fixture generation (not the table-based reader).
function fixtureCrc(payload: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of payload) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function fixture(entries: [string, Uint8Array][] = [['a.txt', bytes('hello')]]): Uint8Array {
  const localSize = entries.reduce((sum, [path, content]) => sum + 30 + bytes(path).length + content.length, 0);
  const centralSize = entries.reduce((sum, [path]) => sum + 46 + bytes(path).length, 0);
  const result = new Uint8Array(localSize + centralSize + 22);
  const view = new DataView(result.buffer);
  const u16 = (offset: number, value: number): void => view.setUint16(offset, value, true);
  const u32 = (offset: number, value: number): void => view.setUint32(offset, value, true);
  let local = 0;
  let central = localSize;
  for (const [path, content] of entries) {
    const name = bytes(path);
    const crc = fixtureCrc(content);
    u32(local, 0x04034b50); u16(local + 4, 10); u16(local + 12, 33);
    u32(local + 14, crc); u32(local + 18, content.length); u32(local + 22, content.length); u16(local + 26, name.length);
    result.set(name, local + 30); result.set(content, local + 30 + name.length);
    u32(central, 0x02014b50); u16(central + 4, 0x0314); u16(central + 6, 10); u16(central + 14, 33);
    u32(central + 16, crc); u32(central + 20, content.length); u32(central + 24, content.length); u16(central + 28, name.length);
    u32(central + 38, 0x81a40000); u32(central + 42, local); result.set(name, central + 46);
    local += 30 + name.length + content.length;
    central += 46 + name.length;
  }
  u32(central, 0x06054b50); u16(central + 8, entries.length); u16(central + 10, entries.length);
  u32(central + 12, centralSize); u32(central + 16, localSize);
  return result;
}
function change(input: Uint8Array, offset: number, value: number, width = 2): Uint8Array {
  const output = input.slice();
  const view = new DataView(output.buffer);
  if (width === 4) view.setUint32(offset, value, true);
  else if (width === 2) view.setUint16(offset, value, true);
  else view.setUint8(offset, value);
  return output;
}
const centralOffset = (input: Uint8Array): number => new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(input.length - 6, true);

test('SHA-256 hashes exact bytes and fatal UTF-8 preserves BOMs', async () => {
  assert.equal(await sha256(bytes('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(utf8(bytes('\ufeffa')), '\ufeffa');
  error('json_utf8', () => utf8(new Uint8Array([0xc3, 0x28])));
});

test('canonical JSON accepts the integer-only profile and UTF-16 key order', () => {
  assert.equal(decode('9007199254740991'), Number.MAX_SAFE_INTEGER);
  assert.equal(decode('-9007199254740991'), -Number.MAX_SAFE_INTEGER);
  assert.equal(decode('null'), null);
  assert.equal(decode('true'), true);
  assert.deepEqual(decode('[0,false,"é/\u2028\u2029"]'), [0, false, 'é/\u2028\u2029']);
  const value = decodeCanonicalObject(bytes('{"a":1,"😀":2,"\ue000":3}'));
  assert.equal(value.a, 1);
  assert.equal(encodeCanonical(value), '{"a":1,"😀":2,"\ue000":3}');
  assert.equal(encodeCanonical({ '\ue000': 3, '😀': 2, a: 1 }), '{"a":1,"😀":2,"\ue000":3}');
  assert.equal(encodeCanonical('\b\t\n\f\r\u0000'), '"\\b\\t\\n\\f\\r\\u0000"');
});

test('canonical JSON rejects floats lexically, unsafe integers and PHP bigint conversions', () => {
  for (const value of ['1.0', '1e0', '-0.0', '1E+2', '1e9999', '[1.0]']) error('json_float', () => decode(value));
  for (const value of ['9007199254740992', '-9007199254740992', '9223372036854775807', '-9223372036854775808']) error('json_integer_range', () => decode(value));
  for (const value of ['9223372036854775808', '-9223372036854775809']) error('json_noncanonical', () => decode(value));
  error('json_float', () => encodeCanonical(Infinity));
  error('json_integer_range', () => encodeCanonical(Number.MAX_SAFE_INTEGER + 1));
  error('json_type', () => encodeCanonical(undefined));
});

test('canonical JSON preserves PHP empty-object, numeric-key and replacement behavior', () => {
  for (const value of ['{}', '{"a":{}}', '{"0":"a"}', '{"0":"a","1":"b"}', '{"a":1,"a":1}', '{"a":1.0,"a":1}']) error('json_noncanonical', () => decode(value));
  for (const value of ['{"1":"a"}', '{"a":1,"0":2}', '{"1":"a","0":"b"}']) error('json_object_key', () => decode(value));
  error('json_float', () => decode('{"a":1,"a":1.0}'));
  assert.equal(encodeCanonical({}), '[]');
  assert.equal(encodeCanonical({ 0: 'a', 1: 'b' }), '["a","b"]');
  assert.equal(encodeCanonical({ '-0': 1, '00': 2, '9223372036854775808': 3 }), '{"-0":1,"00":2,"9223372036854775808":3}');
  assert.equal(decodeCanonicalObject(bytes('{"1\\n":1}'))['1\n'], 1);
  assert.equal(decodeCanonicalObject(bytes('{"1\\r":1}'))['1\r'], 1);
  assert.equal(decodeCanonicalObject(bytes('{"' + '9'.repeat(10000) + '":1}'))['9'.repeat(10000)], 1);
  error('json_noncanonical', () => decode('9'.repeat(10000)));
  for (const value of ['[]', '[1]', 'true', 'null', '1', '"a"']) error('json_object', () => decodeCanonicalObject(bytes(value)));
});

test('canonical JSON refuses alternate spellings, malformed UTF-8 and unsafe string escapes', () => {
  for (const value of [' {"a":1}', '{"a":1}\n', '{"b":2,"a":1}', '-0', '"\\u0061"', '"\\/"', '"\\u00e9"']) error('json_noncanonical', () => decode(value));
  for (const value of ['', '\ufeff{}', '[1,]', '{"a":1,}', '{a:1}', '01', '+1', '1.', '1e', 'NaN', '"\n"', '"\\ud800"', '"\\udc00"', '"\\ud800x"', '"\\x00"']) error('json_invalid', () => decode(value));
  error('json_invalid', () => decodeCanonical(new Uint8Array([34, 0xc0, 0xaf, 34])));
  error('json_utf8', () => encodeCanonical('\ud800'));
  const protectedObject = decodeCanonicalObject(bytes('{"__proto__":{"polluted":true},"constructor":1}'));
  assert.equal(Object.getPrototypeOf(protectedObject), null);
  assert.equal(Object.hasOwn(protectedObject, '__proto__'), true);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test('canonical JSON depth and exact-key checks match the reference profile', () => {
  assert.equal(decode('1', 1), 1);
  error('json_invalid', () => decode('[]', 1));
  assert.deepEqual(decode('[]', 2), []);
  error('json_invalid', () => decode('[[]]', 2));
  assert.deepEqual(decode('[[]]', 3), [[]]);
  for (const depth of [0, -1, 1.5, NaN, 2147483648]) error('json_invalid', () => decode('1', depth));
  assert.equal(exactKeys({ b: 2, a: 1 }, ['a', 'b']), true);
  assert.equal(exactKeys({ a: 1 }, ['a', 'a']), false);
  assert.equal(exactKeys({ a: 1, b: 2 }, ['a']), false);
  assert.equal(exactKeys({ 0: 'a' }, ['0']), false);
  assert.equal(exactKeys([], []), true);
});

test('strict ZIP reads a byte snapshot without extracting and preserves empty entries', async () => {
  const input = fixture([['VERIFY.txt', bytes('verify')], ['a.bin', new Uint8Array([0, 255, 128])], ['z.txt', new Uint8Array()]]);
  const zip = StrictZip.parse(input);
  assert.deepEqual(zip.paths(), ['VERIFY.txt', 'a.bin', 'z.txt']);
  assert.equal(zip.has('missing'), false);
  assert.deepEqual(zip.entry('a.bin'), { size: 3 });
  assert.deepEqual(zip.read('a.bin'), new Uint8Array([0, 255, 128]));
  assert.equal(await zip.sha256('z.txt'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  input.fill(0);
  zip.read('a.bin').fill(0);
  zip.entry('a.bin').size = 99;
  zip.paths().push('fake');
  assert.deepEqual(zip.read('a.bin'), new Uint8Array([0, 255, 128]));
  assert.deepEqual(zip.entry('a.bin'), { size: 3 });
  assert.equal(zip.has('fake'), false);
  error('zip_entry_missing', () => zip.read('missing'));
  error('zip_entry_limit', () => zip.read('a.bin', 2));
  error('zip_entry_limit', () => zip.read('z.txt', -1));
});

test('strict ZIP rejects invalid end records and archive size boundaries', () => {
  const input = fixture();
  const end = input.length - 22;
  error('bundle_file', () => StrictZip.parse(new Uint8Array(21)), 'input');
  error('zip_archive_limit', () => StrictZip.parse(new Uint8Array(MAX_PACKAGE_BYTES + 1)));
  error('zip_eocd', () => StrictZip.parse(change(input, end, 0)), 'input');
  error('zip_eocd', () => StrictZip.parse(new Uint8Array([...input, 0])), 'input');
  for (const [offset, value, width] of [[4, 1, 2], [6, 1, 2], [8, 2, 2], [10, 0, 2], [10, 16385, 2], [10, 65535, 2], [12, 0xffffffff, 4], [16, 0xffffffff, 4], [20, 1, 2]]) {
    error('zip_eocd_profile', () => StrictZip.parse(change(input, end + offset, value, width)));
  }
  error('zip_trailing_data', () => StrictZip.parse(change(input, end + 12, 1, 4)));
});

test('strict ZIP accepts exactly 16384 entries and 240-byte paths', () => {
  const many = fixture(Array.from({ length: 16384 }, (_, index) => [`a${String(index).padStart(5, '0')}`, new Uint8Array()]));
  assert.equal(StrictZip.parse(many).paths().length, 16384);
  assert.equal(StrictZip.parse(fixture([['a'.repeat(240), bytes('a')]])).paths()[0].length, 240);
  error('zip_path_unsafe', () => StrictZip.parse(fixture([['a'.repeat(241), bytes('a')]])));
});

test('strict ZIP rejects unsafe paths, devices, collisions and incorrect order', () => {
  for (const path of ['', '/root', 'a/', 'A.txt', 'a\\b', 'a:b', 'é', 'a\n', 'a b']) error('zip_path_unsafe', () => StrictZip.parse(fixture([[path, bytes('a')]])));
  for (const path of ['.', '..', 'a//b', 'a/./b', 'a/../b', 'a.', 'a./b']) error('zip_path_segment', () => StrictZip.parse(fixture([[path, bytes('a')]])));
  for (const path of ['con', 'nul.txt', 'a/aux.txt', 'com1', 'lpt9.bin']) error('zip_path_device', () => StrictZip.parse(fixture([[path, bytes('a')]])));
  error('zip_path_order', () => StrictZip.parse(fixture([['b', bytes('a')], ['a', bytes('b')]])));
  error('zip_path_order', () => StrictZip.parse(fixture([['a', bytes('a')], ['a', bytes('b')]])));
  error('zip_path_collision', () => StrictZip.parse(fixture([['VERIFY.txt', bytes('a')], ['verify.txt', bytes('b')]])));
  error('zip_file_prefix_collision', () => StrictZip.parse(fixture([['a', bytes('a')], ['a/b', bytes('b')]])));
});

test('strict ZIP rejects every unsupported central field and inconsistent local records', () => {
  const input = fixture();
  const central = centralOffset(input);
  for (const [offset, value, width] of [[4, 20, 2], [6, 20, 2], [8, 8, 2], [10, 8, 2], [12, 1, 2], [14, 34, 2], [20, 6, 4], [24, 0xffffffff, 4], [34, 1, 2], [36, 1, 2], [38, 0xa1ff0000, 4], [42, 1, 4]]) {
    error('zip_entry_profile', () => StrictZip.parse(change(input, central + offset, value, width)));
  }
  for (const [offset, value, width] of [[4, 20, 2], [6, 8, 2], [8, 8, 2], [10, 1, 2], [12, 34, 2], [14, 0, 4], [18, 6, 4], [22, 6, 4], [26, 4, 2], [28, 1, 2], [30, 122, 1]]) {
    error('zip_local_central_mismatch', () => StrictZip.parse(change(input, offset, value, width)));
  }
  error('zip_local_signature', () => StrictZip.parse(change(input, 0, 0)));
  error('zip_central_signature', () => StrictZip.parse(change(input, central, 0)));
  error('zip_crc', () => StrictZip.parse(change(input, 35, 0, 1)));
  error('zip_central_truncated', () => StrictZip.parse(change(input, central + 28, 65535)));
  error('bundle_bounds', () => StrictZip.parse(change(input, 26, 65535)), 'input');
});

test('strict ZIP rejects hidden local bytes, impossible payload lengths and central padding', () => {
  const input = fixture();
  const central = centralOffset(input);
  const withGap = new Uint8Array(input.length + 1);
  withGap.set(input.subarray(0, central));
  withGap.set(input.subarray(central), central + 1);
  new DataView(withGap.buffer).setUint32(withGap.length - 6, central + 1, true);
  error('zip_hidden_data', () => StrictZip.parse(withGap));
  let impossible = change(input, central + 20, MAX_PACKAGE_BYTES + 1, 4);
  impossible = change(impossible, central + 24, MAX_PACKAGE_BYTES + 1, 4);
  error('zip_total_limit', () => StrictZip.parse(impossible));
  let overlap = change(input, central + 20, 6, 4);
  overlap = change(overlap, central + 24, 6, 4);
  overlap = change(overlap, 18, 6, 4);
  overlap = change(overlap, 22, 6, 4);
  error('zip_local_bounds', () => StrictZip.parse(overlap));
  const padded = new Uint8Array(input.length + 1);
  padded.set(input.subarray(0, input.length - 22));
  padded.set(input.subarray(input.length - 22), input.length - 21);
  new DataView(padded.buffer).setUint32(padded.length - 10, input.length - 22 - central + 1, true);
  error('zip_central_size', () => StrictZip.parse(padded));
});
