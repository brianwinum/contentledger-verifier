// SPDX-License-Identifier: GPL-2.0-or-later
// Compatibility port of frozen WebVH_Production_Codec.php. This is the WebVH
// number-free JSON profile, NOT the bundle's Canonical_JSON.php codec.
import { sha256 } from './bytes';
import { VerifierError } from './errors';

export type WebvhErrorStatus = 'invalid' | 'unsupported' | 'malformed';
export class WebvhError extends Error {
  constructor(readonly status: WebvhErrorStatus, readonly code: string) {
    super(code);
    this.name = 'WebvhError';
  }
}

export const MAX_JSON_DEPTH = 32;
export const MAX_JSON_NODES = 8192;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const fail = (status: WebvhErrorStatus, code: string): never => { throw new WebvhError(status, code); };

function validUnicode(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

class NumberFreeParser {
  private offset = 0;
  private nodes = 0;
  constructor(private readonly input: Uint8Array) {}

  parse(): unknown {
    this.whitespace();
    const result = this.value(1);
    this.whitespace();
    if (this.offset !== this.input.length) fail('malformed', 'json_syntax');
    return result;
  }

  private value(depth: number): unknown {
    if (depth > MAX_JSON_DEPTH) fail('malformed', 'json_depth');
    this.nodes += 1;
    if (this.nodes > MAX_JSON_NODES) fail('malformed', 'json_nodes');
    if (this.offset >= this.input.length) fail('malformed', 'json_syntax');
    const byte = this.input[this.offset];
    if (byte === 123) return this.object(depth);
    if (byte === 91) return this.array(depth);
    if (byte === 34) return this.string();
    if (byte === 45 || byte >= 48 && byte <= 57) fail('unsupported', 'json_number_unsupported');
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (this.literal(literal)) return value;
    }
    return fail('malformed', 'json_syntax');
  }

  private object(depth: number): Record<string, unknown> {
    this.offset += 1;
    this.whitespace();
    const value = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    if (this.consume(125)) return value;
    while (true) {
      if (this.input[this.offset] !== 34) fail('malformed', 'json_syntax');
      const key = this.string();
      if (seen.has(key)) fail('malformed', 'json_duplicate_member');
      seen.add(key);
      this.whitespace();
      if (!this.consume(58)) fail('malformed', 'json_syntax');
      this.whitespace();
      const item = this.value(depth + 1);
      // PHP's stdClass assignment rejects a property whose name begins with
      // NUL with a non-codec Error. The history verifier maps it to the same
      // sanitized processing_failure as other reference runtime exceptions.
      if (key.startsWith('\0')) throw new Error('Unsupported WebVH property representation.');
      value[key] = item;
      this.whitespace();
      if (this.consume(125)) return value;
      if (!this.consume(44)) fail('malformed', 'json_syntax');
      this.whitespace();
    }
  }

  private array(depth: number): unknown[] {
    this.offset += 1;
    this.whitespace();
    const value: unknown[] = [];
    if (this.consume(93)) return value;
    while (true) {
      value.push(this.value(depth + 1));
      this.whitespace();
      if (this.consume(93)) return value;
      if (!this.consume(44)) fail('malformed', 'json_syntax');
      this.whitespace();
    }
  }

  private string(): string {
    const start = this.offset++;
    while (this.offset < this.input.length) {
      const byte = this.input[this.offset];
      if (byte === 34) {
        this.offset += 1;
        let value: unknown;
        try { value = JSON.parse(decoder.decode(this.input.subarray(start, this.offset))); }
        catch { return fail('malformed', 'json_string'); }
        if (typeof value !== 'string' || !validUnicode(value)) return fail('malformed', 'json_string');
        return value;
      }
      if (byte === 92) {
        this.offset += 1;
        if (this.offset >= this.input.length) fail('malformed', 'json_string');
        const escape = this.input[this.offset];
        if (escape === 117) {
          if (this.offset + 4 >= this.input.length) fail('malformed', 'json_string');
          for (let i = 1; i <= 4; i += 1) {
            const hex = this.input[this.offset + i];
            if (!(hex >= 48 && hex <= 57 || hex >= 65 && hex <= 70 || hex >= 97 && hex <= 102)) fail('malformed', 'json_string');
          }
          this.offset += 5;
          continue;
        }
        if (![34, 92, 47, 98, 102, 110, 114, 116].includes(escape)) fail('malformed', 'json_string');
        this.offset += 1;
        continue;
      }
      if (byte < 32) fail('malformed', 'json_string');
      this.offset += 1;
    }
    return fail('malformed', 'json_string');
  }

  private whitespace(): void {
    while ([32, 9, 13, 10].includes(this.input[this.offset])) this.offset += 1;
  }

  private literal(value: string): boolean {
    for (let i = 0; i < value.length; i += 1) if (this.input[this.offset + i] !== value.charCodeAt(i)) return false;
    this.offset += value.length;
    return true;
  }

  private consume(byte: number): boolean {
    if (this.input[this.offset] !== byte) return false;
    this.offset += 1;
    return true;
  }
}

/** Decode whitespace-tolerant JSON; reject duplicates and all numeric tokens. */
export function decodeNumberFree(input: Uint8Array | string): unknown {
  if (typeof input === 'string' && !validUnicode(input)) fail('malformed', 'json_string');
  return new NumberFreeParser(typeof input === 'string' ? encoder.encode(input) : input).parse();
}

function phpIntegerKey(key: string): boolean {
  if (key.length > 20 || /^(?:0|-?[1-9][0-9]*)$/.exec(key)?.[0] !== key) return false;
  const value = BigInt(key);
  return value >= -9223372036854775808n && value <= 9223372036854775807n;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function encodeValue(value: unknown, depth: number): string {
  if (depth > MAX_JSON_DEPTH) return fail('malformed', 'json_depth');
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    if (!validUnicode(value)) return fail('malformed', 'json_string');
    return JSON.stringify(value);
  }
  if (typeof value === 'number' || typeof value === 'bigint') return fail('unsupported', 'json_number_unsupported');
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.keys(value).some((key, i) => key !== String(i))) return fail('malformed', 'json_internal_shape');
    return `[${value.map(item => encodeValue(item, depth + 1)).join(',')}]`;
  }
  if (!plainObject(value) || Object.getOwnPropertySymbols(value).length > 0) return fail('malformed', 'json_internal_shape');
  // PHP get_object_vars casts signed-64-bit numeric property names to integer
  // array keys; encode_value consequently rejects them as unsupported numbers.
  const keys = Object.keys(value).sort();
  const members = keys.map((key) => {
    // Keep PHP's depth-error precedence for keys at the depth boundary.
    const encodedKey = encodeValue(phpIntegerKey(key) ? BigInt(key) : key, depth + 1);
    return `${encodedKey}:${encodeValue(value[key], depth + 1)}`;
  });
  return `{${members.join(',')}}`;
}

export function canonicalize(value: unknown): string { return encodeValue(value, 1); }

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let leading = 0;
  while (leading < bytes.length && bytes[leading] === 0) leading += 1;
  if (leading === bytes.length) return '1'.repeat(leading);
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] * 256;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
  }
  while (digits.length > 1 && digits[digits.length - 1] === 0) digits.pop();
  return '1'.repeat(leading) + digits.reverse().map(digit => BASE58_ALPHABET[digit]).join('');
}

export function base58Decode(encoded: string, maxEncodedBytes = 128, failureCode = 'base58_invalid'): Uint8Array {
  if (encoded.length === 0 || encoder.encode(encoded).length > maxEncodedBytes) return fail('invalid', failureCode);
  let leading = 0;
  while (leading < encoded.length && encoded[leading] === '1') leading += 1;
  if (leading === encoded.length) return new Uint8Array(leading);
  const bytes = [0];
  for (const character of encoded) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) return fail('invalid', failureCode);
    let carry = digit;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 255;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) { bytes.push(carry & 255); carry = Math.floor(carry / 256); }
  }
  while (bytes.length > 1 && bytes[bytes.length - 1] === 0) bytes.pop();
  return Uint8Array.from([...new Array<number>(leading).fill(0), ...bytes.reverse()]);
}

function prefixed(prefix: readonly number[], bytes: Uint8Array): Uint8Array {
  const value = new Uint8Array(prefix.length + bytes.length);
  value.set(prefix); value.set(bytes, prefix.length);
  return value;
}

async function hashBytes(bytes: Uint8Array | string): Promise<Uint8Array> {
  let digest: string;
  try { digest = await sha256(typeof bytes === 'string' ? encoder.encode(bytes) : bytes); }
  catch (error) {
    if (error instanceof VerifierError && error.kind === 'unsupported') throw error;
    throw new VerifierError('browser_crypto_failed', 'The browser could not complete the required local SHA-256 operation.', 'unsupported');
  }
  return Uint8Array.from(digest.match(/../g)!, hex => Number.parseInt(hex, 16));
}

export async function sha256Multihash(bytes: Uint8Array | string): Promise<string> { return base58Encode(prefixed([0x12, 0x20], await hashBytes(bytes))); }

export function decodeSha256Multihash(encoded: string, failureCode: string): Uint8Array {
  const decoded = base58Decode(encoded, 46, failureCode);
  if (decoded.length !== 34 || decoded[0] !== 0x12 || decoded[1] !== 0x20 || base58Encode(decoded) !== encoded) return fail('invalid', failureCode);
  return decoded.slice(2);
}

// Exact PHP portable encoding screen only: this is NOT curve-membership or
// signature verification. For example y=2 remains accepted by this screen.
export function assertEd25519PublicKeyEncoding(publicKey: Uint8Array, failureCode: string): void {
  if (publicKey.length !== 32) fail('invalid', failureCode);
  const normalized = new Uint8Array(publicKey);
  normalized[31] &= 0x7f;
  const highMaximum = normalized[31] === 0x7f && normalized.subarray(1, 31).every(byte => byte === 0xff);
  if (highMaximum && normalized[0] >= 0xed) fail('invalid', failureCode);
  const hex = Array.from(normalized, byte => byte.toString(16).padStart(2, '0')).join('');
  if ([
    '00'.repeat(32), '01' + '00'.repeat(31),
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'ec' + 'ff'.repeat(30) + '7f', 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + '7f',
  ].includes(hex)) fail('invalid', failureCode);
}

export function encodeEd25519Multikey(publicKey: Uint8Array): string {
  assertEd25519PublicKeyEncoding(publicKey, 'assertion_key_encoding');
  return 'z' + base58Encode(prefixed([0xed, 0x01], publicKey));
}

export function decodeEd25519Multikey(multikey: string, failureCode = 'update_key_encoding'): Uint8Array {
  if (/^z[1-9A-HJ-NP-Za-km-z]{47}$/.exec(multikey)?.[0] !== multikey) return fail('invalid', failureCode);
  const decoded = base58Decode(multikey.slice(1), 47, failureCode);
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 1 || 'z' + base58Encode(decoded) !== multikey) return fail('invalid', failureCode);
  const publicKey = decoded.slice(2);
  assertEd25519PublicKeyEncoding(publicKey, failureCode);
  return publicKey;
}

export async function updateKeyHash(multikey: string): Promise<string> {
  decodeEd25519Multikey(multikey);
  return sha256Multihash(multikey);
}

export function decodeProofValue(value: string): Uint8Array {
  if (/^z[1-9A-HJ-NP-Za-km-z]{64,88}$/.exec(value)?.[0] !== value) return fail('invalid', 'proof_value_encoding');
  const decoded = base58Decode(value.slice(1), 88, 'proof_value_encoding');
  if (decoded.length !== 64 || 'z' + base58Encode(decoded) !== value) return fail('invalid', 'proof_value_encoding');
  return decoded;
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeEd25519JwkX(encoded: string): Uint8Array {
  if (encoded.length !== 43 || /^[A-Za-z0-9_-]{43}$/.exec(encoded)?.[0] !== encoded) return fail('invalid', 'assertion_key_encoding');
  let decoded: Uint8Array;
  try { decoded = Uint8Array.from(atob(encoded.replaceAll('-', '+').replaceAll('_', '/') + '='), character => character.charCodeAt(0)); }
  catch { return fail('invalid', 'assertion_key_encoding'); }
  if (decoded.length !== 32 || base64urlEncode(decoded) !== encoded) return fail('invalid', 'assertion_key_encoding');
  assertEd25519PublicKeyEncoding(decoded, 'assertion_key_encoding');
  return decoded;
}

export async function assertionJwkThumbprint(encodedX: string): Promise<string> {
  decodeEd25519JwkX(encodedX);
  return base64urlEncode(await hashBytes(canonicalize({ crv: 'Ed25519', kty: 'OKP', x: encodedX })));
}

/** Deep immutable replacement including property names, with collision checks. */
export function replaceStrings(value: unknown, search: string, replacement: string): unknown {
  // PHP str_replace treats an empty search as no operation.
  const replace = (text: string): string => search === '' ? text : text.split(search).join(replacement);
  if (typeof value === 'string') return replace(value);
  if (Array.isArray(value)) return value.map(item => replaceStrings(item, search, replacement));
  if (plainObject(value)) {
    const result = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    for (const [key, item] of Object.entries(value)) {
      const next = replace(key);
      if (seen.has(next)) return fail('invalid', 'scid_replacement_collision');
      seen.add(next);
      const replaced = replaceStrings(item, search, replacement);
      if (next.startsWith('\0')) throw new Error('Unsupported WebVH property representation.');
      result[next] = replaced;
    }
    return result;
  }
  return value;
}
