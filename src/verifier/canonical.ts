// SPDX-License-Identifier: GPL-2.0-or-later
// Compatibility port of the frozen portable verifier's Canonical_JSON.php.
import { utf8 } from './bytes';
import { VerifierError } from './errors';

const SAFE_INTEGER = 9007199254740991n;
const PHP_INTEGER_MAX = 9223372036854775807n;
const PHP_INTEGER_MIN = -9223372036854775808n;
type PhpKey = string | bigint;
class PhpObject extends Map<PhpKey, Parsed> {}
class PhpFloat {}
type Parsed = null | boolean | string | bigint | PhpFloat | PhpObject | Parsed[];

function invalid(): never {
  throw new VerifierError('json_invalid', 'A required JSON document is malformed.');
}

function validUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function phpKey(key: string): PhpKey {
  // PHP casts exactly these signed-64-bit string keys to integers, but not '-0'.
  // Check length first to avoid constructing arbitrarily large BigInts for untrusted keys.
  if (key.length <= 20 && /^(?:0|-?[1-9][0-9]*)$/.exec(key)?.[0] === key) {
    const integer = BigInt(key);
    if (integer >= PHP_INTEGER_MIN && integer <= PHP_INTEGER_MAX) return integer;
  }
  return key;
}

/** Parse without losing lexical floats, duplicate-key replacement or PHP integer semantics. */
class Parser {
  private position = 0;
  constructor(private readonly source: string, private readonly depth: number) {}

  parse(): Parsed {
    if (!Number.isInteger(this.depth) || this.depth < 1 || this.depth > 2147483647) invalid();
    const value = this.value(0);
    this.whitespace();
    if (this.position !== this.source.length) invalid();
    return value;
  }

  private whitespace(): void {
    while (/[\x20\t\r\n]/.test(this.source[this.position] ?? '') && this.position < this.source.length) this.position += 1;
  }

  private string(): string {
    const start = this.position++;
    while (this.position < this.source.length) {
      const character = this.source[this.position++];
      if (character === '\\') {
        this.position += 1;
      } else if (character === '"') {
        let value: unknown;
        try { value = JSON.parse(this.source.slice(start, this.position)); } catch { invalid(); }
        if (typeof value !== 'string' || !validUnicode(value)) invalid();
        return value;
      }
    }
    return invalid();
  }

  private value(level: number): Parsed {
    this.whitespace();
    const character = this.source[this.position];
    if (character === '"') return this.string();
    if (character === '[' || character === '{') {
      if (level + 1 >= this.depth) invalid();
      this.position += 1;
      const object = character === '{';
      const close = object ? '}' : ']';
      const value = object ? new PhpObject() : [] as Parsed[];
      this.whitespace();
      if (this.source[this.position] === close) { this.position += 1; return value; }
      while (true) {
        if (value instanceof PhpObject) {
          this.whitespace();
          if (this.source[this.position] !== '"') invalid();
          const key = phpKey(this.string());
          this.whitespace();
          if (this.source[this.position++] !== ':') invalid();
          value.set(key, this.value(level + 1));
        } else value.push(this.value(level + 1));
        this.whitespace();
        const delimiter = this.source[this.position++];
        if (delimiter === close) return value;
        if (delimiter !== ',') invalid();
      }
    }
    for (const [literal, value] of [['null', null], ['true', true], ['false', false]] as const) {
      if (this.source.startsWith(literal, this.position)) { this.position += literal.length; return value; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.source.slice(this.position))?.[0];
    if (number === undefined) invalid();
    this.position += number.length;
    if (/[.eE]/.test(number)) return new PhpFloat();
    if (number.length > (number[0] === '-' ? 20 : 19)) return number;
    const integer = BigInt(number);
    // json_decode(... JSON_BIGINT_AS_STRING) changes integers beyond PHP's range to strings.
    return integer < PHP_INTEGER_MIN || integer > PHP_INTEGER_MAX ? number : integer;
  }
}

function quote(value: string): string {
  if (!validUnicode(value)) throw new VerifierError('json_utf8', 'Canonical JSON contains invalid UTF-8.');
  return JSON.stringify(value);
}

function encodeParsed(value: Parsed): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'bigint') {
    if (value < -SAFE_INTEGER || value > SAFE_INTEGER) {
      throw new VerifierError('json_integer_range', 'Canonical JSON contains an integer outside the I-JSON safe range.');
    }
    return value.toString();
  }
  if (value instanceof PhpFloat) throw new VerifierError('json_float', 'The ContentLedger canonical JSON profile does not permit floating-point values.');
  if (Array.isArray(value)) return `[${value.map(encodeParsed).join(',')}]`;
  const keys = Array.from(value.keys());
  // PHP's associative decoder also treats {} and sequential numeric-key objects as lists.
  if (keys.every((key, index) => key === BigInt(index))) return `[${Array.from(value.values(), encodeParsed).join(',')}]`;
  if (keys.some((key) => typeof key !== 'string')) {
    throw new VerifierError('json_object_key', 'Canonical JSON object keys must be strings.');
  }
  // ECMAScript's default sort is UTF-16 code-unit order, matching PHP's utf16be strcmp.
  return `{${(keys as string[]).sort().map((key) => `${quote(key)}:${encodeParsed(value.get(key)!)}`).join(',')}}`;
}

function fromValue(value: unknown): Parsed {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) return new PhpFloat();
    return BigInt(value);
  }
  if (Array.isArray(value)) return Array.from(value, fromValue);
  if (typeof value === 'object') return new PhpObject(Object.entries(value).map(([key, item]) => [phpKey(key), fromValue(item)]));
  throw new VerifierError('json_type', 'Canonical JSON contains an unsupported value type.');
}

function toValue(value: Parsed): unknown {
  if (typeof value === 'bigint') return Number(value);
  if (Array.isArray(value)) return value.map(toValue);
  if (value instanceof PhpObject) {
    if (Array.from(value.keys()).every((key, index) => key === BigInt(index))) return Array.from(value.values(), toValue);
    const object = Object.create(null) as Record<string, unknown>;
    for (const [key, item] of value) object[String(key)] = toValue(item);
    return object;
  }
  return value;
}

export function encodeCanonical(value: unknown): string {
  return encodeParsed(fromValue(value));
}

export function decodeCanonical(bytes: Uint8Array, depth = 64): unknown {
  let source: string;
  try { source = utf8(bytes); } catch { return invalid(); }
  const parsed = new Parser(source, depth).parse();
  if (source !== encodeParsed(parsed)) throw new VerifierError('json_noncanonical', 'A required JSON document is not in exact canonical form.');
  return toValue(parsed);
}

export function decodeCanonicalObject(bytes: Uint8Array, depth = 64): Record<string, unknown> {
  const value = decodeCanonical(bytes, depth);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new VerifierError('json_object', 'A required JSON document is not an object.');
  }
  return value as Record<string, unknown>;
}

export function exactKeys(value: Record<string, unknown> | unknown[], keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => typeof phpKey(key) === 'string' && key === expected[index]);
}
