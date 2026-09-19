// SPDX-License-Identifier: GPL-2.0-or-later
// Structural detached OpenTimestamps inspection from frozen
// OpenTimestamps_Verifier.php. No calendar requests, Bitcoin consensus checks,
// timestamp authority, or trusted-time verdict are provided by this module.
import { VerifierError } from './errors';
import { isManifestHash } from './manifest';

export const MAX_PROOF_BYTES = 20000;
export const MAX_MESSAGE_BYTES = 4096;
export const MAX_DEPTH = 256;
export const MAX_ATTESTATION_PAYLOAD_BYTES = 8192;
export const MAX_PENDING_URI_BYTES = 1000;
const PHP_INT_MAX = 9223372036854775807n;
const MAGIC = Uint8Array.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294'.match(/../g)!, hex => Number.parseInt(hex, 16));
const PENDING_TAG = '83dfe30d2ef90c8e';
const BITCOIN_TAG = '0588960d73d71901';
const encoder = new TextEncoder();

export interface PendingAttestation { uri: string; commitment: string }
export interface BitcoinAttestation {
  // Decimal string preserves the full PHP signed-64-bit range. A height is an
  // unverified attestation claim, not evidence of a block or trusted time.
  height: string;
  commitment: string;
}
export interface OpenTimestampInspection {
  fileDigest: string;
  proofSha256: string;
  pending: PendingAttestation[];
  bitcoin: BitcoinAttestation[];
  unknownCount: number;
}
type Attestation = { type: 'unknown' } | { type: 'pending'; uri: string } | { type: 'bitcoin'; height: string };
interface TimestampNode { message: Uint8Array; attestations: Attestation[]; operations: TimestampNode[] }
interface Operation { tag: number; argument: Uint8Array | null }

function invalid(code: string, message: string): never { throw new VerifierError(code, message); }
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
function byteString(bytes: Uint8Array): string { return Array.from(bytes, byte => String.fromCharCode(byte)).join(''); }

async function digest(algorithm: 'SHA-1' | 'SHA-256', bytes: Uint8Array): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) throw new VerifierError('browser_crypto_unavailable', 'This browser does not provide the required local cryptographic operations.', 'unsupported');
  try {
    return new Uint8Array(await globalThis.crypto.subtle.digest(algorithm, new Uint8Array(bytes)));
  } catch {
    throw new VerifierError('browser_crypto_failed', 'The browser could not complete the required local hash operation.', 'unsupported');
  }
}

class Reader {
  position = 0;
  constructor(readonly bytes: Uint8Array) {}

  read(length: number): Uint8Array {
    if (length < 0 || this.position < 0 || this.position + length > this.bytes.length) invalid('ots_truncated', 'The OpenTimestamps proof is truncated.');
    const value = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }

  variableInteger(): bigint {
    let value = 0n;
    let factor = 1n;
    for (let index = 0; index < 10; index += 1) {
      const byte = this.read(1)[0];
      const chunk = BigInt(byte & 0x7f);
      if (chunk > (PHP_INT_MAX - value) / factor) invalid('ots_integer', 'An OpenTimestamps integer exceeds the supported range.');
      value += chunk * factor;
      if ((byte & 0x80) === 0) {
        if (index > 0 && chunk === 0n) invalid('ots_integer_nonminimal', 'An OpenTimestamps integer uses a non-minimal encoding.');
        return value;
      }
      if (factor > PHP_INT_MAX / 128n) invalid('ots_integer', 'An OpenTimestamps integer exceeds the supported range.');
      factor *= 128n;
    }
    return invalid('ots_integer', 'An OpenTimestamps integer is too long.');
  }

  variableBytes(maximum: number, minimum = 0): Uint8Array {
    const length = this.variableInteger();
    if (length < BigInt(minimum) || length > BigInt(maximum)) invalid('ots_varbytes', 'An OpenTimestamps variable-length field exceeds its bounds.');
    return this.read(Number(length));
  }
}

function parseAttestation(reader: Reader): Attestation {
  const tag = hex(reader.read(8));
  const payload = reader.variableBytes(MAX_ATTESTATION_PAYLOAD_BYTES);
  if (tag === PENDING_TAG) {
    const inner = new Reader(payload);
    const uri = byteString(inner.variableBytes(MAX_PENDING_URI_BYTES));
    if (inner.position !== payload.length || /^https:\/\/[A-Za-z0-9._/-]+$/.exec(uri)?.[0] !== uri) invalid('ots_pending_attestation', 'A pending-calendar attestation is invalid.');
    return { type: 'pending', uri };
  }
  if (tag === BITCOIN_TAG) {
    const inner = new Reader(payload);
    const height = inner.variableInteger();
    if (inner.position !== payload.length) invalid('ots_bitcoin_attestation', 'A Bitcoin block-height attestation is invalid.');
    return { type: 'bitcoin', height: height.toString() };
  }
  return { type: 'unknown' };
}

function parseOperation(reader: Reader, tag: number): Operation {
  if ([0x02, 0x03, 0x08, 0x67, 0xf2, 0xf3].includes(tag)) return { tag, argument: null };
  if (tag === 0xf0 || tag === 0xf1) return { tag, argument: reader.variableBytes(MAX_MESSAGE_BYTES, 1) };
  return invalid('ots_operation', 'The OpenTimestamps proof contains an unsupported operation tag.');
}

async function apply(operation: Operation, message: Uint8Array): Promise<Uint8Array> {
  if (message.length > MAX_MESSAGE_BYTES) invalid('ots_message_limit', 'An OpenTimestamps operation input exceeds its safe limit.');
  let result: Uint8Array;
  switch (operation.tag) {
    case 0x02: result = await digest('SHA-1', message); break;
    case 0x08: result = await digest('SHA-256', message); break;
    case 0x03:
      // Deliberate browser capability gap: WebCrypto has no RIPEMD-160, and no
      // alternate crypto implementation is silently substituted.
      throw new VerifierError('ots_ripemd160', 'RIPEMD-160 OpenTimestamps branches are not supported by this browser verifier.', 'unsupported');
    case 0x67: throw new VerifierError('ots_keccak', 'Keccak-256 OpenTimestamps branches are not supported.', 'unsupported');
    case 0xf0:
      result = new Uint8Array(message.length + operation.argument!.length);
      result.set(message); result.set(operation.argument!, message.length);
      break;
    case 0xf1:
      result = new Uint8Array(message.length + operation.argument!.length);
      result.set(operation.argument!); result.set(message, operation.argument!.length);
      break;
    case 0xf2: result = new Uint8Array(message).reverse(); break;
    case 0xf3: result = encoder.encode(hex(message)); break;
    default: return invalid('ots_operation', 'The OpenTimestamps proof contains an unsupported operation.');
  }
  if (result.length === 0 || result.length > MAX_MESSAGE_BYTES) invalid('ots_message_limit', 'An OpenTimestamps operation result exceeds its safe limit.');
  return result;
}

async function parseNode(reader: Reader, message: Uint8Array, depth: number): Promise<TimestampNode> {
  if (depth <= 0) invalid('ots_depth', 'The OpenTimestamps proof exceeds its recursion limit.');
  const node: TimestampNode = { message, attestations: [], operations: [] };
  const operationKeys = new Set<string>();
  while (true) {
    let tag = reader.read(1)[0];
    const fork = tag === 0xff;
    if (fork) tag = reader.read(1)[0];
    if (tag === 0x00) node.attestations.push(parseAttestation(reader));
    else {
      if (tag === 0xff) invalid('ots_fork', 'The OpenTimestamps proof contains an invalid fork marker.');
      const operation = parseOperation(reader, tag);
      const key = tag.toString(16).padStart(2, '0') + (operation.argument === null ? '' : hex(operation.argument));
      if (operationKeys.has(key)) invalid('ots_duplicate_branch', 'The OpenTimestamps proof contains a duplicate operation branch.');
      operationKeys.add(key);
      node.operations.push(await parseNode(reader, await apply(operation, message), depth - 1));
    }
    if (!fork) return node;
  }
}

function collect(node: TimestampNode, result: Pick<OpenTimestampInspection, 'pending' | 'bitcoin' | 'unknownCount'>): void {
  // Match PHP's traversal: a node's attestations precede its operation children,
  // even when an operation branch appears first in the serialized proof.
  for (const attestation of node.attestations) {
    if (attestation.type === 'pending') result.pending.push({ uri: attestation.uri, commitment: hex(node.message) });
    else if (attestation.type === 'bitcoin') result.bitcoin.push({ height: attestation.height, commitment: hex(node.message) });
    else result.unknownCount += 1;
  }
  for (const child of node.operations) collect(child, result);
}

/** Exact subject and structural inspection only; never a trusted-time verdict. */
export async function inspectOpenTimestamp(bytes: Uint8Array, expectedDigest: string): Promise<OpenTimestampInspection> {
  if (bytes.length === 0 || bytes.length > MAX_PROOF_BYTES) invalid('ots_size', 'An OpenTimestamps proof is empty or exceeds 20 KiB.');
  if (!isManifestHash(expectedDigest)) invalid('ots_subject', 'An OpenTimestamps proof has no valid expected SHA-256 subject.');
  // One owned snapshot binds parsing, operations, commitments and proof SHA-256
  // to the same exact bytes even if a caller mutates a Buffer during an await.
  const snapshot = new Uint8Array(bytes);
  const reader = new Reader(snapshot);
  if (hex(reader.read(MAGIC.length)) !== hex(MAGIC)) invalid('ots_header', 'The OpenTimestamps detached-proof header is invalid.');
  if (reader.read(1)[0] !== 1 || reader.read(1)[0] !== 0x08) invalid('ots_profile', 'Only a version-1 SHA-256 detached OpenTimestamps proof is supported.');
  const fileDigest = reader.read(32);
  if (hex(fileDigest) !== expectedDigest) invalid('ots_digest', 'An OpenTimestamps proof is for a different file digest.');
  const root = await parseNode(reader, fileDigest, MAX_DEPTH);
  if (reader.position !== snapshot.length) invalid('ots_trailing', 'The OpenTimestamps proof contains trailing data.');
  const result = { pending: [] as PendingAttestation[], bitcoin: [] as BitcoinAttestation[], unknownCount: 0 };
  collect(root, result);
  return { fileDigest: expectedDigest, proofSha256: hex(await digest('SHA-256', snapshot)), ...result };
}
