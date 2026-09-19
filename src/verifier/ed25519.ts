// SPDX-License-Identifier: GPL-2.0-or-later
import { VerifierError } from './errors';
import { ED25519_SMALL_ORDER_Y, ED25519_VECTORS, ed25519VectorBytes } from './ed25519-vectors';

// This module performs byte bounds, not elliptic-curve arithmetic. The native
// backend handles point decoding, SHA-512 and the cofactorless group equation.
// PHP's native Sodium reference rejects S >= L and small-order A/R, requires
// canonical A, and compares canonical computed R to the exact signature bytes:
// https://github.com/jedisct1/libsodium/blob/1.0.22-RELEASE/src/libsodium/crypto_sign/ed25519/ref10/open.c
// WebCrypto's Ed25519 section requires those strict checks but notes backend
// differences: https://www.w3.org/TR/webcrypto/#ed25519-operations
const ORDER = ed25519VectorBytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
const FIELD = ed25519VectorBytes('ed' + 'ff'.repeat(30) + '7f');
const SMALL_ORDER = ED25519_SMALL_ORDER_Y.map(ed25519VectorBytes);

type NativeOperations = Pick<SubtleCrypto, 'importKey' | 'verify'>;
export type Ed25519Verifier = (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => Promise<boolean>;

function lessThanLittleEndian(value: Uint8Array, bound: Uint8Array): boolean {
  for (let index = value.length - 1; index >= 0; index -= 1) {
    if (value[index] !== bound[index]) return value[index] < bound[index];
  }
  return false;
}

function supportedPointEncoding(point: Uint8Array): boolean {
  const y = new Uint8Array(point);
  y[31] &= 0x7f;
  return lessThanLittleEndian(y, FIELD) && !SMALL_ORDER.some((small) => small.every((byte, index) => y[index] === byte));
}

function supportedEncoding(signature: Uint8Array, publicKey: Uint8Array): boolean {
  return signature.length === 64 && publicKey.length === 32
    && lessThanLittleEndian(signature.subarray(32), ORDER)
    && supportedPointEncoding(publicKey) && supportedPointEncoding(signature.subarray(0, 32));
}

function capability(code: string): VerifierError {
  const message = code === 'browser_ed25519_unavailable'
    ? 'This browser does not provide the required native Ed25519 verification operation.'
    : code === 'browser_ed25519_unqualified'
      ? 'This browser did not pass the required local Ed25519 compatibility checks.'
      : 'The browser could not reliably complete a native Ed25519 verification operation.';
  return new VerifierError(code, message, 'unsupported');
}

/**
 * One cached qualification per verifier instance; used once per worker/backend.
 * A finite self-test is a compatibility gate, not a cryptographic proof, vendor
 * certification, identity check, or authorization decision. Unqualified engines
 * never silently fall back to weaker checks. Exposed for deterministic tests.
 */
export function createEd25519Verifier(subtle: NativeOperations | undefined): Ed25519Verifier {
  const available = subtle && typeof subtle.importKey === 'function' && typeof subtle.verify === 'function';
  const importKey = available ? subtle.importKey.bind(subtle) : null;
  const verify = available ? subtle.verify.bind(subtle) : null;
  let qualification: Promise<void> | undefined;

  async function raw(signature: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>, publicKey: Uint8Array<ArrayBuffer>): Promise<boolean> {
    if (!importKey || !verify) throw capability('browser_ed25519_unavailable');
    const key = await importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    const result = await verify({ name: 'Ed25519' }, key, signature, message);
    if (typeof result !== 'boolean') throw capability('browser_ed25519_runtime');
    return result;
  }

  async function qualify(): Promise<void> {
    try {
      for (const vector of ED25519_VECTORS) {
        const signature = ed25519VectorBytes(vector.signature);
        const message = ed25519VectorBytes(vector.message);
        const publicKey = ed25519VectorBytes(vector.publicKey);
        const actual = supportedEncoding(signature, publicKey) && await raw(signature, message, publicKey);
        if (actual !== vector.valid) throw capability('browser_ed25519_unqualified');
        if (vector.valid) {
          const changed = new Uint8Array(message.length + 1);
          changed.set(message);
          if (await raw(signature, changed, publicKey)) throw capability('browser_ed25519_unqualified');
        }
      }
    } catch (failure) {
      if (failure instanceof VerifierError) throw failure;
      if (failure instanceof Error && failure.name === 'NotSupportedError') throw capability('browser_ed25519_unavailable');
      throw capability('browser_ed25519_unqualified');
    }
  }

  return async (signature, message, publicKey) => {
    // Copy before the first await, including Node Buffer inputs in tests. A caller
    // cannot change the signed bytes while backend qualification is in flight.
    const signatureBytes = new Uint8Array(signature);
    const messageBytes = new Uint8Array(message);
    const publicBytes = new Uint8Array(publicKey);
    if (!supportedEncoding(signatureBytes, publicBytes)) return false;
    if (!available) throw capability('browser_ed25519_unavailable');
    qualification ??= qualify();
    await qualification;
    try {
      return await raw(signatureBytes, messageBytes, publicBytes);
    } catch {
      // A native-operation exception is not proof that submitted evidence is
      // invalid. Keep the result indeterminate and omit raw runtime diagnostics.
      throw capability('browser_ed25519_runtime');
    }
  };
}

const runtimeVerifiers = new WeakMap<SubtleCrypto, Ed25519Verifier>();

/** Mathematical signature integrity only; the supplied key is NOT trusted. */
export async function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw capability('browser_ed25519_unavailable');
  let verifier = runtimeVerifiers.get(subtle);
  if (!verifier) {
    verifier = createEd25519Verifier(subtle);
    runtimeVerifiers.set(subtle, verifier);
  }
  return verifier(signature, message, publicKey);
}
