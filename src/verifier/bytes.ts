// SPDX-License-Identifier: GPL-2.0-or-later
import { VerifierError } from './errors';

/** Fatal decoding, preserving a BOM so it cannot silently disappear from signed JSON. */
export function utf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new VerifierError('json_utf8', 'Canonical JSON contains invalid UTF-8.');
  }
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new VerifierError('browser_crypto_unavailable', 'This browser does not provide the required local cryptographic operations.', 'unsupported');
  }
  // A private copy is both a stable digest input and an ArrayBuffer-backed WebCrypto argument.
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
