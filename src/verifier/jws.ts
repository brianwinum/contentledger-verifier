// SPDX-License-Identifier: GPL-2.0-or-later
// Exact compact-JWS profile from Portable Verifier 3.0.0. This verifies the
// embedded public-key math and byte bindings, not identity authorization.
import { sha256, utf8 } from './bytes';
import { decodeCanonicalObject, encodeCanonical, exactKeys } from './canonical';
import { verifyEd25519 } from './ed25519';
import { VerifierError } from './errors';
import { isManifestDate, type VerifiedManifest } from './manifest';

export const MAX_JWS_BYTES = 131072;
export const TRANSITION_JWS_TYPE = 'application/wp-contentledger-key-transition+jws';
export const CHECKPOINT_JWS_TYPE = 'application/wp-contentledger-transparency-checkpoint+jws';
const encoder = new TextEncoder();

export interface PublicJwk { crv: 'Ed25519'; kty: 'OKP'; x: string }
export interface InspectedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  payloadJson: string;
  payloadBytes: Uint8Array;
  kid: string;
  jwk: PublicJwk;
}
export interface ParsedJws extends InspectedJws { signature: Uint8Array; signingInput: Uint8Array }
export interface VerifiedJws extends InspectedJws { signatureValid: true }
export interface VerifiedRecordJws extends VerifiedJws { issuer: string; issuedAt: string }

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Byte-preserving conversion; malformed non-ASCII JWS bytes must not be repaired. */
function byteString(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) result += String.fromCharCode(byte);
  return result;
}

export function base64urlEncode(bytes: Uint8Array): string {
  return btoa(byteString(bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function base64urlDecode(value: string): Uint8Array {
  if (value === '' || /^[A-Za-z0-9_-]+$/.exec(value)?.[0] !== value || value.length % 4 === 1) {
    throw new VerifierError('base64url', 'A JWS field is not exact unpadded base64url.');
  }
  let decoded: Uint8Array;
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
    decoded = Uint8Array.from(binary, character => character.charCodeAt(0));
  } catch {
    throw new VerifierError('base64url', 'A JWS field is not exact canonical base64url.');
  }
  if (base64urlEncode(decoded) !== value) throw new VerifierError('base64url', 'A JWS field is not exact canonical base64url.');
  return decoded;
}

export function isPublicJwk(value: unknown): value is PublicJwk {
  if (!object(value) || !exactKeys(value, ['crv', 'kty', 'x']) || value.crv !== 'Ed25519' || value.kty !== 'OKP' || typeof value.x !== 'string') return false;
  try { return base64urlDecode(value.x).length === 32; }
  catch (error) { if (error instanceof VerifierError) return false; throw error; }
}

export function isDidWebvh(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 64 && value.length <= 2048
    && /^did:webvh:[1-9A-HJ-NP-Za-km-z]{46}:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[a-z0-9._~-]+)*$/.exec(value)?.[0] === value
    && !value.includes('..');
}

export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  if (!isPublicJwk(jwk)) throw new VerifierError('jwk_profile', 'An Ed25519 public JWK is invalid.');
  const hash = await sha256(encoder.encode(encodeCanonical(jwk)));
  return base64urlEncode(Uint8Array.from(hash.match(/../g)!, pair => Number.parseInt(pair, 16)));
}

/** Only envelope/profile parsing: no signature, identity, or application claim is verified. */
export function parseCompactJws(bytes: Uint8Array, expectedType: string | null = null): ParsedJws {
  if (bytes.length === 0 || bytes.length > MAX_JWS_BYTES || bytes.includes(0)) throw new VerifierError('jws_size', 'A compact JWS is empty or exceeds 128 KiB.');
  const snapshot = new Uint8Array(bytes);
  const parts = byteString(snapshot).split('.');
  if (parts.length !== 3 || parts.some(part => part === '')) throw new VerifierError('jws_compact', 'A signature is not an exact three-part compact JWS.');
  const headerBytes = base64urlDecode(parts[0]);
  const payloadBytes = base64urlDecode(parts[1]);
  const signature = base64urlDecode(parts[2]);
  if (signature.length !== 64) throw new VerifierError('jws_signature_size', 'An Ed25519 JWS signature is not exactly 64 bytes.');
  const header = decodeCanonicalObject(headerBytes, 8);
  const payload = decodeCanonicalObject(payloadBytes, 64);
  const keys = expectedType === null ? ['alg', 'jwk', 'kid'] : ['alg', 'jwk', 'kid', 'typ'];
  if (!exactKeys(header, keys) || header.alg !== 'Ed25519' || expectedType !== null && header.typ !== expectedType
    || typeof header.kid !== 'string' || encoder.encode(header.kid).length > 4096 || !isPublicJwk(header.jwk)) {
    throw new VerifierError('jws_header', 'A compact JWS protected header is outside the supported Ed25519 profile.');
  }
  return { header, payload, payloadJson: utf8(payloadBytes), payloadBytes, kid: header.kid, jwk: header.jwk,
    signature, signingInput: encoder.encode(`${parts[0]}.${parts[1]}`) };
}

function inspected(parsed: ParsedJws): InspectedJws {
  const { signature: _signature, signingInput: _signingInput, ...result } = parsed;
  return result;
}

export function inspectCompactJws(bytes: Uint8Array, expectedType: string | null = null): InspectedJws {
  return inspected(parseCompactJws(bytes, expectedType));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Verified means embedded-key Ed25519 math only; no DID authorization is inferred. */
async function verifyParsed(parsed: ParsedJws): Promise<VerifiedJws> {
  if (!await verifyEd25519(parsed.signature, parsed.signingInput, base64urlDecode(parsed.jwk.x))) {
    throw new VerifierError('jws_signature_invalid', 'An Ed25519 compact JWS signature is invalid.');
  }
  return { ...inspected(parsed), signatureValid: true };
}

export async function verifyExactJws(bytes: Uint8Array, expectedPayloadBytes: Uint8Array, expectedType: string | null,
  expectedKid = '', expectedJwk: PublicJwk | null = null): Promise<VerifiedJws> {
  const parsed = parseCompactJws(bytes, expectedType);
  if (!equalBytes(expectedPayloadBytes, parsed.payloadBytes)) throw new VerifierError('jws_payload_binding', 'A compact JWS payload does not match the exact referenced document.');
  if (expectedKid !== '' && expectedKid !== parsed.kid) throw new VerifierError('jws_kid_binding', 'A compact JWS uses a different verification method than its referenced identity.');
  if (expectedJwk !== null && encodeCanonical(expectedJwk) !== encodeCanonical(parsed.jwk)) throw new VerifierError('jws_jwk_binding', 'A compact JWS public key differs from its referenced identity key.');
  return verifyParsed(parsed);
}

export async function verifyRecordJws(bytes: Uint8Array, manifest: Pick<VerifiedManifest, 'uuid' | 'sha256'>): Promise<VerifiedRecordJws> {
  const parsed = parseCompactJws(bytes, null);
  const claims = parsed.payload;
  if (!exactKeys(claims, ['contentLedgerSignatureVersion', 'entryId', 'issuedAt', 'issuer', 'manifestDigest', 'verificationMethod'])) {
    throw new VerifierError('record_jws_claims', 'A record JWS contains unsupported or missing claims.');
  }
  const digest = claims.manifestDigest;
  if (!object(digest) || !exactKeys(digest, ['algorithm', 'value']) || claims.contentLedgerSignatureVersion !== '2.0'
    || claims.entryId !== `urn:uuid:${manifest.uuid}` || digest.algorithm !== 'sha-256' || digest.value !== manifest.sha256
    || !isDidWebvh(claims.issuer) || typeof claims.verificationMethod !== 'string' || claims.verificationMethod !== parsed.kid || !isManifestDate(claims.issuedAt)) {
    throw new VerifierError('record_jws_binding', 'A record JWS is not bound to its exact manifest, did:webvh issuer, key, and claimed signing time.');
  }
  if (`${claims.issuer}#${await jwkThumbprint(parsed.jwk)}` !== parsed.kid) throw new VerifierError('record_jws_controller', 'A record JWS key identifier is not deterministically bound to its did:webvh issuer.');
  return { ...await verifyParsed(parsed), issuer: claims.issuer, issuedAt: claims.issuedAt };
}
