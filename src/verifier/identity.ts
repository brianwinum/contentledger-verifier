// SPDX-License-Identifier: GPL-2.0-or-later
// Native carried-history profile from Portable Verifier 3.0.0. No resolution,
// network trust, independent clock, or present-day website control is implied.
import { sha256, utf8 } from './bytes';
import { decodeCanonicalObject, encodeCanonical, exactKeys } from './canonical';
import { VerifierError } from './errors';
import { base64urlEncode, type PublicJwk } from './jws';
import { isManifestDate, isManifestHash } from './manifest';
import { verifyWebvh, type WebvhVersion } from './webvh';

export const MAX_IDENTITY_LOG_BYTES = 16777216;
export const MAX_IDENTITY_RECEIPT_BYTES = 4259840;
export const IDENTITY_FIELDS = ['assertionMethod', 'did', 'entryCount', 'logBytes', 'logSha256', 'publicKeyJwk', 'publicUrl', 'siteUrl', 'stateSha256', 'versionId', 'versionTime'];
const encoder = new TextEncoder();

export interface IdentityBinding {
  assertionMethod: string; did: string; entryCount: number; logBytes: number;
  logSha256: string; publicKeyJwk: PublicJwk; publicUrl: string; siteUrl: string;
  stateSha256: string; versionId: string; versionTime: string;
}
export interface IdentityKey { from: string; until: string | null; jwk: PublicJwk }
export interface VerifiedIdentityReceipt {
  activeKeyId: string; did: string; document: Record<string, unknown>;
  eventHeadHash: string; identity: IdentityBinding; json: string;
  keys: Record<string, IdentityKey>; log_json: string; sha256: string; versions: WebvhVersion[];
}
export interface RecordKeyAssessment {
  keyFound: boolean; currentAtBundle: boolean;
  authorizationAtClaim: 'authorized' | 'unauthorized'; status: 'current' | 'rotated' | 'unknown';
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
const matches = (pattern: RegExp, value: string): boolean => pattern.exec(value)?.[0] === value;

/** Identity receipts deliberately disallow fractions, unlike record JWS syntax. */
export function identityInstant(value: unknown): number | null {
  if (typeof value !== 'string' || !matches(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|\+00:00)$/, value) || !isManifestDate(value)) return null;
  const date = new Date(0);
  date.setUTCFullYear(Number(value.slice(0, 4)), Number(value.slice(5, 7)) - 1, Number(value.slice(8, 10)));
  date.setUTCHours(Number(value.slice(11, 13)), Number(value.slice(14, 16)), Number(value.slice(17, 19)), 0);
  return date.getTime() / 1000;
}

/** PHP parse_url routing predicate, not WHATWG URL normalization or a fetch. */
export function identityRouteUrl(siteUrl: string): string {
  if (!siteUrl.endsWith('/')) return '';
  const match = /^https:\/\/([^/?#]*)([^?#]*)$/i.exec(siteUrl);
  if (!match || match[0] !== siteUrl) return '';
  let host = match[1];
  // PHP substitutes underscores for ASCII control bytes in parsed components.
  host = host.replace(/[\x00-\x1f\x7f]/g, '_');
  if (host.includes('@')) return '';
  if (!(host.startsWith('[') && host.endsWith(']'))) {
    const colon = host.lastIndexOf(':');
    if (colon >= 0) {
      // A terminal empty port is absent in PHP; any nonempty port is forbidden.
      if (colon !== host.length - 1) return '';
      host = host.slice(0, -1);
    }
  }
  if (!host || /[A-Z]/.test(host)) return '';
  const path = (match[2] || '/').replace(/[\x00-\x1f\x7f]/g, '_');
  return path === '/' ? `https://${host}/.well-known/did.jsonl` : `https://${host}/${path.replace(/^\/+|\/+$/g, '')}/did.jsonl`;
}

// Receipt validation initially checks JWK grammar only, just like PHP. Strict
// canonical decoding/point guards occur in the authenticated log verifier.
function receiptJwk(value: unknown): value is PublicJwk {
  return object(value) && exactKeys(value, ['crv', 'kty', 'x']) && value.crv === 'Ed25519' && value.kty === 'OKP'
    && typeof value.x === 'string' && matches(/^[A-Za-z0-9_-]{43}$/, value.x);
}
async function thumbprint(jwk: PublicJwk): Promise<string> {
  const hex = await sha256(encoder.encode(encodeCanonical(jwk)));
  return base64urlEncode(Uint8Array.from(hex.match(/../g)!, value => parseInt(value, 16)));
}

async function validateIdentity(value: unknown): Promise<IdentityBinding> {
  if (!object(value) || !exactKeys(value, IDENTITY_FIELDS)
    || typeof value.did !== 'string' || encoder.encode(value.did).length > 2048
    || !matches(/^did:webvh:[1-9A-HJ-NP-Za-km-z]{46}:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[a-z0-9._~-]+)*$/, value.did)
    || typeof value.assertionMethod !== 'string' || !value.assertionMethod.startsWith(`${value.did}#`)
    || !Number.isInteger(value.entryCount) || (value.entryCount as number) < 1 || (value.entryCount as number) > 128
    || !Number.isInteger(value.logBytes) || (value.logBytes as number) < 2 || (value.logBytes as number) > MAX_IDENTITY_LOG_BYTES
    || !isManifestHash(value.logSha256) || !isManifestHash(value.stateSha256) || !receiptJwk(value.publicKeyJwk)
    || typeof value.siteUrl !== 'string' || typeof value.publicUrl !== 'string' || identityRouteUrl(value.siteUrl) !== value.publicUrl
    || typeof value.versionId !== 'string' || !matches(/^([1-9][0-9]{0,2})-[A-Za-z0-9_-]+$/, value.versionId)
    || Number(value.versionId.split('-')[0]) !== value.entryCount || identityInstant(value.versionTime) === null) {
    throw new VerifierError('identity_binding', 'The Website Identity checkpoint has an invalid exact public binding.');
  }
  if (`${value.did}#${await thumbprint(value.publicKeyJwk)}` !== value.assertionMethod) throw new VerifierError('identity_assertion_method', 'The Website Identity assertion method does not match its public key.');
  return value as unknown as IdentityBinding;
}

/** Authenticate every carried version before returning any resolved key state. */
export async function verifyIdentityReceipt(bytes: Uint8Array): Promise<VerifiedIdentityReceipt> {
  if (!bytes.length || bytes.length > MAX_IDENTITY_RECEIPT_BYTES) throw new VerifierError('identity_receipt_size', 'A Website Identity receipt is empty or exceeds its bounded size.');
  const snapshot = new Uint8Array(bytes);
  const document = decodeCanonicalObject(snapshot, 32);
  if (!exactKeys(document, ['didLog', 'format', 'identity', 'version']) || document.format !== 'WP ContentLedger Website Identity Checkpoint'
    || document.version !== '2.0' || typeof document.didLog !== 'string') throw new VerifierError('identity_receipt_profile', 'A Website Identity receipt has an unsupported exact profile.');
  const identity = await validateIdentity(document.identity);
  const logBytes = encoder.encode(document.didLog);
  if (logBytes.length !== identity.logBytes || await sha256(logBytes) !== identity.logSha256) throw new VerifierError('identity_log_digest', 'The Website Identity receipt does not bind the exact carried did:webvh log bytes.');
  // Runtime crypto capability errors propagate as indeterminate. Profile-level
  // log failures are rejected like the frozen Identity_Verifier, without raw data.
  const result = await verifyWebvh(identity.did, logBytes, identity.versionTime);
  if (result.status !== 'valid' || result.entryCount !== identity.entryCount) throw new VerifierError('identity_log_invalid', 'The carried did:webvh log fails the native production profile.');
  const versions = result.versions;
  const head = versions.at(-1);
  if (!head || head.versionId !== identity.versionId || head.versionTime !== identity.versionTime || head.assertionKey !== identity.publicKeyJwk.x) throw new VerifierError('identity_log_head', 'The Website Identity receipt does not match its verified did:webvh log head.');
  const projection = {
    activeUpdateMultikey: head.currentUpdateKey, assertionJwkX: identity.publicKeyJwk.x,
    assertionMethod: identity.assertionMethod, committedSuccessorHash: head.committedSuccessorHash,
    did: identity.did, entryCount: identity.entryCount, logBytes: identity.logBytes, logSha256: identity.logSha256,
    publicUrl: identity.publicUrl, siteUrl: identity.siteUrl, versionId: identity.versionId, versionTime: identity.versionTime,
  };
  if (await sha256(encoder.encode(encodeCanonical(projection))) !== identity.stateSha256) throw new VerifierError('identity_state_digest', 'The Website Identity public-state digest cannot be reproduced from the verified log.');
  const keys: Record<string, IdentityKey> = Object.create(null);
  for (const [index, version] of versions.entries()) {
    const jwk: PublicJwk = { crv: 'Ed25519', kty: 'OKP', x: version.assertionKey };
    const kid = version.state.assertionMethod[0];
    if (!kid || `${identity.did}#${await thumbprint(jwk)}` !== kid) throw new VerifierError('identity_assertion_method', 'A verified did:webvh version has an invalid assertion-method binding.');
    // Preserve PHP's first-to-last-occurrence interval, including reused assertion
    // keys. This is a compatibility rule, not a new independent policy.
    keys[kid] = { from: keys[kid]?.from ?? version.versionTime, jwk, until: versions[index + 1]?.versionTime ?? null };
  }
  if (!keys[identity.assertionMethod]) throw new VerifierError('identity_assertion_head', 'The Website Identity head assertion method is absent from its verified log.');
  return { activeKeyId: identity.assertionMethod, did: identity.did, document, eventHeadHash: identity.logSha256,
    identity, json: utf8(snapshot), keys, log_json: document.didLog, sha256: await sha256(snapshot), versions };
}

export function assessRecordKey(receipt: Pick<VerifiedIdentityReceipt, 'keys' | 'activeKeyId'>, kid: string, issuedAt: string): RecordKeyAssessment {
  const key = Object.hasOwn(receipt.keys, kid) ? receipt.keys[kid] : undefined;
  if (!key) return { keyFound: false, currentAtBundle: false, authorizationAtClaim: 'unauthorized', status: 'unknown' };
  const issued = identityInstant(issuedAt), from = identityInstant(key.from), until = key.until === null ? null : identityInstant(key.until);
  const authorized = issued !== null && from !== null && issued >= from && (until === null || issued < until);
  const current = kid === receipt.activeKeyId;
  return { keyFound: true, currentAtBundle: current, authorizationAtClaim: authorized ? 'authorized' : 'unauthorized', status: current ? 'current' : 'rotated' };
}
