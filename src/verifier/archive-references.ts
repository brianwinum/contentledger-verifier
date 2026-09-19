// SPDX-License-Identifier: GPL-2.0-or-later
// Frozen Bundle_Verifier.php archive-reference metadata profile. URLs are only
// parsed as retained strings; no content retrieval or availability is implied.
import { decodeCanonicalObject, exactKeys } from './canonical';
import { VerifierError } from './errors';
import { isHttpsUrl, isManifestDate } from './manifest';

export const MAX_ARCHIVE_REFERENCE_BYTES = 1048576;
export type ArchiveReferenceKind = 'attributable-wayback-capture' | 'exact-byte-wayback-capture';
const encoder = new TextEncoder();
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }

/** The embedded original URL uses PHP parse_url, not FILTER_VALIDATE_URL or
 * WHATWG normalization. Preserve its permissive host and bounded strtol port
 * behavior: original URLs are retained metadata, never network destinations. */
function validOriginalTarget(value: string): boolean {
  if (!value.startsWith('https://') || value.includes('#')) return false;
  const authority = value.slice(8).split(/[/?#]/, 1)[0];
  if (authority.includes('@')) return false;
  let host = authority;
  if (!(authority.startsWith('[') && authority.endsWith(']'))) {
    const colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      const port = authority.slice(colon + 1);
      if (encoder.encode(port).length > 5) return false;
      if (port !== '') {
        const prefix = /^[+-]?[0-9]+/.exec(port)?.[0];
        if (prefix === undefined || Number(prefix) < 0 || Number(prefix) > 65535) return false;
      }
      host = authority.slice(0, colon);
    }
  }
  // PHP empty('0') is true, unlike JavaScript truthiness.
  return host !== '' && host !== '0';
}

/** Exact Wayback carrier and capture-time relation, independent of outer URL
 * validation. Attributable references permit any 0..12 alphabetic/_ modifier;
 * exact-byte references require precisely id_. */
export function validWaybackReference(url: string, capturedAt: string, expectedKind: ArchiveReferenceKind): boolean {
  const match = /^https:\/\/web\.archive\.org(?::443)?\/web\/([0-9]{14})([A-Za-z_]{0,12})\/(https:\/\/[^\x00-\x20]+)$/.exec(url);
  if (!match || match[0] !== url || !validOriginalTarget(match[3])) return false;
  if (expectedKind === 'exact-byte-wayback-capture' && match[2] !== 'id_') return false;
  const stamp = match[1];
  const capture = `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(8, 10)}:${stamp.slice(10, 12)}:${stamp.slice(12, 14)}Z`;
  return isManifestDate(capture) && capture === capturedAt;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) if (left[index] !== right[index]) return left[index] - right[index];
  return left.length - right.length;
}

/** Returns retained reference count only; never an availability or authenticity verdict. */
export function verifyArchiveReferences(bytes: Uint8Array, subjectSha256: string, expectedKind: ArchiveReferenceKind): number {
  // PHP applies this limit at Zip_Reader::read before canonical JSON decoding.
  if (bytes.length > MAX_ARCHIVE_REFERENCE_BYTES) throw new VerifierError('zip_entry_limit', 'A bundle entry exceeds its profile-specific size limit.');
  const document = decodeCanonicalObject(new Uint8Array(bytes), 16);
  if (!exactKeys(document, ['format', 'references', 'subjectSha256', 'version']) || document.format !== 'WP ContentLedger Archive Reference Set' || document.version !== '3.0'
    || document.subjectSha256 !== subjectSha256 || !Array.isArray(document.references) || !document.references.length || document.references.length > 250) {
    throw new VerifierError('archive_reference_profile', 'An archive-reference document has an invalid exact profile or subject binding.');
  }
  let priorUrl: Uint8Array | null = null;
  for (const reference of document.references) {
    if (!object(reference) || !exactKeys(reference, ['capturedAt', 'kind', 'provider', 'remoteUrl', 'verifiedAt']) || reference.kind !== expectedKind || reference.provider !== 'Internet Archive'
      || !isHttpsUrl(reference.remoteUrl) || !isManifestDate(reference.capturedAt) || !isManifestDate(reference.verifiedAt)
      || !validWaybackReference(reference.remoteUrl, reference.capturedAt, expectedKind)) {
      throw new VerifierError('archive_reference_item', 'An archive reference is malformed, duplicated, or not in strict URL order.');
    }
    const url = encoder.encode(reference.remoteUrl);
    if (priorUrl !== null && compareBytes(priorUrl, url) >= 0) throw new VerifierError('archive_reference_item', 'An archive reference is malformed, duplicated, or not in strict URL order.');
    priorUrl = url;
  }
  return document.references.length;
}
