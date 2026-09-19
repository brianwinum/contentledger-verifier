// SPDX-License-Identifier: GPL-2.0-or-later
// Compatibility port of the frozen portable verifier's Manifest_Verifier.php.
import { sha256 } from './bytes';
import { decodeCanonicalObject, exactKeys } from './canonical';
import { VerifierError } from './errors';

export const MAX_MANIFEST_BYTES = 1048576;

export interface VerifiedManifest {
  document: Record<string, unknown>;
  sha256: string;
  uuid: string;
  canonicalUrl: string;
  previous: string | null;
  sealedAt: string;
  version: string;
}

function fullMatch(pattern: RegExp, value: string): boolean {
  return pattern.exec(value)?.[0] === value;
}

export function isManifestHash(value: unknown): value is string {
  return typeof value === 'string' && value.length === 64 && fullMatch(/^[a-f0-9]{64}$/, value);
}

export function isUuidUrn(value: unknown): value is string {
  return typeof value === 'string' && fullMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, value);
}

/** UTC calendar validation without Date's special treatment of years 0 through 99. */
export function isManifestDate(value: unknown): value is string {
  if (typeof value !== 'string' || !fullMatch(/^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|\+00:00)$/, value)) return false;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  if (day > [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]) return false;
  if (value[19] !== '.') return true;
  const fraction = value.slice(20, value.endsWith('Z') ? -1 : -6);
  // PHP timelib_get_frac_nr first parses the fractional digits as a double,
  // scales to microseconds, then truncates. Preserve its overflow and rounding
  // behavior: a midnight rollover fails the reference's exact Y-m-d comparison.
  // https://github.com/php/php-src/blob/PHP-8.4/ext/date/lib/parse_date.re
  const micros = Math.trunc(Number(fraction) * Math.pow(10, 6 - fraction.length));
  const seconds = Number(value.slice(11, 13)) * 3600 + Number(value.slice(14, 16)) * 60 + Number(value.slice(17, 19));
  return Number.isFinite(micros) && seconds + Math.floor(micros / 1000000) < 86400;
}

function isIpv6(value: string): boolean {
  if (!value.includes(':')) return false;
  // An embedded IPv4 tail occupies two groups and forbids octal-looking octets.
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const octets = value.slice(lastColon + 1).split('.');
    if (octets.length !== 4 || octets.some(octet => !fullMatch(/^(?:0|[1-9][0-9]{0,2})$/, octet) || Number(octet) > 255)) return false;
    value = `${value.slice(0, lastColon + 1)}0:0`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const groups = halves.flatMap(half => half === '' ? [] : half.split(':'));
  if (groups.some(group => !fullMatch(/^[a-fA-F0-9]{1,4}$/, group))) return false;
  return halves.length === 2 ? groups.length < 8 : groups.length === 8;
}

/**
 * Match PHP FILTER_VALIDATE_URL for this HTTPS-only profile, not WHATWG URL
 * normalization. This is a byte predicate: it never resolves or opens a URL.
 * The unusual ports, userinfo percent rule, and final-dot hostname rule are
 * retained for compatibility and covered by PHP differential vectors.
 */
export function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 8192 || !value.startsWith('https://') || /[^\x21-\x7e]/.test(value)) return false;
  let authority = value.slice(8).split(/[/?#]/, 1)[0];
  const at = authority.lastIndexOf('@');
  if (at >= 0) {
    const userinfo = authority.slice(0, at);
    if (!fullMatch(/^(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9][a-fA-F0-9])*$/, userinfo)) return false;
    authority = authority.slice(at + 1);
  }
  let host = authority;
  if (!(authority.startsWith('[') && authority.endsWith(']'))) {
    const colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      const port = authority.slice(colon + 1);
      if (port.length > 5) return false;
      if (port !== '') {
        const prefix = /^[+-]?[0-9]+/.exec(port)?.[0];
        if (prefix === undefined || Number(prefix) < 0 || Number(prefix) > 65535) return false;
      }
      host = authority.slice(0, colon);
    }
  }
  if (host.startsWith('[') && host.endsWith(']')) return isIpv6(host.slice(1, -1));
  const finalDot = host.endsWith('.');
  const domain = finalDot ? host.slice(0, -1) : host;
  if (domain.length === 0 || domain.length > 253 || !/^[A-Za-z0-9]/.test(domain)) return false;
  const labels = domain.split('.');
  return labels.every((label, index) => label.length <= 63 && fullMatch(/^[A-Za-z0-9][A-Za-z0-9-]*$/, label)
    && (finalDot && index === labels.length - 1 || /[A-Za-z0-9]$/.test(label)));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function object(value: unknown, code: string): Record<string, unknown> {
  if (!isObject(value)) throw new VerifierError(code, 'A manifest field expected to be an object is invalid.');
  return value;
}

function exactOptional(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], code: string): void {
  if (required.some(key => !Object.hasOwn(value, key))) throw new VerifierError(code, 'A manifest is missing a required field.');
  if (Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) throw new VerifierError(code, 'A manifest contains an unsupported field.');
}

function namedResource(value: unknown): boolean {
  return isObject(value) && exactKeys(value, ['name', 'url']) && typeof value.name === 'string' && isHttpsUrl(value.url);
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function validateSubject(subject: Record<string, unknown>): void {
  exactOptional(subject, ['canonicalUrl', 'postType', 'publisher', 'title', 'type'],
    ['author', 'dateModified', 'datePublished', 'description', 'featuredImage', 'language', 'taxonomies'], 'manifest_subject');
  if (!isHttpsUrl(subject.canonicalUrl) || subject.type !== 'WebPage' || typeof subject.postType !== 'string' || subject.postType === ''
    || typeof subject.title !== 'string' || !namedResource(subject.publisher) || subject.author != null && !namedResource(subject.author)) {
    throw new VerifierError('manifest_subject', 'A manifest has invalid subject identity fields.');
  }
  for (const field of ['dateModified', 'datePublished']) {
    if (subject[field] != null && !isManifestDate(subject[field])) throw new VerifierError('manifest_subject_date', 'A manifest subject date is invalid.');
  }
  if (subject.featuredImage != null && !isHttpsUrl(subject.featuredImage)) throw new VerifierError('manifest_subject_image', 'A manifest featured-image URL is invalid.');
  for (const field of ['description', 'language']) {
    if (subject[field] != null && typeof subject[field] !== 'string') throw new VerifierError('manifest_subject_text', 'A manifest subject text field is invalid.');
  }
  if (subject.taxonomies != null) {
    const taxonomies = object(subject.taxonomies, 'manifest_taxonomies');
    for (const terms of Object.values(taxonomies)) {
      // Canonical decoding has already rejected numeric object keys as PHP does.
      if (!Array.isArray(terms) || terms.length > 1000) throw new VerifierError('manifest_taxonomies', 'A manifest taxonomy list is invalid.');
      for (const value of terms) {
        const term = object(value, 'manifest_term');
        if (!exactKeys(term, ['name', 'slug']) || typeof term.name !== 'string' || typeof term.slug !== 'string') {
          throw new VerifierError('manifest_term', 'A manifest taxonomy term is invalid.');
        }
      }
    }
  }
}

function validateCommon(document: Record<string, unknown>, digestsRequired: boolean): void {
  if (!isHttpsUrl(document.$schema) || !isUuidUrn(document.entryId) || !isManifestDate(document.sealedAt)) {
    throw new VerifierError('manifest_identity', 'A manifest has an invalid schema URL, entryId, or sealedAt value.');
  }
  const generator = object(document.generator, 'manifest_generator');
  if (!exactKeys(generator, ['name', 'version']) || generator.name !== 'WP ContentLedger' || typeof generator.version !== 'string' || generator.version === '' || byteLength(generator.version) > 64) {
    throw new VerifierError('manifest_generator', 'A manifest has invalid generator fields.');
  }
  const digests = document.digests;
  if (!Array.isArray(digests) || digestsRequired && digests.length === 0 || digests.length > 2) {
    throw new VerifierError('manifest_digests', 'A manifest has an invalid digest list.');
  }
  const scopes = new Set<string>();
  for (const value of digests) {
    const digest = object(value, 'manifest_digest');
    exactOptional(digest, ['algorithm', 'canonicalization', 'scope', 'value'], ['mediaType', 'retrievedAt'], 'manifest_digest');
    const scope = digest.scope;
    if (digest.algorithm !== 'sha-256' || typeof digest.canonicalization !== 'string' || digest.canonicalization === ''
      || scope !== 'canonical-content' && scope !== 'public-representation' || scopes.has(scope) || !isManifestHash(digest.value)) {
      throw new VerifierError('manifest_digest', 'A manifest contains an invalid or duplicate digest declaration.');
    }
    if (scope === 'public-representation' && (typeof digest.mediaType !== 'string' || !isManifestDate(digest.retrievedAt))) {
      throw new VerifierError('manifest_digest', 'A public-representation digest lacks its media type or retrieval time.');
    }
    scopes.add(scope);
  }
  // PHP isset deliberately treats a present null optional field as absent.
  if (document.chain != null) {
    const chain = object(document.chain, 'manifest_chain');
    if (!exactKeys(chain, ['algorithm', 'previousManifestDigest']) || chain.algorithm !== 'sha-256' || !isManifestHash(chain.previousManifestDigest)) {
      throw new VerifierError('manifest_chain', 'A manifest has an invalid predecessor declaration.');
    }
  }
  const limitations = document.limitations ?? [];
  if (!Array.isArray(limitations) || document.limitations != null && limitations.length === 0 || limitations.length > 32) {
    throw new VerifierError('manifest_limitations', 'A manifest has an invalid limitations list.');
  }
  for (const limitation of limitations) {
    if (typeof limitation !== 'string' || limitation === '' || byteLength(limitation) > 4096) throw new VerifierError('manifest_limitations', 'A manifest limitation is invalid.');
  }
  validateSubject(object(document.subject, 'manifest_subject'));
}

function validateV2(document: Record<string, unknown>): void {
  exactOptional(document, ['$schema', 'digests', 'entryId', 'evidenceScope', 'generator', 'limitations', 'manifestVersion', 'provenance', 'sealedAt', 'subject'], ['chain'], 'manifest_shape');
  const scope = document.evidenceScope;
  if (!Array.isArray(scope) || scope.length !== 2 || scope[0] !== 'canonical-content-integrity' || scope[1] !== 'publisher-controlled-recording') {
    throw new VerifierError('manifest_scope', 'Manifest v2 has an invalid evidence scope.');
  }
  const provenance = object(document.provenance, 'manifest_provenance');
  if (!exactKeys(provenance, ['evidenceCapturedAt', 'recordSource', 'sealedFromPreviouslyCapturedEvidence']) || !isManifestDate(provenance.evidenceCapturedAt)
    || typeof provenance.recordSource !== 'string' || typeof provenance.sealedFromPreviouslyCapturedEvidence !== 'boolean') {
    throw new VerifierError('manifest_provenance', 'Manifest v2 has invalid provenance.');
  }
  validateCommon(document, true);
}

function validateV1(document: Record<string, unknown>): void {
  exactOptional(document, ['$schema', 'archiveEvidence', 'digests', 'entryId', 'generator', 'manifestVersion', 'provenance', 'sealedAt', 'subject'], ['chain', 'limitations'], 'manifest_shape');
  const archive = object(document.archiveEvidence, 'manifest_archive');
  if (!exactKeys(archive, ['capturedAt', 'discoveryMethod', 'provider', 'snapshotUrl', 'verificationMethod', 'verificationStatus', 'verifiedAt'])
    || !isManifestDate(archive.capturedAt) || !isManifestDate(archive.verifiedAt) || typeof archive.discoveryMethod !== 'string' || archive.discoveryMethod === ''
    || archive.verificationMethod !== 'http-resolution' || archive.verificationStatus !== 'verified' || !isHttpsUrl(archive.snapshotUrl) || !namedResource(archive.provider)) {
    throw new VerifierError('manifest_archive', 'Manifest v1 has invalid archive-evidence fields.');
  }
  const provenance = object(document.provenance, 'manifest_provenance');
  if (!exactKeys(provenance, ['evidenceCapturedAt', 'legacyImported', 'recordSource']) || !isManifestDate(provenance.evidenceCapturedAt)
    || typeof provenance.legacyImported !== 'boolean' || typeof provenance.recordSource !== 'string') {
    throw new VerifierError('manifest_provenance', 'Manifest v1 has invalid provenance.');
  }
  validateCommon(document, false);
}

/** Validate manifest declarations and exact byte bindings, not their truth or signature. */
export async function verifyManifest(bytes: Uint8Array, expectedUuid = '', expectedHash = ''): Promise<VerifiedManifest> {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_MANIFEST_BYTES) throw new VerifierError('manifest_size', 'A manifest is empty or exceeds 1 MiB.');
  const snapshot = new Uint8Array(bytes);
  const document = decodeCanonicalObject(snapshot, 64);
  const version = document.manifestVersion;
  if (version === '1.0') validateV1(document);
  else if (version === '2.0') validateV2(document);
  else throw new VerifierError('manifest_profile', 'The manifest profile is not supported by this verifier.', 'unsupported');
  const hash = await sha256(snapshot);
  if (expectedHash !== '' && (!isManifestHash(expectedHash) || expectedHash !== hash)) throw new VerifierError('manifest_expected_hash', 'A manifest does not match its expected SHA-256 digest.');
  const uuid = (document.entryId as string).slice(9);
  if (expectedUuid !== '' && expectedUuid !== uuid) throw new VerifierError('manifest_entry_path', 'A manifest entryId does not match its bundle path.');
  return {
    document, sha256: hash, uuid, canonicalUrl: (document.subject as Record<string, unknown>).canonicalUrl as string,
    previous: document.chain == null ? null : (document.chain as Record<string, unknown>).previousManifestDigest as string,
    sealedAt: document.sealedAt as string, version,
  };
}
