// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded native did:webvh production-profile history, Portable Verifier 3.0.0.
import { sha256 } from './bytes';
import { verifyEd25519 } from './ed25519';
import { VerifierError } from './errors';
import { type PublicJwk } from './jws';
import { isManifestDate } from './manifest';
import { assertionJwkThumbprint, canonicalize, decodeEd25519JwkX, decodeEd25519Multikey, decodeNumberFree, decodeProofValue,
  decodeSha256Multihash, encodeEd25519Multikey, replaceStrings, sha256Multihash, updateKeyHash, WebvhError } from './webvh-codec';

export const MAX_WEBVH_DID_BYTES = 2048;
export const MAX_WEBVH_JSONL_BYTES = 1048576;
export const MAX_WEBVH_LINE_BYTES = 65536;
export const MAX_WEBVH_ENTRIES = 128;
export const WEBVH_METHOD = 'did:webvh:1.0';
export const WEBVH_CONTEXT = 'https://www.w3.org/ns/did/v1';
export type WebvhStatus = 'valid' | 'invalid' | 'unsupported' | 'malformed';
export interface WebvhState {
  '@context': string[];
  id: string;
  verificationMethod: { id: string; type: 'JsonWebKey'; controller: string; publicKeyJwk: PublicJwk }[];
  assertionMethod: string[];
}
export interface WebvhVersion {
  versionId: string;
  versionTime: string;
  state: WebvhState;
  currentUpdateKey: string;
  committedSuccessorHash: string;
  assertionKey: string;
}
export interface WebvhResult {
  status: WebvhStatus;
  code: string;
  entryCount: number;
  versionIds: string[];
  resolvedStates: WebvhState[];
  versions: WebvhVersion[];
}
const encoder = new TextEncoder();
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function full(pattern: RegExp, value: string): boolean { return pattern.exec(value)?.[0] === value; }
function fail(code: string, status: Exclude<WebvhStatus, 'valid'> = 'invalid'): never { throw new WebvhError(status, code); }
function sameKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function exact(value: Record<string, unknown>, keys: readonly string[], code: string): void { if (!sameKeys(value, keys)) fail(code); }
function requiredString(value: Record<string, unknown>, key: string, code: string): string {
  if (typeof value[key] !== 'string') fail(code);
  return value[key];
}
function equalBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]); }
function singleton(value: unknown): value is string[] { return Array.isArray(value) && value.length === 1 && typeof value[0] === 'string'; }

async function proofDigest(bytes: Uint8Array): Promise<string> {
  try { return await sha256(bytes); }
  catch (error) {
    if (error instanceof VerifierError && error.kind === 'unsupported') throw error;
    throw new VerifierError('browser_crypto_failed', 'The browser could not reliably complete a required SHA-256 operation.', 'unsupported');
  }
}

export function isWebvhUtcSecond(value: string): boolean {
  return value.length === 20 && full(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/, value)
    && value.slice(0, 4) !== '0000' && isManifestDate(value);
}

function failure(status: string, code: string, entryCount = 0): WebvhResult {
  if (status !== 'invalid' && status !== 'unsupported' && status !== 'malformed') { status = 'malformed'; code = 'internal_result_status'; }
  if (!full(/^[a-z][a-z0-9_]{1,63}$/, code)) code = 'internal_result_code';
  return { status: status as WebvhStatus, code, entryCount: Math.max(0, Math.min(128, entryCount)), versionIds: [], resolvedStates: [], versions: [] };
}

function splitJsonl(bytes: Uint8Array): Uint8Array[] {
  if (bytes.length === 0) fail('jsonl_empty', 'malformed');
  if (bytes.length > MAX_WEBVH_JSONL_BYTES) fail('jsonl_size', 'malformed');
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail('jsonl_bom', 'malformed');
  if (bytes.includes(0)) fail('jsonl_nul', 'malformed');
  if (bytes.includes(13)) fail('jsonl_line_endings', 'malformed');
  if (bytes[bytes.length - 1] !== 10) fail('jsonl_final_lf', 'malformed');
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index++) if (bytes[index] === 10) { lines.push(bytes.subarray(start, index)); start = index + 1; }
  if (lines.length < 1 || lines.length > MAX_WEBVH_ENTRIES) fail('jsonl_entry_count', 'malformed');
  for (const line of lines) {
    if (line.length === 0) fail('jsonl_blank_line', 'malformed');
    if (line.length > MAX_WEBVH_LINE_BYTES) fail('jsonl_line_size', 'malformed');
  }
  return lines;
}

function parseExpectedDid(did: string): string {
  const length = encoder.encode(did).length;
  if (length === 0 || length > MAX_WEBVH_DID_BYTES) fail('did_size');
  if (/[%/\\?#\[\]]|[^\x20-\x7e]/.test(did)) fail('did_feature_unsupported', 'unsupported');
  const segments = did.split(':');
  if (segments.length < 4 || segments[0] !== 'did' || segments[1] !== 'webvh') fail('did_syntax');
  const [scid, domain] = segments.slice(2);
  if (!full(/^[1-9A-HJ-NP-Za-km-z]{46}$/, scid)) fail('scid_encoding');
  decodeSha256Multihash(scid, 'scid_encoding');
  if (`.${domain}`.includes('.xn--') || domain.split('.').every(label => full(/^(?:0x[0-9a-f]+|[0-9]+)$/, label))) fail('did_feature_unsupported', 'unsupported');
  if (domain.length > 253 || !full(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/, domain)) fail('did_domain');
  for (const path of segments.slice(4)) {
    if (/[A-Z]/.test(path)) fail('did_feature_unsupported', 'unsupported');
    if (path === '' || path === '.' || path === '..' || path.length > 255 || !full(/^[a-z0-9._~-]+$/, path)) fail('did_path');
  }
  return scid;
}

async function validateState(value: unknown, did: string): Promise<{ publicKeyBytes: Uint8Array; publicKeyX: string; updateKeyHash: string; state: WebvhState }> {
  if (!object(value)) fail('assertion_state_shape');
  const required = ['@context', 'assertionMethod', 'id', 'verificationMethod'];
  if (!sameKeys(value, required)) {
    if (Object.keys(value).some(key => !required.includes(key))) fail('feature_unsupported', 'unsupported');
    fail('assertion_state_shape');
  }
  if (!singleton(value['@context']) || value['@context'][0] !== WEBVH_CONTEXT) fail('state_context');
  if (value.id !== did) fail('state_id');
  if (!Array.isArray(value.verificationMethod) || value.verificationMethod.length !== 1 || !object(value.verificationMethod[0])) fail('assertion_method_count');
  const method = value.verificationMethod[0];
  exact(method, ['controller', 'id', 'publicKeyJwk', 'type'], 'assertion_method_shape');
  if (method.controller !== did || method.type !== 'JsonWebKey') fail('assertion_method_shape');
  if (!object(method.publicKeyJwk)) fail('assertion_key_encoding');
  const jwk = method.publicKeyJwk;
  exact(jwk, ['crv', 'kty', 'x'], 'assertion_key_encoding');
  if (jwk.crv !== 'Ed25519' || jwk.kty !== 'OKP' || typeof jwk.x !== 'string') fail('assertion_key_encoding');
  const publicKeyBytes = decodeEd25519JwkX(jwk.x);
  const methodId = `${did}#${await assertionJwkThumbprint(jwk.x)}`;
  if (method.id !== methodId || !singleton(value.assertionMethod) || value.assertionMethod[0] !== methodId) fail('assertion_reference');
  return { publicKeyBytes, publicKeyX: jwk.x, updateKeyHash: await updateKeyHash(encodeEd25519Multikey(publicKeyBytes)),
    state: { '@context': [WEBVH_CONTEXT], id: did, verificationMethod: [{ id: methodId, type: 'JsonWebKey', controller: did,
      publicKeyJwk: { crv: 'Ed25519', kty: 'OKP', x: jwk.x } }], assertionMethod: [methodId] } };
}

async function verifyProof(entry: Record<string, unknown>, authorizationKey: string, publicKey: Uint8Array, previousUpdateKey: string, versionTime: string): Promise<void> {
  if (!Array.isArray(entry.proof) || entry.proof.length !== 1 || !object(entry.proof[0])) fail('proof_count');
  const proof = entry.proof[0];
  const required = ['created', 'cryptosuite', 'proofPurpose', 'proofValue', 'type', 'verificationMethod'];
  if (required.some(key => !Object.hasOwn(proof, key))) fail('proof_members');
  if (proof.type !== 'DataIntegrityProof') fail('proof_type');
  if (proof.cryptosuite !== 'eddsa-jcs-2022') fail('proof_cryptosuite');
  if (proof.proofPurpose !== 'assertionMethod') fail('proof_purpose');
  if (proof.created !== versionTime) fail('proof_created');
  const method = `did:key:${authorizationKey}#${authorizationKey}`;
  if (typeof proof.verificationMethod !== 'string') fail('proof_unauthorized');
  if (proof.verificationMethod !== method) fail(previousUpdateKey !== '' && proof.verificationMethod === `did:key:${previousUpdateKey}#${previousUpdateKey}` ? 'proof_previous_key' : 'proof_unauthorized');
  if (typeof proof.proofValue !== 'string') fail('proof_value_encoding');
  const signature = decodeProofValue(proof.proofValue);
  if (!sameKeys(proof, required)) fail('feature_unsupported', 'unsupported');
  try {
    const unsecured = { ...entry }; delete unsecured.proof;
    const config = { ...proof }; delete config.proofValue;
    const configHash = await proofDigest(encoder.encode(canonicalize(config)));
    const entryHash = await proofDigest(encoder.encode(canonicalize(unsecured)));
    const hashData = Uint8Array.from((configHash + entryHash).match(/../g)!, pair => Number.parseInt(pair, 16));
    if (!await verifyEd25519(signature, hashData, publicKey)) fail('proof_signature');
  } catch (error) {
    // Browser capability failures are not evidence damage and must remain so.
    if (error instanceof VerifierError && error.kind === 'unsupported') throw error;
    if (error instanceof WebvhError && error.code === 'proof_signature') throw error;
    fail('proof_verification');
  }
}

/** Resolve only a fully authenticated history; failures never expose partial versions. */
export async function verifyWebvh(expectedDid: string, rawJsonl: Uint8Array, callerAsOfUtc: string): Promise<WebvhResult> {
  let entryCount = 0;
  try {
    const scid = parseExpectedDid(expectedDid);
    if (!isWebvhUtcSecond(callerAsOfUtc)) return failure('malformed', 'as_of_invalid');
    const lines = splitJsonl(new Uint8Array(rawJsonl));
    entryCount = lines.length;
    const entries: Record<string, unknown>[] = [];
    for (const line of lines) {
      const entry = decodeNumberFree(line);
      if (!object(entry)) return failure('invalid', 'entry_shape', entryCount);
      if (!equalBytes(line, encoder.encode(canonicalize(entry)))) return failure('invalid', 'noncanonical_json', entryCount);
      entries.push(entry);
    }
    const versions: WebvhVersion[] = [];
    let previousId = '', previousTime = '', previousUpdateKey = '', previousSuccessorHash = '';
    const seenUpdateKeys = new Set<string>(), seenUpdateHashes = new Set<string>();
    const seenSuccessorHashes = new Set<string>(), seenAssertionHashes = new Set<string>();
    for (const [offset, entry] of entries.entries()) {
      const number = offset + 1;
      exact(entry, ['parameters', 'proof', 'state', 'versionId', 'versionTime'], 'entry_members');
      const versionId = requiredString(entry, 'versionId', 'version_id');
      const match = new RegExp(`^${number}-([1-9A-HJ-NP-Za-km-z]{46})$`).exec(versionId);
      if (!match || match[0] !== versionId) fail('version_id');
      decodeSha256Multihash(match[1], 'entry_hash_encoding');
      const versionTime = requiredString(entry, 'versionTime', 'version_time');
      if (!isWebvhUtcSecond(versionTime)) fail('version_time');
      if (previousTime !== '' && versionTime <= previousTime) fail('version_time_order');
      if (versionTime > callerAsOfUtc) fail('version_time_future');
      if (!object(entry.parameters)) fail('parameters_shape');
      const parameters = entry.parameters;
      const allowed = number === 1 ? ['method', 'nextKeyHashes', 'portable', 'scid', 'updateKeys'] : ['nextKeyHashes', 'updateKeys'];
      if (Object.keys(parameters).some(key => !allowed.includes(key))) fail('feature_unsupported', 'unsupported');
      if (number === 1) {
        if (!Object.hasOwn(parameters, 'method')) fail('method_missing');
        if (typeof parameters.method !== 'string') fail('method_shape');
        if (parameters.method !== WEBVH_METHOD) fail('method_unsupported', 'unsupported');
        if (typeof parameters.scid !== 'string') fail('scid_missing');
        decodeSha256Multihash(parameters.scid, 'scid_encoding');
        if (parameters.scid !== scid) fail('scid_mismatch');
        if (!Object.hasOwn(parameters, 'portable')) fail('portable_missing');
        if (parameters.portable !== true) fail('portable_required');
      }
      if (!Object.hasOwn(parameters, 'updateKeys')) fail('update_key_missing');
      if (!singleton(parameters.updateKeys)) fail('update_key_count');
      const currentUpdateKey = parameters.updateKeys[0];
      const currentUpdateBytes = decodeEd25519Multikey(currentUpdateKey);
      const currentUpdateHash = await updateKeyHash(currentUpdateKey);
      if (!Object.hasOwn(parameters, 'nextKeyHashes')) fail('next_key_hashes_missing');
      if (!singleton(parameters.nextKeyHashes)) fail('next_key_hash_count');
      const currentSuccessorHash = parameters.nextKeyHashes[0];
      decodeSha256Multihash(currentSuccessorHash, 'next_key_hash_encoding');
      const assertion = await validateState(entry.state, expectedDid);
      if (equalBytes(currentUpdateBytes, assertion.publicKeyBytes) || currentSuccessorHash === assertion.updateKeyHash
        || seenSuccessorHashes.has(assertion.updateKeyHash) || seenUpdateHashes.has(assertion.updateKeyHash)) fail('key_role_collision');
      if (number === 1) {
        if (currentUpdateHash === currentSuccessorHash) fail('pre_rotation_successor_collision');
      } else {
        if (previousUpdateKey === currentUpdateKey) fail('pre_rotation_retain_key');
        if (previousSuccessorHash !== currentUpdateHash) fail('pre_rotation_current_uncommitted');
        if (seenUpdateKeys.has(currentUpdateKey)) fail('pre_rotation_current_reused');
        if (currentUpdateHash === currentSuccessorHash || await updateKeyHash(previousUpdateKey) === currentSuccessorHash) fail('pre_rotation_successor_collision');
        if (seenSuccessorHashes.has(currentSuccessorHash) || seenAssertionHashes.has(currentSuccessorHash) || seenUpdateHashes.has(currentSuccessorHash)) fail('pre_rotation_successor_reused');
      }
      if (number === 1) {
        const scidEntry = { ...entry }; delete scidEntry.proof; scidEntry.versionId = '{SCID}';
        const calculated = await sha256Multihash(canonicalize(replaceStrings(scidEntry, scid, '{SCID}')));
        if (scid !== calculated) fail('scid_hash_mismatch');
      }
      const hashEntry = { ...entry }; delete hashEntry.proof; hashEntry.versionId = number === 1 ? scid : previousId;
      if (match[1] !== await sha256Multihash(canonicalize(hashEntry))) fail('entry_hash_mismatch');
      await verifyProof(entry, currentUpdateKey, currentUpdateBytes, previousUpdateKey, versionTime);
      versions.push({ versionId, versionTime, state: assertion.state, currentUpdateKey, committedSuccessorHash: currentSuccessorHash, assertionKey: assertion.publicKeyX });
      seenUpdateKeys.add(currentUpdateKey); seenUpdateHashes.add(currentUpdateHash); seenSuccessorHashes.add(currentSuccessorHash); seenAssertionHashes.add(assertion.updateKeyHash);
      previousId = versionId; previousTime = versionTime; previousUpdateKey = currentUpdateKey; previousSuccessorHash = currentSuccessorHash;
    }
    return { status: 'valid', code: 'ok', entryCount: versions.length, versionIds: versions.map(version => version.versionId), resolvedStates: versions.map(version => version.state), versions };
  } catch (error) {
    if (error instanceof VerifierError && error.kind === 'unsupported') throw error;
    if (error instanceof WebvhError) return failure(error.status, error.code, entryCount);
    return failure('malformed', 'processing_failure', entryCount);
  }
}
