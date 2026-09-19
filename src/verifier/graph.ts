// SPDX-License-Identifier: GPL-2.0-or-later
// Declaration and byte-reference checks from Portable Verifier 3.0.0.
// These checks do not authenticate any signature, identity, or transparency claim.
import { exactKeys } from './canonical';
import { sha256 } from './bytes';
import { VerifierError } from './errors';
import { isManifestDate as rfc3339Utc } from './manifest';
import { PROFILE_FILES, roleSizeLimit, validateBundleTop } from './profile';
import { StrictZip } from './zip';

export interface RecordReference {
  archiveReferencePath: string | null;
  entryId: string;
  inclusionProofPaths: string[];
  manifestPath: string;
  manifestSha256: string;
  signaturePath: string | null;
  timestampPaths: string[];
}

export interface CheckpointReference {
  archiveReferencePath: string | null;
  checkpointSha256: string;
  documentPath: string;
  identityReceiptSha256: string;
  jwsPath: string;
  predecessorCheckpointSha256: string | null;
  timestampPaths: string[];
}

export interface IdentityReference {
  archiveReferencePath: string | null;
  assertionMethod: string;
  did: string;
  logPath: string;
  logSha256: string;
  receiptPath: string;
  receiptSha256: string;
  timestampPaths: string[];
  versionId: string;
  versionTime: string;
}

export interface LeafInventoryReference { checkpointSha256: string; path: string }
export interface BundleGraph {
  records: RecordReference[];
  checkpoints: CheckpointReference[];
  identities: IdentityReference[];
  leafInventories: LeafInventoryReference[];
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function hash(value: unknown): value is string {
  return typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value);
}
function uuidUrn(value: unknown): value is string {
  return typeof value === 'string' && value.length === 45 && /^urn:uuid:[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
}
const encoder = new TextEncoder();
function pathOrNull(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && value.length > 0 && encoder.encode(value).length <= 240);
}
function byteCompare(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}
function pathList(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length > 10000) return false;
  let previous: Uint8Array | null = null;
  for (const path of value) {
    if (typeof path !== 'string' || path.length === 0) return false;
    const bytes = encoder.encode(path);
    if (bytes.length > 240 || (previous !== null && byteCompare(previous, bytes) >= 0)) return false;
    previous = bytes;
  }
  return true;
}
function pathsMatch(paths: string[], namespace: string, suffix: 'ots' | 'json'): void {
  // The namespace is constructed only from already validated ASCII UUIDs/hashes.
  const pattern = new RegExp(`^${namespace}/[a-f0-9]{64}\\.${suffix}$`);
  for (const path of paths) {
    if (pattern.exec(path)?.[0] !== path) throw new VerifierError('bundle_artifact_path', 'A supporting-artifact path is outside its exact subject namespace.');
  }
}

function recordItems(items: unknown[]): RecordReference[] {
  let previous: string | null = null;
  const result: RecordReference[] = [];
  for (const item of items) {
    if (!object(item) || !exactKeys(item, ['archiveReferencePath', 'entryId', 'inclusionProofPaths', 'manifestPath', 'manifestSha256', 'signaturePath', 'timestampPaths']) || !uuidUrn(item.entryId) || !hash(item.manifestSha256) || !pathOrNull(item.archiveReferencePath) || !pathOrNull(item.signaturePath) || !pathList(item.inclusionProofPaths) || !pathList(item.timestampPaths)) throw new VerifierError('bundle_record_item', 'A record graph item has an invalid exact shape.');
    const namespace = `records/${item.entryId.slice(9)}`;
    if (item.manifestPath !== `${namespace}/manifest.json` || (item.signaturePath !== null && item.signaturePath !== `${namespace}/signature.jws`) || (item.archiveReferencePath !== null && item.archiveReferencePath !== `${namespace}/archive-references.json`)) throw new VerifierError('bundle_record_path', 'A record graph path does not match its exact entryId namespace.');
    pathsMatch(item.timestampPaths, `${namespace}/timestamps`, 'ots');
    pathsMatch(item.inclusionProofPaths, `${namespace}/inclusion`, 'json');
    if (previous !== null && previous >= item.entryId) throw new VerifierError('bundle_record_order', 'Record graph items are not strictly ordered by unique entryId.');
    previous = item.entryId;
    result.push(item as unknown as RecordReference);
  }
  return result;
}

function checkpointItems(items: unknown[]): CheckpointReference[] {
  const seen = new Set<string>();
  const result: CheckpointReference[] = [];
  for (const item of items) {
    if (!object(item) || !exactKeys(item, ['archiveReferencePath', 'checkpointSha256', 'documentPath', 'identityReceiptSha256', 'jwsPath', 'predecessorCheckpointSha256', 'timestampPaths']) || !hash(item.checkpointSha256) || !hash(item.identityReceiptSha256) || !(item.predecessorCheckpointSha256 === null || hash(item.predecessorCheckpointSha256)) || !pathOrNull(item.archiveReferencePath) || !pathList(item.timestampPaths) || seen.has(item.checkpointSha256)) throw new VerifierError('bundle_checkpoint_item', 'A checkpoint graph item has an invalid exact shape or duplicate digest.');
    const namespace = `transparency/checkpoints/${item.checkpointSha256}`;
    if (item.documentPath !== `${namespace}/checkpoint.json` || item.jwsPath !== `${namespace}/checkpoint.jws` || (item.archiveReferencePath !== null && item.archiveReferencePath !== `${namespace}/archive-references.json`)) throw new VerifierError('bundle_checkpoint_path', 'A checkpoint graph path does not match its exact content-addressed namespace.');
    pathsMatch(item.timestampPaths, `${namespace}/timestamps`, 'ots');
    seen.add(item.checkpointSha256);
    result.push(item as unknown as CheckpointReference);
  }
  return result;
}

function identityItems(items: unknown[]): IdentityReference[] {
  let previous: string | null = null;
  const seen = new Set<string>();
  const result: IdentityReference[] = [];
  for (const item of items) {
    if (!object(item) || !exactKeys(item, ['archiveReferencePath', 'assertionMethod', 'did', 'logPath', 'logSha256', 'receiptPath', 'receiptSha256', 'timestampPaths', 'versionId', 'versionTime']) || !hash(item.logSha256) || !hash(item.receiptSha256) || typeof item.did !== 'string' || !item.did.startsWith('did:webvh:') || typeof item.assertionMethod !== 'string' || !item.assertionMethod.startsWith(`${item.did}#`) || typeof item.versionId !== 'string' || !rfc3339Utc(item.versionTime) || !pathOrNull(item.archiveReferencePath) || !pathList(item.timestampPaths) || seen.has(item.receiptSha256)) throw new VerifierError('bundle_identity_item', 'A Website Identity graph item has an invalid exact shape or duplicate receipt.');
    if (previous !== null && previous >= item.logSha256) throw new VerifierError('bundle_identity_order', 'Website Identity graph items are not ordered by log SHA-256.');
    const namespace = `identity/checkpoints/${item.receiptSha256}`;
    if (item.logPath !== `identity/logs/${item.logSha256}.jsonl` || item.receiptPath !== `${namespace}.json` || (item.archiveReferencePath !== null && item.archiveReferencePath !== `${namespace}/archive-references.json`)) throw new VerifierError('bundle_identity_path', 'A Website Identity graph path does not match its exact content-addressed namespace.');
    pathsMatch(item.timestampPaths, `${namespace}/timestamps`, 'ots');
    previous = item.logSha256;
    seen.add(item.receiptSha256);
    result.push(item as unknown as IdentityReference);
  }
  return result;
}

function leafInventoryItems(items: unknown[]): LeafInventoryReference[] {
  const seen = new Set<string>();
  const result: LeafInventoryReference[] = [];
  for (const item of items) {
    if (!object(item) || !exactKeys(item, ['checkpointSha256', 'path']) || !hash(item.checkpointSha256) || item.path !== `transparency/leaf-inventory/${item.checkpointSha256}.json` || seen.has(item.checkpointSha256)) throw new VerifierError('bundle_leaf_reference', 'A leaf-inventory graph reference is malformed, duplicated, or incorrectly addressed.');
    seen.add(item.checkpointSha256);
    result.push(item as unknown as LeafInventoryReference);
  }
  return result;
}

/** Shape, namespace, and declaration ordering only; scope semantics are separate. */
export function validateBundleGraph(bundle: Record<string, unknown>): BundleGraph {
  validateBundleTop(bundle);
  // Preserve the frozen verifier's declaration-check order.
  const identities = identityItems(bundle.identityLogs as unknown[]);
  const records = recordItems(bundle.records as unknown[]);
  const checkpoints = checkpointItems(bundle.checkpoints as unknown[]);
  const leafInventories = leafInventoryItems(bundle.leafInventories as unknown[]);
  return { records, checkpoints, identities, leafInventories };
}

/**
 * Every declared file must exist; every non-profile file must be declared.
 * Only manifest and identity graph digests are checked here. Checkpoint digests,
 * receipt fields, JWS, proofs, timestamps, and archive-reference contents still
 * require their own semantic/cryptographic verifiers.
 */
export async function verifyGraphReferences(zip: StrictZip, graph: BundleGraph): Promise<void> {
  const consumed = new Set(['bundle.json', 'inventory.json', 'inventory.sha256', ...Object.keys(PROFILE_FILES)]);
  const read = (path: string): Uint8Array => {
    const bytes = zip.read(path, roleSizeLimit(path));
    consumed.add(path);
    return bytes;
  };
  for (const item of graph.identities) {
    const log = read(item.logPath);
    const receipt = read(item.receiptPath);
    if (await sha256(log) !== item.logSha256 || await sha256(receipt) !== item.receiptSha256) throw new VerifierError('identity_graph_digest', 'An identity graph digest does not match its exact file bytes.');
  }
  for (const item of graph.records) {
    if (await sha256(read(item.manifestPath)) !== item.manifestSha256) throw new VerifierError('manifest_graph_digest', 'A record graph manifest digest does not match its exact file bytes.');
  }
  for (const item of graph.checkpoints) {
    read(item.documentPath);
    read(item.jwsPath);
  }
  for (const item of graph.leafInventories) read(item.path);
  for (const item of graph.records) {
    if (item.signaturePath !== null) read(item.signaturePath);
    for (const path of item.inclusionProofPaths) read(path);
  }
  for (const item of [...graph.records, ...graph.checkpoints, ...graph.identities]) {
    if (item.archiveReferencePath !== null) read(item.archiveReferencePath);
    for (const path of item.timestampPaths) read(path);
  }
  for (const path of zip.paths()) {
    if (!consumed.has(path)) throw new VerifierError('bundle_orphan_entry', 'The bundle contains an unreferenced or unsupported entry.');
  }
}
