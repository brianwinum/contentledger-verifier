// SPDX-License-Identifier: GPL-2.0-or-later
// Supported transparency relationships from Portable Verifier 3.0.0. Callers
// supply already authenticated checkpoints/receipts and validated manifests.
import { decodeCanonicalObject, encodeCanonical, exactKeys } from './canonical';
import type { CheckpointDocument } from './checkpoint-document';
import { VerifierError } from './errors';
import { identityInstant, type VerifiedIdentityReceipt } from './identity';
import { isManifestDate, isManifestHash as hash, type VerifiedManifest } from './manifest';
import { inclusionPath, inclusionSides, MAX_LEAVES, MAX_PROOF_HASHES, merkleRoot, nodeHash, prefixRoots, validateLeaf, verifyConsistency } from './merkle';

export const MAX_INCLUSION_BYTES = 65536;
export const MAX_LEAF_INVENTORY_BYTES = 16777216;
export interface VerifiedCheckpoint { sha256: string; document: CheckpointDocument; receipt: VerifiedIdentityReceipt }
export interface TransparencyLeaf { hash: string; uuid: string; manifest: string }
export interface LeafInventory { leaves: TransparencyLeaf[]; hashes: string[]; records: Record<string, number> }
export type CheckpointMap = Map<string, VerifiedCheckpoint>;
export type ManifestMap = Map<string, Omit<VerifiedManifest, 'document'>>;
const encoder = new TextEncoder();
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function fail(code: string, message: string): never { throw new VerifierError(code, message); }
function integer(value: unknown, min: number, max: number): value is number { return Number.isInteger(value) && (value as number) >= min && (value as number) <= max; }

export async function verifyCheckpointChain(checkpoints: CheckpointMap, targetHash: string, leafHashes: readonly string[] = []): Promise<string[]> {
  if (!checkpoints.size || checkpoints.size > MAX_LEAVES || !hash(targetHash) || !checkpoints.has(targetHash)) fail('checkpoint_chain_target', 'The checkpoint set has no valid selected target.');
  for (const [digest, checkpoint] of checkpoints) {
    if (!hash(digest) || !checkpoint || digest !== checkpoint.sha256 || !object(checkpoint.document) || !object(checkpoint.receipt)) fail('checkpoint_map', 'The checkpoint map has an invalid digest key or verified document.');
  }
  const reverse: string[] = [];
  const seen = new Set<string>();
  let currentHash = targetHash;
  while (true) {
    if (seen.has(currentHash)) fail('checkpoint_chain_cycle', 'The checkpoint predecessor graph contains a cycle.');
    seen.add(currentHash); reverse.push(currentHash);
    const predecessor = checkpoints.get(currentHash)!.document.predecessor;
    if (predecessor === null) break;
    currentHash = predecessor.checkpointSha256;
    if (!checkpoints.has(currentHash)) fail('checkpoint_predecessor_missing', 'The bundle lacks a checkpoint predecessor required for consistency verification.');
  }
  if (seen.size !== checkpoints.size) fail('checkpoint_chain_extras', 'The bundle contains an unrelated, branched, or successor checkpoint outside the selected chain.');
  const order = reverse.reverse();
  const roots = leafHashes.length ? await prefixRoots(leafHashes, order.map(digest => checkpoints.get(digest)!.document.tree.leafCount)) : new Map<number, string>();
  let previous: VerifiedCheckpoint | undefined;
  for (const [position, digest] of order.entries()) {
    const checkpoint = checkpoints.get(digest)!;
    const { document } = checkpoint;
    const tree = document.tree;
    if (leafHashes.length && (tree.leafCount > leafHashes.length || !roots.has(tree.leafCount) || tree.rootHash !== roots.get(tree.leafCount))) fail('checkpoint_leaf_root', 'A checkpoint root does not match its exact bundled leaf prefix.');
    if (!previous) {
      if (position !== 0 || document.predecessor !== null) fail('checkpoint_genesis', 'The selected checkpoint chain does not begin with exactly one genesis checkpoint.');
      previous = checkpoint;
      continue;
    }
    const declared = document.predecessor;
    const oldTree = previous.document.tree;
    if (declared === null || previous.sha256 !== declared.checkpointSha256 || oldTree.leafCount !== declared.leafCount || oldTree.rootHash !== declared.rootHash
      || !await verifyConsistency(oldTree.leafCount, oldTree.rootHash, tree.leafCount, tree.rootHash, declared.consistencyProof)) fail('checkpoint_consistency', 'A checkpoint predecessor declaration or consistency proof is invalid.');
    for (const boundary of ['manifestSealedAt', 'identityEventRecordedAt'] as const) {
      const oldTime = identityInstant(previous.document.recordedThrough[boundary]);
      const newTime = identityInstant(document.recordedThrough[boundary]);
      if (oldTime === null || newTime === null || newTime < oldTime) fail('checkpoint_boundary_rollback', 'Checkpoint recorded-through boundaries must be monotonic.');
    }
    verifyHistoryExtension(previous.receipt, checkpoint.receipt);
    previous = checkpoint;
  }
  if (leafHashes.length && leafHashes.length !== checkpoints.get(targetHash)!.document.tree.leafCount) fail('checkpoint_leaf_inventory_count', 'The target leaf inventory is not the exact selected checkpoint prefix.');
  return order;
}

export async function verifyInclusion(bytes: Uint8Array, expectedCheckpoint: string, expectedUuid: string, checkpoints: CheckpointMap,
  manifests: ManifestMap, leafHashes: readonly string[] = []): Promise<Record<string, unknown>> {
  if (!bytes.length || bytes.length > MAX_INCLUSION_BYTES) fail('inclusion_size', 'An inclusion proof is empty or exceeds 64 KiB.');
  const proof = decodeCanonicalObject(new Uint8Array(bytes), 32);
  if (!exactKeys(proof, ['checkpointSha256', 'format', 'leaf', 'leafHash', 'leafIndex', 'path', 'tree', 'version'])
    || proof.format !== 'WP ContentLedger Transparency Inclusion Proof' || proof.version !== '1.0' || !hash(proof.checkpointSha256) || expectedCheckpoint !== proof.checkpointSha256
    || !hash(proof.leafHash) || !Number.isInteger(proof.leafIndex) || !Array.isArray(proof.path) || proof.path.length > MAX_PROOF_HASHES) fail('inclusion_profile', 'An inclusion proof has an unsupported exact profile.');
  const leaf = await validateLeaf(proof.leaf);
  if (leaf.uuid !== expectedUuid || proof.leafHash !== leaf.hash) fail('inclusion_leaf', 'An inclusion proof leaf does not match its path record or canonical leaf hash.');
  const manifest = manifests.get(expectedUuid);
  if (!manifest || manifest.sha256 !== leaf.manifest) fail('inclusion_manifest', 'An inclusion proof leaf does not match its exact bundled manifest.');
  const tree = proof.tree;
  if (!object(tree) || !exactKeys(tree, ['algorithm', 'leafCount', 'rootHash']) || tree.algorithm !== 'rfc6962-sha256-v1'
    || !integer(tree.leafCount, 1, MAX_LEAVES) || !integer(proof.leafIndex, 0, tree.leafCount - 1) || !hash(tree.rootHash)) fail('inclusion_tree', 'An inclusion proof tree declaration is invalid.');
  let current = proof.leafHash;
  const sides: string[] = [];
  for (const step of proof.path) {
    if (!object(step) || !exactKeys(step, ['hash', 'side']) || !hash(step.hash) || step.side !== 'left' && step.side !== 'right') fail('inclusion_path', 'An inclusion proof contains an invalid Merkle path step.');
    sides.push(step.side);
    current = step.side === 'left' ? await nodeHash(step.hash, current) : await nodeHash(current, step.hash);
  }
  const expectedSides = inclusionSides(proof.leafIndex, 0, tree.leafCount);
  if (sides.length !== expectedSides.length || sides.some((side, index) => side !== expectedSides[index])) fail('inclusion_topology', 'An inclusion proof path does not match its declared leaf index and tree size.');
  if (leafHashes.length) {
    if (leafHashes.length !== tree.leafCount || leafHashes[proof.leafIndex] !== proof.leafHash) fail('inclusion_inventory_leaf', 'An inclusion proof leaf does not occupy its declared position in the bundled leaf inventory.');
    const expectedPath = await inclusionPath(proof.leafIndex, 0, tree.leafCount, leafHashes);
    if (encodeCanonical(expectedPath) !== encodeCanonical(proof.path)) fail('inclusion_inventory_path', 'An inclusion proof is not the exact path derived from the bundled leaf inventory.');
  }
  const checkpoint = checkpoints.get(expectedCheckpoint);
  if (tree.rootHash !== current || !checkpoint || checkpoint.document.tree.leafCount !== tree.leafCount || checkpoint.document.tree.rootHash !== tree.rootHash) fail('inclusion_checkpoint_binding', 'An inclusion proof is not bound to its exact signed checkpoint root and size.');
  return proof;
}

export async function verifyLeafInventory(bytes: Uint8Array, expectedCheckpoint: string, checkpoints: CheckpointMap, manifests: ManifestMap): Promise<LeafInventory> {
  if (!bytes.length || bytes.length > MAX_LEAF_INVENTORY_BYTES) fail('leaf_inventory_size', 'A leaf inventory is empty or exceeds 16 MiB.');
  const document = decodeCanonicalObject(new Uint8Array(bytes), 32);
  if (!exactKeys(document, ['checkpointSha256', 'format', 'leaves', 'version']) || document.format !== 'WP ContentLedger Transparency Leaf Inventory' || document.version !== '1.0'
    || !hash(document.checkpointSha256) || expectedCheckpoint !== document.checkpointSha256 || !Array.isArray(document.leaves) || !document.leaves.length || document.leaves.length > MAX_LEAVES) fail('leaf_inventory_profile', 'A leaf inventory has an unsupported exact profile.');
  const checkpoint = checkpoints.get(expectedCheckpoint);
  const items = document.leaves;
  if (!checkpoint || items.length !== checkpoint.document.tree.leafCount) fail('leaf_inventory_checkpoint', 'A leaf inventory is not the exact prefix for its selected checkpoint.');
  const leaves: TransparencyLeaf[] = [], hashes: string[] = [];
  const records: Record<string, number> = Object.create(null);
  for (let index = 0; index < items.length; index++) {
    const item = items[index]; items[index] = null;
    if (!object(item) || !exactKeys(item, ['leaf', 'leafHash', 'leafIndex']) || !Number.isInteger(item.leafIndex) || item.leafIndex !== index || !hash(item.leafHash)) fail('leaf_inventory_item', 'A leaf inventory contains a malformed or non-contiguous item.');
    const leaf = await validateLeaf(item.leaf);
    if (item.leafHash !== leaf.hash || Object.hasOwn(records, leaf.uuid)) fail('leaf_inventory_binding', 'A leaf inventory contains a duplicate record or an invalid canonical leaf hash.');
    const manifest = manifests.get(leaf.uuid);
    if (!manifest || manifest.sha256 !== leaf.manifest) fail('leaf_inventory_manifest', 'A leaf inventory does not bind every leaf to its exact bundled manifest.');
    leaves.push({ hash: leaf.hash, uuid: leaf.uuid, manifest: leaf.manifest }); hashes.push(leaf.hash); records[leaf.uuid] = index;
  }
  if (checkpoint.document.tree.rootHash !== await merkleRoot(hashes)) fail('leaf_inventory_root', 'The leaf inventory does not reproduce the signed checkpoint root.');
  return { leaves, hashes, records };
}

export function verifyAppendOrder(order: readonly string[], checkpoints: CheckpointMap, leaves: readonly TransparencyLeaf[]): void {
  let priorCount = 0;
  for (const digest of order) {
    const count = checkpoints.get(digest)!.document.tree.leafCount;
    if (count < priorCount || count > leaves.length) fail('leaf_append_boundary', 'Checkpoint leaf counts do not delimit one monotonic bundled prefix.');
    let previousUuid: string | null = null;
    for (let index = priorCount; index < count; index++) {
      const uuid = leaves[index].uuid;
      if (previousUuid !== null && previousUuid >= uuid) fail('leaf_append_order', 'Each genesis or appended checkpoint delta must be strictly sorted by record UUID.');
      previousUuid = uuid;
    }
    priorCount = count;
  }
}

/** PHP formats U.u first, then casts to double: negative seconds retain that
 * sign for the decimal fraction. Timelib truncates fractional microseconds. */
function manifestInstant(value: string): number | null {
  if (!isManifestDate(value)) return null;
  const whole = identityInstant(`${value.slice(0, 19)}Z`);
  if (whole === null) return null;
  if (value[19] !== '.') return whole;
  const fraction = value.slice(20, value.endsWith('Z') ? -1 : -6);
  const micros = Math.trunc(Number(fraction) * Math.pow(10, 6 - fraction.length));
  if (!Number.isFinite(micros)) return null;
  const seconds = whole + Math.floor(micros / 1000000);
  return Number(`${seconds}.${String(micros % 1000000).padStart(6, '0')}`);
}

export function verifyManifestBoundaries(order: readonly string[], checkpoints: CheckpointMap, leaves: readonly TransparencyLeaf[], manifests: ManifestMap): void {
  let cursor = 0, latest: string | null = null, latestInstant: number | null = null, latestUuid = '';
  for (const digest of order) {
    const count = checkpoints.get(digest)!.document.tree.leafCount;
    if (count < cursor || count > leaves.length) fail('checkpoint_manifest_boundary', 'Checkpoint manifest boundaries do not describe one monotonic leaf prefix.');
    for (let index = cursor; index < count; index++) {
      const uuid = leaves[index].uuid;
      const sealed = manifests.get(uuid)?.sealedAt ?? '';
      const instant = manifestInstant(sealed);
      if (instant === null) fail('checkpoint_manifest_boundary', 'A checkpoint leaf has no valid bundled manifest sealing time.');
      if (latestInstant === null || instant > latestInstant || instant === latestInstant && uuid > latestUuid) { latest = sealed; latestInstant = instant; latestUuid = uuid; }
    }
    if (latest === null || latest !== checkpoints.get(digest)!.document.recordedThrough.manifestSealedAt) fail('checkpoint_manifest_boundary', 'A checkpoint manifest boundary is not the exact maximum sealing time in its leaf prefix.');
    cursor = count;
  }
}

export function verifyHistoryExtension(prior: VerifiedIdentityReceipt, successor: VerifiedIdentityReceipt): void {
  const priorLog = typeof prior.log_json === 'string' ? encoder.encode(prior.log_json) : new Uint8Array();
  const successorLog = typeof successor.log_json === 'string' ? encoder.encode(successor.log_json) : new Uint8Array();
  const priorIdentity = prior.identity, successorIdentity = successor.identity;
  if (!priorLog.length || !object(priorIdentity) || !object(successorIdentity) || priorIdentity.did !== successorIdentity.did || priorIdentity.siteUrl !== successorIdentity.siteUrl
    || priorIdentity.publicUrl !== successorIdentity.publicUrl || priorLog.length > successorLog.length || priorLog.some((byte, index) => byte !== successorLog[index])) fail('checkpoint_identity_fork', 'A successor checkpoint Website Identity log does not extend its predecessor exact JSONL prefix.');
}
