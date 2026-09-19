// SPDX-License-Identifier: GPL-2.0-or-later
// Carried transparency only, not complete scope or external witnessing.
import { decodeCanonicalObject, exactKeys } from './canonical';
import { VerifierError } from './errors';
import type { BundleGraph, LeafInventoryReference } from './graph';
import { isManifestHash as hash, type VerifiedManifest } from './manifest';
import { inclusionSides, nodeHash, validateLeaf } from './merkle';
import { MAX_JSON_BYTES } from './profile';
import type { BundleScope } from './scope';
import { verifyAppendOrder, verifyCheckpointChain, verifyInclusion, verifyLeafInventory, verifyManifestBoundaries, type LeafInventory, type VerifiedCheckpoint } from './transparency';
import type { StrictZip } from './zip';

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
const equalList = (left: readonly string[], right: readonly string[]): boolean => left.length === right.length && left.every((value, index) => value === right[index]);

/** Every carried leaf inventory must follow the verified chain and extend its predecessor prefix. */
export function verifyLeafInventorySeries(refs: readonly LeafInventoryReference[], inventories: ReadonlyMap<string, LeafInventory>, order: readonly string[]): void {
  const positions = new Map(order.map((hash, index) => [hash, index]));
  let last = -1;
  let prior: readonly string[] = [];
  for (const ref of refs) {
    const position = positions.get(ref.checkpointSha256);
    if (position === undefined || position <= last) throw new VerifierError('leaf_inventory_order', 'Leaf inventories are not in checkpoint-chain order.');
    const current = inventories.get(ref.checkpointSha256)?.hashes;
    if (!current) throw new VerifierError('leaf_inventory_order', 'A declared leaf inventory has not been checked.');
    if (!equalList(prior, current.slice(0, prior.length))) throw new VerifierError('leaf_inventory_fork', 'A later leaf inventory does not exactly extend the prior immutable prefix.');
    prior = current;
    last = position;
  }
}

/** PHP's unsupported-manifest path: structural math only, never checkpoint authority. */
export async function inspectInclusionUnanchored(bytes: Uint8Array, expectedCheckpoint: string, expectedUuid: string, manifestHashes: ReadonlyMap<string, string>): Promise<void> {
  const proof = decodeCanonicalObject(bytes, 32);
  if (!exactKeys(proof, ['checkpointSha256', 'format', 'leaf', 'leafHash', 'leafIndex', 'path', 'tree', 'version'])
    || proof.format !== 'WP ContentLedger Transparency Inclusion Proof' || proof.version !== '1.0'
    || proof.checkpointSha256 !== expectedCheckpoint || !hash(proof.leafHash) || !Number.isInteger(proof.leafIndex)
    || !Array.isArray(proof.path) || proof.path.length > 32) throw new VerifierError('inclusion_profile', 'An inclusion proof has an unsupported exact profile.');
  const leaf = await validateLeaf(proof.leaf);
  if (leaf.uuid !== expectedUuid || proof.leafHash !== leaf.hash || manifestHashes.get(expectedUuid) !== leaf.manifest) throw new VerifierError('inclusion_leaf', 'An inclusion proof leaf does not match its record graph and manifest digest.');
  const tree = proof.tree;
  if (!object(tree) || !exactKeys(tree, ['algorithm', 'leafCount', 'rootHash']) || tree.algorithm !== 'rfc6962-sha256-v1'
    || !Number.isInteger(tree.leafCount) || (tree.leafCount as number) < 1 || (tree.leafCount as number) > 10000
    || (proof.leafIndex as number) < 0 || (proof.leafIndex as number) >= (tree.leafCount as number) || !hash(tree.rootHash)) throw new VerifierError('inclusion_tree', 'An inclusion proof tree declaration is invalid.');
  let current = proof.leafHash;
  const sides: string[] = [];
  for (const step of proof.path) {
    if (!object(step) || !exactKeys(step, ['hash', 'side']) || !hash(step.hash) || step.side !== 'left' && step.side !== 'right') throw new VerifierError('inclusion_path', 'An inclusion proof contains an invalid Merkle path step.');
    sides.push(step.side);
    current = step.side === 'left' ? await nodeHash(step.hash, current) : await nodeHash(current, step.hash);
  }
  if (!equalList(sides, inclusionSides(proof.leafIndex as number, 0, tree.leafCount as number)) || current !== tree.rootHash) throw new VerifierError('inclusion_topology', 'An inclusion proof path does not match its declared leaf index, tree size, and root.');
}

export interface TransparencyCounts { checkpoints: number; leafInventories: number; inclusionProofs: number; unanchoredProofs: number }
export interface VerifiedTransparencyGraph {
  counts: TransparencyCounts;
  targetCheckpoint: string | null;
  inventories: ReadonlyMap<string, LeafInventory>;
}

export async function verifyTransparencyGraph(zip: StrictZip, graph: BundleGraph, scope: BundleScope, checkpoints: Map<string, VerifiedCheckpoint>, manifests: readonly Omit<VerifiedManifest, 'document'>[]): Promise<VerifiedTransparencyGraph> {
  const manifestMap = new Map(manifests.map(manifest => [manifest.uuid, manifest]));
  const inventories = new Map<string, LeafInventory>();
  for (const ref of graph.leafInventories) {
    inventories.set(ref.checkpointSha256, await verifyLeafInventory(zip.read(ref.path, MAX_JSON_BYTES), ref.checkpointSha256, checkpoints, manifestMap));
  }
  const target = scope.kind === 'checkpoint' || scope.kind === 'site' ? scope.checkpointSha256 : graph.checkpoints.at(-1)?.checkpointSha256 ?? null;
  let order: string[] = [];
  if (target !== null) {
    const inventory = inventories.get(target);
    order = await verifyCheckpointChain(checkpoints, target, inventory?.hashes ?? []);
    if (!equalList(order, graph.checkpoints.map(item => item.checkpointSha256))) throw new VerifierError('checkpoint_graph_order', 'Bundle checkpoints are not listed in exact genesis-to-target order.');
    if (inventory) {
      verifyAppendOrder(order, checkpoints, inventory.leaves);
      verifyManifestBoundaries(order, checkpoints, inventory.leaves, manifestMap);
    }
  }
  verifyLeafInventorySeries(graph.leafInventories, inventories, order);
  const counts: TransparencyCounts = { checkpoints: checkpoints.size, leafInventories: inventories.size, inclusionProofs: 0, unanchoredProofs: 0 };
  const manifestHashes = new Map(graph.records.map(record => [record.entryId.slice(9), record.manifestSha256]));
  for (const record of graph.records) {
    const uuid = record.entryId.slice(9);
    for (const path of record.inclusionProofPaths) {
      const checkpointHash = path.slice(path.lastIndexOf('/') + 1, -5);
      const bytes = zip.read(path, 65536);
      if (!manifestMap.has(uuid)) {
        await inspectInclusionUnanchored(bytes, checkpointHash, uuid, manifestHashes);
        counts.unanchoredProofs++;
      } else {
        await verifyInclusion(bytes, checkpointHash, uuid, checkpoints, manifestMap, inventories.get(checkpointHash)?.hashes ?? []);
        counts.inclusionProofs++;
      }
    }
  }
  // Checked leaf metadata stays inside the worker for scope closure, not reports.
  return { counts, targetCheckpoint: target, inventories };
}
