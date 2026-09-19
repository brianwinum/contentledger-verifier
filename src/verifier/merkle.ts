// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded RFC6962 tree routines from frozen Transparency_Verifier.php.
import { sha256 } from './bytes';
import { encodeCanonical, exactKeys } from './canonical';
import { VerifierError } from './errors';
import { isManifestHash, isUuidUrn } from './manifest';

export const MAX_LEAVES = 10000;
export const MAX_PROOF_HASHES = 32;
export interface MerkleLeaf { hash: string; uuid: string; manifest: string }
export type MerkleSide = 'left' | 'right';
export interface MerklePathStep { hash: string; side: MerkleSide }
const encoder = new TextEncoder();

async function digest(bytes: Uint8Array): Promise<string> {
  try { return await sha256(bytes); }
  catch (error) {
    if (error instanceof VerifierError && error.kind === 'unsupported') throw error;
    throw new VerifierError('browser_crypto_failed', 'The browser could not complete the required local SHA-256 operation.', 'unsupported');
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function validateLeaf(leaf: unknown): Promise<MerkleLeaf> {
  if (!object(leaf) || !exactKeys(leaf, ['entryId', 'manifestDigest']) || !isUuidUrn(leaf.entryId)) {
    throw new VerifierError('leaf_profile', 'A transparency leaf has an invalid exact profile.');
  }
  const manifestDigest = leaf.manifestDigest;
  if (!object(manifestDigest) || !exactKeys(manifestDigest, ['algorithm', 'value'])
    || manifestDigest.algorithm !== 'sha-256' || !isManifestHash(manifestDigest.value)) {
    throw new VerifierError('leaf_digest', 'A transparency leaf has an invalid manifest digest.');
  }
  // Snapshot document bytes and returned fields before crossing an async edge.
  const bytes = encoder.encode('\0' + encodeCanonical(leaf));
  const uuid = leaf.entryId.slice(9);
  const manifest = manifestDigest.value;
  return { hash: await digest(bytes), uuid, manifest };
}

function hexBytes(hex: string): Uint8Array | null {
  // Match PHP hex2bin: even-length hexadecimal of either case, including empty.
  // Public tree/proof entry points separately require exact lower-case SHA-256.
  if (hex.length % 2 !== 0 || /^[0-9a-fA-F]*$/.exec(hex)?.[0] !== hex) return null;
  return Uint8Array.from(hex.match(/../g) ?? [], byte => Number.parseInt(byte, 16));
}

export async function nodeHash(left: string, right: string): Promise<string> {
  const leftBytes = hexBytes(left);
  const rightBytes = hexBytes(right);
  if (leftBytes === null || rightBytes === null) return '';
  const bytes = new Uint8Array(1 + leftBytes.length + rightBytes.length);
  bytes[0] = 1;
  bytes.set(leftBytes, 1);
  bytes.set(rightBytes, 1 + leftBytes.length);
  return digest(bytes);
}

function countError(): never {
  throw new VerifierError('leaf_inventory_count', 'A transparency leaf inventory is empty or exceeds 10,000 leaves.');
}

function snapshotHashes(hashes: readonly string[], allowEmpty = false): string[] {
  if (!Array.isArray(hashes) || (!allowEmpty && hashes.length === 0) || hashes.length > MAX_LEAVES) countError();
  const snapshot = Array.from(hashes);
  for (const hash of snapshot) {
    if (!isManifestHash(hash)) throw new VerifierError('leaf_inventory_hash', 'A leaf inventory contains an invalid leaf hash.');
  }
  return snapshot;
}

function largestPowerLessThan(length: number): number {
  let split = 1;
  while ((split << 1) < length) split <<= 1;
  return split;
}

async function treeHash(hashes: readonly string[], start: number, length: number): Promise<string> {
  if (length === 1) return hashes[start];
  const split = largestPowerLessThan(length);
  const left = await treeHash(hashes, start, split);
  const right = await treeHash(hashes, start + split, length - split);
  return nodeHash(left, right);
}

export async function merkleRoot(hashes: readonly string[]): Promise<string> {
  const snapshot = snapshotHashes(hashes);
  return treeHash(snapshot, 0, snapshot.length);
}

export async function verifyConsistency(oldCount: number, oldRoot: string, newCount: number, newRoot: string, proof: readonly string[]): Promise<boolean> {
  if (!Number.isInteger(oldCount) || !Number.isInteger(newCount) || oldCount < 1 || newCount < oldCount || newCount > MAX_LEAVES
    || !isManifestHash(oldRoot) || !isManifestHash(newRoot) || !Array.isArray(proof) || proof.length > MAX_PROOF_HASHES) return false;
  const hashes = Array.from(proof);
  if (hashes.some(hash => !isManifestHash(hash))) return false;
  if (oldCount === newCount) return hashes.length === 0 && oldRoot === newRoot;
  let fn = oldCount - 1;
  let sn = newCount - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let index = 0;
  let fr: string;
  let sr: string;
  if (fn === 0) { fr = oldRoot; sr = oldRoot; }
  else {
    if (hashes.length === 0) return false;
    fr = hashes[0]; sr = hashes[0]; index = 1;
  }
  for (; index < hashes.length; index += 1) {
    if (sn === 0) return false;
    const hash = hashes[index];
    if ((fn & 1) === 1 || fn === sn) {
      fr = await nodeHash(hash, fr);
      sr = await nodeHash(hash, sr);
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
    } else sr = await nodeHash(sr, hash);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && oldRoot === fr && newRoot === sr;
}

/** Compute selected prefix roots in one bounded pass without rebuilding trees. */
export async function prefixRoots(hashes: readonly string[], neededCounts: readonly number[]): Promise<Map<number, string>> {
  const snapshot = snapshotHashes(hashes, true);
  const needed = new Set(neededCounts);
  const roots = new Map<number, string>();
  const frontier = new Map<number, string>();
  for (let index = 0; index < snapshot.length; index += 1) {
    let node = snapshot[index];
    let level = 0;
    let occupied = index;
    while ((occupied & 1) === 1) {
      node = await nodeHash(frontier.get(level)!, node);
      frontier.delete(level);
      occupied >>= 1;
      level += 1;
    }
    frontier.set(level, node);
    const count = index + 1;
    if (needed.has(count)) {
      let root: string | null = null;
      for (const partLevel of [...frontier.keys()].sort((a, b) => a - b)) {
        const part = frontier.get(partLevel)!;
        root = root === null ? part : await nodeHash(part, root);
      }
      roots.set(count, root!);
    }
  }
  return roots;
}

function topologyBounds(index: number, start: number, length: number): void {
  if (!Number.isInteger(index) || !Number.isInteger(start) || !Number.isInteger(length)
    || start < 0 || length < 1 || length > MAX_LEAVES || start + length > MAX_LEAVES || index < start || index >= start + length) {
    // The PHP helpers are private and only receive validated tree ranges. These
    // exported helpers repeat that boundary before recursion can take place.
    throw new VerifierError('inclusion_tree', 'An inclusion proof tree declaration is invalid.');
  }
}

interface PathTreeCache {
  start: number;
  length: number;
  snapshot: readonly string[];
  subtrees: Map<string, Promise<string>>;
}

// One active tree range per leaf-array identity. No global hash-content cache:
// weak keys release completed inventories, and ranges/mutations replace the
// entire cache. Within a tree there are at most 2 * length - 1 subtree nodes.
const pathTrees = new WeakMap<readonly string[], PathTreeCache>();

function pathTree(hashes: readonly string[], snapshot: readonly string[], start: number, length: number): PathTreeCache {
  let cache = pathTrees.get(hashes);
  if (!cache || cache.start !== start || cache.length !== length || cache.snapshot.length !== snapshot.length
    || cache.snapshot.some((hash, index) => hash !== snapshot[index])) {
    cache = { start, length, snapshot, subtrees: new Map() };
    pathTrees.set(hashes, cache);
  }
  return cache;
}

function cachedTreeHash(cache: PathTreeCache, start: number, length: number): Promise<string> {
  const key = `${start}:${length}`;
  const known = cache.subtrees.get(key);
  if (known) return known;
  const calculated = (async () => {
    if (length === 1) return cache.snapshot[start];
    const split = largestPowerLessThan(length);
    const left = await cachedTreeHash(cache, start, split);
    const right = await cachedTreeHash(cache, start + split, length - split);
    return nodeHash(left, right);
  })();
  cache.subtrees.set(key, calculated);
  return calculated;
}

async function path(index: number, start: number, length: number, cache: PathTreeCache): Promise<MerklePathStep[]> {
  if (length === 1) return [];
  const split = largestPowerLessThan(length);
  if (index < start + split) {
    const result = await path(index, start, split, cache);
    result.push({ hash: await cachedTreeHash(cache, start + split, length - split), side: 'right' });
    return result;
  }
  const result = await path(index, start + split, length - split, cache);
  result.push({ hash: await cachedTreeHash(cache, start, split), side: 'left' });
  return result;
}

export async function inclusionPath(index: number, start: number, length: number, hashes: readonly string[]): Promise<MerklePathStep[]> {
  topologyBounds(index, start, length);
  const snapshot = snapshotHashes(hashes);
  if (start + length > snapshot.length) throw new VerifierError('inclusion_tree', 'An inclusion proof tree declaration is invalid.');
  return path(index, start, length, pathTree(hashes, snapshot, start, length));
}

function sides(index: number, start: number, length: number): MerkleSide[] {
  if (length === 1) return [];
  const split = largestPowerLessThan(length);
  return index < start + split ? [...sides(index, start, split), 'right'] : [...sides(index, start + split, length - split), 'left'];
}

export function inclusionSides(index: number, start: number, length: number): MerkleSide[] {
  topologyBounds(index, start, length);
  return sides(index, start, length);
}
