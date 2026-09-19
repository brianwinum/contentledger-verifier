// SPDX-License-Identifier: GPL-2.0-or-later
// Exact signed-document declarations only. No Merkle root, consistency proof,
// inclusion proof, append order, or history-extension verification happens here.
import { decodeCanonicalObject, exactKeys } from './canonical';
import { VerifierError } from './errors';
import { IDENTITY_FIELDS, MAX_IDENTITY_LOG_BYTES, identityInstant, type IdentityBinding } from './identity';
import { isPublicJwk } from './jws';
import { isManifestHash as hash } from './manifest';

export const MAX_CHECKPOINT_BYTES = 65536;
export interface CheckpointDocument {
  format: 'WP ContentLedger Transparency Checkpoint'; version: '2.0'; identity: IdentityBinding;
  recordedThrough: { identityEventRecordedAt: string; manifestSealedAt: string };
  scope: { manifestDigestAlgorithm: 'sha-256'; recordIdentifier: 'entryId'; selection: 'all-sealed-contentledger-manifests' };
  tree: { algorithm: 'rfc6962-sha256-v1'; leafCanonicalization: 'wp-contentledger-transparency-leaf-v1'; leafCount: number; rootHash: string };
  predecessor: null | { checkpointSha256: string; consistencyProof: string[]; leafCount: number; rootHash: string };
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
const integer = (value: unknown, low: number, high: number): value is number => Number.isInteger(value) && (value as number) >= low && (value as number) <= high;

export function readCheckpointDocument(bytes: Uint8Array): CheckpointDocument {
  if (!bytes.length || bytes.length > MAX_CHECKPOINT_BYTES) throw new VerifierError('checkpoint_size', 'A transparency checkpoint is empty or exceeds 64 KiB.');
  const document = decodeCanonicalObject(bytes, 32);
  if (!exactKeys(document, ['format', 'identity', 'predecessor', 'recordedThrough', 'scope', 'tree', 'version']) || document.format !== 'WP ContentLedger Transparency Checkpoint' || document.version !== '2.0') throw new VerifierError('checkpoint_profile', 'A checkpoint has unsupported native did:webvh profile markers.');
  const identity = document.identity;
  if (!object(identity) || !exactKeys(identity, IDENTITY_FIELDS) || typeof identity.did !== 'string' || typeof identity.assertionMethod !== 'string'
    || !identity.did.startsWith('did:webvh:') || !identity.assertionMethod.startsWith(`${identity.did}#`)
    || !integer(identity.entryCount, 1, 128) || !integer(identity.logBytes, 2, MAX_IDENTITY_LOG_BYTES)
    || !hash(identity.logSha256) || !hash(identity.stateSha256) || !isPublicJwk(identity.publicKeyJwk)
    || typeof identity.publicUrl !== 'string' || typeof identity.siteUrl !== 'string' || typeof identity.versionId !== 'string' || identityInstant(identity.versionTime) === null) throw new VerifierError('checkpoint_identity', 'A checkpoint has an invalid native did:webvh identity binding.');
  const recorded = document.recordedThrough;
  if (!object(recorded) || !exactKeys(recorded, ['identityEventRecordedAt', 'manifestSealedAt'])
    || identityInstant(recorded.identityEventRecordedAt) === null || identityInstant(recorded.manifestSealedAt) === null
    || recorded.identityEventRecordedAt !== identity.versionTime) throw new VerifierError('checkpoint_boundary', 'A checkpoint has invalid recorded-through boundaries.');
  const scope = document.scope;
  if (!object(scope) || !exactKeys(scope, ['manifestDigestAlgorithm', 'recordIdentifier', 'selection']) || scope.manifestDigestAlgorithm !== 'sha-256'
    || scope.recordIdentifier !== 'entryId' || scope.selection !== 'all-sealed-contentledger-manifests') throw new VerifierError('checkpoint_scope', 'A checkpoint has an invalid transparency scope.');
  const tree = document.tree;
  if (!object(tree) || !exactKeys(tree, ['algorithm', 'leafCanonicalization', 'leafCount', 'rootHash']) || tree.algorithm !== 'rfc6962-sha256-v1'
    || tree.leafCanonicalization !== 'wp-contentledger-transparency-leaf-v1' || !integer(tree.leafCount, 1, 10000) || !hash(tree.rootHash)) throw new VerifierError('checkpoint_tree', 'A checkpoint has an invalid bounded Merkle-tree declaration.');
  const predecessor = document.predecessor;
  if (predecessor !== null) {
    if (!object(predecessor) || !exactKeys(predecessor, ['checkpointSha256', 'consistencyProof', 'leafCount', 'rootHash']) || !hash(predecessor.checkpointSha256) || !hash(predecessor.rootHash)
      || !integer(predecessor.leafCount, 1, tree.leafCount) || !Array.isArray(predecessor.consistencyProof) || predecessor.consistencyProof.length > 32) throw new VerifierError('checkpoint_predecessor', 'A checkpoint predecessor declaration is invalid.');
    if (predecessor.consistencyProof.some(value => !hash(value))) throw new VerifierError('checkpoint_consistency_hash', 'A checkpoint consistency proof contains an invalid hash.');
    if (predecessor.leafCount === tree.leafCount && predecessor.consistencyProof.length > 0) throw new VerifierError('checkpoint_equal_consistency', 'An equal-size checkpoint predecessor must have an empty consistency proof.');
  }
  return document as unknown as CheckpointDocument;
}
