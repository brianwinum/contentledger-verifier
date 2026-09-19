// SPDX-License-Identifier: GPL-2.0-or-later
// Frozen Bundle_Verifier::verify_scope_completeness. These closure checks use
// previously validated graph declarations and authenticated carried evidence.
// Completeness is limited to the declared package scope, not the live website.
import { VerifierError } from './errors';
import type { RecordReference } from './graph';
import type { VerifiedManifest } from './manifest';
import { validateManifestScope, type BundleScope } from './scope';
import type { LeafInventory } from './transparency';

export function verifyScopeCompleteness(
  scope: BundleScope,
  records: readonly RecordReference[],
  manifests: readonly Omit<VerifiedManifest, 'document'>[],
  targetCheckpoint: string | null,
  inventories: ReadonlyMap<string, LeafInventory>,
  semanticDegraded = false,
): void {
  if ((scope.kind === 'record' || scope.kind === 'url-history') && inventories.size) {
    throw new VerifierError('scope_leaf_inventory', 'Record and URL-history scopes must not carry a bulk leaf inventory.');
  }
  if (scope.kind === 'record' || scope.kind === 'url-history') {
    let proofCount = 0;
    for (const record of records) {
      for (const path of record.inclusionProofPaths) {
        proofCount++;
        const name = path.slice(path.lastIndexOf('/') + 1);
        const digest = name.endsWith('.json') ? name.slice(0, -5) : name;
        if (targetCheckpoint === null || targetCheckpoint !== digest) {
          throw new VerifierError('scope_inclusion_target', 'Every record/URL-history inclusion proof must target the exact terminal carried checkpoint.');
        }
      }
    }
    if (targetCheckpoint === null && proofCount !== 0 || targetCheckpoint !== null && proofCount === 0 || scope.kind === 'record' && proofCount > 1) {
      throw new VerifierError('scope_checkpoint_closure', 'A record/URL-history checkpoint chain must be closed by its exact permitted terminal inclusion proof set.');
    }
  }
  // Reuse the exact supported-manifest checks, but preserve PHP's placement:
  // inventory/proof closure errors above precede record/URL/chain errors.
  // Unknown manifest profiles skip only chain interpretation, never closures.
  validateManifestScope(scope, records, manifests, !semanticDegraded);
  if (scope.kind === 'checkpoint' || scope.kind === 'site') {
    if (targetCheckpoint === null || scope.checkpointSha256 !== targetCheckpoint || !inventories.has(targetCheckpoint)) {
      throw new VerifierError('scope_checkpoint_inventory', 'A checkpoint/site bundle lacks the exact target checkpoint leaf prefix.');
    }
    const leafRecords = Object.keys(inventories.get(targetCheckpoint)!.records).sort();
    const recordUuids = records.map(record => record.entryId.slice(9)).sort();
    if (leafRecords.length !== recordUuids.length || leafRecords.some((uuid, index) => uuid !== recordUuids[index])) {
      throw new VerifierError('scope_leaf_records', 'A checkpoint/site bundle records list does not exactly match the selected global leaf prefix.');
    }
    for (const record of records) {
      if (record.inclusionProofPaths.length) {
        throw new VerifierError('scope_record_inclusion', 'Checkpoint and site scopes do not carry per-record inclusion proofs alongside their exact bulk leaf inventory.');
      }
      if (scope.kind === 'checkpoint' && (record.archiveReferencePath !== null || record.signaturePath !== null || record.timestampPaths.length)) {
        throw new VerifierError('scope_checkpoint_record_artifact', 'Checkpoint scope records must contain manifests only, without record-level external artifacts.');
      }
    }
  }
}
