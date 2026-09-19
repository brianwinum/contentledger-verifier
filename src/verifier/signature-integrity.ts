// SPDX-License-Identifier: GPL-2.0-or-later
// Signature math is separate from carried-history authorization callbacks.
import { sha256 } from './bytes';
import { VerifierError } from './errors';
import type { BundleGraph, CheckpointReference } from './graph';
import { CHECKPOINT_JWS_TYPE, MAX_JWS_BYTES, inspectCompactJws, verifyExactJws, verifyRecordJws, type VerifiedJws, type VerifiedRecordJws } from './jws';
import type { VerifiedManifest } from './manifest';
import { roleSizeLimit } from './profile';
import type { StrictZip } from './zip';

export interface SignatureIntegrityCounts {
  recordSignatures: number;
  checkpointSignatures: number;
  unsupportedRecordSignatures: number;
}
export interface SignatureAuthorizationHooks {
  checkpoint(bytes: Uint8Array, signature: VerifiedJws, item: CheckpointReference): void;
  record(signature: VerifiedRecordJws): void;
}

/** Exact JWS bindings and mathematics only, never key ownership/authorization. */
export async function verifySignatureIntegrity(zip: StrictZip, graph: BundleGraph, manifests: readonly Omit<VerifiedManifest, 'document'>[], authorization?: SignatureAuthorizationHooks): Promise<SignatureIntegrityCounts> {
  const counts: SignatureIntegrityCounts = { recordSignatures: 0, checkpointSignatures: 0, unsupportedRecordSignatures: 0 };
  for (const item of graph.checkpoints) {
    const document = zip.read(item.documentPath, roleSizeLimit(item.documentPath));
    if (!document.length) throw new VerifierError('checkpoint_size', 'A transparency checkpoint is empty or exceeds 64 KiB.');
    const signature = await verifyExactJws(zip.read(item.jwsPath, MAX_JWS_BYTES), document, CHECKPOINT_JWS_TYPE);
    if (await sha256(document) !== item.checkpointSha256) throw new VerifierError('checkpoint_graph_binding', 'A checkpoint graph digest differs from its exact signed document bytes.');
    authorization?.checkpoint(document, signature, item);
    counts.checkpointSignatures++;
  }
  const byUuid = new Map(manifests.map(manifest => [manifest.uuid, manifest]));
  for (const item of graph.records) {
    if (item.signaturePath === null) continue;
    const bytes = zip.read(item.signaturePath, MAX_JWS_BYTES);
    const manifest = byUuid.get(item.entryId.slice(9));
    if (!manifest) {
      // Like PHP, unknown manifest profiles allow compact-header inspection but
      // cannot acquire interpreted record claims or an authenticated signature.
      inspectCompactJws(bytes);
      counts.unsupportedRecordSignatures++;
      continue;
    }
    const signature = await verifyRecordJws(bytes, manifest);
    authorization?.record(signature);
    counts.recordSignatures++;
  }
  return counts;
}
