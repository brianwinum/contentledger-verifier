// SPDX-License-Identifier: GPL-2.0-or-later
import { utf8 } from './bytes';
import { encodeCanonical } from './canonical';
import { readCheckpointDocument } from './checkpoint-document';
import { VerifierError } from './errors';
import type { BundleGraph, CheckpointReference } from './graph';
import { assessRecordKey, MAX_IDENTITY_LOG_BYTES, MAX_IDENTITY_RECEIPT_BYTES, verifyIdentityReceipt, type VerifiedIdentityReceipt } from './identity';
import type { VerifiedJws, VerifiedRecordJws } from './jws';
import type { StrictZip } from './zip';
import type { VerifiedCheckpoint } from './transparency';

export async function verifyIdentityGraph(zip: StrictZip, graph: BundleGraph): Promise<VerifiedIdentityReceipt[]> {
  const receipts: VerifiedIdentityReceipt[] = [];
  for (const item of graph.identities) {
    const receipt = await verifyIdentityReceipt(zip.read(item.receiptPath, MAX_IDENTITY_RECEIPT_BYTES));
    const identity = receipt.identity;
    if (utf8(zip.read(item.logPath, MAX_IDENTITY_LOG_BYTES)) !== receipt.log_json || item.logSha256 !== identity.logSha256
      || item.receiptSha256 !== receipt.sha256 || item.did !== identity.did || item.assertionMethod !== identity.assertionMethod
      || item.versionId !== identity.versionId || item.versionTime !== identity.versionTime) throw new VerifierError('identity_graph_log', 'An identity graph item differs from its exact verified did:webvh log receipt.');
    receipts.push(receipt);
  }
  return receipts;
}

/** Longest matching carried history wins; ties retain graph order, as in PHP. */
export function receiptForKey(receipts: readonly VerifiedIdentityReceipt[], did: string, kid: string): VerifiedIdentityReceipt | undefined {
  let best: VerifiedIdentityReceipt | undefined;
  for (const receipt of receipts) {
    if (receipt.did === did && Object.hasOwn(receipt.keys, kid) && (!best || receipt.versions.length > best.versions.length)) best = receipt;
  }
  return best;
}

/** Hooks accept only JWS results already verified by signature-integrity.ts. */
export function createSigningAuthorization(receipts: readonly VerifiedIdentityReceipt[]) {
  const used = new Set<string>();
  const checkpoints = new Map<string, VerifiedCheckpoint>();
  let recordSignatures = 0, checkpointSignatures = 0;
  return {
    checkpoint(bytes: Uint8Array, signature: VerifiedJws, item: CheckpointReference): void {
      const document = readCheckpointDocument(bytes);
      const identity = document.identity;
      const identityJson = encodeCanonical(identity);
      const matches = receipts.filter(receipt => encodeCanonical(receipt.identity) === identityJson);
      if (matches.length !== 1) throw new VerifierError('checkpoint_receipt_missing', 'A checkpoint does not resolve exactly one verified Website Identity log receipt.');
      const receipt = matches[0];
      if (receipt.did !== identity.did || receipt.eventHeadHash !== identity.logSha256 || identity.versionTime !== document.recordedThrough.identityEventRecordedAt
        || receipt.activeKeyId !== identity.assertionMethod) throw new VerifierError('checkpoint_receipt_binding', 'A checkpoint identity binding differs from its exact verified did:webvh log receipt.');
      if (signature.kid !== identity.assertionMethod) throw new VerifierError('jws_kid_binding', 'A compact JWS uses a different verification method than its referenced identity.');
      if (encodeCanonical(signature.jwk) !== encodeCanonical(identity.publicKeyJwk)) throw new VerifierError('jws_jwk_binding', 'A compact JWS public key differs from its referenced identity key.');
      if (item.identityReceiptSha256 !== receipt.sha256 || item.predecessorCheckpointSha256 !== (document.predecessor?.checkpointSha256 ?? null)) throw new VerifierError('checkpoint_graph_binding', 'A checkpoint graph item differs from its signed document or identity receipt.');
      used.add(receipt.sha256);
      checkpoints.set(item.checkpointSha256, { sha256: item.checkpointSha256, document, receipt });
      checkpointSignatures++;
    },
    record(signature: VerifiedRecordJws): void {
      const receipt = receiptForKey(receipts, signature.issuer, signature.kid);
      if (!receipt) throw new VerifierError('record_identity_receipt_missing', 'A signed record lacks the exact carried identity receipt for its issuer and verification key.');
      if (assessRecordKey(receipt, signature.kid, signature.issuedAt).authorizationAtClaim !== 'authorized') throw new VerifierError('record_authorization', 'A record signature was not authorized by its self-contained did:webvh log at the claimed signing time.');
      used.add(receipt.sha256);
      recordSignatures++;
    },
    finish() {
      if (receipts.some(receipt => !used.has(receipt.sha256))) throw new VerifierError('identity_graph_orphan', 'A Website Identity log is not required by a carried checkpoint or record signature.');
      return { recordSignatures, checkpointSignatures, usedReceipts: used.size };
    },
    verifiedCheckpoints(): Map<string, VerifiedCheckpoint> { return new Map(checkpoints); },
  };
}
