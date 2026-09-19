// SPDX-License-Identifier: GPL-2.0-or-later
// Offline structural/metadata inspection only: no calendar, Bitcoin or archive requests.
import type { CheckLayer } from '../model';
import { sha256 } from './bytes';
import { VerifierError } from './errors';
import type { BundleGraph } from './graph';
import { verifyArchiveReferences } from './archive-references';
import { inspectOpenTimestamp } from './opentimestamps';
import type { StrictZip } from './zip';

export async function verifySupportingArtifacts(zip: StrictZip, graph: BundleGraph): Promise<CheckLayer[]> {
  let proofs = 0, unsupportedProofs = 0, references = 0;
  // Aggregate diagnostics instead of returning one layer/path per artifact.
  const unsupported = new Map<string, number>();
  const subjects = [
    ...graph.records.map(item => ({ ...item, hash: item.manifestSha256, kind: 'attributable-wayback-capture' as const })),
    ...graph.checkpoints.map(item => ({ ...item, hash: item.checkpointSha256, kind: 'exact-byte-wayback-capture' as const })),
    ...graph.identities.map(item => ({ ...item, hash: item.receiptSha256, kind: 'exact-byte-wayback-capture' as const })),
  ];
  for (const subject of subjects) {
    for (const path of subject.timestampPaths) {
      const bytes = zip.read(path, 20000);
      const expectedHash = path.slice(path.lastIndexOf('/') + 1, -4);
      let digest: string;
      try { digest = await sha256(bytes); }
      catch { throw new VerifierError('browser_crypto_failed', 'The browser could not complete a required local SHA-256 operation.', 'unsupported'); }
      if (digest !== expectedHash) throw new VerifierError('ots_path_digest', 'An OpenTimestamps filename does not match the proof SHA-256 digest.');
      try { await inspectOpenTimestamp(bytes, subject.hash); }
      catch (error) {
        if (!(error instanceof VerifierError) || error.kind !== 'unsupported' || !['ots_ripemd160', 'ots_keccak'].includes(error.code)) throw error;
        unsupported.set(error.code, (unsupported.get(error.code) ?? 0) + 1);
        unsupportedProofs++;
        continue;
      }
      proofs++;
    }
    if (subject.archiveReferencePath !== null) references += verifyArchiveReferences(zip.read(subject.archiveReferencePath, 1048576), subject.hash, subject.kind);
  }
  const layers: CheckLayer[] = [];
  for (const [code, count] of unsupported) layers.push({
    layer: 'timestamps', status: 'unsupported', code,
    message: code === 'ots_ripemd160'
      ? 'This browser verifier does not implement RIPEMD-160 OpenTimestamps operations. Affected proofs were not completely checked.'
      : 'Keccak-256 OpenTimestamps operations are unsupported. Affected proofs were not completely checked.',
    details: { proofs: count },
  });
  layers.push({
    layer: 'timestamps',
    status: proofs ? 'structural_only' : unsupportedProofs ? 'not_checked' : 'not_present',
    code: proofs ? 'ots_structural_only' : unsupportedProofs ? 'ots_profiles_unsupported' : 'timestamps_absent',
    message: proofs
      ? 'Supported OpenTimestamps proofs are structurally valid and bind their subjects. Calendar promises and block-height claims are not independently authenticated; Bitcoin consensus and trusted time were not checked.'
      : unsupportedProofs ? 'No timestamp proof used a fully supported structural operation profile.' : 'No timestamp proof is present in this scope.',
    details: { proofs, unsupportedProofs },
  }, {
    layer: 'archive_references', status: references ? 'retained_only' : 'not_present',
    code: references ? 'archive_references_retained' : 'archive_references_absent',
    message: references
      ? 'Archive references have the required format and subject bindings. They are retained metadata only; no URL was requested, capture claims were not independently authenticated, and present availability was not checked.'
      : 'No archive reference is present in this scope.',
    details: { references },
  });
  return layers;
}
