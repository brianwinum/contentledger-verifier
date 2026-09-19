// SPDX-License-Identifier: GPL-2.0-or-later
// External comparison semantics from frozen Bundle_Verifier::verify_expectations.
import type { CheckLayer, Expectations } from '../model';
import { VerifierError } from './errors';
import type { RecordReference } from './graph';
import type { VerifiedIdentityReceipt } from './identity';

/**
 * Compare already normalized, validated inputs against the checked graph.
 * Record UUID and manifest digest are independent membership assertions, not a
 * claimed relationship between one UUID and one manifest. Graph digest presence
 * also does not promote an unsupported manifest profile to a verified profile.
 * Callers must supply only verified receipts and the selected terminal checkpoint.
 */
export function verifyComparisons(
  expectations: Expectations,
  records: readonly RecordReference[],
  targetCheckpoint: string | null,
  receipts: readonly VerifiedIdentityReceipt[],
  packageSha256: string,
): CheckLayer {
  let count = 0;
  // Preserve PHP's failure order independently of UI field order.
  if (expectations.bundleSha256 !== undefined) {
    count++;
    if (expectations.bundleSha256 !== packageSha256) throw new VerifierError('expected_bundle', 'The exact held bundle bytes do not match the externally expected SHA-256 digest.');
  }
  if (expectations.recordUuid !== undefined) {
    count++;
    const urn = `urn:uuid:${expectations.recordUuid}`;
    if (!records.some(record => record.entryId === urn)) throw new VerifierError('expected_record', 'The requested record is not present in this bundle.');
  }
  if (expectations.manifestSha256 !== undefined) {
    count++;
    if (!records.some(record => record.manifestSha256 === expectations.manifestSha256)) throw new VerifierError('expected_manifest', 'No bundled manifest matches the externally expected SHA-256 digest.');
  }
  if (expectations.checkpointSha256 !== undefined) {
    count++;
    if (targetCheckpoint === null || expectations.checkpointSha256 !== targetCheckpoint) throw new VerifierError('expected_checkpoint', 'The selected bundle checkpoint does not match the external expectation.');
  }
  if (expectations.did !== undefined) {
    count++;
    if (!receipts.some(receipt => receipt.did === expectations.did)) throw new VerifierError('expected_did', 'No bundled Website Identity receipt matches the externally expected did:webvh identifier.');
  }
  return {
    layer: 'external_anchor',
    status: count ? 'matched' : 'self_contained_only',
    code: count ? 'expectations_matched' : 'no_external_expectation',
    message: count
      ? 'Every supplied external expectation matches the selected self-contained evidence.'
      : 'No external expectation was supplied; this result does not establish a live DID, current site state, Bitcoin consensus, completeness, or authorship.',
    // Keep independently supplied values, identifiers, and paths out of details.
    details: { expectations: count },
  };
}
