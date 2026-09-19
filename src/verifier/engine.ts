// SPDX-License-Identifier: GPL-2.0-or-later
import { validateExpectations, type CheckResult, type Expectations } from '../model';
import { sha256 } from './bytes';
import { decodeCanonicalObject } from './canonical';
import { VerifierError } from './errors';
import { MAX_JSON_BYTES, requireProfileFiles, validateBundleTop, verifyInventory } from './profile';
import { MAX_PACKAGE_BYTES, StrictZip } from './zip';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from '../browser-version';
import { validateBundleGraph, verifyGraphReferences } from './graph';
import { MAX_MANIFEST_BYTES, verifyManifest, type VerifiedManifest } from './manifest';
import { validateScopeDeclaration, validateDeclaredCheckpointOrder, validateManifestScope } from './scope';
import { verifySignatureIntegrity } from './signature-integrity';
import { createSigningAuthorization, verifyIdentityGraph } from './authorization';
import { verifyTransparencyGraph } from './transparency-graph';
import { verifySupportingArtifacts } from './supporting-artifacts';
import { verifyScopeCompleteness } from './scope-completeness';
import { verifyComparisons } from './comparisons';
import { isDidWebvh } from './jws';

export { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from '../browser-version';
export const INCOMPLETE_MESSAGE = 'One or more carried evidence profiles or required capabilities are unsupported. All checkable evidence was assessed, but no successful verification is claimed.';

/** Only a completed supported profile can pass, always with offline limitations. */
export async function verifyBrowserPackage(
  bytes: Uint8Array,
  expectations: Expectations,
  metadata: { fileName: string; checkedAt?: string },
): Promise<CheckResult> {
  const result: CheckResult = {
    schemaVersion: 1, checkedAt: metadata.checkedAt ?? new Date().toISOString(), appVersion: BROWSER_APP_VERSION,
    fileName: metadata.fileName, packageSha256: null, outcome: 'could_not_check', code: 'browser_verifier_incomplete',
    message: INCOMPLETE_MESSAGE, verifierVersion: BROWSER_VERIFIER_VERSION, layers: [], expectations: {},
  };
  const add = (layer: string, status: string, code: string, message: string, details: unknown = {}): void => {
    result.layers.push({ layer, status, code, message, details });
  };
  try {
    if (!expectations || typeof expectations !== 'object' || Array.isArray(expectations) || Object.entries(expectations).some(([key, value]) => !['bundleSha256', 'checkpointSha256', 'manifestSha256', 'did', 'recordUuid'].includes(key) || (value !== undefined && typeof value !== 'string'))) throw new VerifierError('browser_options', 'The comparison inputs are not supported.', 'input');
    const normalized = validateExpectations(expectations);
    if (normalized.error) throw new VerifierError('browser_options', 'One or more comparison inputs are malformed.', 'input');
    if (normalized.values.did !== undefined && !isDidWebvh(normalized.values.did)) throw new VerifierError('did_option', 'The expected identity must be a canonical did:webvh identifier.', 'input');
    result.expectations = normalized.values;
    if (!(bytes instanceof Uint8Array)) throw new VerifierError('browser_input', 'The selected package bytes could not be read.', 'input');
    if (bytes.byteLength > MAX_PACKAGE_BYTES) throw new VerifierError('bundle_size_limit', 'The package exceeds the 128 MiB input limit.', 'input');
    if (!globalThis.crypto?.subtle) throw new VerifierError('browser_crypto_unavailable', 'This browser cannot provide the required SHA-256 capability.', 'unsupported');
    // Snapshot before any await, including when called directly by tests/tools.
    // Fingerprinting and parsing must see the same bytes if a caller mutates input.
    const snapshot = new Uint8Array(bytes);
    result.packageSha256 = await sha256(snapshot);
    const zip = StrictZip.parse(snapshot);
    add('container', 'valid', 'zip_profile_valid', 'The archive matches the strict deterministic STORE-only ZIP profile.', { entries: zip.paths().length, sha256: result.packageSha256 });
    const count = await verifyInventory(zip);
    add('inventory', 'valid', 'inventory_valid', 'The sidecar, canonical inventory, entry sizes, and SHA-256 digests all match.', { entries: count });
    await requireProfileFiles(zip);
    const bundle = decodeCanonicalObject(zip.read('bundle.json', MAX_JSON_BYTES), 64);
    validateBundleTop(bundle);
    add('bundle_graph', 'valid', 'bundle_profile_valid', 'The canonical bundle graph uses the supported native did:webvh v3 profile.');
    const graph = validateBundleGraph(bundle);
    await verifyGraphReferences(zip, graph);
    add('graph_references', 'valid', 'graph_references_valid', 'Graph declarations have the required shape, order, file namespaces, and exact file coverage. Manifest and identity-file digest references match. These reference checks do not authenticate identity receipts, signing authority, or supporting artifact contents.');
    const receipts = await verifyIdentityGraph(zip, graph);
    if (receipts.length) {
      add('website_identity', 'valid', 'carried_did_webvh_logs_valid', 'Carried did:webvh log proofs, key-rotation commitments, receipt state digests, and graph bindings are valid. This checks only the supplied histories, not current website control, a person or organization, or independent time.', { receipts: receipts.length, versions: receipts.reduce((count, receipt) => count + receipt.versions.length, 0) });
    } else {
      add('website_identity', 'not_present', 'did_webvh_logs_absent', 'No website identity log receipt is carried in this package.', { receipts: 0, versions: 0 });
    }
    const manifests: Omit<VerifiedManifest, 'document'>[] = [];
    let unsupportedManifests = 0;
    for (const item of graph.records) {
      try {
        const manifest = await verifyManifest(zip.read(item.manifestPath, MAX_MANIFEST_BYTES), item.entryId.slice(9), item.manifestSha256);
        // Retain bounded metadata, not every decoded manifest document.
        const { document: _document, ...metadata } = manifest;
        manifests.push(metadata);
      } catch (error) {
        if (!(error instanceof VerifierError) || error.kind !== 'unsupported') throw error;
        unsupportedManifests++;
      }
    }
    if (unsupportedManifests) {
      // Aggregate to keep the worker response bounded even with 10,000 records.
      add('manifests', 'unsupported', 'manifest_profile', 'One or more manifest profiles are not supported. Their semantics and dependent chain checks are incomplete.', { checked: manifests.length, unsupported: unsupportedManifests });
    } else {
      add('manifests', 'valid', 'manifest_semantics_valid', 'All carried manifests match supported v1/v2 field rules, exact-byte digests, and record identifiers. These field checks alone do not establish content or signing authenticity; signatures and authorization are reported separately.', { count: manifests.length });
    }
    const scope = validateScopeDeclaration(bundle.scope);
    validateDeclaredCheckpointOrder(scope, graph.checkpoints);
    validateManifestScope(scope, graph.records, manifests, unsupportedManifests === 0);
    add('scope_declaration', 'valid', 'scope_declaration_valid', 'The scope declaration and listed checkpoint predecessor order are well formed. Supported record/URL-history manifest relationships were checked; this is not a signed checkpoint or full scope-completeness verdict.', { manifestChainChecked: scope.kind === 'url-history' && unsupportedManifests === 0 });
    const authorization = createSigningAuthorization(receipts);
    const signatures = await verifySignatureIntegrity(zip, graph, manifests, authorization);
    const authorized = authorization.finish();
    if (signatures.unsupportedRecordSignatures) {
      add('signature_integrity', 'not_checked', 'record_manifest_unsupported', 'Some record signatures depend on unsupported manifest profiles and cannot be verified. Other supported signatures passed their mathematical checks.', signatures);
    } else if (signatures.recordSignatures + signatures.checkpointSignatures > 0) {
      add('signature_integrity', 'valid', 'embedded_jws_signatures_valid', 'Supported record and checkpoint JWS signatures match their exact referenced data and public keys. Carried-history authorization is reported separately; no claim about a person, organization, or current website control is made.', signatures);
    } else {
      add('signature_integrity', 'not_present', 'embedded_jws_signatures_absent', 'No record or checkpoint JWS signatures are carried in this package.', signatures);
    }
    if (signatures.unsupportedRecordSignatures) {
      add('signing_authorization', 'not_checked', 'record_manifest_unsupported', 'Unsupported manifest profiles prevent authorization checks for some record signatures.', { records: authorized.recordSignatures, unsupported: signatures.unsupportedRecordSignatures });
    } else if (authorized.recordSignatures) {
      add('signing_authorization', 'valid', 'carried_history_authorization_valid', 'The carried did:webvh histories authorize the checked record keys at their claimed signing times. These are self-contained claims, not independent proof of signing time or current key control.', { records: authorized.recordSignatures });
    } else {
      add('signing_authorization', 'not_present', 'record_signatures_absent', 'No record signature is present for signing-time authorization assessment.', { records: 0 });
    }
    if (authorized.checkpointSignatures) {
      add('checkpoint_identity', 'valid', 'checkpoint_identity_bindings_valid', 'Checkpoint signing keys and identity declarations match their exact verified carried receipts and graph references. Merkle and checkpoint-chain checks are reported separately.', { checkpoints: authorized.checkpointSignatures });
    } else {
      add('checkpoint_identity', 'not_present', 'checkpoint_signatures_absent', 'No checkpoint signature is present for identity-binding checks.', { checkpoints: 0 });
    }
    const transparencyGraph = await verifyTransparencyGraph(zip, graph, scope, authorization.verifiedCheckpoints(), manifests);
    const transparency = transparencyGraph.counts;
    if (unsupportedManifests) {
      add('transparency', 'not_checked', 'transparency_manifest_dependency', 'Unsupported manifest profiles prevent a complete carried-transparency verdict. Their inclusion paths were inspected structurally only, without claiming an authenticated manifest-to-checkpoint binding.', transparency);
    } else if (transparency.checkpoints) {
      add('transparency', 'valid', 'carried_transparency_proofs_valid', 'The carried signed checkpoint chain, consistency proofs, and identity-history extensions are valid. Carried leaf inventories reproduce their roots; append-order and sealing-time boundaries are checked when the target leaf inventory is present. Carried record inclusion proofs bind their exact manifests and checkpoints. Required evidence and scope closure are reported separately. This does not establish independent witnessing, current state, or trusted time.', transparency);
    } else {
      add('transparency', 'not_present', 'transparency_absent', 'No transparency checkpoint is carried in this package.', transparency);
    }
    result.layers.push(...await verifySupportingArtifacts(zip, graph));
    add('content_digests', 'not_checked', 'content_digests_not_recomputed', 'Original website content is not retrieved or recomputed. Manifest content digests are retained claims, not an unfinished browser check.');
    verifyScopeCompleteness(scope, graph.records, manifests, transparencyGraph.targetCheckpoint, transparencyGraph.inventories, unsupportedManifests > 0);
    if (unsupportedManifests) {
      add('scope', 'not_checked', 'scope_profile_dependency', 'Unsupported embedded profiles prevent a complete semantic scope verdict; all checkable graph relationships were assessed.');
    } else {
      add('scope', 'valid', 'scope_graph_complete', 'The bundle files and semantic graph are closed and internally complete for the declared portable scope. This does not prove that the sender supplied the latest or every externally existing record.', { kind: scope.kind, records: graph.records.length, checkpoints: graph.checkpoints.length });
    }
    result.layers.push(verifyComparisons(result.expectations, graph.records, transparencyGraph.targetCheckpoint, receipts, result.packageSha256));
    if (result.layers.some(layer => layer.status === 'unsupported')) {
      result.code = 'browser_profile_unsupported';
      result.message = INCOMPLETE_MESSAGE;
      add('capability', 'unsupported', result.code, INCOMPLETE_MESSAGE);
    } else {
      result.outcome = 'passed_with_limitations';
      result.code = 'browser_profile_checks_complete';
      result.message = 'The required offline checks passed for this supported package. Read the individual results: absent signatures confer no signing assurance, timestamps are structural only, and archive references are retained metadata. This does not establish content truth, human identity, current state, or trusted time.';
      add('capability', 'valid', result.code, 'All required checks for this supported browser profile completed. This local development build has not completed cross-browser release qualification or independent security review.');
    }
  } catch (error) {
    if (error instanceof VerifierError) {
      const invalid = error.kind === 'invalid';
      result.outcome = invalid ? 'failed' : 'could_not_check';
      result.code = error.code;
      result.message = invalid
        ? 'The package failed a required offline check or did not match supplied independent comparison information. Do not rely on it as verified evidence.'
        : 'The browser could not complete the implemented checks. No successful verification is claimed.';
      add(invalid ? 'evidence' : 'capability', invalid ? 'invalid' : 'unsupported', error.code, error.message);
    } else {
      result.code = 'browser_runtime_diagnostic';
      result.message = 'The browser could not complete a reliable check. No successful verification is claimed.';
      add('capability', 'unsupported', result.code, result.message);
    }
  }
  return result;
}
