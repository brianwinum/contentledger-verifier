// SPDX-License-Identifier: GPL-2.0-or-later
// Independent response-envelope gate. This checks completion/claim consistency,
// not evidence bytes; cryptographic verification happens only in the worker.
import type { CheckLayer, CheckResult } from './model';

export function assertBrowserCompletion(result: CheckResult): void {
  const fail = (): never => { throw new Error('Incomplete or inconsistent browser completion.'); };
  if (result.outcome !== 'passed_with_limitations' || result.code !== 'browser_profile_checks_complete'
    || !result.packageSha256 || result.packageSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(result.packageSha256) || result.layers.length !== 17) fail();
  const layers = new Map(result.layers.map(layer => [layer.layer, layer]));
  if (layers.size !== result.layers.length) fail();
  const layer = (name: string, status: string, code: string): CheckLayer => {
    const value = layers.get(name);
    if (!value || value.status !== status || value.code !== code) fail();
    return value!;
  };
  const number = (name: string, field: string, max = 10000): number => {
    const details = layers.get(name)?.details;
    if (!details || typeof details !== 'object' || Array.isArray(details)) fail();
    const value = (details as Record<string, unknown>)[field];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) fail();
    return value as number;
  };
  const presence = (name: string, count: number, validCode: string, absentCode: string) => layer(name, count ? 'valid' : 'not_present', count ? validCode : absentCode);
  const container = layer('container', 'valid', 'zip_profile_valid');
  layer('inventory', 'valid', 'inventory_valid');
  if (number('container', 'entries', 16384) < 1 || number('container', 'entries', 16384) !== number('inventory', 'entries', 16384) + 2
    || (container.details as Record<string, unknown>).sha256 !== result.packageSha256) fail();
  for (const [name, code] of [
    ['bundle_graph', 'bundle_profile_valid'], ['graph_references', 'graph_references_valid'],
    ['manifests', 'manifest_semantics_valid'], ['scope_declaration', 'scope_declaration_valid'],
    ['scope', 'scope_graph_complete'], ['capability', 'browser_profile_checks_complete'],
  ]) layer(name, 'valid', code);
  const records = number('scope', 'records'), checkpoints = number('scope', 'checkpoints');
  if (!records || records !== number('manifests', 'count')) fail();
  const scope = (layers.get('scope')!.details as Record<string, unknown>).kind;
  if (!['record', 'url-history', 'checkpoint', 'site'].includes(scope as string)) fail();
  const signatures = number('signature_integrity', 'recordSignatures');
  if (signatures > records || number('signature_integrity', 'checkpointSignatures') !== checkpoints || number('signature_integrity', 'unsupportedRecordSignatures') !== 0) fail();
  presence('signature_integrity', signatures + checkpoints, 'embedded_jws_signatures_valid', 'embedded_jws_signatures_absent');
  if (number('signing_authorization', 'records') !== signatures || number('checkpoint_identity', 'checkpoints') !== checkpoints) fail();
  presence('signing_authorization', signatures, 'carried_history_authorization_valid', 'record_signatures_absent');
  presence('checkpoint_identity', checkpoints, 'checkpoint_identity_bindings_valid', 'checkpoint_signatures_absent');
  const receipts = number('website_identity', 'receipts'), versions = number('website_identity', 'versions', 1280000);
  if (versions < receipts || versions > receipts * 128 || receipts > signatures + checkpoints || Boolean(receipts) !== Boolean(signatures + checkpoints)) fail();
  presence('website_identity', receipts, 'carried_did_webvh_logs_valid', 'did_webvh_logs_absent');
  if (number('transparency', 'checkpoints') !== checkpoints || number('transparency', 'unanchoredProofs') !== 0) fail();
  presence('transparency', checkpoints, 'carried_transparency_proofs_valid', 'transparency_absent');
  const inventories = number('transparency', 'leafInventories'), inclusions = number('transparency', 'inclusionProofs', 16384);
  if (inventories > checkpoints) fail();
  if (scope === 'record' || scope === 'url-history') {
    if (inventories || Boolean(checkpoints) !== Boolean(inclusions) || scope === 'record' && (records !== 1 || inclusions > 1)) fail();
  } else if (!checkpoints || !inventories || inclusions || scope === 'checkpoint' && signatures) fail();
  const proofs = number('timestamps', 'proofs', 16384);
  if (number('timestamps', 'unsupportedProofs', 16384)) fail();
  layer('timestamps', proofs ? 'structural_only' : 'not_present', proofs ? 'ots_structural_only' : 'timestamps_absent');
  const references = number('archive_references', 'references', 4096000);
  layer('archive_references', references ? 'retained_only' : 'not_present', references ? 'archive_references_retained' : 'archive_references_absent');
  layer('content_digests', 'not_checked', 'content_digests_not_recomputed');
  const expected = Object.values(result.expectations).filter(value => value !== undefined).length;
  if (result.expectations.did !== undefined && !receipts || result.expectations.checkpointSha256 !== undefined && !checkpoints) fail();
  if (number('external_anchor', 'expectations', 5) !== expected || result.expectations.bundleSha256 !== undefined && result.expectations.bundleSha256 !== result.packageSha256) fail();
  layer('external_anchor', expected ? 'matched' : 'self_contained_only', expected ? 'expectations_matched' : 'no_external_expectation');
}
