// SPDX-License-Identifier: GPL-2.0-or-later
import { parseCheckResult, type CheckResult, type Expectations } from './model';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';
import { assertBrowserCompletion } from './browser-completion';

export { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';
export const BROWSER_INPUT_LIMIT = 128 * 1024 * 1024;
export const BROWSER_TIMEOUT_MS = 120_000;
export interface BrowserRequest { type: 'verify'; file: File; fileName: string; checkedAt: string; expectations: Expectations }

export function browserFailure(fileName: string, expectations: Expectations, checkedAt: string, code: string, message: string, cancelled = false): CheckResult {
  return { schemaVersion: 1, checkedAt, appVersion: BROWSER_APP_VERSION, verifierVersion: BROWSER_VERIFIER_VERSION, fileName, expectations: { ...expectations }, packageSha256: null, outcome: cancelled ? 'cancelled' : 'could_not_check', code, message, layers: [] };
}

export function parseBrowserResult(value: unknown, request: Pick<BrowserRequest, 'fileName' | 'checkedAt' | 'expectations'>): CheckResult {
  const result = parseCheckResult(value);
  // A bare pass is never supported: every successful offline result is limited.
  if (!['passed_with_limitations', 'failed', 'could_not_check', 'cancelled'].includes(result.outcome) || result.appVersion !== BROWSER_APP_VERSION || result.verifierVersion !== BROWSER_VERIFIER_VERSION || result.fileName !== request.fileName || result.checkedAt !== request.checkedAt || result.layers.length > 64) throw new Error('Invalid browser result.');
  const implemented = new Map([
    ['container', 'zip_profile_valid'], ['inventory', 'inventory_valid'], ['bundle_graph', 'bundle_profile_valid'],
    ['graph_references', 'graph_references_valid'], ['manifests', 'manifest_semantics_valid'],
    ['scope_declaration', 'scope_declaration_valid'],
    ['signature_integrity', 'embedded_jws_signatures_valid'],
    ['website_identity', 'carried_did_webvh_logs_valid'],
    ['signing_authorization', 'carried_history_authorization_valid'],
    ['checkpoint_identity', 'checkpoint_identity_bindings_valid'],
    ['transparency', 'carried_transparency_proofs_valid'],
    ['scope', 'scope_graph_complete'], ['capability', 'browser_profile_checks_complete'],
  ]);
  const milestoneStatuses = new Set(['valid', 'invalid', 'unsupported', 'not_checked']);
  // Structural/retained/absent claims are permitted only for their exact layer/code,
  // never promoted to cryptographic validity, archive availability or trusted time.
  const supportingClaims = new Set([
    'timestamps:structural_only:ots_structural_only', 'timestamps:not_present:timestamps_absent',
    'archive_references:retained_only:archive_references_retained', 'archive_references:not_present:archive_references_absent',
    'website_identity:not_present:did_webvh_logs_absent', 'signature_integrity:not_present:embedded_jws_signatures_absent',
    'signing_authorization:not_present:record_signatures_absent', 'checkpoint_identity:not_present:checkpoint_signatures_absent',
    'transparency:not_present:transparency_absent',
    'external_anchor:matched:expectations_matched', 'external_anchor:self_contained_only:no_external_expectation',
  ]);
  if (result.layers.some(layer => (!milestoneStatuses.has(layer.status) && !supportingClaims.has(`${layer.layer}:${layer.status}:${layer.code}`)) || (layer.status === 'valid' && implemented.get(layer.layer) !== layer.code))) throw new Error('Unimplemented browser verification claim.');
  if ((result.outcome === 'failed') !== result.layers.some(layer => layer.status === 'invalid')) throw new Error('Inconsistent browser failure.');
  if (result.outcome === 'cancelled' && (result.layers.length || result.packageSha256 !== null)) throw new Error('Invalid cancelled browser result.');
  const keys = ['bundleSha256', 'checkpointSha256', 'manifestSha256', 'did', 'recordUuid'] as const;
  if (Object.keys(result.expectations).some(key => !keys.includes(key as typeof keys[number])) || keys.some(key => result.expectations[key] !== request.expectations[key])) throw new Error('Invalid comparison result.');
  if (result.packageSha256 !== null && result.packageSha256.length !== 64) throw new Error('Invalid browser fingerprint.');
  const token = (value: string) => /^[a-z0-9_]{1,128}$/.exec(value)?.[0] === value;
  if (!token(result.code) || !result.message || result.message.length > 16384 || result.layers.some(layer => !token(layer.layer) || !token(layer.code) || !layer.message || layer.message.length > 16384)) throw new Error('Invalid browser diagnostics.');
  let nodes = 0;
  const bounded = (value: unknown, depth: number): boolean => {
    if (++nodes > 2000 || depth > 8) return false;
    if (value === null || value === undefined || typeof value === 'boolean') return true;
    if (typeof value === 'number') return Number.isFinite(value);
    if (typeof value === 'string') return value.length <= 16384;
    if (typeof value !== 'object') return false;
    return Object.entries(value).every(([key, item]) => key.length <= 128 && bounded(item, depth + 1));
  };
  if (!result.layers.every(layer => bounded(layer.details, 0))) throw new Error('Invalid browser details.');
  const completionClaim = result.code === 'browser_profile_checks_complete' || result.layers.some(layer => layer.layer === 'capability' && layer.status === 'valid');
  if (result.outcome === 'passed_with_limitations' || completionClaim) assertBrowserCompletion(result);
  return result;
}
