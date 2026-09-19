export type Outcome = 'passed' | 'passed_with_limitations' | 'failed' | 'could_not_check' | 'cancelled';
export type Tone = 'positive' | 'limited' | 'negative' | 'neutral';
export interface SelectedPackage { id: string; name: string; size: number }
export interface Expectations {
  bundleSha256?: string;
  checkpointSha256?: string;
  manifestSha256?: string;
  did?: string;
  recordUuid?: string;
}
export interface CheckLayer { layer: string; status: string; code: string; message: string; details: unknown }
export interface CheckResult {
  schemaVersion: 1;
  checkedAt: string;
  appVersion: string;
  fileName: string;
  packageSha256: string | null;
  outcome: Outcome;
  code: string;
  message: string;
  verifierVersion: string;
  layers: CheckLayer[];
  expectations: Expectations;
}

const outcomes = new Set(['passed', 'passed_with_limitations', 'failed', 'could_not_check', 'cancelled']);
const statuses = new Set(['valid', 'invalid', 'matched', 'self_contained_only', 'structural_only', 'retained_only', 'not_present', 'not_checked', 'indeterminate', 'unsupported']);

// Replace invisible direction/control characters so package-provided text cannot
// visually masquerade as another filename, verdict, or diagnostic.
export function safeText(value: unknown): string {
  return String(value ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '\uFFFD');
}

export function parseSelectedPackage(value: unknown): SelectedPackage {
  if (!value || typeof value !== 'object') throw new Error('Invalid package selection response.');
  const p = value as Record<string, unknown>;
  if (typeof p.id !== 'string' || !p.id || typeof p.name !== 'string' || typeof p.size !== 'number' || !Number.isSafeInteger(p.size) || p.size < 0) throw new Error('Invalid package selection response.');
  return { id: p.id, name: p.name, size: p.size };
}

export function parseCheckResult(value: unknown): CheckResult {
  if (!value || typeof value !== 'object') throw new Error('The checker returned an unreadable result.');
  const r = value as Record<string, unknown>;
  const strings = ['checkedAt', 'appVersion', 'fileName', 'outcome', 'code', 'message', 'verifierVersion'];
  if (r.schemaVersion !== 1 || strings.some(key => typeof r[key] !== 'string') || !outcomes.has(r.outcome as string) || (r.packageSha256 !== null && (typeof r.packageSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(r.packageSha256))) || !Array.isArray(r.layers) || r.layers.length > 10000) throw new Error('The checker returned an unreadable result.');
  for (const layer of r.layers) {
    if (!layer || typeof layer !== 'object' || ['layer', 'status', 'code', 'message'].some(key => typeof layer[key] !== 'string') || !statuses.has(layer.status)) throw new Error('The checker returned an unsupported check status.');
  }
  if (!r.expectations || typeof r.expectations !== 'object' || Array.isArray(r.expectations)) throw new Error('The checker returned unreadable comparison information.');
  // Even a malformed bridge success must never hide a failed/unavailable layer.
  if (r.outcome === 'passed' || r.outcome === 'passed_with_limitations') {
    if (r.layers.some(layer => layer.status === 'invalid' || layer.status === 'unsupported')) throw new Error('The checker returned inconsistent results.');
    if (!r.layers.length) throw new Error('The checker did not return any checks.');
  }
  return value as CheckResult;
}

export function outcomeView(outcome: Outcome): { title: string; description: string; tone: Tone; symbol: string } {
  switch (outcome) {
    case 'passed':
    case 'passed_with_limitations':
      return { title: 'Passed offline checks — limitations apply', description: 'The required offline checks passed for this package. Read the individual checks to see which evidence was present and what was verified.', tone: 'limited', symbol: '✓' };
    case 'failed':
      return { title: 'The package did not pass', description: 'At least one required check failed. Do not rely on this package as verified evidence. Review the details or ask the sender for the original package.', tone: 'negative', symbol: '×' };
    case 'could_not_check':
      return { title: 'This package could not be checked', description: 'The check could not be completed. This is not a passed result or, by itself, proof that the evidence has been changed.', tone: 'neutral', symbol: '!' };
    case 'cancelled':
      return { title: 'Check cancelled', description: 'No completed verification result is available. You can check the package again when you are ready.', tone: 'neutral', symbol: '–' };
  }
}

export function cancellationView(result: CheckResult, cancellationRequested: boolean): CheckResult {
  if (!cancellationRequested || (result.outcome !== 'passed' && result.outcome !== 'passed_with_limitations')) return result;
  // A late success can race a cancellation request. Operational failures must
  // retain their outcome and explanation, especially failed temporary cleanup.
  return { ...result, outcome: 'cancelled', code: 'cancel_requested', message: 'Cancellation was requested. A completed verification result is not being presented.', layers: [], packageSha256: null };
}

export function layerView(status: string): { label: string; tone: Tone } {
  const labels: Record<string, { label: string; tone: Tone }> = {
    valid: { label: 'Passed', tone: 'positive' },
    matched: { label: 'Matched', tone: 'positive' },
    invalid: { label: 'Failed', tone: 'negative' },
    self_contained_only: { label: 'No independent comparison', tone: 'limited' },
    structural_only: { label: 'Structure only', tone: 'limited' },
    retained_only: { label: 'Metadata only', tone: 'limited' },
    not_present: { label: 'Not present', tone: 'neutral' },
    not_checked: { label: 'Not checked', tone: 'limited' },
    indeterminate: { label: 'Not established', tone: 'limited' },
    unsupported: { label: 'Unavailable or unsupported', tone: 'negative' },
  };
  return labels[status] ?? { label: 'Unknown check status', tone: 'neutral' };
}

export function layerName(name: string): string {
  const names: Record<string, string> = {
    graph_references: 'Declared file references', scope_declaration: 'Declared scope & relationships',
    signature_integrity: 'Signature checks — embedded keys',
    checkpoint_identity: 'Checkpoint signing identity',
    container: 'Package structure', inventory: 'File sizes & fingerprints', bundle_graph: 'Evidence connections', capability: 'Checker capabilities', evidence: 'Evidence validation', manifests: 'Content manifests', scope: 'Package scope', website_identity: 'Website identity history', transparency: 'Checkpoints & inclusion proofs', record_evidence: 'Record evidence', signatures: 'Cryptographic signatures', signing_authorization: 'Signing authorization', timestamps: 'Timestamp proofs', archive_references: 'Archive references', external_anchor: 'Independent comparisons', content_digests: 'Original content digests',
  };
  return names[name] ?? safeText(name.replace(/_/g, ' '));
}

export function validateExpectations(values: Expectations): { values: Expectations; error: string | null; field?: keyof Expectations } {
  const normalized: Expectations = {};
  const labels: Record<string, string> = { bundleSha256: 'Package SHA-256', checkpointSha256: 'Checkpoint SHA-256', manifestSha256: 'Manifest SHA-256' };
  for (const key of ['bundleSha256', 'checkpointSha256', 'manifestSha256', 'did', 'recordUuid'] as const) {
    const value = values[key]?.trim();
    if (!value) continue;
    if (key in labels && !/^[a-f0-9]{64}$/i.test(value)) return { values: {}, error: `${labels[key]} must contain exactly 64 hexadecimal characters (0–9 and a–f).`, field: key };
    if (key === 'did' && (!value.startsWith('did:webvh:') || value.length > 2048 || /[\s\u0000-\u001F\u007F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/.test(value))) return { values: {}, error: 'Enter a did:webvh identity without spaces or control characters.', field: key };
    if (key === 'recordUuid' && !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)) return { values: {}, error: 'Enter a canonical record UUID (version 1–5) using lowercase letters, numbers, and hyphens.', field: key };
    normalized[key] = key in labels ? value.toLowerCase() : value;
  }
  return { values: normalized, error: null };
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
