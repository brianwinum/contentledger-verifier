// SPDX-License-Identifier: GPL-2.0-or-later
import { exactKeys } from './canonical';
import { VerifierError } from './errors';
import { isHttpsUrl, isManifestHash, isUuidUrn, type VerifiedManifest } from './manifest';

export type BundleScope = { kind: 'record'; entryId: string }
  | { kind: 'url-history'; url: string }
  | { kind: 'checkpoint' | 'site'; checkpointSha256: string };

/** Declaration only. Never confers signed checkpoint/leaf or full scope validity. */
export function validateScopeDeclaration(value: unknown): BundleScope {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const scope = value as Record<string, unknown>;
    if (scope.kind === 'record' && exactKeys(scope, ['entryId', 'kind']) && isUuidUrn(scope.entryId)
      || scope.kind === 'url-history' && exactKeys(scope, ['kind', 'url']) && isHttpsUrl(scope.url)
      || (scope.kind === 'checkpoint' || scope.kind === 'site') && exactKeys(scope, ['checkpointSha256', 'kind']) && isManifestHash(scope.checkpointSha256)) return scope as BundleScope;
  }
  throw new VerifierError('bundle_scope_profile', 'The bundle scope is outside the exact supported record, URL-history, checkpoint, or site profile.');
}

export function validateDeclaredCheckpointOrder(scope: BundleScope, checkpoints: readonly { checkpointSha256: string; predecessorCheckpointSha256: string | null }[]): void {
  const target = scope.kind === 'checkpoint' || scope.kind === 'site'
    ? scope.checkpointSha256 : checkpoints.at(-1)?.checkpointSha256 ?? null;
  let previous: string | null = null;
  for (const item of checkpoints) {
    if (item.predecessorCheckpointSha256 !== previous) throw new VerifierError('checkpoint_graph_order', 'Bundle checkpoints do not form the exact listed genesis-to-target predecessor chain.');
    previous = item.checkpointSha256;
  }
  if (previous !== target) throw new VerifierError('checkpoint_graph_target', 'The declared checkpoint graph does not end at the selected target.');
}

type ManifestLink = Pick<VerifiedManifest, 'sha256' | 'previous' | 'canonicalUrl'>;

/** Manifest-declared relationships; authenticated evidence closure is checked separately. */
export function validateManifestScope(scope: BundleScope, records: readonly { entryId: string }[], manifests: readonly ManifestLink[], allSupported: boolean): void {
  if (scope.kind === 'record' && (records.length !== 1 || scope.entryId !== records[0].entryId)) throw new VerifierError('scope_record', 'A record bundle does not contain exactly its declared record.');
  if (scope.kind !== 'url-history') return;
  if (!records.length) throw new VerifierError('scope_url_empty', 'A URL-history bundle contains no records.');
  for (const manifest of manifests) {
    if (manifest.canonicalUrl !== scope.url) throw new VerifierError('scope_url_binding', 'A URL-history bundle contains a record for a different canonical URL.');
  }
  // The reference skips chain interpretation when an embedded profile is unknown.
  if (allSupported) validateManifestChain(manifests);
}

export function validateManifestChain(manifests: readonly ManifestLink[]): void {
  const byHash = new Map<string, ManifestLink>();
  const referenced = new Map<string, number>();
  let genesis: string | null = null;
  for (const manifest of manifests) {
    byHash.set(manifest.sha256, manifest);
    if (manifest.previous === null) {
      if (genesis !== null) throw new VerifierError('scope_url_chain', 'A URL-history scope does not contain exactly one manifest-chain genesis.');
      genesis = manifest.sha256;
    } else referenced.set(manifest.previous, (referenced.get(manifest.previous) ?? 0) + 1);
  }
  if (genesis === null) throw new VerifierError('scope_url_chain', 'A URL-history scope does not contain exactly one manifest-chain genesis.');
  for (const manifest of manifests) {
    if (manifest.previous !== null && !byHash.has(manifest.previous)) throw new VerifierError('scope_url_chain', 'A URL-history scope omits a declared manifest predecessor.');
    if ((referenced.get(manifest.sha256) ?? 0) > 1) throw new VerifierError('scope_url_branch', 'A URL-history scope contains a branched manifest chain.');
  }
  const successors = new Map(manifests.filter(item => item.previous !== null).map(item => [item.previous!, item.sha256]));
  const visited = new Set<string>();
  let current: string | undefined = genesis;
  while (current !== undefined) {
    if (visited.has(current)) throw new VerifierError('scope_url_cycle', 'A URL-history scope contains a manifest-chain cycle.');
    visited.add(current);
    current = successors.get(current);
  }
  if (visited.size !== manifests.length) throw new VerifierError('scope_url_disconnected', 'A URL-history scope contains a disconnected chain or cycle.');
}
