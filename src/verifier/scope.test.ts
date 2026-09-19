// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { validateScopeDeclaration, validateDeclaredCheckpointOrder, validateManifestScope, validateManifestChain } from './scope';
import { VerifierError } from './errors';

const uuid = 'urn:uuid:12345678-1234-4123-8123-123456789abc';
const hash = 'a'.repeat(64), next = 'b'.repeat(64);
const url = 'https://example.test/article';
const fails = (action: () => void, code: string) => assert.throws(action, (error: unknown) => error instanceof VerifierError && error.code === code);
const link = (sha256: string, previous: string | null = null) => ({ sha256, previous, canonicalUrl: url });

test('scope declarations require exactly the supported shape without implying scope completeness', () => {
  for (const scope of [{ kind: 'record', entryId: uuid }, { kind: 'url-history', url }, { kind: 'checkpoint', checkpointSha256: hash }, { kind: 'site', checkpointSha256: hash }]) assert.deepEqual(validateScopeDeclaration(scope), scope);
  for (const scope of [null, [], {}, { kind: 'record', entryId: `${uuid}\n` }, { kind: 'url-history', url: 'http://example.test' }, { kind: 'site', checkpointSha256: `${hash}\n` }, { kind: 'record', entryId: uuid, extra: null }, { kind: 'future' }]) fails(() => validateScopeDeclaration(scope), 'bundle_scope_profile');
});

test('declared checkpoint chains must run genesis-to-selected-target with no skipped predecessor', () => {
  const scope = validateScopeDeclaration({ kind: 'checkpoint', checkpointSha256: next });
  const checkpoints = [{ checkpointSha256: hash, predecessorCheckpointSha256: null }, { checkpointSha256: next, predecessorCheckpointSha256: hash }];
  validateDeclaredCheckpointOrder(scope, checkpoints);
  fails(() => validateDeclaredCheckpointOrder(scope, checkpoints.slice(1)), 'checkpoint_graph_order');
  fails(() => validateDeclaredCheckpointOrder(scope, checkpoints.slice(0, 1)), 'checkpoint_graph_target');
  validateDeclaredCheckpointOrder({ kind: 'record', entryId: uuid }, []);
});

test('manifest chain rejects absent genesis, missing ancestors, branches and disconnected cycles', () => {
  validateManifestChain([link(next, hash), link(hash)]); // UUID graph order is not chain order.
  fails(() => validateManifestChain([]), 'scope_url_chain');
  fails(() => validateManifestChain([link(hash, next)]), 'scope_url_chain');
  fails(() => validateManifestChain([link(hash), link(next)]), 'scope_url_chain');
  fails(() => validateManifestChain([link(hash), link(next, 'c'.repeat(64))]), 'scope_url_chain');
  fails(() => validateManifestChain([link(hash), link(next, hash), link('c'.repeat(64), hash)]), 'scope_url_branch');
  fails(() => validateManifestChain([link(hash), link(next, next)]), 'scope_url_disconnected');
});

test('record membership and URL manifest binding are checked, unknown profiles do not invent a chain verdict', () => {
  fails(() => validateManifestScope({ kind: 'record', entryId: uuid }, [], [], true), 'scope_record');
  validateManifestScope({ kind: 'record', entryId: uuid }, [{ entryId: uuid }], [], false);
  const scope = validateScopeDeclaration({ kind: 'url-history', url });
  fails(() => validateManifestScope(scope, [], [], true), 'scope_url_empty');
  fails(() => validateManifestScope(scope, [{ entryId: uuid }], [{ ...link(hash), canonicalUrl: 'https://other.test' }], false), 'scope_url_binding');
  validateManifestScope(scope, [{ entryId: uuid }], [link(hash, next)], false);
  fails(() => validateManifestScope(scope, [{ entryId: uuid }], [link(hash, next)], true), 'scope_url_chain');
});
