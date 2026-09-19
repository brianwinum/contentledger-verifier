// SPDX-License-Identifier: GPL-2.0-or-later
// Frozen public Evidence Bundle v3 contract, matching Portable Verifier 3.0.0.
import { decodeCanonicalObject, exactKeys } from './canonical';
import { sha256, utf8 } from './bytes';
import { VerifierError } from './errors';
import { StrictZip, MAX_PACKAGE_BYTES } from './zip';

export const MAX_JSON_BYTES = 16777216;
const AGGREGATE_LIMIT = 8388608;
export const PROFILE_FILES: Readonly<Record<string, { mediaType: string; sha256: string }>> = Object.freeze({
  'VERIFY.txt': { mediaType: 'text/plain; charset=utf-8', sha256: 'e9073a334a2eb458e14001c2df4c5c59b19fffa451a51cc08354cd30938e04a8' },
  'schemas/content-ledger-evidence-bundle-inventory-v1.schema.json': { mediaType: 'application/schema+json', sha256: 'd1776001130b53e6df1c11a5da9e1278252cb3413515106fd460ef774ba090cc' },
  'schemas/content-ledger-evidence-bundle-v3.schema.json': { mediaType: 'application/schema+json', sha256: '93666d0113f5dd237f0c1f67d9e766cbf904997095e14ff1cd09309c93966fc8' },
  'schemas/content-ledger-manifest-v1.schema.json': { mediaType: 'application/schema+json', sha256: '557814ccf21cad75056015d9af3c050f5ecb8c81a67d32891dd8543d0b0fc0c9' },
  'schemas/content-ledger-manifest-v2.schema.json': { mediaType: 'application/schema+json', sha256: '9a8c6ed7167c0f8cdfe41d4a08a52b947a2dccfcfd9320b6319f90c120cd9209' },
  'schemas/content-ledger-transparency-checkpoint-v2.schema.json': { mediaType: 'application/schema+json', sha256: '76b5325e14b8f1e079f08eb4d1152bb56d332d0b970c57c85d8885ceaa1ad97b' },
  'schemas/content-ledger-transparency-inclusion-proof-v1.schema.json': { mediaType: 'application/schema+json', sha256: '332ded8bdb549a9615b7478d0706c8067faf32646014b5825af8546598990b12' },
  'schemas/content-ledger-transparency-leaf-inventory-v1.schema.json': { mediaType: 'application/schema+json', sha256: 'fd75f3decde961ddc9bdd505fec0bb716bfc7d891ac8590cae3b488b975ada2c' },
  'specifications/contentledger-evidence-bundle-v3.md': { mediaType: 'text/markdown; charset=utf-8', sha256: '02f9a4261c7b012f331e7bc8dc45e121e2e69d4fc7440db9a396973b63a42bac' },
});

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function mediaTypeForPath(path: string): string | null {
  if (Object.hasOwn(PROFILE_FILES, path)) return PROFILE_FILES[path].mediaType;
  if (path === 'bundle.json' || /^(?:records\/[a-f0-9-]{36}\/(?:manifest|archive-references)\.json|records\/[a-f0-9-]{36}\/inclusion\/[a-f0-9]{64}\.json|transparency\/checkpoints\/[a-f0-9]{64}\/(?:checkpoint|archive-references)\.json|transparency\/leaf-inventory\/[a-f0-9]{64}\.json|identity\/checkpoints\/[a-f0-9]{64}(?:\.json|\/archive-references\.json))$/.test(path)) return 'application/json';
  if (/^identity\/logs\/[a-f0-9]{64}\.jsonl$/.test(path)) return 'application/jsonl';
  if (/^(?:records\/[a-f0-9-]{36}\/signature|transparency\/checkpoints\/[a-f0-9]{64}\/checkpoint)\.jws$/.test(path)) return 'application/jose';
  if (/^(?:records\/[a-f0-9-]{36}|transparency\/checkpoints\/[a-f0-9]{64}|identity\/checkpoints\/[a-f0-9]{64})\/timestamps\/[a-f0-9]{64}\.ots$/.test(path)) return 'application/vnd.opentimestamps.ots';
  return null;
}

export function roleSizeLimit(path: string): number {
  if (path === 'bundle.json' || path === 'inventory.json') return MAX_JSON_BYTES;
  if (/^records\/[a-f0-9-]{36}\/manifest\.json$/.test(path)) return 1048576;
  if (/^records\/[a-f0-9-]{36}\/signature\.jws$/.test(path)) return 131072;
  if (/^records\/[a-f0-9-]{36}\/inclusion\/[a-f0-9]{64}\.json$/.test(path)) return 65536;
  if (/^transparency\/checkpoints\/[a-f0-9]{64}\/checkpoint\.json$/.test(path)) return 65536;
  if (/^transparency\/checkpoints\/[a-f0-9]{64}\/checkpoint\.jws$/.test(path)) return 131072;
  if (/^transparency\/leaf-inventory\/[a-f0-9]{64}\.json$/.test(path)) return MAX_JSON_BYTES;
  if (/^identity\/logs\/[a-f0-9]{64}\.jsonl$/.test(path)) return 16777216;
  if (/^identity\/checkpoints\/[a-f0-9]{64}\.json$/.test(path)) return 4259840;
  if (path.endsWith('/archive-references.json')) return 1048576;
  if (path.endsWith('.ots')) return 20000;
  return 2097152;
}

export async function verifyInventory(zip: StrictZip): Promise<number> {
  if (!zip.has('inventory.json') || !zip.has('inventory.sha256')) throw new VerifierError('inventory_missing', 'The archive lacks its required inventory and sidecar.');
  const json = zip.read('inventory.json', MAX_JSON_BYTES);
  const sidecar = zip.read('inventory.sha256', 81);
  const hash = await sha256(json);
  // Decode as single-byte ASCII; invalid UTF-8 still has the sidecar failure code.
  if (sidecar.length !== 81 || Array.from(sidecar).some(byte => byte > 127) || utf8(sidecar) !== `${hash}  inventory.json\n`) throw new VerifierError('inventory_sidecar', 'The inventory sidecar does not match the exact canonical inventory bytes.');
  const document = decodeCanonicalObject(json, 32);
  if (!exactKeys(document, ['algorithm', 'entries', 'format', 'version']) || document.format !== 'WP ContentLedger Evidence Bundle Inventory' || document.version !== '1.0' || document.algorithm !== 'sha-256' || !Array.isArray(document.entries)) throw new VerifierError('inventory_profile', 'The inventory has an unsupported exact profile.');
  const paths = zip.paths().filter(path => path !== 'inventory.json' && path !== 'inventory.sha256');
  if (document.entries.length !== paths.length) throw new VerifierError('inventory_coverage', 'The inventory does not list every other archive entry exactly once.');
  const aggregates = [
    { pattern: /^records\/[a-f0-9-]{36}\/manifest\.json$/, size: 0, code: 'manifest_aggregate_limit' },
    { pattern: /^transparency\/checkpoints\/[a-f0-9]{64}\/checkpoint\.(?:json|jws)$/, size: 0, code: 'checkpoint_aggregate_limit' },
    { pattern: /^identity\/logs\/[a-f0-9]{64}\.jsonl$/, size: 0, code: 'identity_log_aggregate_limit' },
    { pattern: /^identity\/checkpoints\/[a-f0-9]{64}\.json$/, size: 0, code: 'identity_receipt_aggregate_limit' },
  ];
  for (const [index, value] of document.entries.entries()) {
    if (!isObject(value) || !exactKeys(value, ['mediaType', 'path', 'sha256', 'size']) || typeof value.path !== 'string' || value.path !== paths[index] || typeof value.mediaType !== 'string' || value.mediaType.trim() !== value.mediaType || !/^[\x20-\x7e]{1,100}$/.test(value.mediaType) || mediaTypeForPath(value.path) !== value.mediaType || typeof value.sha256 !== 'string' || value.sha256.length !== 64 || !/^[a-f0-9]{64}$/.test(value.sha256) || typeof value.size !== 'number' || !Number.isSafeInteger(value.size) || value.size < 0 || value.size > MAX_PACKAGE_BYTES) throw new VerifierError('inventory_entry', 'An inventory entry has an invalid exact shape, order, path, media type, digest, or size.');
    if (value.size > roleSizeLimit(value.path)) throw new VerifierError('bundle_role_size', 'A bundle entry exceeds the frozen size limit for its semantic role.');
    for (const aggregate of aggregates) {
      if (aggregate.pattern.test(value.path)) {
        aggregate.size += value.size;
        if (aggregate.size > AGGREGATE_LIMIT) throw new VerifierError(aggregate.code, 'Bundled role bytes exceed the frozen 8 MiB materialization bound.');
      }
    }
    if (value.size !== zip.entry(value.path).size || value.sha256 !== await zip.sha256(value.path)) throw new VerifierError('inventory_entry_binding', 'An inventory size or SHA-256 digest does not match its exact archive entry.');
  }
  return document.entries.length;
}

export async function requireProfileFiles(zip: StrictZip): Promise<void> {
  for (const [path, pin] of Object.entries(PROFILE_FILES)) {
    if (!zip.has(path)) throw new VerifierError('bundle_profile_file', 'The bundle lacks a required inert profile file.');
    if (await zip.sha256(path) !== pin.sha256) throw new VerifierError('bundle_profile_hash', 'A packaged schema, specification, or VERIFY text differs from the trusted verifier profile.');
  }
}

export function validateBundleTop(bundle: Record<string, unknown>): void {
  if (!exactKeys(bundle, ['checkpoints', 'format', 'identityLogs', 'leafInventories', 'profile', 'records', 'scope', 'version']) || bundle.format !== 'WP ContentLedger Evidence Bundle' || bundle.profile !== 'contentledger-evidence-bundle-native-webvh-v1' || bundle.version !== '3.0') throw new VerifierError('bundle_profile', 'The bundle graph has unsupported top-level fields or profile markers.');
  for (const [field, limit] of Object.entries({ checkpoints: 10000, identityLogs: 128, leafInventories: 1, records: 10000 })) {
    if (!Array.isArray(bundle[field]) || bundle[field].length > limit) throw new VerifierError('bundle_graph_list', 'A bundle graph list is malformed or exceeds its profile limit.');
  }
  if (!isObject(bundle.scope)) throw new VerifierError('bundle_scope', 'The bundle scope is not an object.');
}
