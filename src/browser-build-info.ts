// SPDX-License-Identifier: GPL-2.0-or-later
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';

export interface BrowserBuildInfo {
  readonly schemaVersion: 1;
  readonly kind: 'contentledger-browser-build';
  readonly appVersion: string;
  readonly verifierVersion: string;
  readonly sourceSha256: string;
  readonly sourceFileCount: number;
  readonly dependencyLockSha256: string;
  readonly toolchain: Readonly<{ node: string; vite: string; typescript: string }>;
  readonly releaseStatus: 'development-unpublished' | 'development-preview';
  readonly sourceRevision: string | null;
}

declare const __CONTENTLEDGER_BUILD__: unknown;
const fields = ['schemaVersion', 'kind', 'appVersion', 'verifierVersion', 'sourceSha256', 'sourceFileCount', 'dependencyLockSha256', 'toolchain', 'releaseStatus', 'sourceRevision'];
function exactObject(value: unknown, keys: string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

// This is descriptive build identity, not a publisher signature, package digest,
// independent source audit, or proof that the running browser is uncompromised.
// Copy only bounded public fields; dev servers and Node tests have no build ID.
export function parseBrowserBuildInfo(value: unknown): BrowserBuildInfo | null {
  if (!exactObject(value, fields) || value.schemaVersion !== 1 || value.kind !== 'contentledger-browser-build'
    || value.appVersion !== BROWSER_APP_VERSION || value.verifierVersion !== BROWSER_VERIFIER_VERSION
    || value.releaseStatus !== 'development-unpublished' && value.releaseStatus !== 'development-preview'
    || value.releaseStatus === 'development-unpublished' && value.sourceRevision !== null
    || value.releaseStatus === 'development-preview' && (typeof value.sourceRevision !== 'string' || !/^[a-f0-9]{40}$/.test(value.sourceRevision))
    || typeof value.sourceSha256 !== 'string' || value.sourceSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(value.sourceSha256)
    || typeof value.dependencyLockSha256 !== 'string' || value.dependencyLockSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(value.dependencyLockSha256)
    || !Number.isSafeInteger(value.sourceFileCount) || (value.sourceFileCount as number) < 1 || (value.sourceFileCount as number) > 1000
    || !exactObject(value.toolchain, ['node', 'vite', 'typescript'])) return null;
  const versions = value.toolchain;
  for (const version of Object.values(versions)) {
    if (typeof version !== 'string' || version.length > 80 || /[^a-zA-Z0-9.+-]/.test(version) || !/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.+-]+)?$/.test(version)) return null;
  }
  return Object.freeze({
    schemaVersion: 1, kind: 'contentledger-browser-build', appVersion: BROWSER_APP_VERSION, verifierVersion: BROWSER_VERIFIER_VERSION,
    sourceSha256: value.sourceSha256, sourceFileCount: value.sourceFileCount as number, dependencyLockSha256: value.dependencyLockSha256,
    toolchain: Object.freeze({ node: versions.node as string, vite: versions.vite as string, typescript: versions.typescript as string }),
    releaseStatus: value.releaseStatus, sourceRevision: value.sourceRevision as string | null,
  });
}

export const BROWSER_BUILD_INFO = parseBrowserBuildInfo(typeof __CONTENTLEDGER_BUILD__ === 'undefined' ? null : __CONTENTLEDGER_BUILD__);
