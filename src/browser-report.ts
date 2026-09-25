// SPDX-License-Identifier: GPL-2.0-or-later
import type { CheckResult } from './model';
import { BROWSER_BUILD_INFO, parseBrowserBuildInfo } from './browser-build-info';

function utcStamp(value: string): string {
  // Date.parse alone silently normalizes invalid dates such as February 30.
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!parts || parts[0] !== value) return 'time-unknown';
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = parts;
  const y = Number(year), m = Number(month), d = Number(day);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (m < 1 || m > 12 || d < 1 || d > days[m - 1] || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59 || Number(offsetHour ?? 0) > 23 || Number(offsetMinute ?? 0) > 59) return 'time-unknown';
  const time = new Date(value);
  if (!Number.isFinite(time.getTime())) return 'time-unknown';
  const stamp = time.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return /^\d{8}T\d{6}Z$/.test(stamp) ? stamp : 'time-unknown';
}

export function reportFileName(result: CheckResult): string {
  const fingerprint = result.packageSha256?.length === 64 && /^[a-f0-9]{64}$/.test(result.packageSha256) ? result.packageSha256.slice(0, 12) : 'no-fingerprint';
  return `contentledger-check-summary-${fingerprint}-${utcStamp(result.checkedAt)}.json`;
}

export function browserReport(result: CheckResult, buildInfo: unknown = BROWSER_BUILD_INFO) {
  const build = parseBrowserBuildInfo(buildInfo);
  // Keep the native summary contract: never serialize package filenames, raw
  // layer messages/details, paths, or independently supplied comparison values.
  return {
    schemaVersion: 1,
    kind: 'contentledger-local-check-summary',
    notice: 'Local verification summary, not a signed attestation or a replacement for the original evidence package.',
    checkedAt: result.checkedAt,
    appVersion: result.appVersion,
    verifierVersion: result.verifierVersion,
    checkerBuild: build?.appVersion === result.appVersion && build.verifierVersion === result.verifierVersion ? build : null,
    checkerBuildNotice: 'Build-source identity only, not a publisher signature or independent proof of the running code. Null means no matching production-build identity is available.',
    packageSha256: result.packageSha256,
    outcome: result.outcome,
    code: result.code,
    message: result.message,
    expectationsSupplied: Object.fromEntries(['bundleSha256', 'checkpointSha256', 'manifestSha256', 'did', 'recordUuid'].map(key => [key, Boolean(result.expectations[key as keyof typeof result.expectations])])),
    expectationSemantics: 'Independent membership comparisons; matching a record UUID and a manifest hash does not establish a relationship between them.',
    limitations: ['Checks only the supplied offline package.', 'Does not establish authorship, ownership, live website state, exclusive key custody, trusted time or completeness outside the package.', 'Original website content digests are retained claims; original content is not independently retrieved or recomputed.', 'Archive references are retained metadata; OpenTimestamps checks do not verify Bitcoin consensus.', 'Build-source identity is not a publisher signature or an independent security audit.'],
    checks: result.layers.map(({ layer, status, code }) => ({ layer, status, code })),
  };
}

export function reportDownload(result: CheckResult): { name: string; json: string } {
  const snapshot = structuredClone(result);
  return { name: reportFileName(snapshot), json: `${JSON.stringify(browserReport(snapshot), null, 2)}\n` };
}
