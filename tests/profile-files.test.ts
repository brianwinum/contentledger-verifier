// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { PROFILE_FILES } from '../src/verifier/profile';

const publicPath = (bundlePath: string): URL => {
  if (bundlePath === 'VERIFY.txt') return new URL('../specifications/VERIFY.txt', import.meta.url);
  if (bundlePath === 'specifications/contentledger-evidence-bundle-v3.md') return new URL('../specifications/CONTENTLEDGER-EVIDENCE-BUNDLE-v3.md', import.meta.url);
  return new URL(`../${bundlePath}`, import.meta.url);
};

test('the public specification and schema copies match every verifier profile pin', () => {
  assert.equal(Object.keys(PROFILE_FILES).length, 9);
  for (const [bundlePath, pin] of Object.entries(PROFILE_FILES)) {
    const bytes = readFileSync(publicPath(bundlePath));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), pin.sha256, bundlePath);
  }
});
