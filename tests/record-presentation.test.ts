// SPDX-License-Identifier: GPL-2.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verifyBrowserPackage } from '../src/verifier/engine';
import { outcomeView } from '../src/model';

for (const fileName of ['unsigned-record.zip', 'record.zip']) {
  test(`selected record presentation for ${fileName}`, async () => {
    const bytes = await readFile(new URL(`./fixtures/${fileName}`, import.meta.url));
    const result = await verifyBrowserPackage(bytes, {}, { fileName });
    assert.equal(result.outcome, 'passed_with_limitations');
    const signature = result.layers.find(layer => layer.layer === 'signature_integrity')!;
    if (fileName === 'unsigned-record.zip') {
      assert.match(outcomeView(result.outcome, result.layers).title, /unsigned/i);
      assert.match(signature.message, /selected record is unsigned/i);
    } else {
      assert.match(signature.message, /Signer: (did:webvh:[^ ]+)\. Key ID: \1#[^ ]+/);
    }
  });
}
