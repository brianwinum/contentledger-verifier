// SPDX-License-Identifier: GPL-2.0-or-later
import { verifyBrowserPackage } from './verifier/engine';
import { BROWSER_INPUT_LIMIT, browserFailure, parseBrowserResult, type BrowserRequest } from './platform-browser-protocol';

const workerScope = self as unknown as { onmessage: ((event: MessageEvent<BrowserRequest>) => void) | null; postMessage(value: unknown): void };
let started = false;
workerScope.onmessage = event => {
  if (started) return;
  started = true;
  void (async () => {
    const request = event.data;
    try {
      if (request.type !== 'verify' || !(request.file instanceof Blob) || !Number.isSafeInteger(request.file.size) || request.file.size > BROWSER_INPUT_LIMIT) throw new Error('Invalid browser input.');
      const bytes = new Uint8Array(await request.file.arrayBuffer());
      const result = await verifyBrowserPackage(bytes, request.expectations, { fileName: request.fileName, checkedAt: request.checkedAt });
      workerScope.postMessage(parseBrowserResult(result, request));
    } catch {
      workerScope.postMessage(browserFailure(request.fileName, request.expectations, request.checkedAt, 'browser_runtime_diagnostic', 'The browser verification engine could not complete a reliable check. No successful verification is claimed.'));
    }
  })();
};
