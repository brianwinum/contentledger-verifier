// SPDX-License-Identifier: GPL-2.0-or-later
import type { CheckResult, Expectations } from './model';
import { BROWSER_INPUT_LIMIT, BROWSER_TIMEOUT_MS, browserFailure, parseBrowserResult, type BrowserRequest } from './platform-browser-protocol';

type WorkerPort = Pick<Worker, 'postMessage' | 'terminate' | 'onmessage' | 'onerror' | 'onmessageerror'>;
export function runBrowserVerification(file: File, expectations: Expectations, options: { createWorker: () => WorkerPort; timeoutMs?: number }): { promise: Promise<CheckResult>; cancel(): void } {
  const request: BrowserRequest = { type: 'verify', file, fileName: file.name, checkedAt: new Date().toISOString(), expectations: { ...expectations } };
  let stop = () => {};
  const promise = new Promise<CheckResult>(resolve => {
    let settled = false;
    let worker: WorkerPort | undefined;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: CheckResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (worker) {
        worker.onmessage = worker.onerror = worker.onmessageerror = null;
        worker.terminate();
      }
      resolve(result);
    };
    const fail = (code: string, message: string, cancelled = false) => finish(browserFailure(request.fileName, request.expectations, request.checkedAt, code, message, cancelled));
    stop = () => fail('browser_cancelled', 'The browser check was cancelled. No completed verification result is available.', true);
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > BROWSER_INPUT_LIMIT) {
      fail('browser_input_limit', 'The browser checker accepts packages no larger than 128 MiB. No verification was completed.');
      return;
    }
    try {
      worker = options.createWorker();
      worker.onmessage = event => {
        try { finish(parseBrowserResult(event.data, request)); }
        catch { fail('browser_result_unavailable', 'The browser verification engine returned an unreadable or incomplete result. No successful verification is claimed.'); }
      };
      worker.onerror = () => fail('browser_worker_error', 'The browser verification engine stopped unexpectedly. No successful verification is claimed.');
      worker.onmessageerror = () => fail('browser_result_unavailable', 'The browser verification engine returned an unreadable result. No successful verification is claimed.');
      timeout = setTimeout(() => fail('browser_timeout', 'The browser check exceeded its two-minute time limit and was stopped. No successful verification is claimed.'), options.timeoutMs ?? BROWSER_TIMEOUT_MS);
      // File is structured-cloned to the worker. Reading and parsing happen there,
      // so termination can stop the entire job, including the initial file read.
      worker.postMessage(request);
    } catch { fail('browser_worker_unavailable', 'This browser could not start the local verification engine. No successful verification is claimed.'); }
  });
  return { promise, cancel: () => stop() };
}
