// SPDX-License-Identifier: GPL-2.0-or-later
import { reportDownload } from './browser-report';
import { BROWSER_BUILD_INFO } from './browser-build-info';
import type { CheckResult, SelectedPackage } from './model';
import type { CheckerPlatform } from './platform';
import { runBrowserVerification } from './platform-browser-job';
import { BROWSER_INPUT_LIMIT } from './platform-browser-protocol';
import BrowserWorker from './browser-worker?worker&inline';

let selectedFile: File | null = null;
let selectedId = 0;
let activeJob: ReturnType<typeof runBrowserVerification> | null = null;

function chooseFile(): Promise<File | null> {
  return new Promise(resolve => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.zip,application/zip';
    input.hidden = true;
    let settled = false;
    let focusTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (file: File | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(focusTimer);
      window.removeEventListener('focus', focus);
      input.remove();
      resolve(file);
    };
    // Modern browsers dispatch cancel; the focus fallback also releases controls
    // in older browsers when the native picker closes without a selection.
    const focus = () => { focusTimer = setTimeout(() => finish(input.files?.[0] ?? null), 500); };
    input.addEventListener('change', () => finish(input.files?.[0] ?? null), { once: true });
    input.addEventListener('cancel', () => finish(null), { once: true });
    window.addEventListener('focus', focus);
    document.body.append(input);
    try { input.click(); } catch { finish(null); }
  });
}

export const platform: CheckerPlatform = {
  kind: 'browser',
  available: true,
  buildInfo: BROWSER_BUILD_INFO,
  selectionError: 'Choose one accessible Evidence Bundle v3 ZIP file no larger than 128 MiB.',
  cancellationMessage: 'Cancelling the browser check and releasing its working memory.',
  async select(input) {
    if (typeof input === 'string') throw new Error('Browser files cannot be selected by path.');
    const file = input ?? await chooseFile();
    if (!file) return null;
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > BROWSER_INPUT_LIMIT) throw new Error('Package exceeds the browser size limit.');
    selectedFile = file;
    selectedId += 1;
    return { id: String(selectedId), name: file.name, size: file.size } satisfies SelectedPackage;
  },
  async verify(packageId, expectations) {
    if (!selectedFile || packageId !== String(selectedId) || activeJob) throw new Error('No current browser package.');
    // Production uses a bundled blob worker, inheriting the document's network-
    // denying CSP instead of creating a separately served worker security realm.
    const job = runBrowserVerification(selectedFile, expectations, { createWorker: () => new BrowserWorker() });
    activeJob = job;
    try { return await job.promise; }
    finally { if (activeJob === job) activeJob = null; }
  },
  async cancel() { activeJob?.cancel(); },
  async save(result: CheckResult) {
    const download = reportDownload(result);
    const url = URL.createObjectURL(new Blob([download.json], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = download.name;
    anchor.hidden = true;
    document.body.append(anchor);
    try { anchor.click(); }
    finally { anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 60_000); }
    return 'download_requested';
  },
  async listenForDrops(callbacks) {
    window.addEventListener('dragenter', event => { event.preventDefault(); callbacks.dragging(true); });
    window.addEventListener('dragleave', event => { if (!event.relatedTarget) callbacks.dragging(false); });
    window.addEventListener('drop', event => {
      event.preventDefault();
      callbacks.dragging(false);
      const files = event.dataTransfer?.files;
      if (!files || files.length !== 1) callbacks.error('Choose one evidence package at a time.');
      else callbacks.select(files[0]);
    });
  },
};
