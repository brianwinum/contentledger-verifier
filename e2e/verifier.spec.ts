// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { mkdir, open, readFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const fixtures = resolve(process.cwd(), 'tests', 'fixtures');
const validPackage = resolve(fixtures, 'site-chain.zip');
const packageSha256 = '2f954c30e6ae3b6e41b3645cabdd84099497aa1c06ed8b9e115f61188654b018';
const passedTitle = 'Passed offline checks — limitations apply';

async function selectPackage(page: Page, file: string): Promise<void> {
  const chooserPromise = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: /Drop an evidence package here|choose a file from your computer/i }).click();
  const chooser = await chooserPromise;
  await chooser.setFiles(file);
}

async function checkSelectedPackage(page: Page): Promise<void> {
  await page.getByRole('button', { name: /Check package|Check again/ }).click();
  const title = page.locator('#result-title');
  await expect(title).not.toHaveText('Taking a closer look.', { timeout: 30_000 });
  const actual = await title.textContent();
  if (actual !== passedTitle) {
    await expect(page.locator('#package-information')).toContainText('Result code');
    throw new Error(`Expected a completed pass, received ${JSON.stringify(actual)}. ${await page.locator('#package-information').textContent()}`);
  }
  await expect(page.locator('#check-count')).toHaveText('17 checks');
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Check an evidence package.' })).toBeVisible();
});

test('presents production and local-source builds without prerelease copy', async ({ page }) => {
  const status = (await page.locator('#browser-build-status').textContent()) ?? '';
  const localNotice = page.locator('#local-build-banner');
  await expect(localNotice).toHaveCount(1);
  if (status.includes('Production release')) {
    await expect(localNotice).toBeHidden();
    await expect(page.locator('body')).not.toContainText(/development preview/i);
  } else {
    await expect(page.locator('#browser-build-status')).toContainText('Local source build');
    await expect(localNotice).toBeVisible();
    await expect(localNotice).toContainText('not the deployed production release');
  }
  await expect(page.locator('#app-version')).toContainText('1.0.0');
});

test('checks a supported package twice without network egress and downloads a redacted report', async ({ page, browserName }) => {
  test.skip(browserName === 'webkit', 'Playwright WebKit lacks the required Ed25519 WebCrypto capability; a separate test asserts fail-closed behavior.');
  await page.waitForLoadState('networkidle');
  const verificationRequests: string[] = [];
  page.on('request', request => {
    const protocol = new URL(request.url()).protocol;
    if (protocol === 'http:' || protocol === 'https:') verificationRequests.push(request.url());
  });

  await selectPackage(page, validPackage);
  await expect(page.locator('#drop-title')).toHaveText('site-chain.zip');
  await expect(page.locator('#verify-package')).toBeEnabled();
  await checkSelectedPackage(page);
  await expect(page.locator('#package-information')).toContainText(packageSha256);

  await checkSelectedPackage(page);
  expect(verificationRequests).toEqual([]);

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download report' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^contentledger-check-summary-2f954c30e6ae-\d{8}T\d{6}Z\.json$/);
  const downloadedPath = await download.path();
  expect(downloadedPath).not.toBeNull();
  const report = JSON.parse(await readFile(downloadedPath!, 'utf8')) as Record<string, unknown>;
  expect(report).toMatchObject({
    schemaVersion: 1,
    kind: 'contentledger-local-check-summary',
    packageSha256,
    outcome: 'passed_with_limitations',
    code: 'browser_profile_checks_complete',
  });
  expect(report).not.toHaveProperty('fileName');
  expect(report).not.toHaveProperty('layers');
  expect(report.checks).toHaveLength(17);
});

for (const [file, code] of [
  ['invalid-signature.zip', 'jws_signature_invalid'],
  ['wrong-profile.zip', 'bundle_profile'],
] as const) {
  test(`rejects ${file} with ${code}`, async ({ page }) => {
    test.skip(test.info().project.name === 'webkit' && file === 'invalid-signature.zip', 'This case reaches Ed25519; WebKit capability refusal is asserted separately.');
    await selectPackage(page, resolve(fixtures, file));
    await page.getByRole('button', { name: 'Check package' }).click();
    await expect(page.locator('#result-title')).toHaveText('The package did not pass', { timeout: 30_000 });
    await expect(page.locator('#package-information')).toContainText(code);
  });
}

test('WebKit either completes Ed25519 checks or fails closed with an explicit capability result', async ({ page, browserName }) => {
  test.skip(browserName !== 'webkit', 'The other automated engines complete the full signed-package workflow in the primary test.');
  await selectPackage(page, validPackage);
  await page.getByRole('button', { name: 'Check package' }).click();
  const title = page.locator('#result-title');
  await expect(title).not.toHaveText('Taking a closer look.', { timeout: 30_000 });
  await expect(page.locator('#package-information')).toContainText(packageSha256);
  const completed = await title.textContent() === passedTitle;
  if (completed) {
    await expect(page.locator('#package-information')).toContainText('browser_profile_checks_complete');
    await expect(page.locator('#check-count')).toHaveText('17 checks');
  } else {
    await expect(title).toHaveText('This package could not be checked');
    const information = await page.locator('#package-information').textContent();
    const capabilityCode = information?.includes('browser_ed25519_unavailable')
      ? 'browser_ed25519_unavailable'
      : information?.includes('browser_ed25519_unqualified')
        ? 'browser_ed25519_unqualified'
        : null;
    expect(capabilityCode, 'WebKit must fail closed with a bounded Ed25519 capability result.').not.toBeNull();
    await expect(page.locator('#check-count')).toHaveText('5 checks');
    test.info().annotations.push({ type: 'capability', description: `This Playwright WebKit host returned ${capabilityCode} and failed closed.` });
  }

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download report' }).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  expect(downloadedPath).not.toBeNull();
  const report = JSON.parse(await readFile(downloadedPath!, 'utf8')) as { outcome: string; code: string; checks: unknown[] };
  if (completed) expect(report).toMatchObject({ outcome: 'passed_with_limitations', code: 'browser_profile_checks_complete' });
  else {
    expect(report.outcome).toBe('could_not_check');
    expect(['browser_ed25519_unavailable', 'browser_ed25519_unqualified']).toContain(report.code);
  }
  expect(report.checks).toHaveLength(completed ? 17 : 5);

  if (completed) {
    await selectPackage(page, resolve(fixtures, 'invalid-signature.zip'));
    await page.getByRole('button', { name: 'Check again' }).click();
    await expect(page.locator('#result-title')).toHaveText('The package did not pass', { timeout: 30_000 });
    await expect(page.locator('#package-information')).toContainText('jws_signature_invalid');
  }
});

test('releases the interface when the native chooser is cancelled', async ({ page }) => {
  const chooserPromise = page.waitForEvent('filechooser');
  await page.locator('#choose-package').click();
  await chooserPromise;
  await page.locator('input[type="file"]').dispatchEvent('cancel');
  await expect(page.locator('input[type="file"]')).toHaveCount(0);
  await expect(page.locator('#choose-package')).toBeEnabled();
  await expect(page.locator('#verify-package')).toBeDisabled();
});

test('cancels an in-flight verification without presenting a completed pass', async ({ page }) => {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    class DelayedWorker extends NativeWorker {
      private timers: ReturnType<typeof setTimeout>[] = [];
      override postMessage(message: unknown, options?: StructuredSerializeOptions | Transferable[]): void {
        this.timers.push(setTimeout(() => {
          if (Array.isArray(options)) NativeWorker.prototype.postMessage.call(this, message, options);
          else NativeWorker.prototype.postMessage.call(this, message, options);
        }, 500));
      }
      override terminate(): void {
        for (const timer of this.timers) clearTimeout(timer);
        this.timers = [];
        NativeWorker.prototype.terminate.call(this);
      }
    }
    Object.defineProperty(window, 'Worker', { value: DelayedWorker, configurable: true, writable: true });
  });
  await page.reload();
  await selectPackage(page, validPackage);
  await page.getByRole('button', { name: 'Check package' }).click();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.locator('#result-title')).toHaveText('Check cancelled');
  await expect(page.locator('#save-report')).toBeHidden();
  await expect(page.locator('#package-information')).toContainText('Not available');
});

test('accepts drag and drop through the same local verification path', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'One engine exercises the drag/drop adapter; verification parity runs in every engine.');
  const base64 = (await readFile(validPackage)).toString('base64');
  await page.locator('#choose-package').evaluate((target, value) => {
    const bytes = Uint8Array.from(atob(value), character => character.charCodeAt(0));
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], 'site-chain.zip', { type: 'application/zip' }));
    target.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: transfer }));
  }, base64);
  await expect(page.locator('#drop-title')).toHaveText('site-chain.zip');
  await checkSelectedPackage(page);
});

test('rejects a package above the 128 MiB browser limit before verification', async ({ page, browserName }, testInfo) => {
  test.skip(browserName !== 'chromium', 'The shared adapter limit is engine-independent; the full verifier runs in every engine.');
  await mkdir(testInfo.outputDir, { recursive: true });
  const oversized = resolve(testInfo.outputDir, 'oversized-129mib.zip');
  const handle = await open(oversized, 'w');
  try { await handle.truncate(128 * 1024 * 1024 + 1); }
  finally { await handle.close(); }
  try {
    await selectPackage(page, oversized);
    await expect(page.locator('#input-error')).toHaveText('Choose one accessible Evidence Bundle v3 ZIP file no larger than 128 MiB.');
    await expect(page.locator('#verify-package')).toBeDisabled();
  } finally {
    await rm(oversized, { force: true });
  }
});
