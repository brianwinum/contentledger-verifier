// SPDX-License-Identifier: GPL-2.0-or-later
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { resolve } from 'node:path';

const fixtures = resolve(process.cwd(), 'tests', 'fixtures');
const wrongProfilePackage = resolve(fixtures, 'wrong-profile.zip');

async function selectPackage(page: Page, file = wrongProfilePackage): Promise<void> {
  const chooserPromise = page.waitForEvent('filechooser');
  await page.locator('#choose-package').click();
  const chooser = await chooserPromise;
  await chooser.setFiles(file);
}

async function assertNoSeriousAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(results.violations.map(({ id, impact, nodes }) => ({
    id,
    impact,
    nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary })),
  }))).toEqual([]);
}

async function expectVisibleKeyboardFocus(locator: Locator): Promise<void> {
  await expect(locator).toBeFocused();
  const focus = await locator.evaluate(element => {
    const style = getComputedStyle(element);
    return {
      focusVisible: element.matches(':focus-visible'),
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
    };
  });
  expect(focus.focusVisible).toBe(true);
  expect(focus.outlineStyle).not.toBe('none');
  expect(focus.outlineWidth).toBeGreaterThanOrEqual(2);
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Check an evidence package.' })).toBeVisible();
});

test('initial, comparison, validation, and result states have no WCAG A/AA Axe violations', async ({ page }) => {
  await assertNoSeriousAxeViolations(page);

  await page.locator('#expectations-section > summary').click();
  await assertNoSeriousAxeViolations(page);

  await selectPackage(page);
  await page.locator('#bundle-sha256').fill('not-a-sha256-fingerprint');
  await page.locator('#bundle-sha256').press('Enter');
  await expect(page.locator('#input-error')).toBeVisible();
  await assertNoSeriousAxeViolations(page);

  await page.locator('#bundle-sha256').fill('');
  await page.locator('#bundle-sha256').press('Enter');
  await expect(page.locator('#result-title')).toHaveText('The package did not pass', { timeout: 30_000 });
  await assertNoSeriousAxeViolations(page);
});

test('keyboard order, disclosure operation, validation focus, and completion focus are coherent', async ({ page, browserName }) => {
  const header = page.getByRole('banner');
  await expect(header.getByRole('link', { name: 'WP ContentLedger home', exact: true })).toHaveAttribute('href', 'https://wpcontentledger.com/');
  const main = page.locator('#main');
  await expect(main).toHaveAttribute('tabindex', '-1');
  const skip = page.getByRole('link', { name: 'Skip to content', exact: true });
  await expect(skip).toHaveAttribute('href', '#main');
  await page.keyboard.press('Tab');
  if (browserName === 'webkit' && !(await skip.evaluate(element => document.activeElement === element))) {
    // WebKit's host keyboard model may include ordinary links or begin at the
    // first form control. Both paths must reach the checker without requiring
    // a brittle count of header links (the repository CTA is responsive).
    await expectVisibleKeyboardFocus(page.locator('#choose-package'));
  } else {
    await expectVisibleKeyboardFocus(skip);
    await skip.press('Enter');
    await expect(main).toBeFocused();
    await page.keyboard.press('Tab');
  }
  await expectVisibleKeyboardFocus(page.locator('#choose-package'));
  await page.keyboard.press('Tab');
  const comparisonSummary = page.locator('#expectations-section > summary');
  await expectVisibleKeyboardFocus(comparisonSummary);

  await comparisonSummary.press('Enter');
  await expect(page.locator('#expectations-section')).toHaveAttribute('open', '');
  await page.keyboard.press('Tab');
  await expectVisibleKeyboardFocus(page.locator('#bundle-sha256'));

  await selectPackage(page);
  await page.locator('#bundle-sha256').focus();
  await page.locator('#bundle-sha256').fill('not-a-sha256-fingerprint');
  await page.locator('#bundle-sha256').press('Enter');
  await expect(page.locator('#bundle-sha256')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#bundle-sha256')).toHaveAttribute('aria-errormessage', 'input-error');
  await expect(page.locator('#bundle-sha256')).toBeFocused();
  await expect(page.locator('#input-error')).toHaveAttribute('role', 'alert');

  await page.locator('#bundle-sha256').fill('');
  await page.locator('#bundle-sha256').press('Enter');
  await expect(page.locator('#result-title')).toHaveText('The package did not pass', { timeout: 30_000 });
  await expect(page.locator('#result-summary')).toBeFocused();
  await expect(page.locator('#announcement')).toHaveText('The package did not pass');
});

test('content reflows without horizontal scrolling at 200% and 400% equivalents', async ({ page }) => {
  await selectPackage(page);
  await page.locator('#verify-package').click();
  await expect(page.locator('#result-title')).toHaveText('The package did not pass', { timeout: 30_000 });

  for (const width of [640, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await expectNoHorizontalOverflow(page);
    await expect(page.locator('#choose-package')).toBeVisible();
    await expect(page.locator('#save-report')).toBeVisible();
    const controlWidth = await page.locator('#save-report').evaluate(element => element.getBoundingClientRect().width);
    expect(controlWidth).toBeLessThanOrEqual(width);
  }
});

test('Windows forced colors preserve focus and controls while reduced motion removes animation', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Forced-colors emulation is qualified in the Chromium engine used by Windows Chrome and Edge.');
  await page.emulateMedia({ forcedColors: 'active', contrast: 'more', reducedMotion: 'reduce' });
  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true);
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);

  await page.locator('#choose-package').focus();
  await expectVisibleKeyboardFocus(page.locator('#choose-package'));
  const control = await page.locator('#choose-package').evaluate(element => {
    const style = getComputedStyle(element);
    return { borderStyle: style.borderTopStyle, borderWidth: Number.parseFloat(style.borderTopWidth) };
  });
  expect(control.borderStyle).not.toBe('none');
  expect(control.borderWidth).toBeGreaterThanOrEqual(1);
  await expect(page.locator('.progress-track span')).toHaveCSS('animation-name', 'none');
  await assertNoSeriousAxeViolations(page);
});
