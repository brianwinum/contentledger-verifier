// SPDX-License-Identifier: GPL-2.0-or-later
// Static regression checks for explicit semantics and interaction affordances.
// These do not emulate a browser accessibility tree, test a screen reader, or
// qualify keyboard navigation, zoom, mobile reflow, focus visibility or contrast.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const main = readFileSync(new URL('./main.ts', import.meta.url), 'utf8');
const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
type Tag = { name: string; text: string; attrs: Record<string, string> };
const tags: Tag[] = [...html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*>/gi)].map(match => ({
  name: match[1].toLowerCase(), text: match[0],
  attrs: Object.fromEntries([...match[0].matchAll(/([a-z][a-z0-9-]*)\s*=\s*(["'])(.*?)\2/gi)].map(([, name, , value]) => [name.toLowerCase(), value])),
}));
function tag(id: string): Tag {
  const found = tags.filter(item => item.attrs.id === id);
  assert.equal(found.length, 1, `Exactly one element must have id ${id}.`);
  return found[0];
}
function textBody(name: string): string {
  // Deliberately bounded to this source's top-level function formatting. This is
  // a review tripwire, not a general TypeScript parser or control-flow analysis.
  const match = new RegExp(`^(?:async )?function ${name}\\([^\\n]*\\)[^{]*\\{[\\s\\S]*?^\\}`, 'm').exec(main);
  assert.ok(match, `Missing top-level function ${name}.`);
  return match[0];
}

test('page has a language, meaningful title, one main landmark and zoomable viewport', () => {
  assert.equal(tags.find(item => item.name === 'html')?.attrs.lang, 'en');
  assert.match(html, /<title>ContentLedger Checker<\/title>/);
  assert.equal(tags.filter(item => item.name === 'main').length, 1);
  assert.equal(tags.filter(item => item.name === 'h1').length, 1);
  assert.equal(tag('main').name, 'main');
  const viewport = tags.find(item => item.name === 'meta' && item.attrs.name === 'viewport')?.attrs.content ?? '';
  assert.match(viewport, /width=device-width/);
  assert.doesNotMatch(viewport, /user-scalable\s*=\s*(?:no|0)|maximum-scale\s*=/i);
  const fallback = /<noscript\b[^>]*>([\s\S]*?)<\/noscript>/i.exec(html)?.[1] ?? '';
  assert.match(fallback, /JavaScript is required/i);
  assert.match(fallback, /No package has been checked/i);
});

test('all static IDs are unique and accessibility references resolve to existing elements', () => {
  const ids = tags.flatMap(item => item.attrs.id ? [item.attrs.id] : []);
  assert.equal(new Set(ids).size, ids.length);
  for (const item of tags) {
    for (const attribute of ['aria-labelledby', 'aria-describedby', 'aria-errormessage', 'for']) {
      for (const target of (item.attrs[attribute] ?? '').split(/\s+/).filter(Boolean)) assert.ok(ids.includes(target), `${item.name}[${attribute}] references missing ${target}.`);
    }
    if (item.attrs.tabindex !== undefined) assert.ok(Number(item.attrs.tabindex) <= 0, 'Positive tabindex must not reorder keyboard navigation.');
    if (item.attrs.role === 'button') assert.equal(item.name, 'button', 'Use a native keyboard-operable button.');
  }
  for (const id of ['package-heading', 'explainer-heading', 'result-title']) assert.equal(tag(id).name, 'h2');
  assert.equal(tag('result-section').attrs['aria-labelledby'], 'result-title');
});

test('each comparison field has an explicit label and disables spelling and value autocomplete', () => {
  const fields = ['bundle-sha256', 'checkpoint-sha256', 'manifest-sha256', 'expected-did', 'record-uuid'];
  const inputs = tags.filter(item => item.name === 'input');
  assert.deepEqual(inputs.map(item => item.attrs.id), fields);
  for (const id of fields) {
    const field = tag(id);
    assert.equal(field.name, 'input');
    assert.equal(field.attrs.type, 'text');
    assert.equal(field.attrs.autocomplete, 'off');
    assert.equal(field.attrs.spellcheck, 'false');
    assert.equal(tags.filter(item => item.name === 'label' && item.attrs.for === id).length, 1);
    assert.match(html, new RegExp(`<label\\s+for="${id}">[^<\\s][\\s\\S]*?<\\/label>`));
    assert.doesNotMatch(field.text, /\bdisabled\b/);
  }
  assert.equal(tag('expectations-fields').name, 'fieldset');
  assert.equal(tag('expectations-form').name, 'form');
  assert.equal(tag('verify-package').attrs.type, 'submit');
  assert.equal(tag('verify-package').attrs.form, 'expectations-form', 'The visible submit button must belong to the comparison form for implicit Enter submission.');
  assert.match(main, /'expectations-form'\)\.addEventListener\('submit', event => \{ event\.preventDefault\(\); void verifyPackage\(\); \}\)/);
  assert.doesNotMatch(main, /checkButton\.addEventListener\('click'/, 'A form submission must not also start verification through a button click handler.');
  assert.equal([...main.matchAll(/void verifyPackage\(\)/g)].length, 1, 'Form submission is the single UI verification entry point.');
});

test('package selection, verification, cancellation and saving use native named buttons', () => {
  for (const id of ['choose-package', 'verify-package', 'cancel-check', 'save-report']) {
    const control = tag(id);
    assert.equal(control.name, 'button');
    assert.equal(control.attrs.type, id === 'verify-package' ? 'submit' : 'button');
    assert.doesNotMatch(control.text, /aria-hidden="true"|tabindex="-1"/);
    assert.match(html, new RegExp(`<button\\b[^>]*id="${id}"[^>]*>[\\s\\S]*?[A-Za-z][\\s\\S]*?<\\/button>`));
  }
  assert.equal(tag('choose-package').attrs['aria-describedby'], 'supported-packages privacy-note');
  assert.match(main, /chooseButton\.addEventListener\('click'/);
  assert.match(main, /cancelButton\.addEventListener\('click'/);
  for (const summary of html.matchAll(/<summary\b[^>]*>([\s\S]*?)<\/summary>/gi)) assert.match(summary[1].replace(/<[^>]*>/g, ''), /[A-Za-z]/);
});

test('progress, validation, completion and report outcomes have explicit announcement channels', () => {
  assert.equal(tag('announcement').attrs.role, 'status');
  assert.equal(tag('announcement').attrs['aria-live'], 'polite');
  assert.equal(tag('announcement').attrs['aria-atomic'], 'true');
  assert.doesNotMatch(tag('announcement').text, /\bhidden\b|aria-hidden="true"/);
  assert.equal(tag('input-error').attrs.role, 'alert');
  assert.equal(tag('report-status').attrs.role, 'status');
  assert.match(textBody('announce'), /setText\('announcement', message\)/);
  assert.match(textBody('showBusy'), /summary\.setAttribute\('aria-busy', 'true'\)/);
  assert.match(textBody('showBusy'), /announce\('Checking the package\./);
  assert.match(textBody('renderResult'), /summary\.removeAttribute\('aria-busy'\)/);
  assert.match(textBody('renderResult'), /announce\(view\.title\)/);
  assert.match(textBody('cancelVerification'), /announce\(platform\.cancellationMessage\)/);
  assert.match(textBody('saveReport'), /reportStatus\.textContent =/);
  assert.match(textBody('saveReport'), /reportStatus\.hidden = false/);
});

test('invalid fields expose and focus their error and stale markers are cleared on reread/reset', () => {
  const verify = textBody('verifyPackage');
  assert.match(verify, /'expectations-section'\)\.open = true/);
  assert.match(verify, /expectationFields\[expectations\.field\]\.setAttribute\('aria-invalid', 'true'\)/);
  assert.match(verify, /expectationFields\[expectations\.field\]\.setAttribute\('aria-errormessage', 'input-error'\)/);
  assert.match(verify, /expectationFields\[expectations\.field\]\.focus\(\)/);
  for (const attribute of ['aria-invalid', 'aria-errormessage']) assert.ok(textBody('clearFieldErrors').includes(`removeAttribute('${attribute}')`));
  assert.match(textBody('readExpectations'), /clearFieldErrors\(\)/);
  assert.match(textBody('clearResult'), /clearFieldErrors\(\)/);
  assert.match(main, /fields\.addEventListener\('input',[\s\S]*?clearResult\(\)/);
});

test('completed results always become visible to keyboard focus including reduced-motion users', () => {
  assert.equal(tag('result-summary').attrs.tabindex, '-1');
  const render = textBody('renderResult');
  assert.match(render, /^  summary\.focus\(\{ preventScroll: true \}\);\r?\n  summary\.scrollIntoView\(/m, 'Result focus and scrolling must remain unconditional adjacent completion steps.');
  assert.equal([...render.matchAll(/summary\.scrollIntoView\(/g)].length, 1);
  assert.match(render, /matchMedia\('\(prefers-reduced-motion: reduce\)'\)\.matches\s*\?\s*'auto'\s*:\s*'smooth'/);
});

test('focus indicators, narrow-layout rules and reduced-motion alternatives remain explicit', () => {
  for (const selector of ['button:focus-visible', 'a:focus-visible', 'summary:focus-visible', 'input:focus-visible']) assert.ok(css.includes(selector), `${selector} needs a focus style.`);
  assert.match(css, /:focus-visible[^{}]*\{[^}]*outline:\s*3px solid var\(--focus\)/);
  assert.match(css, /\.result-summary:focus\s*\{[^}]*outline:\s*2px solid var\(--focus\)/);
  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{\s*\*,\s*\*::before,\s*\*::after\s*\{[^}]*animation:\s*none !important;[^}]*transition:\s*none !important;[^}]*scroll-behavior:\s*auto !important/);
  assert.match(css, /@media\s*\(max-width:\s*700px\)[\s\S]*?\.workspace\s*\{\s*display:\s*block/);
  assert.match(css, /\.sr-only\s*\{[^}]*clip:/);
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none !important/);
  assert.doesNotMatch(css, /outline:\s*(?:none|0)\s*[;!}]/);
});

test('status labels and package-provided text do not rely on color or active HTML', () => {
  const layer = textBody('renderLayer');
  assert.match(layer, /badge\.textContent = status\.label/);
  assert.match(layer, /message\.textContent = safeText\(result\.message\)/);
  assert.match(textBody('setText'), /\.textContent = safeText\(value\)/);
  assert.match(textBody('addInfo'), /detail\.textContent = safeText\(value\)/);
  assert.equal(tag('result-symbol').attrs['aria-hidden'], 'true');
  assert.doesNotMatch(main, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
});
