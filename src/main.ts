import { platform } from '@checker-platform';
import type { PackageInput } from './platform';
import { BROWSER_APP_VERSION, BROWSER_VERIFIER_VERSION } from './browser-version';
import { cancellationView, formatFileSize, layerName, layerView, outcomeView, parseCheckResult, parseSelectedPackage, safeText, validateExpectations, type CheckResult, type Expectations, type SelectedPackage } from './model';
import './style.css';
import './site-shell.css';
import './site-integration.css';

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing interface element: ${id}`);
  return value as T;
}

const available = platform.available;
const chooseButton = element<HTMLButtonElement>('choose-package');
const checkButton = element<HTMLButtonElement>('verify-package');
const cancelButton = element<HTMLButtonElement>('cancel-check');
const saveButton = element<HTMLButtonElement>('save-report');
const fields = element<HTMLFieldSetElement>('expectations-fields');
const error = element('input-error');
const resultSection = element('result-section');
const summary = element('result-summary');
const reportStatus = element('report-status');
const expectationFields: Record<keyof Expectations, HTMLInputElement> = {
  bundleSha256: element('bundle-sha256'), checkpointSha256: element('checkpoint-sha256'), manifestSha256: element('manifest-sha256'), did: element('expected-did'), recordUuid: element('record-uuid'),
};

let selected: SelectedPackage | null = null;
let busy = false;
let choosing = false;
let saving = false;
let cancellationRequested = false;
let currentResult: CheckResult | null = null;
let operation = 0;

function setText(id: string, value: unknown): void { element(id).textContent = safeText(value); }
function announce(message: string): void { setText('announcement', message); }
function showError(message: string | null): void {
  error.textContent = message;
  error.hidden = !message;
}

function syncControls(): void {
  chooseButton.disabled = busy || choosing || saving || !available;
  checkButton.disabled = !selected || busy || choosing || saving || !available;
  fields.disabled = busy || choosing || saving;
  cancelButton.hidden = !busy;
  cancelButton.disabled = cancellationRequested;
  cancelButton.textContent = cancellationRequested ? 'Cancelling…' : 'Cancel';
  saveButton.disabled = !currentResult || busy || choosing || saving || !available;
  checkButton.querySelector('span')!.textContent = busy ? 'Checking package…' : currentResult ? 'Check again' : 'Check package';
  chooseButton.classList.toggle('is-selected', Boolean(selected));
  element('selected-size').hidden = !selected;
  setText('drop-title', selected?.name ?? 'Drop an evidence package here');
  if (selected) {
    setText('drop-description', 'Choose a different file or drop another package');
    setText('selected-size', `${formatFileSize(selected.size)} · ZIP package`);
  }
}

function clearResult(): void {
  currentResult = null;
  resultSection.hidden = true;
  element('check-list').replaceChildren();
  element('package-information').replaceChildren();
  reportStatus.hidden = true;
  showError(null);
  clearFieldErrors();
}

function clearFieldErrors(): void {
  for (const field of Object.values(expectationFields)) {
    field.removeAttribute('aria-invalid');
    field.removeAttribute('aria-errormessage');
  }
}

async function selectPackage(input?: PackageInput): Promise<void> {
  if (!available || busy || choosing || saving) return;
  choosing = true;
  clearResult();
  syncControls();
  try {
    const response = await platform.select(input);
    if (response !== null) {
      selected = parseSelectedPackage(response);
      operation += 1;
      clearResult();
      announce(`${safeText(selected.name)} selected. Ready to check.`);
    }
  } catch {
    showError(platform.selectionError);
  } finally {
    choosing = false;
    syncControls();
  }
}

function readExpectations(): Expectations {
  const values: Expectations = {};
  clearFieldErrors();
  for (const [name, field] of Object.entries(expectationFields)) {
    values[name as keyof Expectations] = field.value;
  }
  return values;
}

function showBusy(): void {
  resultSection.hidden = false;
  summary.dataset.tone = 'neutral';
  summary.setAttribute('aria-busy', 'true');
  setText('result-symbol', '↻');
  setText('result-eyebrow', 'CHECKING ON YOUR COMPUTER');
  setText('result-title', 'Taking a closer look.');
  setText('result-description', 'Checking package structure, signatures, identity authorization, checkpoint proofs, supporting artifacts, scope, and supplied comparisons. Nothing is uploaded.');
  element('busy-status').hidden = false;
  element('completed-result').hidden = true;
  announce('Checking the package. Nothing is uploaded.');
}

function addInfo(label: string, value: unknown): void {
  const term = document.createElement('dt');
  term.textContent = label;
  const detail = document.createElement('dd');
  detail.textContent = safeText(value);
  element('package-information').append(term, detail);
}

function renderLayer(result: CheckResult['layers'][number]): HTMLElement {
  const row = document.createElement('article');
  row.className = 'check-row';
  const heading = document.createElement('div');
  heading.className = 'check-row-heading';
  const title = document.createElement('h3');
  title.textContent = layerName(result.layer);
  const badge = document.createElement('span');
  badge.className = 'status-label';
  const status = layerView(result.status);
  badge.textContent = status.label;
  badge.dataset.tone = status.tone;
  heading.append(title, badge);
  const message = document.createElement('p');
  message.textContent = safeText(result.message);
  const diagnostics = document.createElement('details');
  diagnostics.className = 'diagnostics';
  const toggle = document.createElement('summary');
  toggle.textContent = 'Technical information';
  const details = document.createElement('pre');
  details.textContent = safeText(JSON.stringify({ code: result.code, details: result.details }, null, 2));
  diagnostics.append(toggle, details);
  row.append(heading, message, diagnostics);
  return row;
}

function renderResult(result: CheckResult): void {
  currentResult = result;
  const view = outcomeView(result.outcome);
  resultSection.hidden = false;
  summary.removeAttribute('aria-busy');
  summary.dataset.tone = view.tone;
  setText('result-symbol', view.symbol);
  setText('result-eyebrow', result.outcome === 'cancelled' ? 'CHECK STOPPED' : 'CHECK RESULT');
  setText('result-title', view.title);
  setText('result-description', result.outcome === 'could_not_check' && result.message ? `${result.message} ${view.description}` : view.description);
  element('busy-status').hidden = true;
  element('completed-result').hidden = false;
  setText('result-file', result.fileName);
  const date = new Date(result.checkedAt);
  setText('result-time', Number.isNaN(date.getTime()) ? 'Check time unavailable' : `Checked ${date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}`);
  setText('app-version', result.appVersion ? `· ${result.appVersion}` : '');
  element('check-list').replaceChildren(...result.layers.map(renderLayer));
  setText('check-count', `${result.layers.length} ${result.layers.length === 1 ? 'check' : 'checks'}`);
  if (!result.layers.length) {
    const message = document.createElement('p');
    message.className = 'empty-checks';
    message.textContent = safeText(result.message || 'No completed individual checks are available.');
    element('check-list').append(message);
  }
  element('package-information').replaceChildren();
  addInfo('Package SHA-256', result.packageSha256 ?? 'Not available');
  addInfo('Checker version', result.appVersion || 'Not available');
  addInfo('Verifier version', result.verifierVersion || 'Not available');
  addInfo('Result code', result.code);
  addInfo('Result detail', result.message);
  const comparisons = Object.entries(result.expectations).filter(([, value]) => value);
  const comparisonNames: Record<string, string> = { bundleSha256: 'Expected package SHA-256', checkpointSha256: 'Expected checkpoint SHA-256', manifestSha256: 'Expected manifest SHA-256', did: 'Expected website identity', recordUuid: 'Expected record UUID' };
  if (comparisons.length) for (const [name, value] of comparisons) addInfo(comparisonNames[name] ?? name, value);
  else addInfo('Independent comparisons', 'None supplied. The result is self-contained.');
  syncControls();
  announce(view.title);
  summary.focus({ preventScroll: true });
  summary.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
}

async function verifyPackage(): Promise<void> {
  if (!available || !selected || busy || choosing || saving) return;
  const expectations = validateExpectations(readExpectations());
  if (expectations.error) {
    showError(expectations.error);
    if (expectations.field) {
      element<HTMLDetailsElement>('expectations-section').open = true;
      expectationFields[expectations.field].setAttribute('aria-invalid', 'true');
      expectationFields[expectations.field].setAttribute('aria-errormessage', 'input-error');
      expectationFields[expectations.field].focus();
    }
    return;
  }
  const token = ++operation;
  const packageId = selected.id;
  const fileName = selected.name;
  clearResult();
  busy = true;
  cancellationRequested = false;
  syncControls();
  showBusy();
  try {
    const response = await platform.verify(packageId, expectations.values);
    if (token !== operation) return;
    const result = cancellationView(parseCheckResult(response), cancellationRequested);
    // A cancellation request and process completion can cross. Never present a
    // completed success while the interface is promising a cancelled operation.
    renderResult(result);
    saveButton.hidden = result.outcome === 'cancelled';
  } catch {
    if (token !== operation) return;
    renderResult({ schemaVersion: 1, checkedAt: new Date().toISOString(), appVersion: BROWSER_APP_VERSION, fileName, packageSha256: null, outcome: 'could_not_check', code: 'browser_result_unavailable', message: 'The browser checker could not return a complete, readable result. No successful verification is claimed.', verifierVersion: BROWSER_VERIFIER_VERSION, layers: [], expectations: expectations.values });
    saveButton.hidden = true;
  } finally {
    if (token === operation) {
      busy = false;
      cancellationRequested = false;
      syncControls();
    }
  }
}

async function cancelVerification(): Promise<void> {
  if (!busy || cancellationRequested) return;
  cancellationRequested = true;
  syncControls();
  announce(platform.cancellationMessage);
  try {
    await platform.cancel();
  } catch {
    // Keep selection frozen until the in-flight verification settles. Do not
    // start a second process when cancellation has an uncertain outcome.
    showError('The cancellation request could not be confirmed. Waiting for the current check to stop.');
  }
}

async function saveReport(): Promise<void> {
  if (!available || !currentResult || busy || saving || choosing) return;
  const snapshot = structuredClone(currentResult);
  saving = true;
  reportStatus.hidden = true;
  syncControls();
  try {
    const saved = await platform.save(snapshot);
    if (saved !== 'cancelled') {
      reportStatus.textContent = saved === 'download_requested' ? 'Redacted report download requested. Check your browser downloads to confirm it was saved.' : 'Redacted report saved. It includes the package fingerprint and check results.';
      reportStatus.hidden = false;
    }
  } catch {
    reportStatus.textContent = 'The report download could not be started. Check your browser download settings and try again.';
    reportStatus.hidden = false;
  } finally {
    saving = false;
    syncControls();
  }
}

chooseButton.addEventListener('click', () => { void selectPackage(); });
cancelButton.addEventListener('click', () => { void cancelVerification(); });
saveButton.addEventListener('click', () => { void saveReport(); });
element<HTMLFormElement>('expectations-form').addEventListener('submit', event => { event.preventDefault(); void verifyPackage(); });
fields.addEventListener('input', () => {
  if (busy || saving || choosing) return;
  const hadResult = currentResult !== null;
  operation += 1;
  clearResult();
  syncControls();
  if (hadResult) announce('The comparison values changed. Check the package again to get a current result.');
});

// Do not let a dropped archive navigate away. The browser adapter retains the
// selected File object in memory for the duration of the check.
window.addEventListener('dragover', event => event.preventDefault());
window.addEventListener('drop', event => event.preventDefault());

if (available) {
  void platform.listenForDrops({
    select: input => { void selectPackage(input); },
    error: message => { if (!busy && !choosing && !saving) { clearResult(); syncControls(); showError(message); } },
    dragging: active => chooseButton.classList.toggle('is-dragging', active && !busy && !choosing && !saving),
  }).catch(() => {
    setText('drop-title', 'Choose an evidence package');
    setText('drop-description', 'Open a ZIP file from your computer');
  });
}

element('browser-build-details').hidden = false;
const build = platform.buildInfo;
setText('browser-build-status', build
  ? build.releaseStatus === 'production'
    ? 'Production release · source revision and build snapshot recorded.'
    : 'Local source build · build snapshot recorded.'
  : 'Unidentified build · no production-build fingerprint is available.');
const buildRows: [string, unknown][] = build ? [
  ...(build.sourceRevision ? [['Source revision', build.sourceRevision] as [string, unknown]] : []),
  ['Source snapshot SHA-256', build.sourceSha256],
  ['Dependency lock SHA-256', build.dependencyLockSha256],
  ['Inventoried source files', build.sourceFileCount],
  ['Build tools', `Node ${build.toolchain.node} · Vite ${build.toolchain.vite} · TypeScript ${build.toolchain.typescript}`],
] : [];
buildRows.push(['Supported profile', 'ContentLedger Evidence Bundle v3'], ['License', 'GPL-2.0-or-later']);
for (const [label, value] of buildRows) {
  const term = document.createElement('dt'); term.textContent = label;
  const detail = document.createElement('dd'); detail.textContent = safeText(value);
  element('browser-build-information').append(term, detail);
}
if (!build || build.releaseStatus !== 'production') {
  element('local-build-banner').hidden = false;
  setText('local-build-banner', 'Local source build — not the deployed production release.');
}
setText('connection-label', 'Runs locally in your browser');
setText('intro-eyebrow', 'LOCAL BROWSER CHECKER');
setText('intro-copy', 'Choose a public ContentLedger evidence package to check its carried evidence and declared scope. Your file stays on this device. Read the result limitations before relying on it.');
setText('supported-packages', 'ContentLedger Evidence Bundle v3 · Maximum 128 MiB.');
setText('privacy-copy', 'Package processing happens in browser memory. Nothing is uploaded or saved by this app unless you request a report download.');
setText('explainer-copy', 'Check package integrity, carried signatures and identity history, checkpoint proofs, declared scope, and any trusted values you supply. Timestamp proofs receive structural checks and archive references receive metadata checks only.');
setText('run-checks-label', 'Run the local offline checks');
setText('run-checks-copy', 'After the app loads, processing stays on this device. No account is needed.');
setText('read-result-copy', 'Read each check and its limitations. An offline pass does not prove authorship, content truth, current website state, or trusted time.');
setText('app-version', `· Browser ${BROWSER_APP_VERSION}`);
setText('footer-note', 'Local browser processing. No account needed.');
setText('busy-copy', 'Checking signatures, identity history, and checkpoint proofs. Larger packages may take a moment.');
setText('evidence-limitations-copy', 'Checks cover the supplied package and its declared scope, not evidence the sender omitted. An absent signature provides no signing assurance. Timestamp structure and retained archive metadata do not establish trusted time, Bitcoin consensus, or current archive availability. Supplied UUID and manifest-hash comparisons are independent membership checks, not proof of a relationship between them.');
saveButton.textContent = 'Download report';
syncControls();
