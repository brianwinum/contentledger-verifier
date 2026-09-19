// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import type { CheckResult } from './model';
import { runBrowserVerification } from './platform-browser-job';
import { BROWSER_INPUT_LIMIT, browserFailure, parseBrowserResult, type BrowserRequest } from './platform-browser-protocol';

const file = () => new File(['synthetic bounded lifecycle input'], 'lifecycle.zip');
function fixture(post?: (request: BrowserRequest, emit: (value: unknown) => void) => void) {
  let input!: BrowserRequest;
  let terminations = 0;
  const worker = {
    onmessage: null as Worker['onmessage'], onerror: null as Worker['onerror'], onmessageerror: null as Worker['onmessageerror'],
    postMessage(value: unknown) { input = value as BrowserRequest; post?.(input, emit); },
    terminate() { terminations++; },
  };
  const emit = (value: unknown) => worker.onmessage?.call(worker as unknown as Worker, new MessageEvent('message', { data: value }));
  const response = () => browserFailure(input.fileName, input.expectations, input.checkedAt, 'synthetic_incomplete', 'No completed verification.');
  return { worker, emit, response, input: () => input, terminations: () => terminations };
}
function clean(value: ReturnType<typeof fixture>): void {
  assert.equal(value.terminations(), 1);
  assert.equal(value.worker.onmessage, null);
  assert.equal(value.worker.onerror, null);
  assert.equal(value.worker.onmessageerror, null);
}

test('a synchronous postMessage exception closes the worker and redacts its diagnostic', async context => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const value = fixture(() => { throw new DOMException('private path or sensitive browser state', 'DataCloneError'); });
  const job = runBrowserVerification(file(), {}, { createWorker: () => value.worker, timeoutMs: 10 });
  const result = await job.promise;
  assert.equal(result.code, 'browser_worker_unavailable');
  assert.equal(result.outcome, 'could_not_check');
  assert.ok(!JSON.stringify(result).includes('private path'));
  context.mock.timers.tick(20);
  job.cancel();
  clean(value);
});

test('a synchronous response followed by postMessage throwing retains only the first result', async context => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const value = fixture((request, emit) => {
    emit(browserFailure(request.fileName, request.expectations, request.checkedAt, 'first_response', 'First valid response.'));
    throw new Error('Later dispatch failure cannot replace a settled result.');
  });
  const job = runBrowserVerification(file(), {}, { createWorker: () => value.worker, timeoutMs: 10 });
  assert.equal((await job.promise).code, 'first_response');
  context.mock.timers.tick(20);
  job.cancel();
  clean(value);
});

test('message, error, cancellation, and timeout races settle exactly once in each deterministic order', async context => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  for (const first of ['message', 'error', 'messageerror', 'cancel', 'timeout'] as const) {
    const value = fixture();
    const job = runBrowserVerification(file(), {}, { createWorker: () => value.worker, timeoutMs: 10 });
    const handlers = { message: value.worker.onmessage!, error: value.worker.onerror!, messageerror: value.worker.onmessageerror! };
    const actions = {
      message: () => handlers.message.call(value.worker as unknown as Worker, new MessageEvent('message', { data: value.response() })),
      error: () => handlers.error.call(value.worker as unknown as Worker, {} as ErrorEvent),
      messageerror: () => handlers.messageerror.call(value.worker as unknown as Worker, new MessageEvent('messageerror')),
      cancel: () => job.cancel(), timeout: () => context.mock.timers.tick(10),
    };
    actions[first]();
    const settled = await job.promise;
    for (const action of Object.values(actions)) action();
    assert.equal(await job.promise, settled);
    const codes = { message: 'synthetic_incomplete', error: 'browser_worker_error', messageerror: 'browser_result_unavailable', cancel: 'browser_cancelled', timeout: 'browser_timeout' };
    assert.equal(settled.code, codes[first]);
    assert.equal(settled.outcome, first === 'cancel' ? 'cancelled' : 'could_not_check');
    clean(value);
  }
});

test('100 fresh jobs cannot reuse prior cancellation, callbacks, expectations, or timeout state', async context => {
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const priorCallbacks: Array<() => void> = [];
  for (let index = 0; index < 100; index++) {
    const value = fixture();
    const expectations = { bundleSha256: index.toString(16).padStart(64, '0') };
    const job = runBrowserVerification(file(), expectations, { createWorker: () => value.worker, timeoutMs: 5 });
    const callback = value.worker.onmessage!;
    const response = value.response();
    priorCallbacks.push(() => callback.call(value.worker as unknown as Worker, new MessageEvent('message', { data: response })));
    expectations.bundleSha256 = 'f'.repeat(64); // The request owns its original comparison snapshot.
    if (index % 3 === 0) value.emit(response);
    else if (index % 3 === 1) job.cancel();
    else context.mock.timers.tick(5);
    const result = await job.promise;
    for (const late of priorCallbacks.slice(-4)) late();
    job.cancel();
    assert.equal(await job.promise, result);
    assert.equal(result.expectations.bundleSha256, index.toString(16).padStart(64, '0'));
    assert.equal(result.code, ['synthetic_incomplete', 'browser_cancelled', 'browser_timeout'][index % 3]);
    clean(value);
  }
  context.mock.timers.tick(1000);
  for (const late of priorCallbacks) late();
});

test('invalid input sizes do not construct a worker or access any file-reading API', async () => {
  for (const size of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, BROWSER_INPUT_LIMIT + 1]) {
    let starts = 0, reads = 0;
    const input = { name: 'synthetic.zip', size };
    for (const name of ['arrayBuffer', 'bytes', 'stream', 'text', 'slice']) Object.defineProperty(input, name, { get() { reads++; throw new Error('Input must remain unread.'); } });
    const job = runBrowserVerification(input as File, {}, { createWorker: () => { starts++; throw new Error('Worker must not start.'); } });
    assert.equal((await job.promise).code, 'browser_input_limit');
    job.cancel();
    assert.equal(starts, 0);
    assert.equal(reads, 0);
  }
  for (const size of [0, BROWSER_INPUT_LIMIT]) {
    const value = fixture();
    const input = { name: 'bounded-size.zip', size, arrayBuffer() { throw new Error('Main thread must not read.'); } } as unknown as File;
    const job = runBrowserVerification(input, {}, { createWorker: () => value.worker });
    assert.equal(value.input().file, input);
    job.cancel();
    assert.equal((await job.promise).outcome, 'cancelled');
    clean(value);
  }
});

const request = { fileName: 'diagnostics.zip', checkedAt: '2026-09-19T00:00:00Z', expectations: {} };
function diagnostic(details: unknown = {}): CheckResult {
  const result = browserFailure(request.fileName, {}, request.checkedAt, 'bounded_diagnostic', 'No completed verification.');
  result.layers.push({ layer: 'capability', status: 'unsupported', code: 'bounded_diagnostic', message: 'Unavailable.', details });
  return result;
}
function nested(depth: number): unknown { let value: unknown = null; for (let index = 0; index < depth; index++) value = { child: value }; return value; }

test('diagnostic depth, per-value string, property-name, and overall node limits are exact', () => {
  for (const details of [nested(8), 'x'.repeat(16384), { ['x'.repeat(128)]: null }, Array(1999).fill(null)]) assert.doesNotThrow(() => parseBrowserResult(diagnostic(details), request));
  const cyclic: Record<string, unknown> = {}; cyclic.child = cyclic;
  for (const details of [nested(9), 'x'.repeat(16385), { ['x'.repeat(129)]: null }, Array(2000).fill(null), cyclic, NaN, Infinity, 1n, () => {}, Symbol('x')]) {
    assert.throws(() => parseBrowserResult(diagnostic(details), request));
  }
});

test('diagnostic node budget is shared across layers and the 64-layer envelope cap is enforced', () => {
  const result = diagnostic(Array(999).fill(null));
  result.layers.push({ ...result.layers[0], details: Array(999).fill(null) });
  assert.doesNotThrow(() => parseBrowserResult(result, request)); // Two roots plus 1998 leaves.
  (result.layers[1].details as unknown[]).push(null);
  assert.throws(() => parseBrowserResult(result, request));
  const many = diagnostic();
  many.layers = Array.from({ length: 64 }, () => ({ ...many.layers[0], details: {} }));
  assert.doesNotThrow(() => parseBrowserResult(many, request));
  many.layers.push({ ...many.layers[0] });
  assert.throws(() => parseBrowserResult(many, request));
});

test('diagnostic message and token lengths reject off-by-one, controls, and fake framing', () => {
  const result = diagnostic();
  result.message = result.layers[0].message = 'x'.repeat(16384);
  result.code = result.layers[0].code = result.layers[0].layer = 'a'.repeat(128);
  assert.doesNotThrow(() => parseBrowserResult(result, request));
  for (const value of ['', 'a'.repeat(129), 'code\n', 'code\r', 'CODE', '../path', 'code\u0000']) {
    assert.throws(() => parseBrowserResult({ ...result, code: value }, request));
    assert.throws(() => parseBrowserResult({ ...result, layers: [{ ...result.layers[0], code: value }] }, request));
  }
  for (const value of ['', 'x'.repeat(16385)]) {
    assert.throws(() => parseBrowserResult({ ...result, message: value }, request));
    assert.throws(() => parseBrowserResult({ ...result, layers: [{ ...result.layers[0], message: value }] }, request));
  }
});
