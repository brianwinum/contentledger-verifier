import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const tokens = Object.fromEntries([...readFileSync(new URL('./tokens.css', import.meta.url), 'utf8').matchAll(/(--[\w-]+):\s*(#[a-f0-9]{6});/gi)].map(([, name, value]) => [name, value.toLowerCase()]));

function luminance(name: string): number {
  const hex = tokens[name];
  assert.ok(hex, `Missing color token ${name}`);
  const channels = [1, 3, 5].map(offset => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255).map(channel => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrast(foreground: string, background: string): number {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

test('brand colors use the supplied palette independently of result semantics', () => {
  assert.equal(tokens['--ink'], '#111111');
  assert.equal(tokens['--muted'], '#555555');
  assert.equal(tokens['--paper'], '#ffffff');
  assert.equal(tokens['--brand-accent'], '#b3251e');
  for (const state of ['positive', 'limited', 'negative']) assert.notEqual(tokens[`--status-${state}-ink`], tokens['--brand-accent']);
});

test('text, links, and primary button labels maintain normal-text contrast', () => {
  const pairs = [
    ['--ink', '--paper'], ['--muted', '--paper'], ['--muted', '--surface-soft'], ['--muted', '--surface-muted'],
    ['--brand-accent', '--paper'], ['--brand-accent', '--surface-soft'], ['--paper', '--brand-accent'], ['--paper', '--brand-accent-hover'],
    ['--status-positive-ink', '--status-positive-background'], ['--status-limited-ink', '--status-limited-background'], ['--status-negative-ink', '--status-negative-background'],
    ['--muted', '--status-limited-background'], ['--muted', '--status-negative-background'],
  ];
  for (const [foreground, background] of pairs) assert.ok(contrast(foreground, background) >= 4.5, `${foreground} on ${background} needs 4.5:1 contrast`);
});

test('focus rings and control boundaries remain visible on their adjacent surfaces', () => {
  for (const background of ['--paper', '--surface-soft', '--surface-muted', '--status-limited-background', '--status-negative-background']) {
    assert.ok(contrast('--focus', background) >= 3, `Focus indicator on ${background} needs 3:1 contrast`);
  }
  for (const background of ['--paper', '--surface-soft']) assert.ok(contrast('--control-border', background) >= 3, `Control border on ${background} needs 3:1 contrast`);
});
