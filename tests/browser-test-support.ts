// SPDX-License-Identifier: GPL-2.0-or-later
// Test-only mutation helpers. They are deliberately independent of the browser
// reader/canonicalizer, and never ship in the static application.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export type FixtureEntries = Map<string, Buffer>;

export function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function fixtureEntries(bytes: Buffer): FixtureEntries {
  const entries: FixtureEntries = new Map();
  const end = bytes.length - 22;
  assert.equal(bytes.readUInt32LE(end), 0x06054b50, 'Expected a generated classic-ZIP fixture.');
  let cursor = bytes.readUInt32LE(end + 16);
  const count = bytes.readUInt16LE(end + 10);
  for (let index = 0; index < count; index++) {
    assert.equal(bytes.readUInt32LE(cursor), 0x02014b50);
    assert.equal(bytes.readUInt16LE(cursor + 10), 0, 'Test mutation only supports STORE fixtures.');
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameLength).toString('ascii');
    const size = bytes.readUInt32LE(cursor + 24);
    const local = bytes.readUInt32LE(cursor + 42);
    const start = local + 30 + bytes.readUInt16LE(local + 26) + bytes.readUInt16LE(local + 28);
    entries.set(name, Buffer.from(bytes.subarray(start, start + size)));
    cursor += 46 + nameLength + bytes.readUInt16LE(cursor + 30) + bytes.readUInt16LE(cursor + 32);
  }
  return entries;
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Repack public fixture bytes only, without invoking the private exporter. */
export function fixtureZip(entries: FixtureEntries): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [path, bytes] of [...entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    const name = Buffer.from(path, 'ascii');
    const crc = crc32(bytes);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(10, 4);
    local.writeUInt16LE(33, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(bytes.length, 18);
    local.writeUInt32LE(bytes.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, bytes);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50);
    header.writeUInt16LE(0x0314, 4);
    header.writeUInt16LE(10, 6);
    header.writeUInt16LE(33, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(bytes.length, 20);
    header.writeUInt32LE(bytes.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt32LE(0x81a40000, 38);
    header.writeUInt32LE(offset, 42);
    central.push(header, name);
    offset += local.length + name.length + bytes.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.size, 8);
  end.writeUInt16LE(entries.size, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

// Only controlled test objects are accepted here, not arbitrary evidence JSON.
export function fixtureCanonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(fixtureCanonical).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${fixtureCanonical(object[key])}`).join(',')}}`;
}

export interface FixtureInventoryEntry { path: string; size: number; sha256: string; mediaType: string }
export interface FixtureInventory { entries: FixtureInventoryEntry[]; [key: string]: unknown }

export function fixtureInventory(entries: FixtureEntries): FixtureInventory {
  return JSON.parse(entries.get('inventory.json')!.toString('utf8')) as FixtureInventory;
}

export function replaceInventory(entries: FixtureEntries, document: FixtureInventory): void {
  const bytes = Buffer.from(fixtureCanonical(document));
  entries.set('inventory.json', bytes);
  replaceSidecar(entries);
}

export function replaceSidecar(entries: FixtureEntries): void {
  entries.set('inventory.sha256', Buffer.from(`${sha256(entries.get('inventory.json')!)}  inventory.json\n`));
}

export function refreshInventory(entries: FixtureEntries): void {
  const document = fixtureInventory(entries);
  document.entries = document.entries.filter(entry => entries.has(entry.path)).map(entry => {
    const bytes = entries.get(entry.path)!;
    return { ...entry, size: bytes.length, sha256: sha256(bytes) };
  });
  replaceInventory(entries, document);
}
