// SPDX-License-Identifier: GPL-2.0-or-later
// Compatibility port of the frozen portable verifier's Zip_Reader.php. No extraction.
import { sha256 } from './bytes';
import { VerifierError } from './errors';

export const MAX_PACKAGE_BYTES = 134217728;
const MAX_ENTRIES = 16384;
const MAX_PATH = 240;
const EOCD_SIZE = 22;

type Entry = { size: number; crc: number; localOffset: number; dataOffset: number };
function fail(code: string, message: string, input = false): never {
  throw new VerifierError(code, message, input ? 'input' : 'invalid');
}

const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, byte) => {
  let crc = byte;
  for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  return crc >>> 0;
});
function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 255];
  return (crc ^ 0xffffffff) >>> 0;
}

/** A private, immutable byte snapshot of the deterministic STORE-only ZIP profile. */
export class StrictZip {
  readonly #bytes: Uint8Array;
  readonly #view: DataView;
  readonly #entries = new Map<string, Entry>();

  private constructor(bytes: Uint8Array) {
    this.#bytes = new Uint8Array(bytes);
    this.#view = new DataView(this.#bytes.buffer);
  }

  static parse(bytes: Uint8Array): StrictZip {
    if (bytes.byteLength < EOCD_SIZE) fail('bundle_file', 'The bundle is too short to be a ZIP archive.', true);
    if (bytes.byteLength > MAX_PACKAGE_BYTES) fail('zip_archive_limit', 'The bundle archive exceeds the 128 MiB limit.');
    const zip = new StrictZip(bytes);
    zip.parse();
    return zip;
  }

  paths(): string[] { return Array.from(this.#entries.keys()); }
  has(path: string): boolean { return this.#entries.has(path); }
  entry(path: string): { size: number } { return { size: this.metadata(path).size }; }
  read(path: string, maximum = MAX_PACKAGE_BYTES): Uint8Array {
    const entry = this.metadata(path);
    if (maximum < 0 || entry.size > maximum) fail('zip_entry_limit', `A bundle entry exceeds its profile-specific size limit: ${path}`);
    return this.readAt(entry.dataOffset, entry.size).slice();
  }
  async sha256(path: string): Promise<string> {
    const entry = this.metadata(path);
    return sha256(this.readAt(entry.dataOffset, entry.size));
  }

  private metadata(path: string): Entry {
    const entry = this.#entries.get(path);
    if (!entry) fail('zip_entry_missing', `A required bundle entry is missing: ${path}`);
    return entry;
  }

  private readAt(offset: number, length: number): Uint8Array {
    if (offset < 0 || length < 0 || offset + length > this.#bytes.byteLength) {
      fail('bundle_bounds', 'The bundle contains or requested an unreadable byte range.', true);
    }
    return this.#bytes.subarray(offset, offset + length);
  }
  private u16(offset: number): number { return this.#view.getUint16(offset, true); }
  private u32(offset: number): number { return this.#view.getUint32(offset, true); }
  private signature(offset: number, signature: number): boolean { return this.u32(offset) === signature; }
  private nameAt(offset: number, length: number): string {
    const bytes = this.readAt(offset, length);
    // A byte-preserving string is needed here: non-ASCII bytes must fail path validation.
    let name = '';
    for (const byte of bytes) name += String.fromCharCode(byte);
    return name;
  }

  private validatePath(path: string): void {
    if (!path || path.length > MAX_PATH || path.endsWith('/') || (path !== 'VERIFY.txt' && /[^a-z0-9._/-]/.test(path)) || path.includes('\\') || path.includes(':') || path.startsWith('/')) {
      fail('zip_path_unsafe', 'The ZIP contains an unsafe or non-ASCII path.');
    }
    for (const segment of path.split('/')) {
      if (!segment || segment === '.' || segment === '..' || /[. ]$/.test(segment)) {
        fail('zip_path_segment', 'The ZIP contains an empty, dot, or Windows-ambiguous path segment.');
      }
      if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(segment.split('.', 1)[0].toUpperCase())) {
        fail('zip_path_device', 'The ZIP contains a Windows device-name path segment.');
      }
    }
  }

  private parse(): void {
    const end = this.#bytes.byteLength - EOCD_SIZE;
    if (!this.signature(end, 0x06054b50)) fail('zip_eocd', 'The input is not an exact classic ContentLedger ZIP bundle.', true);
    const count = this.u16(end + 10);
    const centralSize = this.u32(end + 12);
    const centralOffset = this.u32(end + 16);
    if (this.u16(end + 4) !== 0 || this.u16(end + 6) !== 0 || this.u16(end + 8) !== count || count === 0 || count > MAX_ENTRIES || count === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff || this.u16(end + 20) !== 0) {
      fail('zip_eocd_profile', 'The ZIP uses multidisk, ZIP64, comments, an empty archive, or an unsupported entry count.');
    }
    if (centralOffset + centralSize !== end) fail('zip_trailing_data', 'The ZIP central directory boundary is invalid or the archive contains trailing data.');

    let position = centralOffset;
    let totalBytes = 0;
    let lastPath: string | null = null;
    let expectedLocalOffset = 0;
    for (let index = 0; index < count; index += 1) {
      if (position + 46 > end) fail('zip_central_truncated', 'The ZIP central directory is truncated.');
      if (!this.signature(position, 0x02014b50)) fail('zip_central_signature', 'The ZIP central directory contains an invalid entry signature.');
      const nameLength = this.u16(position + 28);
      const extraLength = this.u16(position + 30);
      const commentLength = this.u16(position + 32);
      const recordSize = 46 + nameLength + extraLength + commentLength;
      if (position + recordSize > end) fail('zip_central_truncated', 'A ZIP central-directory entry is truncated.');
      const name = this.nameAt(position + 46, nameLength);
      this.validatePath(name);
      if (lastPath !== null && lastPath >= name) fail('zip_path_order', 'ZIP entries are not in strict bytewise path order.');
      if (this.#entries.has(name) || (name === 'VERIFY.txt' ? this.#entries.has('verify.txt') : name === 'verify.txt' && this.#entries.has('VERIFY.txt'))) {
        fail('zip_path_collision', 'The ZIP contains an exact, case-insensitive, or Windows-normalized path collision.');
      }
      lastPath = name;
      const segments = name.split('/');
      for (let part = 1; part < segments.length; part += 1) {
        if (this.#entries.has(segments.slice(0, part).join('/'))) fail('zip_file_prefix_collision', 'A ZIP file path is also used as a parent directory.');
      }
      const size = this.u32(position + 24);
      const localOffset = this.u32(position + 42);
      if (this.u16(position + 8) !== 0 || this.u16(position + 10) !== 0 || this.u16(position + 12) !== 0 || this.u16(position + 14) !== 33 || extraLength !== 0 || commentLength !== 0 || this.u16(position + 34) !== 0 || this.u32(position + 20) !== size || size === 0xffffffff || localOffset === 0xffffffff || this.u16(position + 6) !== 10 || this.u16(position + 4) !== 0x0314 || this.u16(position + 36) !== 0 || this.u32(position + 38) !== 0x81a40000 || localOffset !== expectedLocalOffset) {
        fail('zip_entry_profile', 'A ZIP entry uses compression, encryption, flags, timestamps, extras, comments, ZIP64, or another unsupported feature.');
      }
      // Exact version/attribute values above imply a Unix regular file, never a symlink/directory/device.
      totalBytes += size;
      if (totalBytes > MAX_PACKAGE_BYTES) fail('zip_total_limit', 'The total uncompressed bundle payload exceeds 128 MiB.');
      this.#entries.set(name, { size, crc: this.u32(position + 16), localOffset, dataOffset: 0 });
      expectedLocalOffset += 30 + nameLength + size;
      position += recordSize;
    }
    if (position !== end) fail('zip_central_size', 'The ZIP central directory size is inconsistent.');

    let expectedOffset = 0;
    for (const [name, meta] of this.#entries) {
      const offset = meta.localOffset;
      if (offset !== expectedOffset || offset + 30 > centralOffset) fail('zip_local_layout', 'The ZIP has overlapping, reordered, prefixed, or hidden local-entry data.');
      if (!this.signature(offset, 0x04034b50)) fail('zip_local_signature', 'A ZIP local entry has an invalid signature.');
      const localName = this.nameAt(offset + 30, this.u16(offset + 26));
      if (name !== localName || this.u16(offset + 28) !== 0 || this.u16(offset + 4) !== 10 || this.u16(offset + 6) !== 0 || this.u16(offset + 8) !== 0 || this.u16(offset + 10) !== 0 || this.u16(offset + 12) !== 33 || this.u32(offset + 14) !== meta.crc || this.u32(offset + 18) !== meta.size || this.u32(offset + 22) !== meta.size) {
        fail('zip_local_central_mismatch', 'A ZIP local entry does not exactly match its central-directory record.');
      }
      const dataOffset = offset + 30 + localName.length;
      const dataEnd = dataOffset + meta.size;
      if (dataEnd > centralOffset) fail('zip_local_bounds', 'A ZIP entry extends into the central directory.');
      if (crc32(this.readAt(dataOffset, meta.size)) !== meta.crc) fail('zip_crc', `A ZIP entry failed its CRC-32 check: ${name}`);
      meta.dataOffset = dataOffset;
      expectedOffset = dataEnd;
    }
    if (expectedOffset !== centralOffset) fail('zip_hidden_data', 'The ZIP contains unaccounted bytes before its central directory.');
  }
}
