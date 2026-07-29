/**
 * SAMPLE-AES / CENC decryption of fMP4 media segments.
 *
 * For every `traf` in the segment we need three things:
 *   - `tfhd`: which track this is, and where its sample data starts
 *   - `trun`: the size of each sample, in order
 *   - `senc`: the per-sample IV and the clear/protected byte map
 * With those, each sample's protected ranges are decrypted in place.
 *
 * Scheme notes (ISO/IEC 23001-7):
 *   cbcs, no pattern (crypt_byte_block == 0) - AES-CBC over the whole
 *     protected range. This is what audio tracks normally use.
 *   cbcs, 1:9 pattern - one encrypted 16-byte block followed by nine clear
 *     ones. CBC chaining continues *across* the skipped blocks, and the IV is
 *     reset at the start of each subsample. This matches Apple's original
 *     SAMPLE-AES scheme for TS (see `src/demux/sample-aes.ts`, which gathers
 *     the 1-in-10 blocks into one buffer and runs a single CBC pass over them).
 *   A trailing partial 16-byte block is always left in the clear.
 */

import AesCbcDecryptor, { BLOCK_SIZE } from './aes-cbc';
import {
  type Box,
  copyBytes,
  findBoxes,
  neutralizeBox,
  readSint32,
  readUint16,
  readUint32,
} from './mp4-boxes';
import type { TrackEncryption } from './init-segment';

// tfhd flags (ISO/IEC 14496-12 §8.8.7)
const TFHD_BASE_DATA_OFFSET = 0x000001;
const TFHD_SAMPLE_DESCRIPTION_INDEX = 0x000002;
const TFHD_DEFAULT_SAMPLE_DURATION = 0x000008;
const TFHD_DEFAULT_SAMPLE_SIZE = 0x000010;

// trun flags (ISO/IEC 14496-12 §8.8.8)
const TRUN_DATA_OFFSET = 0x000001;
const TRUN_FIRST_SAMPLE_FLAGS = 0x000004;
const TRUN_SAMPLE_DURATION = 0x000100;
const TRUN_SAMPLE_SIZE = 0x000200;
const TRUN_SAMPLE_FLAGS = 0x000400;
const TRUN_SAMPLE_CTS = 0x000800;

// senc flags
const SENC_USE_SUBSAMPLES = 0x000002;

const boxFlags = (data: Uint8Array, offset: number): number =>
  readUint32(data, offset) & 0xffffff;

interface Subsample {
  clearBytes: number;
  protectedBytes: number;
}

interface SencEntry {
  iv: Uint8Array | null;
  subsamples: Subsample[] | null;
}

interface Tfhd {
  trackId: number;
  baseDataOffset: number;
  defaultSampleSize: number;
}

interface SampleRange {
  offset: number;
  size: number;
}

/**
 * Parse a `senc` box into one entry per sample.
 *
 * Layout: version+flags, sample_count, then per sample an IV of
 * `ivSize` bytes and - when the subsample flag is set - a list of
 * (clearBytes:uint16, protectedBytes:uint32) pairs.
 *
 * When the track uses a constant IV, `ivSize` is 0 and the box carries no IVs.
 */
function parseSenc(data: Uint8Array, senc: Box, ivSize: number): SencEntry[] {
  const flags = boxFlags(data, senc.dataStart);
  const useSubsamples = (flags & SENC_USE_SUBSAMPLES) !== 0;
  const sampleCount = readUint32(data, senc.dataStart + 4);
  const entries: SencEntry[] = [];
  let offset = senc.dataStart + 8;

  for (let i = 0; i < sampleCount && offset <= senc.dataEnd; i++) {
    let iv: Uint8Array | null = null;
    if (ivSize > 0) {
      iv = data.slice(offset, offset + ivSize);
      offset += ivSize;
    }
    let subsamples: Subsample[] | null = null;
    if (useSubsamples) {
      const count = readUint16(data, offset);
      offset += 2;
      subsamples = [];
      for (let j = 0; j < count; j++) {
        subsamples.push({
          clearBytes: readUint16(data, offset),
          protectedBytes: readUint32(data, offset + 2),
        });
        offset += 6;
      }
    }
    entries.push({ iv, subsamples });
  }
  return entries;
}

/** Read `tfhd`: track id, base data offset and the default sample size. */
function parseTfhd(data: Uint8Array, tfhd: Box, moofStart: number): Tfhd {
  const flags = boxFlags(data, tfhd.dataStart);
  let offset = tfhd.dataStart + 8; // version+flags, track_ID
  const trackId = readUint32(data, tfhd.dataStart + 4);

  // `default-base-is-moof` (0x020000) is what CMAF/HLS packagers emit; when
  // neither that nor an explicit offset is present, the moof start is still
  // the only sane base for a single-fragment segment.
  let baseDataOffset = moofStart;
  if (flags & TFHD_BASE_DATA_OFFSET) {
    baseDataOffset =
      readUint32(data, offset) * 4294967296 + readUint32(data, offset + 4);
    offset += 8;
  }
  if (flags & TFHD_SAMPLE_DESCRIPTION_INDEX) {
    offset += 4;
  }
  if (flags & TFHD_DEFAULT_SAMPLE_DURATION) {
    offset += 4;
  }
  const defaultSampleSize =
    flags & TFHD_DEFAULT_SAMPLE_SIZE ? readUint32(data, offset) : 0;

  return { trackId, baseDataOffset, defaultSampleSize };
}

/**
 * Walk a `trun` and yield `{ offset, size }` for each sample.
 * `cursor` is where the previous trun's data ended, used when this trun has no
 * explicit data offset.
 */
function trunSamples(
  data: Uint8Array,
  trun: Box,
  baseDataOffset: number,
  defaultSampleSize: number,
  cursor: number
): SampleRange[] {
  const flags = boxFlags(data, trun.dataStart);
  const sampleCount = readUint32(data, trun.dataStart + 4);
  let field = trun.dataStart + 8;

  let position = cursor;
  if (flags & TRUN_DATA_OFFSET) {
    // signed, and relative to base_data_offset
    position = baseDataOffset + readSint32(data, field);
    field += 4;
  }
  if (flags & TRUN_FIRST_SAMPLE_FLAGS) {
    field += 4;
  }

  const samples: SampleRange[] = [];
  for (let i = 0; i < sampleCount; i++) {
    if (flags & TRUN_SAMPLE_DURATION) {
      field += 4;
    }
    let size = defaultSampleSize;
    if (flags & TRUN_SAMPLE_SIZE) {
      size = readUint32(data, field);
      field += 4;
    }
    if (flags & TRUN_SAMPLE_FLAGS) {
      field += 4;
    }
    if (flags & TRUN_SAMPLE_CTS) {
      field += 4;
    }
    samples.push({ offset: position, size });
    position += size;
  }
  return samples;
}

export default class SegmentDecrypter {
  private aes: AesCbcDecryptor;
  private encryption: Map<number, TrackEncryption>;
  private iv: Uint8Array;
  private scratch: Uint8Array;

  /**
   * @param key raw 16-byte content key
   * @param encryption per-track defaults from the init segment's `tenc` boxes
   */
  constructor(key: Uint8Array, encryption: Map<number, TrackEncryption>) {
    this.aes = new AesCbcDecryptor(key);
    this.encryption = encryption;
    this.iv = new Uint8Array(BLOCK_SIZE);
    this.scratch = new Uint8Array(0);
  }

  /**
   * Decrypt a media segment.
   * @returns a decrypted copy, ready to append to a SourceBuffer
   */
  decrypt(segment: Uint8Array): Uint8Array {
    const data = copyBytes(segment);
    for (const moof of findBoxes(data, ['moof'])) {
      for (const traf of findBoxes(
        data,
        ['traf'],
        moof.dataStart,
        moof.dataEnd
      )) {
        // prettier-ignore
        this.decryptTraf(data, traf, moof.start);
      }
    }
    return data;
  }

  private decryptTraf(data: Uint8Array, traf: Box, moofStart: number): void {
    const [tfhd] = findBoxes(data, ['tfhd'], traf.dataStart, traf.dataEnd);
    if (!tfhd) {
      return;
    }
    const { trackId, baseDataOffset, defaultSampleSize } = parseTfhd(
      data,
      tfhd,
      moofStart
    );
    const defaults = this.encryption.get(trackId);
    if (!defaults) {
      return; // this track is in the clear
    }

    const [senc] = findBoxes(data, ['senc'], traf.dataStart, traf.dataEnd);
    if (!senc) {
      return;
    }
    const entries = parseSenc(data, senc, defaults.ivSize);

    // Collect samples across every trun in this traf, in order.
    let cursor = baseDataOffset;
    const samples: SampleRange[] = [];
    for (const trun of findBoxes(
      data,
      ['trun'],
      traf.dataStart,
      traf.dataEnd
    )) {
      const runSamples = trunSamples(data, trun, baseDataOffset, defaultSampleSize, cursor); // prettier-ignore
      samples.push(...runSamples);
      if (runSamples.length) {
        const last = runSamples[runSamples.length - 1];
        cursor = last.offset + last.size;
      }
    }

    for (let i = 0; i < samples.length; i++) {
      const entry = entries[i];
      const { offset, size } = samples[i];
      if (!entry || !size) {
        continue;
      }
      this.decryptSample(data, offset, size, entry, defaults);
    }

    // MSE must not see the protection metadata, or it will ask for a CDM.
    // Renaming keeps every byte offset intact.
    for (const type of ['senc', 'saiz', 'saio']) {
      for (const box of findBoxes(data, [type], traf.dataStart, traf.dataEnd)) {
        neutralizeBox(data, box);
      }
    }
  }

  private decryptSample(
    data: Uint8Array,
    sampleStart: number,
    sampleSize: number,
    entry: SencEntry,
    defaults: TrackEncryption
  ): void {
    // Per-sample IV from senc, or the track-wide constant IV from tenc.
    // Short IVs (8 bytes) are right-padded with zeros to a full AES block.
    const source = defaults.ivSize > 0 ? entry.iv : defaults.constantIv;
    if (!source?.length) {
      return;
    }
    const iv = this.iv;
    iv.fill(0);
    iv.set(source.subarray(0, BLOCK_SIZE));

    const { cryptByteBlock, skipByteBlock } = defaults;

    if (!entry.subsamples) {
      // Whole sample is protected.
      this.decryptRange(data, sampleStart, sampleSize, iv, cryptByteBlock, skipByteBlock); // prettier-ignore
      return;
    }

    let position = sampleStart;
    for (const { clearBytes, protectedBytes } of entry.subsamples) {
      position += clearBytes;
      if (protectedBytes > 0) {
        // The IV is reset for every subsample.
        this.decryptRange(data, position, protectedBytes, iv, cryptByteBlock, skipByteBlock); // prettier-ignore
        position += protectedBytes;
      }
    }
  }

  /** Decrypt one protected range, honouring the crypt/skip pattern. */
  private decryptRange(
    data: Uint8Array,
    start: number,
    length: number,
    iv: Uint8Array,
    cryptByteBlock: number,
    skipByteBlock: number
  ): void {
    if (!cryptByteBlock) {
      // No pattern: straight CBC over every whole block in the range.
      this.aes.decrypt(data, start, length, iv);
      return;
    }

    const cryptBytes = cryptByteBlock * BLOCK_SIZE;
    const skipBytes = skipByteBlock * BLOCK_SIZE;

    // Gather the encrypted stripes, decrypt them as one CBC stream (chaining
    // runs across the skipped blocks), then scatter the plaintext back.
    const stripes: SampleRange[] = [];
    let gathered = 0;
    for (let p = 0; p + BLOCK_SIZE <= length; p += cryptBytes + skipBytes) {
      const available = length - p;
      const take = Math.min(cryptBytes, available - (available % BLOCK_SIZE));
      if (take < BLOCK_SIZE) {
        break;
      }
      stripes.push({ offset: start + p, size: take });
      gathered += take;
    }
    if (!gathered) {
      return;
    }

    if (this.scratch.length < gathered) {
      this.scratch = new Uint8Array(gathered);
    }
    const scratch = this.scratch;

    let write = 0;
    for (const stripe of stripes) {
      scratch.set(data.subarray(stripe.offset, stripe.offset + stripe.size), write); // prettier-ignore
      write += stripe.size;
    }

    this.aes.decrypt(scratch, 0, gathered, iv);

    let read = 0;
    for (const stripe of stripes) {
      data.set(scratch.subarray(read, read + stripe.size), stripe.offset);
      read += stripe.size;
    }
  }
}
