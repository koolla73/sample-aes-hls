/**
 * fMP4 init segment handling: read the track/codec/encryption description out
 * of `moov`, and rewrite the segment so MSE will accept it without EME.
 *
 * Mirrors `parseInitSegment()` / `stripEncryptionFromInitSegment()` in
 * `src/utils/mp4-tools.ts`, reduced to what SAMPLE-AES playback needs.
 */

import {
  type Box,
  copyBytes,
  findBox,
  findBoxes,
  fourCC,
  listBoxes,
  neutralizeBox,
  readUint32,
} from './mp4-boxes';

// Byte counts of the fixed fields at the start of a sample entry, i.e. where
// the codec-specific child boxes (esds, avcC, sinf, ...) begin. Keyed by track
// handler, so it applies equally to `mp4a`/`enca` and `avc1`/`encv` entries.
const SAMPLE_ENTRY_HEADER: Record<string, number> = {
  audio: 28, // AudioSampleEntry
  video: 78, // VisualSampleEntry
};

// The same, keyed by the four-character code of an encrypted sample entry.
const ENCRYPTED_SAMPLE_ENTRY: Record<string, number> = {
  enca: 28,
  encv: 78,
};

export interface TrackEncryption {
  scheme: 'cbcs' | 'cenc';
  /** number of encrypted 16-byte blocks per pattern cycle (0 = encrypt everything) */
  cryptByteBlock: number;
  /** number of clear 16-byte blocks per pattern cycle */
  skipByteBlock: number;
  /** per-sample IV size in bytes; 0 means `constantIv` is used */
  ivSize: number;
  constantIv: Uint8Array | null;
}

export interface Track {
  id: number;
  type: 'audio' | 'video' | string;
  timescale: number;
  /** RFC 6381 codec string, e.g. `mp4a.40.2` */
  codec: string;
  encryption: TrackEncryption | null;
}

export interface ParsedInitSegment {
  tracks: Track[];
  encrypted: boolean;
  mimeType: string;
}

const toHex = (v: number): string => v.toString(16).padStart(2, '0');

/** Skip a BER/MP4-style variable-length integer, returning the next offset. */
function skipDescriptorLength(data: Uint8Array, offset: number): number {
  while (data[offset++] & 0x80) {
    /* continuation bit set */
  }
  return offset;
}

/** `mp4a` -> `mp4a.40.2` (object type indication + audio object type). */
function mp4aCodec(
  data: Uint8Array,
  entry: Box,
  childrenStart: number
): string {
  const esds = findBox(data, ['esds'], childrenStart, entry.dataEnd);
  if (!esds) {
    return 'mp4a';
  }
  let i = esds.dataStart + 4; // version + flags
  if (data[i++] !== 0x03) {
    return 'mp4a';
  }
  i = skipDescriptorLength(data, i);
  i += 2; // ES_ID
  const flags = data[i++];
  if (flags & 0x80) {
    i += 2; // dependsOn_ES_ID
  }
  if (flags & 0x40) {
    i += data[i] + 1; // URL
  }
  if (flags & 0x20) {
    i += 2; // OCR_ES_Id
  }
  if (data[i++] !== 0x04) {
    return 'mp4a';
  }
  i = skipDescriptorLength(data, i);
  const objectTypeIndication = data[i++];
  let codec = `mp4a.${toHex(objectTypeIndication)}`;
  // streamType(1) + bufferSizeDB(3) + maxBitrate(4) + avgBitrate(4)
  i += 12;
  if (data[i++] !== 0x05) {
    return codec;
  }
  i = skipDescriptorLength(data, i);
  // AudioSpecificConfig: 5-bit audioObjectType (31 == escape to 6 more bits)
  let audioObjectType = data[i] >>> 3;
  if (audioObjectType === 31) {
    audioObjectType = 32 + (((data[i] & 0x07) << 3) | (data[i + 1] >>> 5));
  }
  codec += `.${audioObjectType}`;
  return codec;
}

/** `avc1` -> `avc1.640028` (profile + constraints + level from avcC). */
function avcCodec(
  data: Uint8Array,
  entry: Box,
  childrenStart: number,
  type: string
): string {
  const avcC = findBox(data, ['avcC'], childrenStart, entry.dataEnd);
  if (!avcC || avcC.dataEnd - avcC.dataStart < 4) {
    return type;
  }
  const p = avcC.dataStart;
  return `${type}.${toHex(data[p + 1])}${toHex(data[p + 2])}${toHex(data[p + 3])}`;
}

/**
 * Build the RFC 6381 codec string for a sample entry.
 * Only AAC and AVC are resolved in detail; anything else falls back to the
 * bare four-character code, which most browsers still accept for `avc3`-style
 * entries but not for HEVC/AC-3. See README for the trade-off.
 */
function codecString(
  data: Uint8Array,
  entry: Box,
  format: string,
  childrenStart: number
): string {
  switch (format) {
    case 'mp4a':
      return mp4aCodec(data, entry, childrenStart);
    case 'avc1':
    case 'avc2':
    case 'avc3':
    case 'avc4':
      return avcCodec(data, entry, childrenStart, format);
    default:
      return format;
  }
}

/** Read the `tenc` (Track Encryption) box out of a `sinf`. */
function parseSinf(data: Uint8Array, sinf: Box): TrackEncryption | null {
  const schm = findBox(data, ['schm'], sinf.dataStart, sinf.dataEnd);
  if (!schm) {
    return null;
  }
  const scheme = fourCC(data, schm.dataStart + 4);
  if (scheme !== 'cbcs' && scheme !== 'cenc') {
    return null;
  }
  const tenc = findBox(data, ['schi', 'tenc'], sinf.dataStart, sinf.dataEnd);
  if (!tenc) {
    return null;
  }

  // tenc payload:
  //   [0]     version
  //   [1..3]  flags
  //   [4]     reserved (v0) | crypt_byte_block << 4 | skip_byte_block (v>=1)
  //   [5]     reserved
  //   [6]     default_isProtected
  //   [7]     default_Per_Sample_IV_Size
  //   [8..23] default_KID
  //   if isProtected && ivSize == 0: [24] constant IV size, then the IV
  const p = tenc.dataStart;
  const version = data[p];
  const isProtected = data[p + 6];
  const ivSize = data[p + 7];
  let constantIv: Uint8Array | null = null;
  if (isProtected === 1 && ivSize === 0) {
    const size = data[p + 24];
    constantIv = data.slice(p + 25, p + 25 + size);
  }
  return {
    scheme,
    cryptByteBlock: version >= 1 ? (data[p + 4] >> 4) & 0x0f : 0,
    skipByteBlock: version >= 1 ? data[p + 4] & 0x0f : 0,
    ivSize,
    constantIv,
  };
}

/** Describe every track in an init segment. */
export function parseInitSegment(initSegment: Uint8Array): ParsedInitSegment {
  const data = initSegment;
  const tracks: Track[] = [];

  for (const trak of findBoxes(data, ['moov', 'trak'])) {
    const tkhd = findBox(data, ['tkhd'], trak.dataStart, trak.dataEnd);
    const mdhd = findBox(data, ['mdia', 'mdhd'], trak.dataStart, trak.dataEnd);
    const hdlr = findBox(data, ['mdia', 'hdlr'], trak.dataStart, trak.dataEnd);
    const stsd = findBox(
      data,
      ['mdia', 'minf', 'stbl', 'stsd'],
      trak.dataStart,
      trak.dataEnd
    );
    if (!tkhd || !mdhd || !hdlr || !stsd) {
      continue;
    }

    const id = readUint32(data, tkhd.dataStart + (data[tkhd.dataStart] === 0 ? 12 : 20)); // prettier-ignore
    const timescale = readUint32(data, mdhd.dataStart + (data[mdhd.dataStart] === 0 ? 12 : 20)); // prettier-ignore
    const handler = fourCC(data, hdlr.dataStart + 8);
    const type = { soun: 'audio', vide: 'video' }[handler] || handler;

    // stsd payload: version + flags + entry_count, then the sample entries.
    const entry = listBoxes(data, stsd.dataStart + 8, stsd.dataEnd)[0];
    if (!entry) {
      continue;
    }

    // Codec-specific boxes start after the fixed sample entry fields; the
    // offset depends on the track type, not on whether it is encrypted.
    const childrenStart = entry.dataStart + (SAMPLE_ENTRY_HEADER[type] ?? 0);

    let format = entry.type;
    let encryption: TrackEncryption | null = null;

    if (format === 'encv' || format === 'enca') {
      for (const sinf of findBoxes(
        data,
        ['sinf'],
        childrenStart,
        entry.dataEnd
      )) {
        // prettier-ignore
        const parsed = parseSinf(data, sinf);
        if (!parsed) {
          continue;
        }
        encryption = parsed;
        // The real codec four-character code lives in `sinf > frma`.
        const frma = findBox(data, ['frma'], sinf.dataStart, sinf.dataEnd);
        if (frma) {
          format = fourCC(data, frma.dataStart);
        }
        break;
      }
    }

    tracks.push({
      id,
      type,
      timescale,
      codec: codecString(data, entry, format, childrenStart),
      encryption,
    });
  }

  const playable = tracks.filter((t) => t.type === 'audio' || t.type === 'video'); // prettier-ignore
  const container = playable.some((t) => t.type === 'video')
    ? 'video'
    : 'audio';
  const codecs = playable.map((t) => t.codec).join(',');

  return {
    tracks,
    encrypted: tracks.some((t) => t.encryption !== null),
    mimeType: `${container}/mp4; codecs="${codecs}"`,
  };
}

/** Map of trackId -> encryption defaults, for the segment decrypter. */
export function encryptionByTrackId(
  parsed: ParsedInitSegment
): Map<number, TrackEncryption> {
  const map = new Map<number, TrackEncryption>();
  for (const track of parsed.tracks) {
    if (track.encryption) {
      map.set(track.id, track.encryption);
    }
  }
  return map;
}

/**
 * Remove the encryption wrapping from an init segment so MSE accepts it
 * without a CDM. Samples are decrypted in JS, so the browser must not be told
 * the content is protected.
 *
 *  1. `encv`/`enca` is renamed back to the original codec (from `sinf > frma`).
 *  2. `sinf` is renamed to `free`, keeping its size so offsets stay valid.
 *
 * @returns a modified copy; the input is not touched
 */
export function stripEncryption(initSegment: Uint8Array): Uint8Array {
  const data = copyBytes(initSegment);

  for (const trak of findBoxes(data, ['moov', 'trak'])) {
    const stsd = findBox(
      data,
      ['mdia', 'minf', 'stbl', 'stsd'],
      trak.dataStart,
      trak.dataEnd
    );
    if (!stsd) {
      continue;
    }
    for (const entry of listBoxes(data, stsd.dataStart + 8, stsd.dataEnd)) {
      const headerSize = ENCRYPTED_SAMPLE_ENTRY[entry.type];
      if (headerSize === undefined) {
        continue; // not an encrypted sample entry
      }
      const sinfs = findBoxes(
        data,
        ['sinf'],
        entry.dataStart + headerSize,
        entry.dataEnd
      );
      for (const sinf of sinfs) {
        const frma = findBox(data, ['frma'], sinf.dataStart, sinf.dataEnd);
        if (frma) {
          // encv/enca -> avc1/mp4a/...
          data.set(data.subarray(frma.dataStart, frma.dataStart + 4), entry.typeOffset); // prettier-ignore
        }
        neutralizeBox(data, sinf);
      }
    }
  }
  return data;
}
