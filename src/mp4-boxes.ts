/**
 * Minimal ISO-BMFF (ISO/IEC 14496-12) box reader.
 *
 * hls.js does this in `src/utils/mp4-tools.ts` with `findBox()` returning
 * subarrays; callers then do `box.byteOffset - 4` arithmetic to get back to
 * the box header when they need to patch bytes. Here boxes are returned as
 * explicit descriptors instead, so patching is unambiguous.
 */

export function readUint16(data: Uint8Array, offset: number): number {
  return (data[offset] << 8) | data[offset + 1];
}

export function readUint32(data: Uint8Array, offset: number): number {
  return (
    ((data[offset] << 24) |
      (data[offset + 1] << 16) |
      (data[offset + 2] << 8) |
      data[offset + 3]) >>>
    0
  );
}

export function readSint32(data: Uint8Array, offset: number): number {
  return (
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3]
  );
}

/** Read a 64-bit big-endian value as a JS number (exact below 2^53). */
export function readUint64(data: Uint8Array, offset: number): number {
  return readUint32(data, offset) * 4294967296 + readUint32(data, offset + 4);
}

export function fourCC(data: Uint8Array, offset: number): string {
  return String.fromCharCode(
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3]
  );
}

export interface Box {
  /** four-character box type */
  type: string;
  /** offset of the box header (the size field) */
  start: number;
  /** offset of the four-character type field */
  typeOffset: number;
  /** offset of the first payload byte */
  dataStart: number;
  /** offset one past the last payload byte */
  dataEnd: number;
}

/** Iterate the direct children of the byte range [start, end). */
export function listBoxes(
  data: Uint8Array,
  start = 0,
  end: number = data.length
): Box[] {
  const found: Box[] = [];
  let offset = start;
  while (offset + 8 <= end) {
    let size = readUint32(data, offset);
    let headerSize = 8;
    if (size === 1) {
      // 64-bit largesize follows the type field
      if (offset + 16 > end) {
        break;
      }
      size = readUint64(data, offset + 8);
      headerSize = 16;
    } else if (size === 0) {
      // box extends to the end of the enclosing range
      size = end - offset;
    }
    if (size < headerSize || offset + size > end) {
      break;
    }
    found.push({
      type: fourCC(data, offset + 4),
      start: offset,
      typeOffset: offset + 4,
      dataStart: offset + headerSize,
      dataEnd: offset + size,
    });
    offset += size;
  }
  return found;
}

/** Find every box matching a path of box types, e.g. `['moov', 'trak']`. */
export function findBoxes(
  data: Uint8Array,
  path: string[],
  start = 0,
  end: number = data.length
): Box[] {
  let level: Array<Pick<Box, 'dataStart' | 'dataEnd'>> = [
    { dataStart: start, dataEnd: end },
  ];
  for (const type of path) {
    const next: Box[] = [];
    for (const parent of level) {
      for (const box of listBoxes(data, parent.dataStart, parent.dataEnd)) {
        if (box.type === type) {
          next.push(box);
        }
      }
    }
    level = next;
    if (!level.length) {
      break;
    }
  }
  return level as Box[];
}

/** The first box matching `path`, or null. */
export function findBox(
  data: Uint8Array,
  path: string[],
  start?: number,
  end?: number
): Box | null {
  return findBoxes(data, path, start, end)[0] || null;
}

/**
 * Overwrite a box's four-character type with `free`, the ISO-BMFF "ignore me"
 * box. The size field is untouched, so every byte offset in the file stays
 * valid - which matters because trun data offsets are relative to the moof.
 */
export function neutralizeBox(data: Uint8Array, box: Box): void {
  data[box.typeOffset] = 0x66; // 'f'
  data[box.typeOffset + 1] = 0x72; // 'r'
  data[box.typeOffset + 2] = 0x65; // 'e'
  data[box.typeOffset + 3] = 0x65; // 'e'
}

/** Detached copy, so mutations never touch the caller's ArrayBuffer. */
export function copyBytes(data: Uint8Array): Uint8Array {
  return new Uint8Array(
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
  );
}
