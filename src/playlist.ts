/**
 * Minimal M3U8 parser - only the tags fMP4 SAMPLE-AES playback needs.
 *
 * Compare `src/loader/m3u8-parser.ts`, which additionally handles byte ranges,
 * discontinuities, live/low-latency parts, date ranges, variable substitution,
 * alternate renditions and so on.
 */

/** Split an attribute list such as `METHOD=SAMPLE-AES,URI="key.bin"`. */
function parseAttributes(input: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  // key=value, where value is either quoted or runs to the next comma
  const re = /([A-Z0-9-]+)=("[^"]*"|[^,]*)/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(input)) !== null) {
    const value = match[2];
    attrs[match[1]] =
      value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
  }
  return attrs;
}

/** `0x7308...` -> Uint8Array(16) */
function parseHexIv(value: string | undefined): Uint8Array | null {
  if (!value) {
    return null;
  }
  const hex = value.replace(/^0x/i, '');
  const iv = new Uint8Array(hex.length / 2);
  for (let i = 0; i < iv.length; i++) {
    iv[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return iv;
}

const resolve = (uri: string, base: string): string => new URL(uri, base).href;

export interface InitSegmentRef {
  uri: string;
}

export interface KeyInfo {
  method: string;
  uri: string;
  iv: Uint8Array | null;
  keyFormat: string;
}

export interface Segment {
  url: string;
  start: number;
  duration: number;
}

export interface MediaPlaylist {
  url: string;
  /** from EXT-X-MAP */
  initSegment: InitSegmentRef | null;
  key: KeyInfo | null;
  segments: Segment[];
  duration: number;
  live: boolean;
}

/**
 * Parse a media playlist.
 * @param url absolute URL the playlist was loaded from
 */
export function parseMediaPlaylist(text: string, url: string): MediaPlaylist {
  const segments: Segment[] = [];
  let initSegment: InitSegmentRef | null = null;
  let key: KeyInfo | null = null;
  let pendingDuration = 0;
  let start = 0;
  let live = true;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    if (line.startsWith('#EXTINF:')) {
      pendingDuration = parseFloat(line.slice(8)) || 0;
    } else if (line.startsWith('#EXT-X-MAP:')) {
      const attrs = parseAttributes(line.slice(11));
      initSegment = { uri: resolve(attrs.URI, url) };
    } else if (line.startsWith('#EXT-X-KEY:')) {
      const attrs = parseAttributes(line.slice(11));
      key =
        attrs.METHOD === 'NONE'
          ? null
          : {
              method: attrs.METHOD,
              uri: attrs.URI ? resolve(attrs.URI, url) : '',
              iv: parseHexIv(attrs.IV),
              keyFormat: attrs.KEYFORMAT || 'identity',
            };
    } else if (line === '#EXT-X-ENDLIST') {
      live = false;
    } else if (!line.startsWith('#')) {
      segments.push({
        url: resolve(line, url),
        start,
        duration: pendingDuration,
      });
      start += pendingDuration;
      pendingDuration = 0;
    }
  }

  return { url, initSegment, key, segments, duration: start, live };
}

/**
 * Pick a variant from a multivariant (master) playlist.
 * Returns the absolute URL of the variant with the lowest bandwidth at or
 * above `preferredBandwidth`, or null if this is not a master playlist.
 */
export function selectVariant(
  text: string,
  url: string,
  preferredBandwidth = 0
): string | null {
  const lines = text.split(/\r?\n/).map((l) => l.trim());
  const variants: Array<{ url: string; bandwidth: number }> = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].startsWith('#EXT-X-STREAM-INF:')) {
      continue;
    }
    const attrs = parseAttributes(lines[i].slice(18));
    const uri = lines.slice(i + 1).find((l) => l && !l.startsWith('#'));
    if (uri) {
      variants.push({
        url: resolve(uri, url),
        bandwidth: parseInt(attrs.BANDWIDTH, 10) || 0,
      });
    }
  }
  if (!variants.length) {
    return null;
  }
  variants.sort((a, b) => a.bandwidth - b.bandwidth);
  const chosen = variants.find((v) => v.bandwidth >= preferredBandwidth);
  return (chosen || variants[variants.length - 1]).url;
}

export const isMasterPlaylist = (text: string): boolean =>
  text.includes('#EXT-X-STREAM-INF:');
