/**
 * A minimal HLS player for fMP4 streams protected with METHOD=SAMPLE-AES.
 *
 * The whole pipeline is:
 *
 *   playlist  ->  key + EXT-X-MAP init segment  ->  MediaSource
 *                        |                              ^
 *                        v                              |
 *                 tenc defaults ---> decrypt samples ---'
 *
 * In hls.js the same path is spread across PlaylistLoader, LevelController,
 * KeyLoader, StreamController, Transmuxer/MP4Demuxer, PassThroughRemuxer and
 * BufferController. Everything not needed for a single-rendition VOD fMPT4
 * SAMPLE-AES stream (ABR, alternate tracks, TS demuxing, remuxing, live
 * playlist refresh, error recovery, gap jumping) is left out.
 */

import SegmentDecrypterClient from './decrypt-worker-client';
import {
  encryptionByTrackId,
  type ParsedInitSegment,
  parseInitSegment,
  stripEncryption,
} from './init-segment';
import {
  isMasterPlaylist,
  type KeyInfo,
  type MediaPlaylist,
  parseMediaPlaylist,
  type Segment,
  selectVariant,
} from './playlist';

export interface SimpleSampleAesPlayerConfig {
  /** Stop loading once this many seconds are buffered ahead of the playhead. */
  maxBufferLength: number;
  /** How often the buffer is re-evaluated, in ms. */
  tickInterval: number;
  /** Ignore buffered gaps smaller than this when measuring the buffer end. */
  maxBufferHole: number;
  /**
   * Offload segment decryption to a Worker (`decrypt-worker.ts`) so a
   * CPU-heavy AES-CBC pass over a segment never blocks the main thread.
   * Mirrors `HlsConfig.enableWorker`, which does the same for
   * demuxing/remuxing in `TransmuxerInterface`. Falls back to decrypting on
   * the main thread when Workers are unavailable, or if the worker errors.
   */
  useWorker: boolean;
}

const DEFAULT_CONFIG: SimpleSampleAesPlayerConfig = {
  maxBufferLength: 30,
  tickInterval: 100,
  maxBufferHole: 0.1,
  useWorker: true,
};

async function fetchBytes(url: string): Promise<Uint8Array> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} for ${url}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} for ${url}`);
  }
  return response.text();
}

/**
 * End of the buffered range containing `position`, skipping holes smaller
 * than `maxBufferHole`. Returns `position` when nothing is buffered there.
 */
function bufferedEnd(
  buffered: TimeRanges,
  position: number,
  maxBufferHole: number
): number {
  let end = position;
  for (let i = 0; i < buffered.length; i++) {
    if (buffered.start(i) > end + maxBufferHole) {
      break;
    }
    if (buffered.end(i) > end) {
      end = buffered.end(i);
    }
  }
  return end;
}

export default class SimpleSampleAesPlayer extends EventTarget {
  private media: HTMLMediaElement;
  private config: SimpleSampleAesPlayerConfig;

  private mediaSource: MediaSource | null = null;
  private sourceBuffer: SourceBuffer | null = null;
  private playlist: MediaPlaylist | null = null;
  private decrypter: SegmentDecrypterClient | null = null;
  private appended: Set<number> = new Set();
  private loading = false;
  private timer = 0;
  private destroyed = false;

  constructor(
    media: HTMLMediaElement,
    config: Partial<SimpleSampleAesPlayerConfig> = {}
  ) {
    super();
    this.media = media;
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  static isSupported(): boolean {
    return (
      typeof MediaSource !== 'undefined' &&
      typeof MediaSource.isTypeSupported === 'function'
    );
  }

  /**
   * Load a playlist and start playback.
   * @param url media or multivariant playlist URL
   */
  async load(url: string): Promise<void> {
    try {
      await this.loadInternal(url);
    } catch (error) {
      if (!this.destroyed) {
        this.emit('error', { error });
      }
    }
  }

  private async loadInternal(url: string): Promise<void> {
    const absolute = new URL(url, location.href).href;

    // --- Playlist -------------------------------------------------------
    let text = await fetchText(absolute);
    let playlistUrl = absolute;
    if (isMasterPlaylist(text)) {
      playlistUrl = selectVariant(text, absolute) ?? absolute;
      text = await fetchText(playlistUrl);
    }
    const playlist = (this.playlist = parseMediaPlaylist(text, playlistUrl));
    if (this.destroyed) {
      return;
    }
    if (!playlist.segments.length) {
      throw new Error('playlist contains no segments');
    }
    if (!playlist.initSegment) {
      throw new Error('no EXT-X-MAP: this player only handles fMP4 streams');
    }
    if (playlist.live) {
      this.emit('warning', {
        message: 'playlist has no #EXT-X-ENDLIST; live playback is not supported', // prettier-ignore
      });
    }
    this.emit('playlistparsed', { playlist });

    // --- Key and init segment -------------------------------------------
    const [initSegment, key] = await Promise.all([
      fetchBytes(playlist.initSegment.uri),
      this.loadKey(playlist.key),
    ]);
    if (this.destroyed) {
      return;
    }

    const parsed: ParsedInitSegment = parseInitSegment(initSegment);
    this.emit('trackinfo', {
      tracks: parsed.tracks,
      mimeType: parsed.mimeType,
    });

    if (parsed.encrypted) {
      if (!key) {
        throw new Error(
          'init segment is encrypted but no usable key was found'
        );
      }
      this.decrypter = new SegmentDecrypterClient(
        key,
        encryptionByTrackId(parsed),
        this.config.useWorker
      );
    }

    if (!MediaSource.isTypeSupported(parsed.mimeType)) {
      throw new Error(`unsupported mime type: ${parsed.mimeType}`);
    }

    // --- MediaSource ----------------------------------------------------
    await this.attachMediaSource();
    if (this.destroyed) {
      return;
    }

    const mediaSource = this.mediaSource as MediaSource;
    this.sourceBuffer = mediaSource.addSourceBuffer(parsed.mimeType);
    this.sourceBuffer.addEventListener('error', () =>
      this.emit('error', { error: new Error('SourceBuffer error') })
    );
    // Without this the media element reports a NaN duration until endOfStream,
    // which leaves the scrub bar unusable and blocks seeking ahead.
    mediaSource.duration = playlist.duration;

    // The init segment must reach MSE with its encryption boxes removed,
    // otherwise the browser demands a CDM for content we decrypt ourselves.
    await this.append(parsed.encrypted ? stripEncryption(initSegment) : initSegment); // prettier-ignore

    this.timer = self.setInterval(() => this.tick(), this.config.tickInterval);
    this.tick();
  }

  private async loadKey(keyInfo: KeyInfo | null): Promise<Uint8Array | null> {
    if (!keyInfo) {
      return null;
    }
    if (keyInfo.method !== 'SAMPLE-AES') {
      throw new Error(`unsupported EXT-X-KEY METHOD: ${keyInfo.method}`);
    }
    if (keyInfo.keyFormat !== 'identity') {
      // A non-identity KEYFORMAT means a DRM system holds the key; that needs
      // EME, which is exactly what this player avoids.
      throw new Error(`unsupported KEYFORMAT: ${keyInfo.keyFormat}`);
    }
    const key = await fetchBytes(keyInfo.uri);
    if (key.length !== 16) {
      throw new Error(`expected a 16-byte key, got ${key.length}`);
    }
    return key;
  }

  private attachMediaSource(): Promise<void> {
    return new Promise((resolve, reject) => {
      const mediaSource = (this.mediaSource = new MediaSource());
      mediaSource.addEventListener('sourceopen', () => resolve(), { once: true }); // prettier-ignore
      mediaSource.addEventListener('sourceclose', () => reject(new Error('MediaSource closed')), { once: true }); // prettier-ignore
      this.media.src = URL.createObjectURL(mediaSource);
    });
  }

  /**
   * Decide whether another segment is needed, and load it. Driven by the
   * buffered range around the playhead, so seeking is handled implicitly.
   */
  private tick(): void {
    if (this.destroyed || this.loading || !this.sourceBuffer) {
      return;
    }
    const position = this.media.currentTime;
    const end = bufferedEnd(
      this.media.buffered,
      position,
      this.config.maxBufferHole
    );
    if (end - position >= this.config.maxBufferLength) {
      return;
    }

    const index = this.nextSegmentIndex(end, end > position);
    if (index === -1) {
      this.finish();
      return;
    }
    this.loading = true;
    this.loadSegment(index)
      .catch((error) => this.emit('error', { error }))
      .finally(() => {
        this.loading = false;
      });
  }

  /**
   * First segment that is not yet loaded and that covers or follows
   * `bufferEnd`.
   *
   * When data is already buffered ahead of the playhead we shave
   * `maxBufferHole` off each segment's end, so a segment whose buffered range
   * falls a few milliseconds short of nominal is not fetched again. That
   * tolerance must NOT be applied when the buffer is empty at the playhead:
   * after seeking to the last moments of a segment it would skip straight to
   * the next one and leave a hole exactly where playback is about to resume.
   */
  private nextSegmentIndex(bufferEnd: number, hasBufferAhead: boolean): number {
    const tolerance = hasBufferAhead ? this.config.maxBufferHole : 0;
    const segments = (this.playlist as MediaPlaylist).segments;
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      if (
        !this.appended.has(i) &&
        bufferEnd < segment.start + segment.duration - tolerance
      ) {
        return i;
      }
    }
    return -1;
  }

  private async loadSegment(index: number): Promise<void> {
    const segment = (this.playlist as MediaPlaylist).segments[index];
    const encrypted = await fetchBytes(segment.url);
    if (this.destroyed) {
      return;
    }
    // Decrypt off the main thread when possible, then hand plain fMP4 to
    // MSE. This is the step that hls.js performs in
    // MP4Demuxer.demuxSampleAes(), via TransmuxerInterface's worker.
    const data = this.decrypter
      ? await this.decrypter.decrypt(encrypted)
      : encrypted;
    await this.append(data);
    this.appended.add(index);
    this.emit('segmentappended', { index, segment });
  }

  /** Append to the SourceBuffer and resolve once MSE has taken the data. */
  private append(data: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      const sourceBuffer = this.sourceBuffer as SourceBuffer;
      const onUpdateEnd = () => {
        sourceBuffer.removeEventListener('updateend', onUpdateEnd);
        resolve();
      };
      sourceBuffer.addEventListener('updateend', onUpdateEnd);
      try {
        sourceBuffer.appendBuffer(data as BufferSource);
      } catch (error) {
        sourceBuffer.removeEventListener('updateend', onUpdateEnd);
        reject(error);
      }
    });
  }

  /**
   * Signal end-of-stream once the buffer runs to the end of the playlist.
   *
   * The gate is the *last* segment rather than "every segment", because
   * seeking forward legitimately leaves unloaded holes behind the playhead.
   * Appending into such a hole later flips the MediaSource back to `open`, and
   * this runs again when the buffer reaches the end once more.
   */
  private finish(): void {
    const segments = (this.playlist as MediaPlaylist).segments;
    if (
      this.mediaSource?.readyState !== 'open' ||
      !this.appended.has(segments.length - 1)
    ) {
      return;
    }
    this.mediaSource.endOfStream();
    this.emit('complete', {});
  }

  private emit(type: string, detail: unknown): void {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  destroy(): void {
    this.destroyed = true;
    clearInterval(this.timer);
    this.timer = 0;
    if (this.mediaSource?.readyState === 'open') {
      try {
        this.mediaSource.endOfStream();
      } catch (error) {
        /* already torn down */
      }
    }
    if (this.media) {
      this.media.removeAttribute('src');
      this.media.load();
    }
    this.sourceBuffer = null;
    this.mediaSource = null;
    this.decrypter?.destroy();
    this.decrypter = null;
    this.playlist = null;
  }
}

export type { Segment };
