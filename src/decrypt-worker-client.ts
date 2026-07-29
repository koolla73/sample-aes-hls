/**
 * Main-thread client for `decrypt-worker.ts`.
 *
 * Mirrors the worker/inline-fallback pattern in
 * `src/demux/transmuxer-interface.ts`:
 *   - try to create a Worker and hand it the CPU-heavy job (there: demuxing
 *     and remuxing; here: AES-CBC decryption of a whole segment), passing
 *     data as a transferable `ArrayBuffer` so the copy from main thread to
 *     worker is zero-cost (see `TransmuxerInterface.push()`'s
 *     `postMessage(data, [data])`);
 *   - if the Worker can't be created, or errors out at runtime, fall back to
 *     running the exact same decryption code on the main thread instead
 *     (`TransmuxerInterface`'s constructor `catch` and `onWorkerError`).
 *
 * Falling back matters here for the same reason it does in hls.js: some
 * environments (older WebViews, restrictive CSPs, `file://` pages) can't
 * spin up a dedicated Worker at all, and a demo that only works with workers
 * enabled would just be broken there.
 */

import SegmentDecrypter from './sample-aes';
import type { TrackEncryption } from './init-segment';
import workerUrl from './decrypt-worker?worker&url';

interface DecryptedMessage {
  cmd: 'decrypted';
  id: number;
  segment: ArrayBuffer;
}

interface WorkerErrorMessage {
  cmd: 'error';
  id: number;
  message: string;
}

interface Pending {
  resolve: (data: Uint8Array) => void;
  reject: (error: Error) => void;
}

export default class SegmentDecrypterClient {
  private worker: Worker | null = null;
  private fallback: SegmentDecrypter | null = null;
  private readonly pending: Map<number, Pending> = new Map();
  private nextId = 0;

  /**
   * @param key raw 16-byte content key
   * @param encryption per-track defaults from the init segment's `tenc` boxes
   * @param useWorker whether to attempt to offload decryption to a Worker
   */
  constructor(
    key: Uint8Array,
    encryption: Map<number, TrackEncryption>,
    useWorker: boolean
  ) {
    if (useWorker && typeof Worker !== 'undefined') {
      try {
        const worker = (this.worker = new Worker(workerUrl, { type: 'module' }));
        worker.addEventListener('message', this.onMessage);
        worker.addEventListener('error', (event) =>
          this.onWorkerError(event, key, encryption)
        );
        worker.postMessage({ cmd: 'init', key, encryption });
        return;
      } catch (error) {
        this.worker = null;
      }
    }
    // No Worker support (or construction failed above): decrypt inline.
    this.fallback = new SegmentDecrypter(key, encryption);
  }

  /** Decrypt a media segment. Same contract as `SegmentDecrypter.decrypt()`, but async. */
  decrypt(segment: Uint8Array): Promise<Uint8Array> {
    if (this.fallback) {
      return Promise.resolve(this.fallback.decrypt(segment));
    }
    const worker = this.worker as Worker;
    const id = this.nextId++;
    // `segment` may be a view onto a larger ArrayBuffer (e.g. a fetch body);
    // copy out the exact range before transferring, since a transfer detaches
    // the *entire* underlying buffer from this thread, not just the view.
    const buffer = segment.buffer.slice(
      segment.byteOffset,
      segment.byteOffset + segment.byteLength
    );
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ cmd: 'decrypt', id, segment: buffer }, [buffer]);
    });
  }

  destroy(): void {
    if (this.worker) {
      this.worker.removeEventListener('message', this.onMessage);
      this.worker.terminate();
      this.worker = null;
    }
    this.rejectAllPending(new Error('SegmentDecrypterClient destroyed'));
    this.fallback = null;
  }

  private onMessage = (
    event: MessageEvent<DecryptedMessage | WorkerErrorMessage>
  ): void => {
    const data = event.data;
    const pending = this.pending.get(data.id);
    if (!pending) {
      return;
    }
    this.pending.delete(data.id);
    if (data.cmd === 'error') {
      pending.reject(new Error(data.message));
    } else {
      pending.resolve(new Uint8Array(data.segment));
    }
  };

  /**
   * Worker crashed (or failed to load): fall back to inline decryption for
   * every request from here on, same as `TransmuxerInterface.onWorkerError`.
   */
  private onWorkerError(
    event: ErrorEvent,
    key: Uint8Array,
    encryption: Map<number, TrackEncryption>
  ): void {
    if (this.worker) {
      this.worker.removeEventListener('message', this.onMessage);
      this.worker.terminate();
      this.worker = null;
    }
    this.fallback = new SegmentDecrypter(key, encryption);
    // Requests already in flight are lost along with the worker; rejecting
    // lets the caller re-fetch/re-decrypt the segment through the fallback.
    this.rejectAllPending(new Error(`decrypt-worker error: ${event.message}`));
  }

  private rejectAllPending(error: Error): void {
    this.pending.forEach(({ reject }) => reject(error));
    this.pending.clear();
  }
}
