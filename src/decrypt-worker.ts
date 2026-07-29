/**
 * Web Worker companion for `SegmentDecrypter`.
 *
 * AES-CBC decryption of a segment is pure CPU work with no DOM access, so
 * hls.js never runs it on the main thread if it can help it: the equivalent
 * heavy lifting (demuxing/remuxing, plus AES for legacy TS SAMPLE-AES) is
 * offloaded to a Worker running `src/demux/transmuxer-worker.ts`, created by
 * `src/demux/inject-worker.ts`. This file plays the same role here, just for
 * fMP4 SAMPLE-AES segment decryption instead of demuxing.
 *
 * Protocol (see `decrypt-worker-client.ts` for the main-thread side):
 *   -> { cmd: 'init', key, encryption }      once, before any 'decrypt'
 *   -> { cmd: 'decrypt', id, segment }       segment is a transferable ArrayBuffer
 *   <- { cmd: 'decrypted', id, segment }     segment is a transferable ArrayBuffer
 *   <- { cmd: 'error', id, message }
 */

import SegmentDecrypter from './sample-aes';
import type { TrackEncryption } from './init-segment';

interface InitMessage {
  cmd: 'init';
  key: Uint8Array;
  encryption: Map<number, TrackEncryption>;
}

interface DecryptMessage {
  cmd: 'decrypt';
  id: number;
  segment: ArrayBuffer;
}

type InMessage = InitMessage | DecryptMessage;

const ctx = self as unknown as Worker;

let decrypter: SegmentDecrypter | null = null;

ctx.addEventListener('message', (event: MessageEvent<InMessage>) => {
  const data = event.data;
  switch (data.cmd) {
    case 'init':
      decrypter = new SegmentDecrypter(data.key, data.encryption);
      return;

    case 'decrypt': {
      if (!decrypter) {
        ctx.postMessage({
          cmd: 'error',
          id: data.id,
          message: 'decrypt-worker: received "decrypt" before "init"',
        });
        return;
      }
      try {
        // Decrypting in place on the transferred buffer avoids an extra copy.
        const plain = decrypter.decrypt(new Uint8Array(data.segment));
        ctx.postMessage(
          { cmd: 'decrypted', id: data.id, segment: plain.buffer },
          [plain.buffer]
        );
      } catch (error) {
        ctx.postMessage({
          cmd: 'error',
          id: data.id,
          message: error instanceof Error ? error.message : String(error),
        });
      }
      return;
    }
  }
});
