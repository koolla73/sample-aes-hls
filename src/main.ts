import SimpleSampleAesPlayer from './player';
import type { Track } from './init-segment';
import type { MediaPlaylist, Segment } from './playlist';

interface PlaylistParsedDetail {
  playlist: MediaPlaylist;
}

interface TrackInfoDetail {
  tracks: Track[];
  mimeType: string;
}

interface SegmentAppendedDetail {
  index: number;
  segment: Segment;
}

interface WarningDetail {
  message: string;
}

interface ErrorDetail {
  error: Error;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing required element #${id}`);
  }
  return element as T;
}

const form = requireElement<HTMLFormElement>('form');
const urlInput = requireElement<HTMLInputElement>('url');
const video = requireElement<HTMLVideoElement>('video');
const logEl = requireElement<HTMLDivElement>('log');

const set = (id: string, text: string): void => {
  requireElement<HTMLElement>(id).textContent = text;
};

function log(message: string, isError = false): void {
  const line = document.createElement('div');
  line.textContent = `${new Date().toISOString().slice(14, 23)}  ${message}`;
  if (isError) {
    line.className = 'error';
  }
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

let player: SimpleSampleAesPlayer | null = null;

form.addEventListener('submit', (event) => {
  event.preventDefault();
  player?.destroy();
  logEl.textContent = '';

  if (!SimpleSampleAesPlayer.isSupported()) {
    log('MediaSource Extensions are not available', true);
    return;
  }

  player = new SimpleSampleAesPlayer(video);

  player.addEventListener('playlistparsed', (event: Event) => {
    const { detail } = event as CustomEvent<PlaylistParsedDetail>;
    log(
      `playlist: ${detail.playlist.segments.length} segments, ` +
        `${detail.playlist.duration.toFixed(2)}s, ` +
        `key method ${detail.playlist.key?.method ?? 'NONE'}`
    );
  });

  player.addEventListener('trackinfo', (event: Event) => {
    const { detail } = event as CustomEvent<TrackInfoDetail>;
    set(
      'tracks',
      detail.tracks.map((track) => `${track.type} ${track.codec}`).join(', ')
    );
    set('mime', detail.mimeType);
    const encryption = detail.tracks.find((track) => track.encryption)?.encryption;
    set(
      'encryption',
      encryption
        ? `${encryption.scheme}, pattern ${encryption.cryptByteBlock}:${encryption.skipByteBlock}, ` +
            (encryption.ivSize
              ? `${encryption.ivSize}-byte per-sample IV`
              : 'constant IV')
        : 'clear'
    );
    log(`init segment parsed: ${detail.mimeType}`);
  });

  player.addEventListener('segmentappended', (event: Event) => {
    const { detail } = event as CustomEvent<SegmentAppendedDetail>;
    log(`appended segment ${detail.index} (${detail.segment.url.split('/').pop()})`);
  });

  player.addEventListener('complete', () => log('all segments appended'));

  player.addEventListener('warning', (event: Event) => {
    const { detail } = event as CustomEvent<WarningDetail>;
    log(`warning: ${detail.message}`);
  });

  player.addEventListener('error', (event: Event) => {
    const { detail } = event as CustomEvent<ErrorDetail>;
    log(`error: ${detail.error.message}`, true);
    console.error(detail.error);
  });

  log(`loading ${urlInput.value}`);
  player.load(urlInput.value);
});

setInterval(() => {
  const ranges: string[] = [];
  for (let i = 0; i < video.buffered.length; i++) {
    ranges.push(
      `${video.buffered.start(i).toFixed(1)}-${video.buffered.end(i).toFixed(1)}`
    );
  }
  set('buffered', ranges.join(', ') || '–');
}, 250);

form.dispatchEvent(new Event('submit'));