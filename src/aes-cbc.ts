/**
 * Minimal software AES-CBC decryptor.
 *
 * SAMPLE-AES needs *raw* CBC over exact multiples of 16 bytes, with no PKCS#7
 * padding. `crypto.subtle` always strips padding on AES-CBC, so it cannot be
 * used directly; hls.js has the same problem and ships a software fallback in
 * `src/crypt/aes-decryptor.ts`. This is the same algorithm written for clarity
 * rather than speed.
 *
 * Only the inverse cipher is implemented - decryption is all a player needs.
 */

const BLOCK_SIZE = 16;

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
// Pre-multiplied GF(2^8) tables for InvMixColumns.
const MUL9 = new Uint8Array(256);
const MUL11 = new Uint8Array(256);
const MUL13 = new Uint8Array(256);
const MUL14 = new Uint8Array(256);

/** Multiply by x in GF(2^8) with the AES reduction polynomial 0x11b. */
function xtime(a: number): number {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
}

(function buildTables() {
  // exp/log tables base 3 (a generator of GF(2^8)*), used for inversion.
  const exp = new Uint8Array(512);
  const log = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    x ^= xtime(x); // x * 3
  }
  for (let i = 255; i < 512; i++) {
    exp[i] = exp[i - 255];
  }
  const mul = (a: number, b: number): number =>
    a && b ? exp[log[a] + log[b]] : 0;

  for (let i = 0; i < 256; i++) {
    // S-box = multiplicative inverse followed by the AES affine transform.
    // Shifting past bit 7 and folding the overflow back is a rotate.
    const s = i ? exp[255 - log[i]] : 0;
    let v = s ^ (s << 1) ^ (s << 2) ^ (s << 3) ^ (s << 4);
    v = (v ^ (v >> 8) ^ 0x63) & 0xff;
    SBOX[i] = v;
    INV_SBOX[v] = i;

    MUL9[i] = mul(i, 9);
    MUL11[i] = mul(i, 11);
    MUL13[i] = mul(i, 13);
    MUL14[i] = mul(i, 14);
  }
})();

interface ExpandedKey {
  roundKeys: Uint8Array;
  rounds: number;
}

/**
 * AES key expansion (FIPS-197 §5.2). Accepts 128/192/256-bit keys; SAMPLE-AES
 * always uses 128-bit.
 */
function expandKey(key: Uint8Array): ExpandedKey {
  const nk = key.length / 4;
  if (nk !== 4 && nk !== 6 && nk !== 8) {
    throw new Error(`invalid AES key length: ${key.length}`);
  }
  const rounds = nk + 6;
  const words = 4 * (rounds + 1);
  const roundKeys = new Uint8Array(words * 4);
  roundKeys.set(key);

  let rcon = 1;
  for (let i = nk; i < words; i++) {
    const p = (i - 1) * 4;
    let t0 = roundKeys[p];
    let t1 = roundKeys[p + 1];
    let t2 = roundKeys[p + 2];
    let t3 = roundKeys[p + 3];

    if (i % nk === 0) {
      // RotWord + SubWord + Rcon
      const tmp = t0;
      t0 = SBOX[t1] ^ rcon;
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[tmp];
      rcon = xtime(rcon);
    } else if (nk > 6 && i % nk === 4) {
      t0 = SBOX[t0];
      t1 = SBOX[t1];
      t2 = SBOX[t2];
      t3 = SBOX[t3];
    }

    const q = (i - nk) * 4;
    const o = i * 4;
    roundKeys[o] = roundKeys[q] ^ t0;
    roundKeys[o + 1] = roundKeys[q + 1] ^ t1;
    roundKeys[o + 2] = roundKeys[q + 2] ^ t2;
    roundKeys[o + 3] = roundKeys[q + 3] ^ t3;
  }
  return { roundKeys, rounds };
}

/** state is column-major: state[c * 4 + r]. */
function invShiftRows(s: Uint8Array): void {
  let t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;

  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;

  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

function invMixColumns(s: Uint8Array): void {
  for (let c = 0; c < 16; c += 4) {
    const a0 = s[c];
    const a1 = s[c + 1];
    const a2 = s[c + 2];
    const a3 = s[c + 3];
    s[c] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3];
    s[c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3];
    s[c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3];
    s[c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3];
  }
}

export default class AesCbcDecryptor {
  private roundKeys: Uint8Array;
  private rounds: number;
  // Scratch buffers, reused to keep per-block allocation at zero.
  private state: Uint8Array;
  private prev: Uint8Array;
  private cipher: Uint8Array;

  /** @param key raw key bytes (16 for SAMPLE-AES) */
  constructor(key: Uint8Array) {
    const { roundKeys, rounds } = expandKey(key);
    this.roundKeys = roundKeys;
    this.rounds = rounds;
    this.state = new Uint8Array(BLOCK_SIZE);
    this.prev = new Uint8Array(BLOCK_SIZE);
    this.cipher = new Uint8Array(BLOCK_SIZE);
  }

  /** Inverse cipher on `this.state`, in place. */
  private decryptBlock(): void {
    const { state: s, roundKeys: rk, rounds } = this;
    let round = rounds;
    let o = round * 16;
    for (let i = 0; i < 16; i++) {
      s[i] ^= rk[o + i];
    }
    for (round--; round > 0; round--) {
      invShiftRows(s);
      o = round * 16;
      for (let i = 0; i < 16; i++) {
        s[i] = INV_SBOX[s[i]] ^ rk[o + i];
      }
      invMixColumns(s);
    }
    invShiftRows(s);
    for (let i = 0; i < 16; i++) {
      s[i] = INV_SBOX[s[i]] ^ rk[i];
    }
  }

  /**
   * Decrypt `length` bytes of `data` starting at `offset`, in place.
   *
   * `length` is rounded down to a whole number of AES blocks; a trailing
   * partial block is left untouched, which is exactly what the CENC/SAMPLE-AES
   * specs require (the tail of a protected range stays in the clear).
   *
   * @param iv 16-byte initialization vector
   */
  decrypt(
    data: Uint8Array,
    offset: number,
    length: number,
    iv: Uint8Array
  ): void {
    const blocks = Math.floor(length / BLOCK_SIZE);
    if (blocks < 1) {
      return;
    }
    const { state, prev, cipher } = this;
    prev.set(iv);

    for (let b = 0, p = offset; b < blocks; b++, p += BLOCK_SIZE) {
      // Stash the ciphertext block: it is the XOR mask for the next block.
      for (let i = 0; i < BLOCK_SIZE; i++) {
        cipher[i] = state[i] = data[p + i];
      }
      this.decryptBlock();
      for (let i = 0; i < BLOCK_SIZE; i++) {
        data[p + i] = state[i] ^ prev[i];
      }
      prev.set(cipher);
    }
  }
}

export { BLOCK_SIZE };
