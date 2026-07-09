// Pure cryptographic primitives used by the ZIP reader: CRC-32, a small AES
// block cipher (for the WinZip AES-CTR keystream, which Web Crypto's AES-CTR
// cannot reproduce because WinZip uses a little-endian counter), traditional
// ZipCrypto, and WinZip AES (PBKDF2/HMAC via the platform Web Crypto).
//
// Everything here is platform-portable (Node >=22 and browsers). The Web Crypto
// pieces (PBKDF2, HMAC) require a secure context (HTTPS) in browsers.

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected) — also used as ZipCrypto's key-update CRC.
// ---------------------------------------------------------------------------

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

const crc32Byte = (crc: number, byte: number): number =>
  (CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)) >>> 0;

/** Incremental CRC-32, for verifying decompressed output (including streaming). */
export class Crc32 {
  private state = 0xffffffff;

  update(bytes: Uint8Array): void {
    let c = this.state;
    for (let i = 0; i < bytes.length; i += 1) {
      c = crc32Byte(c, bytes[i]);
    }
    this.state = c;
  }

  digest(): number {
    return (this.state ^ 0xffffffff) >>> 0;
  }
}

/** Compute the CRC-32 of `bytes` (the ZIP/IEEE variant). */
export const crc32 = (bytes: Uint8Array): number => {
  const crc = new Crc32();
  crc.update(bytes);
  return crc.digest();
};

// ---------------------------------------------------------------------------
// AES block cipher (encrypt only — CTR uses encryption in both directions).
// The S-box and round constants are derived in GF(2^8) to avoid a 256-entry
// transcription error; correctness is pinned by a FIPS-197 known-answer test.
// ---------------------------------------------------------------------------

const xtime = (a: number): number => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

const SBOX = (() => {
  const sbox = new Uint8Array(256);
  const exp = new Uint8Array(256);
  const log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    exp[i] = x;
    log[x] = i;
    x = (x ^ xtime(x)) & 0xff; // x *= 3 (a generator of GF(2^8)*)
  }
  const inv = (a: number): number => (a === 0 ? 0 : exp[(255 - log[a]) % 255]);
  for (let i = 0; i < 256; i += 1) {
    let s = inv(i);
    let out = s;
    for (let k = 0; k < 4; k += 1) {
      s = ((s << 1) | (s >> 7)) & 0xff;
      out ^= s;
    }
    sbox[i] = (out ^ 0x63) & 0xff;
  }
  return sbox;
})();

const RCON = (() => {
  const rcon = new Uint8Array(11);
  let c = 1;
  for (let i = 1; i <= 10; i += 1) {
    rcon[i] = c;
    c = xtime(c);
  }
  return rcon;
})();

interface AesKey {
  /** Expanded round-key bytes. */
  w: Uint8Array;
  /** Number of rounds (10/12/14 for AES-128/192/256). */
  rounds: number;
}

const aesKeyExpansion = (key: Uint8Array): AesKey => {
  const Nk = key.length / 4; // 4, 6, 8
  const Nr = Nk + 6;
  const totalWords = 4 * (Nr + 1);
  const w = new Uint8Array(totalWords * 4);
  w.set(key);
  for (let i = Nk; i < totalWords; i += 1) {
    let t0 = w[(i - 1) * 4];
    let t1 = w[(i - 1) * 4 + 1];
    let t2 = w[(i - 1) * 4 + 2];
    let t3 = w[(i - 1) * 4 + 3];
    if (i % Nk === 0) {
      const a = t0; // RotWord + SubWord + Rcon
      t0 = SBOX[t1] ^ RCON[i / Nk];
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[a];
    } else if (Nk > 6 && i % Nk === 4) {
      t0 = SBOX[t0];
      t1 = SBOX[t1];
      t2 = SBOX[t2];
      t3 = SBOX[t3];
    }
    w[i * 4] = w[(i - Nk) * 4] ^ t0;
    w[i * 4 + 1] = w[(i - Nk) * 4 + 1] ^ t1;
    w[i * 4 + 2] = w[(i - Nk) * 4 + 2] ^ t2;
    w[i * 4 + 3] = w[(i - Nk) * 4 + 3] ^ t3;
  }
  return { w, rounds: Nr };
};

const aesEncryptBlock = (
  { w, rounds }: AesKey,
  input: Uint8Array,
): Uint8Array => {
  const s = input.slice(0, 16);
  const addRoundKey = (round: number) => {
    for (let c = 0; c < 16; c += 1) s[c] ^= w[round * 16 + c];
  };
  addRoundKey(0);
  for (let round = 1; round <= rounds; round += 1) {
    for (let c = 0; c < 16; c += 1) s[c] = SBOX[s[c]]; // SubBytes
    // ShiftRows (state is column-major: byte = col*4 + row)
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    t = s[3];
    s[3] = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = t;
    if (round !== rounds) {
      for (let c = 0; c < 4; c += 1) {
        const i = c * 4;
        const a0 = s[i];
        const a1 = s[i + 1];
        const a2 = s[i + 2];
        const a3 = s[i + 3];
        s[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        s[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        s[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        s[i + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
      }
    }
    addRoundKey(round);
  }
  return s;
};

/** Test seam: raw AES block encryption (FIPS-197), used to validate the core. */
export const aesEncryptBlockRaw = (
  key: Uint8Array,
  block: Uint8Array,
): Uint8Array => aesEncryptBlock(aesKeyExpansion(key), block);

/**
 * AES-CTR with WinZip's little-endian counter (starts at 1). Symmetric, so this
 * both encrypts and decrypts.
 */
const aesCtrXor = (data: Uint8Array, key: Uint8Array): Uint8Array => {
  const aesKey = aesKeyExpansion(key);
  const out = new Uint8Array(data.length);
  const counter = new Uint8Array(16);
  for (let off = 0, block = 1; off < data.length; off += 16, block += 1) {
    counter.fill(0);
    for (
      let v = block, i = 0;
      v > 0 && i < 16;
      v = Math.floor(v / 256), i += 1
    ) {
      counter[i] = v & 0xff;
    }
    const keystream = aesEncryptBlock(aesKey, counter);
    const n = Math.min(16, data.length - off);
    for (let i = 0; i < n; i += 1) out[off + i] = data[off + i] ^ keystream[i];
  }
  return out;
};

// ---------------------------------------------------------------------------
// Traditional PKWARE encryption (ZipCrypto). Weak, but still common on legacy
// password-protected archives. Pure JS, streamable.
// ---------------------------------------------------------------------------

class ZipCryptoKeys {
  private k0 = 0x12345678;
  private k1 = 0x23456789;
  private k2 = 0x34567890;

  constructor(password: Uint8Array) {
    for (const b of password) this.update(b);
  }

  update(byte: number): void {
    this.k0 = crc32Byte(this.k0, byte);
    this.k1 = (this.k1 + (this.k0 & 0xff)) >>> 0;
    this.k1 = (Math.imul(this.k1, 134775813) + 1) >>> 0;
    this.k2 = crc32Byte(this.k2, this.k1 >>> 24);
  }

  streamByte(): number {
    const temp = (this.k2 | 2) & 0xffff;
    return ((temp * (temp ^ 1)) >>> 8) & 0xff;
  }
}

/**
 * Decrypt traditional-ZipCrypto bytes (the 12-byte encryption header is consumed
 * and stripped). Returns the compressed plaintext and the header's check byte.
 */
export const decryptZipCrypto = (
  data: Uint8Array,
  password: Uint8Array,
): { plaintext: Uint8Array; checkByte: number } => {
  const keys = new ZipCryptoKeys(password);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 1) {
    const c = (data[i] ^ keys.streamByte()) & 0xff;
    keys.update(c);
    out[i] = c;
  }
  return { plaintext: out.subarray(12), checkByte: out[11] };
};

/** Encrypt for ZipCrypto (used by tests to build fixtures). */
export const encryptZipCrypto = (
  plaintext: Uint8Array,
  password: Uint8Array,
  header: Uint8Array,
): Uint8Array => {
  const keys = new ZipCryptoKeys(password);
  const input = new Uint8Array(12 + plaintext.length);
  input.set(header.subarray(0, 12));
  input.set(plaintext, 12);
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i += 1) {
    out[i] = (input[i] ^ keys.streamByte()) & 0xff;
    keys.update(input[i]);
  }
  return out;
};

// ---------------------------------------------------------------------------
// WinZip AES (AE-1/AE-2): PBKDF2-HMAC-SHA1 key derivation + AES-CTR + HMAC-SHA1
// authentication. PBKDF2/HMAC use the platform Web Crypto.
// ---------------------------------------------------------------------------

const AES_PARAMS: Record<number, { saltLength: number; keyLength: number }> = {
  1: { saltLength: 8, keyLength: 16 },
  2: { saltLength: 12, keyLength: 24 },
  3: { saltLength: 16, keyLength: 32 },
};

/** Parse the WinZip AES extra field (id 0x9901): strength + actual method. */
export const parseAesExtra = (
  extra: ArrayBuffer,
): { strength: number; actualMethod: number } | null => {
  const view = new DataView(extra);
  for (let p = 0; p + 4 <= extra.byteLength; ) {
    const id = view.getUint16(p, true);
    const size = view.getUint16(p + 2, true);
    const end = p + 4 + size;
    if (end > extra.byteLength) return null;
    if (id === 0x9901) {
      if (size < 7) return null;
      // data: version(2) + vendor "AE"(2) + strength(1) + actualMethod(2)
      return {
        strength: view.getUint8(p + 4 + 4),
        actualMethod: view.getUint16(p + 4 + 5, true),
      };
    }
    p = end;
  }
  return null;
};

/** Copy a (possibly subarray) view into a fresh ArrayBuffer for Web Crypto. */
const toArrayBuffer = (u: Uint8Array): ArrayBuffer =>
  u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

const deriveAesKeys = async (
  password: Uint8Array,
  salt: Uint8Array,
  keyLength: number,
): Promise<{ encKey: Uint8Array; authKey: Uint8Array; verify: Uint8Array }> => {
  const subtle = globalThis.crypto.subtle;
  const baseKey = await subtle.importKey(
    "raw",
    toArrayBuffer(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = new Uint8Array(
    await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: toArrayBuffer(salt),
        iterations: 1000,
        hash: "SHA-1",
      },
      baseKey,
      (keyLength * 2 + 2) * 8,
    ),
  );
  return {
    encKey: derived.subarray(0, keyLength),
    authKey: derived.subarray(keyLength, keyLength * 2),
    verify: derived.subarray(keyLength * 2, keyLength * 2 + 2),
  };
};

const hmacSha1 = async (
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> => {
  const subtle = globalThis.crypto.subtle;
  const hmacKey = await subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await subtle.sign("HMAC", hmacKey, toArrayBuffer(message)),
  );
};

/** Reasons a WinZip AES decryption can fail (mapped to RemoteZipError codes). */
export type AesDecryptError = "WRONG_PASSWORD" | "BAD_MAC" | "UNSUPPORTED";

export class CryptoError extends Error {
  constructor(public reason: AesDecryptError) {
    super(reason);
  }
}

/**
 * Decrypt a WinZip AES entry payload (salt || pwVerify || ciphertext || mac).
 * Verifies the password-check bytes and the authentication code, then returns
 * the still-compressed plaintext.
 */
export const decryptWinzipAes = async (
  data: Uint8Array,
  password: Uint8Array,
  strength: number,
): Promise<Uint8Array> => {
  const params = AES_PARAMS[strength];
  if (!params) throw new CryptoError("UNSUPPORTED");
  const { saltLength, keyLength } = params;
  if (data.length < saltLength + 12) throw new CryptoError("BAD_MAC");

  const salt = data.subarray(0, saltLength);
  const pwVerify = data.subarray(saltLength, saltLength + 2);
  const mac = data.subarray(data.length - 10);
  const ciphertext = data.subarray(saltLength + 2, data.length - 10);

  const { encKey, authKey, verify } = await deriveAesKeys(
    password,
    salt,
    keyLength,
  );
  if (verify[0] !== pwVerify[0] || verify[1] !== pwVerify[1]) {
    throw new CryptoError("WRONG_PASSWORD");
  }

  const fullMac = await hmacSha1(authKey, ciphertext);
  let macOk = mac.length === 10;
  for (let i = 0; i < 10; i += 1) {
    if (fullMac[i] !== mac[i]) macOk = false;
  }
  if (!macOk) throw new CryptoError("BAD_MAC");

  return aesCtrXor(ciphertext, encKey);
};

/** Encrypt a WinZip AES payload (used by tests to build fixtures). */
export const encryptWinzipAes = async (
  plaintext: Uint8Array,
  password: Uint8Array,
  strength: number,
  salt: Uint8Array,
): Promise<Uint8Array> => {
  const { keyLength } = AES_PARAMS[strength];
  const { encKey, authKey, verify } = await deriveAesKeys(
    password,
    salt,
    keyLength,
  );
  const ciphertext = aesCtrXor(plaintext, encKey);
  const mac = (await hmacSha1(authKey, ciphertext)).subarray(0, 10);
  const out = new Uint8Array(salt.length + 2 + ciphertext.length + 10);
  out.set(salt, 0);
  out.set(verify, salt.length);
  out.set(ciphertext, salt.length + 2);
  out.set(mac, salt.length + 2 + ciphertext.length);
  return out;
};
