import { describe, it, expect } from "vitest";
import {
  aesEncryptBlockRaw,
  crc32,
  decryptWinzipAes,
  encryptWinzipAes,
  parseAesExtra,
} from "./crypto";

const fromHex = (s: string): Uint8Array =>
  new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (u: Uint8Array): string =>
  [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("AES core (FIPS-197 known-answer tests)", () => {
  const pt = fromHex("00112233445566778899aabbccddeeff");

  it("encrypts a block with AES-128", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    expect(toHex(aesEncryptBlockRaw(key, pt))).toBe(
      "69c4e0d86a7b0430d8cdb78070b4c55a",
    );
  });

  it("encrypts a block with AES-256", () => {
    const key = fromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    expect(toHex(aesEncryptBlockRaw(key, pt))).toBe(
      "8ea2b7ca516745bfeafc49904b496089",
    );
  });
});

describe("crc32", () => {
  it("matches the standard check value", () => {
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
  });
});

describe("parseAesExtra", () => {
  it("finds the 0x9901 field after another extra field", () => {
    // [other field id=0x0001 size=2] then [AES field id=0x9901 size=7]
    const buf = new Uint8Array([
      0x01,
      0x00,
      0x02,
      0x00,
      0xaa,
      0xbb, // unrelated extra field
      0x01,
      0x99,
      0x07,
      0x00,
      0x02,
      0x00,
      0x41,
      0x45,
      0x03,
      0x08,
      0x00,
    ]);
    expect(parseAesExtra(buf.buffer)).toEqual({ strength: 3, actualMethod: 8 });
  });

  it("returns null when there is no AES field", () => {
    const buf = new Uint8Array([0x01, 0x00, 0x02, 0x00, 0xaa, 0xbb]);
    expect(parseAesExtra(buf.buffer)).toBeNull();
  });
});

describe("decryptWinzipAes failure modes", () => {
  const password = new TextEncoder().encode("pw");
  const plaintext = new TextEncoder().encode("payload");

  it("rejects an unsupported key strength", async () => {
    await expect(
      decryptWinzipAes(new Uint8Array(40), password, 4),
    ).rejects.toMatchObject({ reason: "UNSUPPORTED" });
  });

  it("rejects a tampered ciphertext (bad MAC, right password)", async () => {
    const salt = new Uint8Array(16).map((_, i) => i);
    const blob = await encryptWinzipAes(plaintext, password, 3, salt);
    blob[blob.length - 11] ^= 0xff; // flip a ciphertext byte (before the MAC)
    await expect(decryptWinzipAes(blob, password, 3)).rejects.toMatchObject({
      reason: "BAD_MAC",
    });
  });
});
