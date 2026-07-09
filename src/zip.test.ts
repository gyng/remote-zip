import { RemoteZipPointer } from "./zip";

import * as http from "http";
import { Server } from "http";
import { readFileSync } from "fs";
import { join } from "path";
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import { deflateRaw } from "pako";
import { encryptZipCrypto, encryptWinzipAes } from "./crypto";
import {
  parseZipDatetime,
  isZip64,
  parseOneEOCD,
  parseOneCD,
  parseAllCDs,
  parseOneLocalFile,
  parseZip64EOCD,
  parseZip64EOCDLocator,
  decodeZipString,
  crc32,
  RemoteZipError,
  EndOfCentralDirectory,
} from ".";

const encode = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * Send `body` over HTTP with Range support (the ~30 lines of node:http + node:fs
 * that replace the http-server dev dependency). Returns 405 for non-GET/HEAD.
 */
function sendBody(req: http.IncomingMessage, res: http.ServerResponse, body: Uint8Array): void {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    res.end();
    return;
  }

  const isHead = req.method === "HEAD";
  const rangeMatch = /^bytes=(\d+)-(\d*)$/.exec(req.headers["range"] ?? "");
  if (rangeMatch) {
    const start = Number(rangeMatch[1]);
    // A range that starts at or past EOF is unsatisfiable (RFC 7233 -> 416).
    if (start >= body.length) {
      res.statusCode = 416;
      res.setHeader("Content-Range", `bytes */${body.length}`);
      res.end();
      return;
    }
    const end = rangeMatch[2] ? Math.min(Number(rangeMatch[2]), body.length - 1) : body.length - 1;
    res.statusCode = 206;
    res.setHeader("Content-Range", `bytes ${start}-${end}/${body.length}`);
    res.setHeader("Content-Length", String(end - start + 1));
    res.end(isHead ? undefined : body.subarray(start, end + 1));
    return;
  }

  res.statusCode = 200;
  res.setHeader("Content-Length", String(body.length));
  res.end(isHead ? undefined : body);
}

/**
 * Static file server with Range support, serving files from `root`. `onRequest`
 * is invoked for every request so tests can assert on forwarded headers.
 */
function createFixtureServer(root: string, onRequest: (req: http.IncomingMessage) => void): Server {
  return http.createServer((req, res) => {
    onRequest(req);
    const path = (req.url ?? "").split("?")[0];
    let body: Uint8Array;
    try {
      body = new Uint8Array(readFileSync(join(root, path)));
    } catch {
      res.statusCode = 404;
      res.end();
      return;
    }
    sendBody(req, res, body);
  });
}

/** Listen on an ephemeral port and resolve the chosen port. */
function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? addr.port : 0);
    });
  });
}

/** Serve a single buffer with Range support; returns its URL and a closer. */
async function serveBuffer(zip: Uint8Array): Promise<{ url: URL; close: () => void }> {
  const server = http.createServer((req, res) => sendBody(req, res, zip));
  const port = await listen(server);
  return {
    url: new URL(`http://127.0.0.1:${port}/archive.zip`),
    close: () => server.close(),
  };
}

describe("RemoteZip integration tests", () => {
  let server: Server;
  const serverCheck = vi.fn<(req: http.IncomingMessage) => void>();
  const url = new URL("http://127.0.0.1:9875/test.zip");

  beforeAll(() => {
    server = createFixtureServer("fixtures", serverCheck);
    server.listen(9875, "127.0.0.1");
  });

  afterAll(() => {
    server.close();
  });

  beforeEach(() => {
    serverCheck.mockClear();
  });

  describe("RemoteZip", () => {
    it("fetches and decompresses remote file in zip", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      const decoder = new TextDecoder();
      const bytes = await remoteZip.fetch("test.txt");
      expect(decoder.decode(bytes)).toBe("Hello, world!\n");
    });

    it("errors when fetching a missing file", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("bad")).rejects.toThrow("File not found in remote ZIP: bad");
    });

    it("supports alternative HTTP methods", async () => {
      await expect(
        new RemoteZipPointer({
          url,
          additionalHeaders: undefined,
          method: "POST",
        }).populate(),
      ).rejects.toThrow(
        "Could not fetch remote ZIP at http://127.0.0.1:9875/test.zip: HTTP status 405",
      );
    });

    it("forwards additional headers to every request (incl. EOCD)", async () => {
      const additionalHeaders = new Headers();
      additionalHeaders.append("x-test", "some-value");
      const remoteZip = await new RemoteZipPointer({
        url,
        additionalHeaders,
      }).populate();
      await remoteZip.fetch("test.txt", additionalHeaders);

      // Every request the server saw (HEAD, EOCD range, CD range, file range)
      // must carry the custom header. Before the fix, the EOCD range request
      // dropped it.
      expect(serverCheck.mock.calls.length).toBeGreaterThan(0);
      for (const [request] of serverCheck.mock.calls) {
        expect(request.headers).toHaveProperty("x-test", "some-value");
      }
    });

    it("returns the file when under maxUncompressedSize", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const decoder = new TextDecoder();
      const bytes = await remoteZip.fetch("test.txt", undefined, {
        maxUncompressedSize: 1000,
      });
      expect(decoder.decode(bytes)).toBe("Hello, world!\n");
    });

    it("throws when output exceeds maxUncompressedSize (zip bomb guard)", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(
        remoteZip.fetch("test.txt", undefined, { maxUncompressedSize: 5 }),
      ).rejects.toMatchObject({
        name: "RemoteZipError",
        code: "DECOMPRESSION_LIMIT_EXCEEDED",
      });
    });

    it("streams a file via fetchStream", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const stream = await remoteZip.fetchStream("test.txt");
      expect(new TextDecoder().decode(await collect(stream))).toBe("Hello, world!\n");
    });

    it("provides a friendly listing of files in the zip", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      const files = remoteZip.files();

      expect(files).toHaveLength(4);
      expect(files[0]).toEqual({
        filename: "dir/",
        modified: "2021-11-10T12:37:26",
        size: 0,
        attributes: 1107099648,
      });
      expect(files[1]).toEqual({
        filename: "xir/testdir.txt",
        modified: "2021-06-17T12:28:02",
        size: 14,
        attributes: 2176057344,
      });
    });
  });

  describe("RemoteZipPointer", () => {
    it("fetches and parses end of central directory record", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      expect(remoteZip.contentLength).toBe(863);
      expect(remoteZip.endOfCentralDirectory?.data.centralDirectoryByteOffset).toBe(488);
    });

    it("fetches and parses central directory records", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      expect(remoteZip.centralDirectoryRecords?.length).toBe(4);
      expect(remoteZip.centralDirectoryRecords[0].data.filename).toBe("dir/");
      expect(remoteZip.centralDirectoryRecords[1].data.filename).toBe("xir/testdir.txt");
      expect(remoteZip.centralDirectoryRecords[2].data.filename).toBe("test.txt");
      expect(remoteZip.centralDirectoryRecords[3].data.filename).toBe("test-inner.zip");
    });
  });
});

describe("parseZipDatetime", () => {
  it("parses a date safely", () => {
    expect(parseZipDatetime(0, 0)).toBe("1980-01-01T00:00:00");

    const time = 0x7d1c; // 0111110100011100, 15:40:56
    const date = 0x354b; // 0011010101001011, 10/11/2006
    expect(parseZipDatetime(date, time)).toBe("2006-10-11T15:40:56");

    expect(parseZipDatetime(NaN, NaN)).toBe("1980-01-01T00:00:00");
    expect(parseZipDatetime(0.5, 0.5)).toBe("1980-01-01T00:00:00");
    expect(parseZipDatetime(Infinity, Infinity)).toBe("1980-01-01T00:00:00");
    expect(parseZipDatetime(-Infinity, -Infinity)).toBe("1980-01-01T00:00:00");
  });

  it("falls back to 1980 for out-of-range DOS components", () => {
    // month bits = 13 (>12): the DOS layout permits it; Date.parse must reject.
    const month13 = (13 << 5) | 1; // day = 1
    expect(parseZipDatetime(month13, 0)).toBe("1980-01-01T00:00:00");

    // second field = (time & 0x1f) << 1 can reach 62, an invalid ISO second.
    const second62 = 0x1f;
    expect(parseZipDatetime(0x21, second62)).toBe("1980-01-01T00:00:00");
  });
});

describe("isZip64", () => {
  const eocd = (over: Partial<EndOfCentralDirectory["data"]> = {}): EndOfCentralDirectory => ({
    meta: {},
    data: {
      signature: new ArrayBuffer(4),
      diskNumber: 0,
      cdDisk: 0,
      centralDirectoryDiskNumber: 0,
      centralDirectoryRecordCount: 1,
      centralDirectoryByteSize: 46,
      centralDirectoryByteOffset: 0,
      comment: "",
      commentLength: 0,
      ...over,
    },
  });

  it("is false for a normal single-disk archive", () => {
    expect(isZip64(eocd())).toBe(false);
  });

  it("is true for any ZIP64 sentinel value", () => {
    expect(isZip64(eocd({ diskNumber: 0xffff }))).toBe(true);
    expect(isZip64(eocd({ cdDisk: 0xffff }))).toBe(true);
    expect(isZip64(eocd({ centralDirectoryDiskNumber: 0xffff }))).toBe(true);
    expect(isZip64(eocd({ centralDirectoryRecordCount: 0xffff }))).toBe(true);
    expect(isZip64(eocd({ centralDirectoryByteSize: 0xffffffff }))).toBe(true);
    expect(isZip64(eocd({ centralDirectoryByteOffset: 0xffffffff }))).toBe(true);
  });
});

describe("parseOneEOCD", () => {
  it("reads multi-byte fields little-endian, incl. comment length", () => {
    const buf = new ArrayBuffer(23); // 22-byte EOCD + 1-byte comment
    const dv = new DataView(buf);
    dv.setUint32(0, 0x504b0506); // signature, big-endian on the wire
    dv.setUint16(4, 0, true); // disk number
    dv.setUint16(6, 0, true); // cd disk
    dv.setUint16(8, 0, true); // cd records on disk
    dv.setUint16(10, 1, true); // cd record count
    dv.setUint32(12, 46, true); // cd size
    // cd offset with the high bit set: must be read UNSIGNED. Read signed it
    // would be -2 and produce a malformed `bytes=-2-...` Range request.
    dv.setUint32(16, 0xfffffffe, true);
    dv.setUint16(20, 1, true); // comment length (little-endian)
    dv.setUint8(22, 0x41); // comment: "A"

    const parsed = parseOneEOCD(buf);
    expect(parsed?.data.commentLength).toBe(1);
    expect(parsed?.data.comment).toBe("A");
    expect(parsed?.data.centralDirectoryByteOffset).toBe(0xfffffffe);
    expect(parsed?.data.centralDirectoryByteSize).toBe(46);
  });

  it("ignores EOCD signatures embedded in the archive comment", () => {
    const buf = new Uint8Array(22 + 30);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0506);
    dv.setUint16(10, 1, true);
    dv.setUint16(20, 30, true);
    dv.setUint32(22, 0x504b0506); // signature-like bytes inside the comment

    expect(parseOneEOCD(buf.buffer)?.data.centralDirectoryRecordCount).toBe(1);
    expect(parseOneEOCD(buf.buffer)?.data.commentLength).toBe(30);
  });
});

describe("RemoteZipError", () => {
  it("carries a machine-readable code", () => {
    expect(new RemoteZipError("boom").code).toBe("UNKNOWN");
    expect(new RemoteZipError("boom", "FILE_NOT_FOUND").code).toBe("FILE_NOT_FOUND");
  });
});

describe("parseOneLocalFile", () => {
  it("parses a stored (uncompressed) local file header", () => {
    const name = "a.txt";
    const data = "hello";
    const buf = new ArrayBuffer(30 + name.length + data.length);
    const dv = new DataView(buf);
    const bytes = new Uint8Array(buf);
    dv.setUint32(0, 0x504b0304); // local file header signature
    dv.setUint16(4, 20, true); // version to extract
    dv.setUint16(6, 0, true); // general purpose flags (no data descriptor)
    dv.setUint16(8, 0, true); // compression method = store
    dv.setUint32(18, data.length, true); // compressed size
    dv.setUint32(22, data.length, true); // uncompressed size
    dv.setUint16(26, name.length, true); // filename length
    dv.setUint16(28, 0, true); // extra field length
    bytes.set(
      name.split("").map((c) => c.charCodeAt(0)),
      30,
    );
    bytes.set(
      data.split("").map((c) => c.charCodeAt(0)),
      30 + name.length,
    );

    const parsed = parseOneLocalFile(buf);
    expect(parsed?.data.filename).toBe("a.txt");
    expect(parsed?.data.compressionMethod).toBe(0);
    expect(new TextDecoder().decode(parsed?.meta.compressedData)).toBe("hello");
  });

  it("returns null when there is no local file header signature", () => {
    expect(parseOneLocalFile(new ArrayBuffer(64))).toBeNull();
  });

  it("parses an exact 30-byte empty local file header", () => {
    const buf = new ArrayBuffer(30);
    new DataView(buf).setUint32(0, 0x504b0304);
    expect(parseOneLocalFile(buf)?.meta.compressedData.byteLength).toBe(0);
  });
});

describe("parseAllCDs / parseOneCD", () => {
  // Build one central directory record (filename "a") followed by an EOCD
  // signature, so parseAllCDs parses the record and stops at the EOCD.
  const buildCd = (): ArrayBuffer => {
    const name = "a";
    const buf = new ArrayBuffer(46 + name.length + 4);
    const dv = new DataView(buf);
    const bytes = new Uint8Array(buf);
    dv.setUint32(0, 0x504b0102); // central directory signature
    dv.setUint16(28, name.length, true); // filename length
    dv.setUint16(30, 0, true); // extra field length
    dv.setUint16(32, 0, true); // file comment length
    dv.setUint32(42, 1234, true); // local file header relative offset
    bytes.set([name.charCodeAt(0)], 46);
    dv.setUint32(46 + name.length, 0x504b0506); // trailing EOCD signature
    return buf;
  };

  it("parses a single record and stops at the EOCD signature", () => {
    const cds = parseAllCDs(buildCd());
    expect(cds).toHaveLength(1);
    expect(cds[0].data.filename).toBe("a");
    expect(cds[0].data.localFileHeaderRelativeOffset).toBe(1234);
  });

  it("parseOneCD returns null when no record is present", () => {
    expect(parseOneCD(new ArrayBuffer(64))).toBeNull();
  });

  it("parses an exact 46-byte empty-name central directory record", () => {
    const buf = new ArrayBuffer(46);
    new DataView(buf).setUint32(0, 0x504b0102);
    expect(parseOneCD(buf)?.meta.length).toBe(46);
  });
});

/**
 * Build a minimal, valid ZIP containing one entry "a.txt". Defaults to a stored
 * "hi"; pass `content`/`deflate` to vary the payload and `comment` for the EOCD.
 */
function buildMinimalZip(
  opts: {
    comment?: string;
    content?: Uint8Array;
    deflate?: boolean;
    crc?: number;
  } = {},
): Uint8Array {
  const enc = new TextEncoder();
  const name = enc.encode("a.txt");
  const uncompressed = opts.content ?? enc.encode("hi");
  const data = opts.deflate ? deflateRaw(uncompressed) : uncompressed;
  const method = opts.deflate ? 8 : 0;
  const crc = opts.crc ?? crc32(uncompressed);
  const commentBytes = enc.encode(opts.comment ?? "");

  const lfhLen = 30 + name.length + data.length;
  const cdLen = 46 + name.length;
  const eocdLen = 22 + commentBytes.length;
  const buf = new Uint8Array(lfhLen + cdLen + eocdLen);
  const dv = new DataView(buf.buffer);

  // Local file header @ 0
  dv.setUint32(0, 0x504b0304); // signature
  dv.setUint16(4, 20, true); // version to extract
  dv.setUint16(8, method, true); // compression method
  dv.setUint32(14, crc, true); // crc-32
  dv.setUint32(18, data.length, true); // compressed size
  dv.setUint32(22, uncompressed.length, true); // uncompressed size
  dv.setUint16(26, name.length, true); // filename length
  buf.set(name, 30);
  buf.set(data, 30 + name.length);

  // Central directory @ lfhLen
  const cdOff = lfhLen;
  dv.setUint32(cdOff, 0x504b0102); // signature
  dv.setUint16(cdOff + 6, 20, true); // version to extract
  dv.setUint16(cdOff + 10, method, true); // compression method
  dv.setUint32(cdOff + 16, crc, true); // crc-32
  dv.setUint32(cdOff + 20, data.length, true); // compressed size
  dv.setUint32(cdOff + 24, uncompressed.length, true); // uncompressed size
  dv.setUint16(cdOff + 28, name.length, true); // filename length
  dv.setUint32(cdOff + 42, 0, true); // local file header relative offset
  buf.set(name, cdOff + 46);

  // End of central directory @ lfhLen + cdLen
  const eOff = lfhLen + cdLen;
  dv.setUint32(eOff, 0x504b0506); // signature
  dv.setUint16(eOff + 8, 1, true); // cd records on this disk
  dv.setUint16(eOff + 10, 1, true); // total cd records
  dv.setUint32(eOff + 12, cdLen, true); // cd size
  dv.setUint32(eOff + 16, lfhLen, true); // cd offset
  dv.setUint16(eOff + 20, commentBytes.length, true); // comment length
  buf.set(commentBytes, eOff + 22);

  return buf;
}

/** Build a single-entry "a.txt" ZIP from a (possibly encrypted) payload. */
function buildSingleEntryZip(params: {
  method: number;
  flags: number;
  crc: number;
  data: Uint8Array;
  uncompressedSize: number;
  extra?: Uint8Array;
}): Uint8Array {
  const { method, flags, crc, data, uncompressedSize } = params;
  const extra = params.extra ?? new Uint8Array(0);
  const name = new TextEncoder().encode("a.txt");

  const lfhLen = 30 + name.length + extra.length + data.length;
  const cdLen = 46 + name.length + extra.length;
  const buf = new Uint8Array(lfhLen + cdLen + 22);
  const dv = new DataView(buf.buffer);

  // Local file header
  dv.setUint32(0, 0x504b0304);
  dv.setUint16(4, 45, true);
  dv.setUint16(6, flags, true);
  dv.setUint16(8, method, true);
  dv.setUint32(14, crc, true);
  dv.setUint32(18, data.length, true);
  dv.setUint32(22, uncompressedSize, true);
  dv.setUint16(26, name.length, true);
  dv.setUint16(28, extra.length, true);
  buf.set(name, 30);
  buf.set(extra, 30 + name.length);
  buf.set(data, 30 + name.length + extra.length);

  // Central directory
  const cdOff = lfhLen;
  dv.setUint32(cdOff, 0x504b0102);
  dv.setUint16(cdOff + 6, 45, true);
  dv.setUint16(cdOff + 8, flags, true);
  dv.setUint16(cdOff + 10, method, true);
  dv.setUint32(cdOff + 16, crc, true);
  dv.setUint32(cdOff + 20, data.length, true);
  dv.setUint32(cdOff + 24, uncompressedSize, true);
  dv.setUint16(cdOff + 28, name.length, true);
  dv.setUint16(cdOff + 30, extra.length, true);
  dv.setUint32(cdOff + 42, 0, true);
  buf.set(name, cdOff + 46);
  buf.set(extra, cdOff + 46 + name.length);

  // End of central directory
  const eOff = lfhLen + cdLen;
  dv.setUint32(eOff, 0x504b0506);
  dv.setUint16(eOff + 8, 1, true);
  dv.setUint16(eOff + 10, 1, true);
  dv.setUint32(eOff + 12, cdLen, true);
  dv.setUint32(eOff + 16, cdOff, true);
  return buf;
}

function aesExtraField(strength: number, actualMethod: number): Uint8Array {
  const extra = new Uint8Array(11);
  const dv = new DataView(extra.buffer);
  dv.setUint16(0, 0x9901, true); // header id
  dv.setUint16(2, 7, true); // data size
  dv.setUint16(4, 2, true); // vendor version (AE-2)
  extra[6] = 0x41; // "A"
  extra[7] = 0x45; // "E"
  extra[8] = strength;
  dv.setUint16(9, actualMethod, true);
  return extra;
}

describe("encryption", () => {
  const password = "hunter2";
  const content = new TextEncoder().encode("top secret payload ".repeat(20));

  const serveZip = async (zip: Uint8Array) => {
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
    return { url, close: () => server.close() };
  };

  it("decrypts a traditional ZipCrypto entry with the correct password", async () => {
    const compressed = deflateRaw(content);
    const crc = crc32(content);
    const header = new Uint8Array(12);
    header[11] = (crc >>> 24) & 0xff; // ZipCrypto check byte
    const data = encryptZipCrypto(compressed, encode(password), header);
    const zip = buildSingleEntryZip({
      method: 8,
      flags: 0x1,
      crc,
      data,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveZip(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const out = await remoteZip.fetch("a.txt", undefined, { password });
      expect(out).toEqual(content);
    } finally {
      close();
    }
  });

  it("rejects a ZipCrypto entry with the wrong password", async () => {
    const compressed = deflateRaw(content);
    const crc = crc32(content);
    const header = new Uint8Array(12);
    header[11] = (crc >>> 24) & 0xff;
    const data = encryptZipCrypto(compressed, encode(password), header);
    const zip = buildSingleEntryZip({
      method: 8,
      flags: 0x1,
      crc,
      data,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveZip(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(
        remoteZip.fetch("a.txt", undefined, { password: "wrong" }),
      ).rejects.toMatchObject({ code: "WRONG_PASSWORD" });
    } finally {
      close();
    }
  });

  it("requires a password for an encrypted entry", async () => {
    const data = encryptZipCrypto(content, encode(password), new Uint8Array(12));
    const zip = buildSingleEntryZip({
      method: 0,
      flags: 0x1,
      crc: crc32(content),
      data,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveZip(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "UNSUPPORTED_ENCRYPTION",
      });
    } finally {
      close();
    }
  });

  it("decrypts a WinZip AES-256 entry (fetch and fetchStream)", async () => {
    const strength = 3;
    const compressed = deflateRaw(content);
    const salt = new Uint8Array(16).map((_, i) => i + 1);
    const data = await encryptWinzipAes(compressed, encode(password), strength, salt);
    const zip = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0, // AE-2 stores no CRC
      data,
      uncompressedSize: content.length,
      extra: aesExtraField(strength, 8),
    });
    const { url, close } = await serveZip(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(await remoteZip.fetch("a.txt", undefined, { password })).toEqual(content);
      const stream = await remoteZip.fetchStream("a.txt", undefined, {
        password,
      });
      expect(await collect(stream)).toEqual(content);
    } finally {
      close();
    }
  });

  it("rejects a WinZip AES entry with the wrong password", async () => {
    const strength = 1;
    const salt = new Uint8Array(8).map((_, i) => i + 1);
    const data = await encryptWinzipAes(content, encode(password), strength, salt);
    const zip = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data,
      uncompressedSize: content.length,
      extra: aesExtraField(strength, 0),
    });
    const { url, close } = await serveZip(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt", undefined, { password: "nope" })).rejects.toMatchObject(
        { code: "WRONG_PASSWORD" },
      );
    } finally {
      close();
    }
  });

  it("maps unexpected Web Crypto failures to a typed error", async () => {
    const strength = 1;
    const salt = new Uint8Array(8).map((_, i) => i + 1);
    const data = await encryptWinzipAes(content, encode(password), strength, salt);
    const zip = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data,
      uncompressedSize: content.length,
      extra: aesExtraField(strength, 0),
    });
    const { url, close } = await serveZip(zip);
    const cryptoMock = vi
      .spyOn(globalThis.crypto.subtle, "importKey")
      .mockRejectedValueOnce(new Error("crypto unavailable"));
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt", undefined, { password })).rejects.toMatchObject({
        code: "DECRYPTION_FAILED",
      });
    } finally {
      cryptoMock.mockRestore();
      close();
    }
  });
});

describe("error paths and edge cases", () => {
  const content = encode("payload payload payload");

  it("rejects a server that ignores Range requests", async () => {
    const zip = buildMinimalZip({ content });
    const server = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader("Content-Length", String(zip.length));
      res.end(req.method === "HEAD" ? undefined : zip);
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "RANGE_NOT_SUPPORTED",
      });
    } finally {
      server.close();
    }
  });

  it("rejects an invalid Content-Length", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(null, {
        status: 200,
        headers: { "Content-Length": "12junk" },
      }),
    );
    try {
      const url = new URL("https://example.test/archive.zip");
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "INVALID_CONTENT_LENGTH",
      });
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("rejects an archive shorter than the minimum EOCD", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(null, {
        status: 200,
        headers: { "Content-Length": "21" },
      }),
    );
    try {
      await expect(
        new RemoteZipPointer({
          url: new URL("https://example.test/archive.zip"),
        }).populate(),
      ).rejects.toMatchObject({ code: "INVALID_CONTENT_LENGTH" });
    } finally {
      fetchMock.mockRestore();
    }
  });

  it.each([
    [undefined, "RANGE_RESPONSE_MISMATCH"],
    ["invalid", "RANGE_RESPONSE_MISMATCH"],
    ["bytes 1-22/22", "RANGE_RESPONSE_MISMATCH"],
    ["bytes 0-23/22", "RANGE_RESPONSE_MISMATCH"],
    ["bytes 0-20/22", "RANGE_RESPONSE_MISMATCH"],
  ])("rejects an invalid Content-Range %s", async (contentRange, code) => {
    const headers = new Headers();
    if (contentRange) headers.set("Content-Range", contentRange);
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(null, {
          status: 200,
          headers: { "Content-Length": "22" },
        }),
      )
      .mockResolvedValueOnce(new Response(new Uint8Array(22), { status: 206, headers }));
    try {
      await expect(
        new RemoteZipPointer({
          url: new URL("https://example.test/archive.zip"),
        }).populate(),
      ).rejects.toMatchObject({ code });
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("throws when the server omits Content-Length on HEAD", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Transfer-Encoding": "chunked" });
      res.end();
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/a.zip`);
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "CONTENT_LENGTH_MISSING",
      });
    } finally {
      server.close();
    }
  });

  it("throws EOCD_NOT_FOUND for a file with no EOCD", async () => {
    const { url, close } = await serveBuffer(new Uint8Array(200));
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "EOCD_NOT_FOUND",
      });
    } finally {
      close();
    }
  });

  it("rejects a central directory that overruns the archive", async () => {
    const buf = new Uint8Array(22);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0506);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, 1, true);
    dv.setUint32(12, 999999, true); // cd size >> archive
    dv.setUint32(16, 0, true);
    const { url, close } = await serveBuffer(buf);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "CENTRAL_DIRECTORY_OUT_OF_BOUNDS",
      });
    } finally {
      close();
    }
  });

  it("rejects ZIP64 sentinels with no locator", async () => {
    const buf = new Uint8Array(22);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0506);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, 1, true);
    dv.setUint32(12, 0xffffffff, true);
    dv.setUint32(16, 0xffffffff, true);
    const { url, close } = await serveBuffer(buf);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "UNSUPPORTED_ZIP64",
      });
    } finally {
      close();
    }
  });

  it("rejects a ZIP64 locator pointing at a missing record", async () => {
    const buf = new Uint8Array(20 + 20 + 22); // filler + locator + eocd
    const dv = new DataView(buf.buffer);
    dv.setUint32(20, 0x504b0607); // locator signature
    dv.setBigUint64(28, 0n, true); // zip64 EOCD offset -> 0 (filler, no record)
    dv.setUint32(36, 1, true); // total disks
    dv.setUint32(40, 0x504b0506); // eocd
    dv.setUint16(48, 1, true);
    dv.setUint16(50, 1, true);
    dv.setUint32(52, 0xffffffff, true);
    dv.setUint32(56, 0xffffffff, true);
    const { url, close } = await serveBuffer(buf);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "UNSUPPORTED_ZIP64",
      });
    } finally {
      close();
    }
  });

  it("rejects a corrupt local file header (fetch and fetchStream)", async () => {
    const zip = buildMinimalZip({ content });
    zip[0] = 0; // corrupt the local file header signature
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "LOCAL_HEADER_PARSE_FAILED",
      });
      await expect(remoteZip.fetchStream("a.txt")).rejects.toMatchObject({
        code: "LOCAL_HEADER_PARSE_FAILED",
      });
    } finally {
      close();
    }
  });

  it("surfaces an inflate error for corrupt deflate (fetch and fetchStream)", async () => {
    const compressed = deflateRaw(content);
    compressed.set([0xff, 0xff, 0xff, 0xff], 1); // corrupt the deflate stream
    const zip = buildSingleEntryZip({
      method: 8,
      flags: 0,
      crc: crc32(content),
      data: compressed,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      // unbounded inflate, capped inflate, and streaming inflate paths
      await expect(remoteZip.fetch("a.txt")).rejects.toBeInstanceOf(RemoteZipError);
      await expect(
        remoteZip.fetch("a.txt", undefined, { maxUncompressedSize: 1_000_000 }),
      ).rejects.toBeInstanceOf(RemoteZipError);
      const stream = await remoteZip.fetchStream("a.txt");
      await expect(collect(stream)).rejects.toBeInstanceOf(RemoteZipError);
    } finally {
      close();
    }
  });

  it("enforces maxUncompressedSize across multiple inflate chunks", async () => {
    const big = encode("x".repeat(200_000));
    const zip = buildSingleEntryZip({
      method: 8,
      flags: 0,
      crc: crc32(big),
      data: deflateRaw(big),
      uncompressedSize: big.length,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(
        remoteZip.fetch("a.txt", undefined, { maxUncompressedSize: 1000 }),
      ).rejects.toMatchObject({ code: "DECOMPRESSION_LIMIT_EXCEEDED" });
    } finally {
      close();
    }
  });

  it("enforces maxUncompressedSize on a stored entry", async () => {
    const zip = buildMinimalZip({ content: encode("hello") }); // stored
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(
        remoteZip.fetch("a.txt", undefined, { maxUncompressedSize: 2 }),
      ).rejects.toMatchObject({ code: "DECOMPRESSION_LIMIT_EXCEEDED" });
    } finally {
      close();
    }
  });

  it("rejects strong-encrypted entries", async () => {
    const zip = buildSingleEntryZip({
      method: 0,
      flags: 0x1 | 0x40, // encrypted + strong encryption
      crc: 0,
      data: new Uint8Array(20),
      uncompressedSize: 8,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt", undefined, { password: "x" })).rejects.toMatchObject({
        code: "UNSUPPORTED_ENCRYPTION",
      });
    } finally {
      close();
    }
  });

  it("rejects unsupported compression methods before decoding", async () => {
    const zip = buildSingleEntryZip({
      method: 12,
      flags: 0,
      crc: 0,
      data: content,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "UNSUPPORTED_COMPRESSION",
      });
    } finally {
      close();
    }
  });

  it.each([4, 6])("rejects multi-disk archives (EOCD field +%i)", async (field) => {
    const zip = buildMinimalZip({ content });
    new DataView(zip.buffer).setUint16(zip.length - 22 + field, 1, true);
    const { url, close } = await serveBuffer(zip);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "UNSUPPORTED_MULTI_DISK",
      });
    } finally {
      close();
    }
  });

  it("accepts an empty archive with a zero-size central directory", async () => {
    const zip = new Uint8Array(22);
    new DataView(zip.buffer).setUint32(0, 0x504b0506);
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(remoteZip.files()).toEqual([]);
    } finally {
      close();
    }
  });

  it("rejects a central-directory count mismatch", async () => {
    const zip = buildMinimalZip({ content });
    const view = new DataView(zip.buffer);
    view.setUint16(zip.length - 22 + 8, 2, true);
    view.setUint16(zip.length - 22 + 10, 2, true);
    const { url, close } = await serveBuffer(zip);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
    } finally {
      close();
    }
  });

  it("rejects a nonzero entry starting disk", async () => {
    const zip = buildMinimalZip({ content });
    const view = new DataView(zip.buffer);
    const cdOffset = view.getUint32(zip.length - 22 + 16, true);
    view.setUint16(cdOffset + 34, 1, true);
    const { url, close } = await serveBuffer(zip);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "UNSUPPORTED_MULTI_DISK",
      });
    } finally {
      close();
    }
  });

  it("rejects a zero-size central directory with a nonzero count", async () => {
    const zip = buildMinimalZip({ content });
    const view = new DataView(zip.buffer);
    view.setUint32(zip.length - 22 + 12, 0, true);
    const { url, close } = await serveBuffer(zip);
    try {
      await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
    } finally {
      close();
    }
  });

  it("fetches entries whose local header exceeds the old fixed allowance", async () => {
    const extra = new Uint8Array(1024);
    const zip = buildSingleEntryZip({
      method: 0,
      flags: 0,
      crc: crc32(content),
      data: content,
      uncompressedSize: content.length,
      extra,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(await remoteZip.fetch("a.txt")).toEqual(content);
    } finally {
      close();
    }
  });

  it("rejects out-of-bounds local-header and entry-data ranges", async () => {
    for (const field of ["offset", "size"] as const) {
      const zip = buildMinimalZip({ content });
      const view = new DataView(zip.buffer);
      const cdOffset = view.getUint32(zip.length - 22 + 16, true);
      view.setUint32(cdOffset + (field === "offset" ? 42 : 20), zip.length + 100, true);
      const { url, close } = await serveBuffer(zip);
      try {
        const remoteZip = await new RemoteZipPointer({ url }).populate();
        await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
          code: "INVALID_ARCHIVE",
        });
      } finally {
        close();
      }
    }
  });

  it("rejects a local header that disagrees with the central directory", async () => {
    const zip = buildMinimalZip({ content });
    new DataView(zip.buffer).setUint16(8, 8, true); // local method differs
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
      await expect(remoteZip.fetchStream("a.txt")).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
    } finally {
      close();
    }
  });

  it("rejects a local filename that disagrees with the central directory", async () => {
    const zip = buildMinimalZip({ content });
    zip[30] = "b".charCodeAt(0);
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
      await expect(collect(await remoteZip.fetchStream("a.txt"))).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
    } finally {
      close();
    }
  });

  it("decrypts ZipCrypto with the data-descriptor check byte", async () => {
    const compressed = deflateRaw(content);
    const header = new Uint8Array(12);
    header[11] = 0; // mod-time high byte is 0 in our builder
    const data = encryptZipCrypto(compressed, encode("pw"), header);
    const zip = buildSingleEntryZip({
      method: 8,
      flags: 0x1 | 0x8, // encrypted + data descriptor
      crc: crc32(content),
      data,
      uncompressedSize: content.length,
    });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(await remoteZip.fetch("a.txt", undefined, { password: "pw" })).toEqual(content);
    } finally {
      close();
    }
  });

  it("maps AES failures: unsupported strength and bad MAC", async () => {
    // Unsupported strength: claim strength 4 in the extra.
    const bogus = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data: new Uint8Array(40),
      uncompressedSize: 8,
      extra: aesExtraField(4, 8),
    });
    const a = await serveBuffer(bogus);
    try {
      const rz = await new RemoteZipPointer({ url: a.url }).populate();
      await expect(rz.fetch("a.txt", undefined, { password: "x" })).rejects.toMatchObject({
        code: "UNSUPPORTED_ENCRYPTION",
      });
    } finally {
      a.close();
    }

    // Bad MAC: a valid AES blob with a flipped ciphertext byte.
    const salt = new Uint8Array(16).map((_, i) => i);
    const blob = await encryptWinzipAes(content, encode("pw"), 3, salt);
    blob[blob.length - 11] ^= 0xff;
    const tampered = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data: blob,
      uncompressedSize: content.length,
      extra: aesExtraField(3, 0),
    });
    const b = await serveBuffer(tampered);
    try {
      const rz = await new RemoteZipPointer({ url: b.url }).populate();
      await expect(rz.fetch("a.txt", undefined, { password: "pw" })).rejects.toMatchObject({
        code: "DECRYPTION_FAILED",
      });
    } finally {
      b.close();
    }
  });

  it("rejects missing or unsupported WinZip AES metadata", async () => {
    const missing = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data: new Uint8Array(20),
      uncompressedSize: 0,
    });
    const a = await serveBuffer(missing);
    try {
      const rz = await new RemoteZipPointer({ url: a.url }).populate();
      await expect(rz.fetch("a.txt", undefined, { password: "pw" })).rejects.toMatchObject({
        code: "INVALID_ARCHIVE",
      });
    } finally {
      a.close();
    }

    const unsupported = buildSingleEntryZip({
      method: 99,
      flags: 0x1,
      crc: 0,
      data: new Uint8Array(20),
      uncompressedSize: 0,
      extra: aesExtraField(1, 12),
    });
    const b = await serveBuffer(unsupported);
    try {
      const rz = await new RemoteZipPointer({ url: b.url }).populate();
      await expect(rz.fetch("a.txt", undefined, { password: "pw" })).rejects.toMatchObject({
        code: "UNSUPPORTED_COMPRESSION",
      });
    } finally {
      b.close();
    }
  });

  it("releases the reader when a stream is cancelled", async () => {
    const zip = buildMinimalZip({ content: encode("abc".repeat(100)) });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const stream = await remoteZip.fetchStream("a.txt");
      const reader = stream.getReader();
      await reader.read();
      await reader.cancel();
    } finally {
      close();
    }
  });

  it("errors a stream whose local header is truncated", async () => {
    // Entry at offset 0; pad the archive so only the file fetch starts at 0.
    const zip = buildMinimalZip({ content: encode("x".repeat(200)) });
    const server = http.createServer((req, res) => {
      const m = /^bytes=(\d+)-(\d+)/.exec(req.headers["range"] ?? "");
      if (req.method === "GET" && m && m[1] === "0" && Number(m[2]) > 29) {
        res.statusCode = 206;
        res.setHeader("Content-Range", `bytes 0-${m[2]}/${zip.length}`);
        res.end(zip.subarray(0, 10)); // truncated header (< 30 bytes)
        return;
      }
      sendBody(req, res, zip);
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const stream = await remoteZip.fetchStream("a.txt");
      await expect(collect(stream)).rejects.toMatchObject({
        code: "LOCAL_HEADER_PARSE_FAILED",
      });
    } finally {
      server.close();
    }
  });

  it("errors when the streamed response changes after the header probe", async () => {
    const zip = buildMinimalZip({ content: encode("x".repeat(200)) });
    const server = http.createServer((req, res) => {
      const m = /^bytes=(\d+)-(\d+)/.exec(req.headers["range"] ?? "");
      if (req.method === "GET" && m && m[1] === "0" && Number(m[2]) > 29) {
        const end = Number(m[2]);
        const corrupt = zip.slice(0, end + 1);
        corrupt[0] = 0;
        res.statusCode = 206;
        res.setHeader("Content-Range", `bytes 0-${end}/${zip.length}`);
        res.setHeader("Content-Length", String(corrupt.length));
        res.end(corrupt);
        return;
      }
      sendBody(req, res, zip);
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt")).rejects.toMatchObject({
        code: "LOCAL_HEADER_PARSE_FAILED",
      });
      await expect(collect(await remoteZip.fetchStream("a.txt"))).rejects.toMatchObject({
        code: "LOCAL_HEADER_PARSE_FAILED",
      });
    } finally {
      server.close();
    }
  });

  it("streams a large stored entry across multiple reads", async () => {
    const big = encode("y".repeat(300_000));
    const zip = buildMinimalZip({ content: big });
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const out = await collect(await remoteZip.fetchStream("a.txt"));
      expect(out.length).toBe(big.length);
    } finally {
      close();
    }
  });

  it("rejects a stream when the body is shorter than the compressed size", async () => {
    const zip = buildMinimalZip({ content: encode("x".repeat(200)) }); // stored
    const server = http.createServer((req, res) => {
      const m = /^bytes=(\d+)-(\d+)/.exec(req.headers["range"] ?? "");
      if (req.method === "GET" && m && m[1] === "0" && Number(m[2]) > 29) {
        res.statusCode = 206;
        res.setHeader("Content-Range", `bytes 0-${m[2]}/${zip.length}`);
        res.end(zip.subarray(0, 50)); // header + only part of the data
        return;
      }
      sendBody(req, res, zip);
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(collect(await remoteZip.fetchStream("a.txt"))).rejects.toMatchObject({
        code: "TRUNCATED_ENTRY",
      });
    } finally {
      server.close();
    }
  });

  it("combines an instance signal with a per-request timeout", async () => {
    const zip = buildMinimalZip();
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({
        url,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      }).populate();
      expect(remoteZip.files()).toHaveLength(1);
    } finally {
      close();
    }
  });
});

describe("parser edge cases", () => {
  it("rejects a ZIP64 value beyond MAX_SAFE_INTEGER", () => {
    const buf = new ArrayBuffer(56);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x504b0606);
    dv.setBigUint64(32, 1n, true);
    dv.setBigUint64(40, 46n, true);
    dv.setBigUint64(48, 0xffffffffffffffffn, true); // > 2^53
    expect(() => parseZip64EOCD(buf)).toThrow(RemoteZipError);
  });

  it("reads the ZIP64 disk field from the extra", () => {
    const name = encode("a");
    const extra = new Uint8Array(8);
    const edv = new DataView(extra.buffer);
    edv.setUint16(0, 0x0001, true);
    edv.setUint16(2, 4, true);
    edv.setUint32(4, 7, true); // disk = 7
    const buf = new Uint8Array(46 + name.length + extra.length);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0102);
    dv.setUint16(28, name.length, true);
    dv.setUint16(30, extra.length, true);
    dv.setUint16(34, 0xffff, true); // disk sentinel
    buf.set(name, 46);
    buf.set(extra, 46 + name.length);
    expect(parseOneCD(buf.buffer)?.data.startingDiskNumber).toBe(7);
  });

  it("rejects a ZIP64 sentinel when the ZIP64 extra is absent", () => {
    const name = encode("a");
    const extra = new Uint8Array([0x99, 0x00, 0x02, 0x00, 0xaa, 0xbb]); // not 0x0001
    const buf = new Uint8Array(46 + name.length + extra.length);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0102);
    dv.setUint32(20, 0xffffffff, true); // compressed size sentinel
    dv.setUint16(28, name.length, true);
    dv.setUint16(30, extra.length, true);
    buf.set(name, 46);
    buf.set(extra, 46 + name.length);
    expect(() => parseOneCD(buf.buffer)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
  });

  it("rejects truncated and undersized ZIP64 extra fields", () => {
    const build = (extra: Uint8Array) => {
      const buf = new Uint8Array(46 + extra.length);
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, 0x504b0102);
      dv.setUint32(20, 0xffffffff, true);
      dv.setUint16(30, extra.length, true);
      buf.set(extra, 46);
      return buf.buffer;
    };
    expect(() => parseOneCD(build(new Uint8Array([1, 0, 8, 0])))).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
    expect(() => parseOneCD(build(new Uint8Array([1, 0, 4, 0, 0, 0, 0, 0])))).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
  });

  it("rejects truncated central and local records with typed errors", () => {
    const cd = new Uint8Array(46);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x504b0102);
    cv.setUint16(28, 1, true);
    expect(() => parseOneCD(cd.buffer)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );

    const header = new Uint8Array(30);
    const hv = new DataView(header.buffer);
    hv.setUint32(0, 0x504b0304);
    hv.setUint16(26, 1, true);
    expect(() => parseOneLocalFile(header.buffer)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );

    hv.setUint16(26, 0, true);
    hv.setUint32(18, 1, true);
    expect(() => parseOneLocalFile(header.buffer)).toThrowError(
      expect.objectContaining({ code: "TRUNCATED_ENTRY" }),
    );
  });

  it("rejects trailing partial central-directory bytes", () => {
    expect(() => parseAllCDs(new Uint8Array([1, 2, 3]).buffer)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
  });

  it("rejects a central-directory signature without a complete record", () => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, 0x504b0102);
    expect(() => parseAllCDs(buf)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
  });

  it("parseAllCDs rejects non-record bytes before a record", () => {
    const cd = new Uint8Array(46 + 1);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x504b0102); // CD signature
    cv.setUint16(28, 1, true); // filename length
    cd[46] = 0x61; // "a"
    // [4 non-signature bytes][valid CD][truncated CD signature with no room to parse]
    const buf = new Uint8Array(4 + cd.length + 4);
    const dv = new DataView(buf.buffer);
    buf.set(cd, 4);
    dv.setUint32(4 + cd.length, 0x504b0102);
    expect(() => parseAllCDs(buf.buffer)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARCHIVE" }),
    );
  });

  it("parses a local file header with a data descriptor + optional signature", () => {
    const buf = new Uint8Array(30 + 1 + 3 + 16);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0304);
    dv.setUint16(6, 0x8, true); // data descriptor flag
    dv.setUint16(26, 1, true); // filename length
    buf[30] = 0x61; // "a"
    buf.set([1, 2, 3], 31); // 3 compressed bytes
    dv.setUint32(34, 0x504b0708); // optional data descriptor signature
    const parsed = parseOneLocalFile(buf.buffer, 3);
    expect(parsed?.meta.dataDescriptor?.optionalSignature).toBeDefined();
  });

  it("parses a complete data descriptor without its optional signature", () => {
    const buf = new Uint8Array(30 + 3 + 12);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x504b0304);
    dv.setUint16(6, 0x8, true);
    buf.set([1, 2, 3], 30);
    expect(parseOneLocalFile(buf.buffer, 3)?.meta.dataDescriptor).toBeDefined();
  });
});

describe("decodeZipString (CP437 vs UTF-8)", () => {
  it("decodes CP437 high bytes when the UTF-8 flag is unset", () => {
    // 0x81 -> ü, 0xe1 -> ß in CP437; ASCII is unchanged.
    const bytes = new Uint8Array([0x66, 0x81, 0xe1]).buffer; // "f", ü, ß
    expect(decodeZipString(bytes, false)).toBe("füß");
  });

  it("decodes UTF-8 when the flag is set", () => {
    const bytes = new TextEncoder().encode("naïve.txt");
    expect(decodeZipString(bytes.buffer, true)).toBe("naïve.txt");
    // The same bytes read as CP437 would mojibake, proving the flag matters.
    expect(decodeZipString(bytes.buffer, false)).not.toBe("naïve.txt");
  });
});

describe("long zip comments", () => {
  it("re-fetches a larger window to find the EOCD past a long comment", async () => {
    // A comment longer than the initial 128-byte EOCD window forces a re-fetch.
    const comment = "x".repeat(500);
    const zip = buildMinimalZip({ comment });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(remoteZip.files().map((f) => f.filename)).toEqual(["a.txt"]);
      expect(remoteZip.endOfCentralDirectory?.data.comment).toBe(comment);
      expect(new TextDecoder().decode(await remoteZip.fetch("a.txt"))).toBe("hi");
    } finally {
      server.close();
    }
  });
});

describe("request options", () => {
  it("rejects when the abort signal is already aborted", async () => {
    const zip = buildMinimalZip();
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      await expect(
        new RemoteZipPointer({ url, signal: AbortSignal.abort() }).populate(),
      ).rejects.toThrow();
    } finally {
      server.close();
    }
  });

  it("times out a slow server via timeoutMs", async () => {
    const zip = buildMinimalZip();
    const server = http.createServer((req, res) => {
      const t = setTimeout(() => sendBody(req, res, zip), 1000);
      req.on("close", () => clearTimeout(t));
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      await expect(new RemoteZipPointer({ url, timeoutMs: 50 }).populate()).rejects.toThrow();
    } finally {
      server.close();
    }
  });

  it("honours the instance signal even when a per-call signal is given", async () => {
    const zip = buildMinimalZip();
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    const controller = new AbortController();
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({
        url,
        signal: controller.signal,
      }).populate();
      controller.abort(); // abort via the INSTANCE signal
      await expect(
        // ...while passing an unrelated, un-aborted per-call signal
        remoteZip.fetch("a.txt", undefined, {
          signal: new AbortController().signal,
        }),
      ).rejects.toThrow();
    } finally {
      server.close();
    }
  });

  it("respects redirect: 'error'", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(302, { Location: "/elsewhere" });
      res.end();
    });
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      await expect(new RemoteZipPointer({ url, redirect: "error" }).populate()).rejects.toThrow();
    } finally {
      server.close();
    }
  });
});

/** Drain a ReadableStream into a single Uint8Array. */
async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

/**
 * Build a minimal, valid ZIP64 archive: one stored entry "a.txt" = "hi" whose
 * 32-bit size/offset fields are 0xffffffff sentinels, with the real values in
 * ZIP64 extra fields, a ZIP64 EOCD record + locator, and a regular EOCD.
 */
function buildZip64(comment = ""): Uint8Array {
  const enc = new TextEncoder();
  const name = enc.encode("a.txt");
  const data = enc.encode("hi");
  const U32 = 0xffffffff;

  // Local file header: sentinel sizes + a 20-byte ZIP64 extra (uncompressed,
  // compressed) + the stored data.
  const lfh = new Uint8Array(30 + name.length + 20 + data.length);
  const lv = new DataView(lfh.buffer);
  lv.setUint32(0, 0x504b0304); // signature
  lv.setUint16(4, 45, true); // version to extract (4.5 = zip64)
  lv.setUint32(18, U32, true); // compressed size sentinel
  lv.setUint32(22, U32, true); // uncompressed size sentinel
  lv.setUint16(26, name.length, true); // filename length
  lv.setUint16(28, 20, true); // extra field length
  lfh.set(name, 30);
  let p = 30 + name.length;
  lv.setUint16(p, 0x0001, true); // ZIP64 extra header id
  lv.setUint16(p + 2, 16, true); // extra data size
  lv.setBigUint64(p + 4, BigInt(data.length), true); // uncompressed size
  lv.setBigUint64(p + 12, BigInt(data.length), true); // compressed size
  lfh.set(data, 30 + name.length + 20);

  // Central directory: sentinel sizes + offset, with a 24-byte ZIP64 extra.
  const cd = new Uint8Array(46 + name.length + 28);
  const cv = new DataView(cd.buffer);
  cv.setUint32(0, 0x504b0102); // signature
  cv.setUint16(6, 45, true); // version to extract
  cv.setUint32(20, U32, true); // compressed size sentinel
  cv.setUint32(24, U32, true); // uncompressed size sentinel
  cv.setUint16(28, name.length, true); // filename length
  cv.setUint16(30, 28, true); // extra field length
  cv.setUint32(42, U32, true); // local header offset sentinel
  cd.set(name, 46);
  p = 46 + name.length;
  cv.setUint16(p, 0x0001, true); // ZIP64 extra header id
  cv.setUint16(p + 2, 24, true); // extra data size
  cv.setBigUint64(p + 4, BigInt(data.length), true); // uncompressed size
  cv.setBigUint64(p + 12, BigInt(data.length), true); // compressed size
  cv.setBigUint64(p + 20, 0n, true); // local header offset

  const cdOffset = lfh.length;
  const cdSize = cd.length;

  // ZIP64 EOCD record (56-byte fixed part) with the real CD offset/size/count.
  const z64 = new Uint8Array(56);
  const zv = new DataView(z64.buffer);
  zv.setUint32(0, 0x504b0606); // signature
  zv.setBigUint64(4, 44n, true); // size of record minus 12
  zv.setUint16(12, 45, true); // version made by
  zv.setUint16(14, 45, true); // version to extract
  zv.setBigUint64(24, 1n, true); // cd records on this disk
  zv.setBigUint64(32, 1n, true); // total cd records
  zv.setBigUint64(40, BigInt(cdSize), true); // cd size
  zv.setBigUint64(48, BigInt(cdOffset), true); // cd offset
  const z64Offset = cdOffset + cdSize;

  // ZIP64 EOCD locator (20 bytes), pointing at the ZIP64 EOCD record.
  const loc = new Uint8Array(20);
  const locv = new DataView(loc.buffer);
  locv.setUint32(0, 0x504b0607); // signature
  locv.setBigUint64(8, BigInt(z64Offset), true); // ZIP64 EOCD offset
  locv.setUint32(16, 1, true); // total disks

  // Regular EOCD with CD size/offset sentinels (triggers ZIP64 detection).
  const commentBytes = enc.encode(comment);
  const eocd = new Uint8Array(22 + commentBytes.length);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x504b0506); // signature
  ev.setUint16(8, 1, true); // cd records on this disk
  ev.setUint16(10, 1, true); // total cd records
  ev.setUint32(12, U32, true); // cd size sentinel
  ev.setUint32(16, U32, true); // cd offset sentinel
  ev.setUint16(20, commentBytes.length, true); // comment length
  eocd.set(commentBytes, 22);

  const parts = [lfh, cd, z64, loc, eocd];
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let o = 0;
  for (const part of parts) {
    out.set(part, o);
    o += part.length;
  }
  return out;
}

describe("ZIP64 parsers", () => {
  it("return null when the signature is absent", () => {
    expect(parseZip64EOCDLocator(new ArrayBuffer(20))).toBeNull();
    expect(parseZip64EOCD(new ArrayBuffer(56))).toBeNull();
  });

  it("parseZip64EOCD reads 64-bit central directory offset/size", () => {
    const buf = new ArrayBuffer(56);
    const dv = new DataView(buf);
    dv.setUint32(0, 0x504b0606); // signature
    dv.setBigUint64(32, 3n, true); // total cd records
    dv.setBigUint64(40, 79n, true); // cd size
    dv.setBigUint64(48, 0x1_0000_0000n, true); // cd offset > 4 GiB
    const parsed = parseZip64EOCD(buf);
    expect(parsed?.centralDirectoryRecordCount).toBe(3);
    expect(parsed?.centralDirectoryByteSize).toBe(79);
    expect(parsed?.centralDirectoryByteOffset).toBe(0x1_0000_0000);
  });
});

describe("ZIP64", () => {
  it("lists and fetches an entry from a ZIP64 archive", async () => {
    const zip = buildZip64();
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(remoteZip.files()).toEqual([expect.objectContaining({ filename: "a.txt", size: 2 })]);
      const cd = remoteZip.centralDirectoryRecords[0].data;
      expect(cd.compressedSize).toBe(2);
      expect(cd.localFileHeaderRelativeOffset).toBe(0);
      expect(new TextDecoder().decode(await remoteZip.fetch("a.txt"))).toBe("hi");
    } finally {
      server.close();
    }
  });

  it("handles a ZIP64 archive whose comment pushes the locator past the first window", async () => {
    // ~100-byte comment: the EOCD lands in the 128-byte window but the preceding
    // ZIP64 locator does not, forcing a widen (regression for a false reject).
    const zip = buildZip64("z".repeat(100));
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(remoteZip.files().map((f) => f.filename)).toEqual(["a.txt"]);
      expect(new TextDecoder().decode(await remoteZip.fetch("a.txt"))).toBe("hi");
    } finally {
      server.close();
    }
  });

  it.each([4, 6, 8, 10])("accepts a ZIP64 sentinel in regular EOCD field +%i", async (field) => {
    const zip = buildZip64();
    new DataView(zip.buffer).setUint16(zip.length - 22 + field, 0xffff, true);
    const { url, close } = await serveBuffer(zip);
    try {
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      expect(remoteZip.files().map((file) => file.filename)).toEqual(["a.txt"]);
    } finally {
      close();
    }
  });

  it.each(["locator-disk", "record-disk", "offset"] as const)(
    "rejects invalid ZIP64 %s metadata",
    async (kind) => {
      const zip = buildZip64();
      const view = new DataView(zip.buffer);
      const locatorOffset = zip.length - 22 - 20;
      const recordOffset = locatorOffset - 56;
      if (kind === "locator-disk") {
        view.setUint32(locatorOffset + 4, 1, true);
      } else if (kind === "record-disk") {
        view.setUint32(recordOffset + 16, 1, true);
      } else {
        view.setBigUint64(locatorOffset + 8, BigInt(zip.length + 100), true);
      }
      const { url, close } = await serveBuffer(zip);
      try {
        await expect(new RemoteZipPointer({ url }).populate()).rejects.toMatchObject({
          code: kind === "offset" ? "INVALID_ARCHIVE" : "UNSUPPORTED_MULTI_DISK",
        });
      } finally {
        close();
      }
    },
  );
});

describe("CRC-32 verification", () => {
  it("crc32 matches the standard check value", () => {
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
  });

  it("fetch(verifyCrc) passes for a valid entry", async () => {
    const content = new TextEncoder().encode("verify me ".repeat(50));
    const zip = buildMinimalZip({ content, deflate: true });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const out = await remoteZip.fetch("a.txt", undefined, {
        verifyCrc: true,
      });
      expect(out).toEqual(content);
    } finally {
      server.close();
    }
  });

  it("fetch(verifyCrc) throws on a CRC mismatch", async () => {
    const zip = buildMinimalZip({
      content: new TextEncoder().encode("hello"),
      crc: 0xdeadbeef,
    });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      await expect(remoteZip.fetch("a.txt", undefined, { verifyCrc: true })).rejects.toMatchObject({
        code: "CRC_MISMATCH",
      });
    } finally {
      server.close();
    }
  });

  it("fetchStream(verifyCrc) errors the stream on a CRC mismatch", async () => {
    const zip = buildMinimalZip({
      content: new TextEncoder().encode("x".repeat(2000)),
      deflate: true,
      crc: 0xdeadbeef,
    });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const stream = await remoteZip.fetchStream("a.txt", undefined, {
        verifyCrc: true,
      });
      await expect(collect(stream)).rejects.toMatchObject({
        code: "CRC_MISMATCH",
      });
    } finally {
      server.close();
    }
  });
});

describe("fetchStream", () => {
  it("streams a stored entry", async () => {
    const content = new TextEncoder().encode("a stored payload");
    const zip = buildMinimalZip({ content });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const out = await collect(await remoteZip.fetchStream("a.txt"));
      expect(new TextDecoder().decode(out)).toBe("a stored payload");
    } finally {
      server.close();
    }
  });

  it("streams and inflates a deflated entry across chunks", async () => {
    // A payload large enough that inflate emits several chunks.
    const content = new TextEncoder().encode("the quick brown fox. ".repeat(2000));
    const zip = buildMinimalZip({ content, deflate: true });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const out = await collect(await remoteZip.fetchStream("a.txt"));
      expect(out).toEqual(content);
    } finally {
      server.close();
    }
  });

  it("errors mid-stream when maxUncompressedSize is exceeded", async () => {
    const content = new TextEncoder().encode("x".repeat(100_000));
    const zip = buildMinimalZip({ content, deflate: true });
    const server = http.createServer((req, res) => sendBody(req, res, zip));
    const port = await listen(server);
    try {
      const url = new URL(`http://127.0.0.1:${port}/archive.zip`);
      const remoteZip = await new RemoteZipPointer({ url }).populate();
      const stream = await remoteZip.fetchStream("a.txt", undefined, {
        maxUncompressedSize: 1000,
      });
      await expect(collect(stream)).rejects.toMatchObject({
        name: "RemoteZipError",
        code: "DECOMPRESSION_LIMIT_EXCEEDED",
      });
    } finally {
      server.close();
    }
  });
});
