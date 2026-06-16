import { RemoteZipPointer } from "./zip";

import * as http from "http";
import { Server } from "http";
import { readFileSync } from "fs";
import { join } from "path";
import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  vi,
} from "vitest";
import { deflateRaw } from "pako";
import {
  parseZipDatetime,
  isZip64,
  parseOneEOCD,
  parseOneCD,
  parseAllCDs,
  parseOneLocalFile,
  parseZip64EOCD,
  parseZip64EOCDLocator,
  RemoteZipError,
  EndOfCentralDirectory,
} from ".";

/**
 * Send `body` over HTTP with Range support (the ~30 lines of node:http + node:fs
 * that replace the http-server dev dependency). Returns 405 for non-GET/HEAD.
 */
function sendBody(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  body: Uint8Array,
): void {
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
    const end = rangeMatch[2]
      ? Math.min(Number(rangeMatch[2]), body.length - 1)
      : body.length - 1;
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
function createFixtureServer(
  root: string,
  onRequest: (req: http.IncomingMessage) => void,
): Server {
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
      await expect(remoteZip.fetch("bad")).rejects.toThrow(
        "File not found in remote ZIP: bad",
      );
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
      expect(new TextDecoder().decode(await collect(stream))).toBe(
        "Hello, world!\n",
      );
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
      expect(
        remoteZip.endOfCentralDirectory?.data.centralDirectoryByteOffset,
      ).toBe(488);
    });

    it("fetches and parses central directory records", async () => {
      const remoteZip = await new RemoteZipPointer({ url }).populate();

      expect(remoteZip.centralDirectoryRecords?.length).toBe(4);
      expect(remoteZip.centralDirectoryRecords[0].data.filename).toBe("dir/");
      expect(remoteZip.centralDirectoryRecords[1].data.filename).toBe(
        "xir/testdir.txt",
      );
      expect(remoteZip.centralDirectoryRecords[2].data.filename).toBe(
        "test.txt",
      );
      expect(remoteZip.centralDirectoryRecords[3].data.filename).toBe(
        "test-inner.zip",
      );
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
  const eocd = (
    over: Partial<EndOfCentralDirectory["data"]> = {},
  ): EndOfCentralDirectory => ({
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
    expect(isZip64(eocd({ centralDirectoryByteOffset: 0xffffffff }))).toBe(
      true,
    );
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
});

describe("RemoteZipError", () => {
  it("carries a machine-readable code", () => {
    expect(new RemoteZipError("boom").code).toBe("UNKNOWN");
    expect(new RemoteZipError("boom", "FILE_NOT_FOUND").code).toBe(
      "FILE_NOT_FOUND",
    );
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
      [...name].map((c) => c.charCodeAt(0)),
      30,
    );
    bytes.set(
      [...data].map((c) => c.charCodeAt(0)),
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
});

/**
 * Build a minimal, valid ZIP containing one entry "a.txt". Defaults to a stored
 * "hi"; pass `content`/`deflate` to vary the payload and `comment` for the EOCD.
 */
function buildMinimalZip(
  opts: { comment?: string; content?: Uint8Array; deflate?: boolean } = {},
): Uint8Array {
  const enc = new TextEncoder();
  const name = enc.encode("a.txt");
  const uncompressed = opts.content ?? enc.encode("hi");
  const data = opts.deflate ? deflateRaw(uncompressed) : uncompressed;
  const method = opts.deflate ? 8 : 0;
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
      expect(new TextDecoder().decode(await remoteZip.fetch("a.txt"))).toBe(
        "hi",
      );
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
      await expect(
        new RemoteZipPointer({ url, timeoutMs: 50 }).populate(),
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
      await expect(
        new RemoteZipPointer({ url, redirect: "error" }).populate(),
      ).rejects.toThrow();
    } finally {
      server.close();
    }
  });
});

/** Drain a ReadableStream into a single Uint8Array. */
async function collect(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
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
function buildZip64(): Uint8Array {
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
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x504b0506); // signature
  ev.setUint16(8, 1, true); // cd records on this disk
  ev.setUint16(10, 1, true); // total cd records
  ev.setUint32(12, U32, true); // cd size sentinel
  ev.setUint32(16, U32, true); // cd offset sentinel

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
      expect(remoteZip.files()).toEqual([
        expect.objectContaining({ filename: "a.txt", size: 2 }),
      ]);
      const cd = remoteZip.centralDirectoryRecords[0].data;
      expect(cd.compressedSize).toBe(2);
      expect(cd.localFileHeaderRelativeOffset).toBe(0);
      expect(new TextDecoder().decode(await remoteZip.fetch("a.txt"))).toBe(
        "hi",
      );
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
    const content = new TextEncoder().encode(
      "the quick brown fox. ".repeat(2000),
    );
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
