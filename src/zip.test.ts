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
import {
  parseZipDatetime,
  isZip64,
  parseOneEOCD,
  parseOneCD,
  parseAllCDs,
  parseOneLocalFile,
  RemoteZipError,
  EndOfCentralDirectory,
} from ".";

/**
 * Minimal static file server with HTTP Range support, serving files from `root`.
 * Replaces the `http-server` dev dependency (which pulled a large, vulnerable
 * transitive tree) with ~30 lines of the Node standard library. `onRequest` is
 * invoked for every request so tests can assert on forwarded headers.
 */
function createFixtureServer(
  root: string,
  onRequest: (req: http.IncomingMessage) => void,
): Server {
  return http.createServer((req, res) => {
    onRequest(req);

    // Mirror http-server: only GET/HEAD are served, everything else is 405.
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.statusCode = 405;
      res.end();
      return;
    }

    const path = (req.url ?? "").split("?")[0];
    let body: Buffer;
    try {
      body = readFileSync(join(root, path));
    } catch {
      res.statusCode = 404;
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
