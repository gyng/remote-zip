// https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
// https://rhardih.io/2021/04/listing-the-contents-of-a-remote-zip-archive-without-downloading-the-entire-file/

import { inflateRaw, Inflate } from "pako";
import {
  Crc32,
  crc32,
  decryptZipCrypto,
  decryptWinzipAes,
  parseAesExtra,
  CryptoError,
} from "./crypto";

export { crc32 } from "./crypto";

// ZIP file signatures
const SIG_CD = 0x504b0102;
const SIG_LOCAL_FILE_HEADER = 0x504b0304;
const SIG_EOCD = 0x504b0506;
const SIG_DATA_DESCRIPTOR = 0x504b0708;
const SIG_ZIP64_EOCD = 0x504b0606;
const SIG_ZIP64_EOCD_LOCATOR = 0x504b0607;
/** ZIP64 sentinel: a 32-bit field equal to this lives in the ZIP64 extra field. */
const ZIP64_U32_SENTINEL = 0xffffffff;
/** ZIP64 sentinel for 16-bit fields (e.g. disk numbers). */
const ZIP64_U16_SENTINEL = 0xffff;

/** Machine-readable discriminant for {@link RemoteZipError}. */
export type RemoteZipErrorCode =
  | "UNKNOWN"
  | "CONTENT_LENGTH_MISSING"
  | "INVALID_CONTENT_LENGTH"
  | "HTTP_ERROR"
  | "RANGE_NOT_SUPPORTED"
  | "RANGE_RESPONSE_MISMATCH"
  | "EOCD_NOT_FOUND"
  | "UNSUPPORTED_ZIP64"
  | "UNSUPPORTED_ENCRYPTION"
  | "FILE_NOT_FOUND"
  | "LOCAL_HEADER_PARSE_FAILED"
  | "CENTRAL_DIRECTORY_OUT_OF_BOUNDS"
  | "INVALID_ARCHIVE"
  | "TRUNCATED_ENTRY"
  | "UNSUPPORTED_COMPRESSION"
  | "UNSUPPORTED_MULTI_DISK"
  | "DECOMPRESSION_LIMIT_EXCEEDED"
  | "CRC_MISMATCH"
  | "WRONG_PASSWORD"
  | "DECRYPTION_FAILED";

export class RemoteZipError extends Error {
  /** Machine-readable error code, for programmatic handling without matching on `message`. */
  code: RemoteZipErrorCode;

  constructor(message: string, code: RemoteZipErrorCode = "UNKNOWN") {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

/** Per-call options for {@link RemoteZip.fetch} / {@link RemoteZip.fetchStream}. */
export interface EntryDecodeOptions {
  /** If set, decompression aborts and throws once output would exceed this many bytes. */
  maxUncompressedSize?: number;
  /** Aborts this request (in addition to any instance-level signal). */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** If set, verify the decompressed output against the entry's CRC-32. */
  verifyCrc?: boolean;
  /** Password for an encrypted entry (traditional ZipCrypto or WinZip AES). */
  password?: string;
}

/** Map a low-level crypto failure (only thrown by decryptWinzipAes) to a typed error. */
const mapCryptoError = (err: CryptoError): RemoteZipError => {
  switch (err.reason) {
    case "WRONG_PASSWORD":
      return new RemoteZipError("Incorrect password (AES)", "WRONG_PASSWORD");
    case "UNSUPPORTED":
      return new RemoteZipError("Unsupported AES key strength", "UNSUPPORTED_ENCRYPTION");
    default:
      return new RemoteZipError(
        "AES authentication failed (corrupt data or wrong password)",
        "DECRYPTION_FAILED",
      );
  }
};

/** Throw a typed HTTP error for a non-success response. */
const assertResponseOk = (status: number, url: URL): void => {
  if (status < 200 || status >= 300) {
    throw new RemoteZipError(
      `Could not fetch remote ZIP at ${url}: HTTP status ${status}`,
      "HTTP_ERROR",
    );
  }
};

/** Validate that a server honoured an inclusive byte-range request exactly. */
const assertRangeResponse = (
  response: Response,
  url: URL,
  expectedStart: number,
  expectedEnd: number,
  expectedTotal: number,
  shortResponseCode: RemoteZipErrorCode = "RANGE_RESPONSE_MISMATCH",
): void => {
  assertResponseOk(response.status, url);
  if (response.status !== 206) {
    throw new RemoteZipError(
      `Server did not honour Range request for ${url}: HTTP status ${response.status}`,
      "RANGE_NOT_SUPPORTED",
    );
  }
  const raw = response.headers.get("content-range");
  const match = raw?.match(/^bytes (\d+)-(\d+)\/(\d+)$/);
  if (!match) {
    throw new RemoteZipError(
      `Invalid or missing Content-Range from ${url}: ${raw ?? "missing"}`,
      "RANGE_RESPONSE_MISMATCH",
    );
  }
  const start = Number(match[1]);
  const end = Number(match[2]);
  const total = Number(match[3]);
  if (start !== expectedStart || total !== expectedTotal) {
    throw new RemoteZipError(
      `Unexpected Content-Range from ${url}: ${raw}`,
      "RANGE_RESPONSE_MISMATCH",
    );
  }
  if (end !== expectedEnd) {
    throw new RemoteZipError(
      `Truncated Range response from ${url}: expected ${expectedStart}-${expectedEnd}, got ${raw}`,
      end < expectedEnd ? shortResponseCode : "RANGE_RESPONSE_MISMATCH",
    );
  }
};

export interface EndOfCentralDirectory {
  meta: Record<string, unknown>;
  data: {
    /** End of central directory signature = 0x06054b50 */
    signature: ArrayBuffer;
    /** Number of this disk (or 0xffff for ZIP64) */
    diskNumber: number;
    /** Disk where central directory starts (or 0xffff for ZIP64) */
    cdDisk: number;
    /** Number of central directory records on this disk (or 0xffff for ZIP64) */
    centralDirectoryDiskNumber: number;
    /** Number of central directory records on this disk (or 0xffff for ZIP64) */
    centralDirectoryRecordCount: number;
    /** Size of central directory (bytes) (or 0xffffffff for ZIP64) */
    centralDirectoryByteSize: number;
    /** Offset of start of central directory, relative to start of archive (or 0xffffffff for ZIP64) */
    centralDirectoryByteOffset: number;
    /** Comment */
    comment: string;
    /** Comment length (n) */
    commentLength: number;
  };
}

export interface CentralDirectoryRecord {
  meta: {
    /** Length of the entire record */
    length: number;
  };
  data: {
    /** Central directory file header signature = 0x02014b50 */
    signature: ArrayBuffer;
    /** Version of the program this ZIP was made by.
     *
     * Upper byte:
     * - 0 - MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
     * - 1 - Amiga
     * - 2 - OpenVMS
     * - 3 - UNIX
     * - 4 - VM/CMS
     * - 5 - Atari ST
     * - 6 - OS/2 H.P.F.S.
     * - 7 - Macintosh
     * - 8 - Z-System
     * - 9 - CP/M
     * - 10 - Windows NTFS
     * - 11 - MVS (OS/390 - Z/OS)
     * - 12 - VSE
     * - 13 - Acorn Risc
     * - 14 - VFAT
     * - 15 - alternate MVS
     * - 16 - BeOS
     * - 17 - Tandem
     * - 18 - OS/400
     * - 19 - OS/X (Darwin)
     * - 20 - 255: Unused
     */
    versionMadeBy: number;
    /** Version needed to extract (minimum) */
    versionToExtract: number;
    /** General purpose bit flag
     *
     * - Bit 00: encrypted file
     * - Bit 01: compression option
     * - Bit 02: compression option
     * - Bit 03: data descriptor
     * - Bit 04: enhanced deflation
     * - Bit 05: compressed patched data
     * - Bit 06: strong encryption
     * - Bit 07-10: unused
     * - Bit 11: language encoding
     * - Bit 12: reserved
     * - Bit 13: mask header values
     * - Bit 14-15: reserved
     */
    generalPurposeBitFlag: number;
    /** Compression method; e.g. none = 0, DEFLATE = 8 (or "\0x08\0x00")
     *
     * - 00: no compression
     * - 01: shrunk
     * - 02: reduced with compression factor 1
     * - 03: reduced with compression factor 2
     * - 04: reduced with compression factor 3
     * - 05: reduced with compression factor 4
     * - 06: imploded
     * - 07: reserved
     * - 08: deflated
     * - 09: enhanced deflated
     * - 10: PKWare DCL imploded
     * - 11: reserved
     * - 12: compressed using BZIP2
     * - 13: reserved
     * - 14: LZMA
     * - 15-17: reserved
     * - 18: compressed using IBM TERSE
     * - 19: IBM LZ77 z
     * - 98: PPMd version I, Rev 1
     */
    compressionMethod: number;
    /** File last modification time (DOS) */
    lastModifiedTime: number;
    /** File last modification date (DOS) */
    lastModifiedDate: number;
    /** CRC-32 of uncompressed data
     * Value computed over file data by CRC-32 algorithm with
     * 'magic number' 0xdebb20e3 (little endian)
     */
    crc32: number;
    /** Compressed size (or 0xffffffff for ZIP64) */
    compressedSize: number;
    /** Uncompressed size (or 0xffffffff for ZIP64) */
    uncompressedSize: number;
    /** File name length (n) */
    filenameLength: number;
    /** Extra field length (m) */
    extraFieldLength: number;
    /** File comment length (k) */
    fileCommentLength: number;
    /** Disk number where file starts */
    startingDiskNumber: number;
    /** Internal file attributes
     *
     * Bit 0: apparent ASCII/text file
     * Bit 1: reserved
     * Bit 2: control field records precede logical records
     * Bits 3-16: unused
     */
    internalFileAttributes: number;
    /** External file attributes (host-system dependent) */
    externalFileAttributes: number;
    /** Relative offset of local file header.
     * This is the number of bytes between the start of the first
     * disk on which the file occurs, and the start of the local file
     * header. This allows software reading the central directory to
     * locate the position of the file inside the ZIP file. */
    localFileHeaderRelativeOffset: number;
    /** File name */
    filename: string;
    /** Extra field
     *
     * Used to store additional information. The field consistes of a sequence of
     * header and data pairs, where the header has a 2 byte identifier and a 2 byte data size field.
     */
    extraField: ArrayBuffer;
    /** File comment */
    fileComment: string;
  };
}

export interface LocalFileHeader {
  meta: {
    compressedData: ArrayBuffer;
    /** If the bit at offset 3 (0x08) of the general-purpose flags field is set,
     * then the CRC-32 and file sizes are not known when the header is written.
     * The fields in the local header are filled with zero, and the CRC-32 and size are
     * appended in a 12-byte structure (optionally preceded by a 4-byte signature) immediately
     * after the compressed data */
    dataDescriptor?: {
      /** Optional data descriptor signature = 0x08074b50 */
      optionalSignature?: ArrayBuffer;
      /** CRC-32 of uncompressed data */
      crc32: number;
      /** Compressed size */
      compressedSize: number;
      /** Uncompressed size */
      uncompressedSize: number;
    };
  };
  data: {
    /** Local file header signature = 0x04034b50 (PK♥♦ or "PK\3\4") */
    signature: ArrayBuffer;
    /** Version needed to extract (minimum) */
    versionToExtract: number;
    /** General purpose bit flag  */
    generalPurposeBitFlag: number;
    /** Compression method; e.g. none = 0, DEFLATE = 8 (or "\0x08\0x00") */
    compressionMethod: number;
    /** File last modification time (DOS format) */
    lastModifiedTime: number;
    /** File last modification date (DOS format) */
    lastModifiedDate: number;
    /** CRC-32 of uncompressed data
     * Value computed over file data by CRC-32 algorithm with
     * 'magic number' 0xdebb20e3 (little endian)
     */
    crc32: number;
    /** Compressed size (or 0xffffffff for ZIP64) */
    compressedSize: number;
    /** Uncompressed size (or 0xffffffff for ZIP64) */
    uncompressedSize: number;
    /** File name length (n) */
    filenameLength: number;
    /** Extra field length (m) */
    extraFieldLength: number;
    /** File name */
    filename: string;
    /** Extra field */
    extraField: ArrayBuffer;
  };
}

/**
 * A friendly representation of a file inside a ZIP archive
 */
export interface RemoteZipFile {
  /** Full path of the file inside the archive */
  filename: string;
  /** Size in bytes */
  size: number;
  /** ISO timestamp without timezone (ZIP/DOS does not preserve timezones) */
  modified: string;
  /** File attributes of host system */
  attributes: number;
}

/**
 * An initialised object representating a remote ZIP archive.
 *
 * Best constructed from a `RemoteZipPointer`.
 *
 * ```ts
 * import { RemoteZipPointer } from "remote-zip";
 *
 * const url = new URL("http://www.example.com/test.zip");
 * const remoteZip = await new RemoteZipPointer({ url }).populate();
 * ```
 */
export class RemoteZip {
  /** Size of the remote ZIP archive in bytes */
  contentLength: number;
  /** URL of the remote ZIP archive */
  url: URL;
  /** Records representing the files in the remote ZIP archive */
  centralDirectoryRecords: CentralDirectoryRecord[];
  /** Metadata of the remote ZIP archive */
  endOfCentralDirectory: EndOfCentralDirectory | null;
  /** HTTP method used to fetch files from the remote ZIP archive */
  method: string;
  /** Credentials passed to `fetch` when retrieving files. Defaults to `same-origin`. */
  credentials: "include" | "omit" | "same-origin";
  /** Redirect mode passed to `fetch`. Defaults to `"follow"`. */
  redirect?: RequestRedirect;
  /** Signal that aborts in-flight requests. */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Extra RequestInit merged into every `fetch`. */
  requestInit?: RequestInit;

  constructor({
    contentLength,
    url,
    centralDirectoryRecords,
    endOfCentralDirectory,
    method,
    credentials = "same-origin",
    redirect,
    signal,
    timeoutMs,
    requestInit,
  }: {
    /** Length of the remote ZIP archive in bytes */
    contentLength: number;
    /** Passed to fetch when performing a HTTP GET request for the file */
    url: URL;
    centralDirectoryRecords: CentralDirectoryRecord[];
    endOfCentralDirectory: EndOfCentralDirectory | null;
    /** Passed to fetch when performing a HTTP GET request for the file */
    method: string;
    /** Passed to fetch when performing a HTTP GET request for the file. */
    credentials?: "include" | "omit" | "same-origin";
  } & Pick<RemoteZipRequestOptions, "redirect" | "signal" | "timeoutMs" | "requestInit">) {
    this.contentLength = contentLength;
    this.url = url;
    this.method = method;
    this.centralDirectoryRecords = centralDirectoryRecords;
    this.endOfCentralDirectory = endOfCentralDirectory;
    this.credentials = credentials;
    this.redirect = redirect;
    this.signal = signal;
    this.timeoutMs = timeoutMs;
    this.requestInit = requestInit;
  }

  /** Build a fetch RequestInit from this instance's network options. */
  private requestInitFor(
    method: string,
    headers?: Headers,
    override?: { signal?: AbortSignal; timeoutMs?: number },
  ): RequestInit {
    // Combine the instance signal with any per-call signal (both can abort).
    const signals: AbortSignal[] = [];
    if (this.signal) signals.push(this.signal);
    if (override?.signal) signals.push(override.signal);
    return buildRequestInit(
      {
        credentials: this.credentials,
        redirect: this.redirect,
        signal: signals.length <= 1 ? signals[0] : AbortSignal.any(signals),
        timeoutMs: override?.timeoutMs ?? this.timeoutMs,
        requestInit: this.requestInit,
      },
      method,
      headers,
    );
  }

  /**
   * Get a formatted file listing of the remote ZIP archive.
   *
   * @returns List of files in the remote ZIP archive.
   *
   * ```ts
   * import { RemoteZipPointer } from "remote-zip";
   *
   * const url = new URL("http://www.example.com/test.zip");
   * const remoteZip = await new RemoteZipPointer({ url }).populate();
   * const files = remoteZip.files();
   * // files = [{ attributes: 1107099648, filename: "text.txt", modified: "2021-06-17T12:28:02", size: 14 }]
   * ```
   */
  public files(): RemoteZipFile[] {
    return this.centralDirectoryRecords.map((r) => ({
      filename: r.data.filename,
      size: r.data.uncompressedSize,
      modified: parseZipDatetime(r.data.lastModifiedDate, r.data.lastModifiedTime),
      attributes: r.data.externalFileAttributes,
    }));
  }

  /**
   * Gets a single uncompressed file in the remote ZIP archive.
   *
   * @param path Path of the file in the remote ZIP archive
   * @param additionalHeaders Additional headers, if any, to be passed to the `fetch` request
   * @param options.maxUncompressedSize If set, inflation aborts and throws once the
   *   decompressed output would exceed this many bytes. Set this when handling
   *   untrusted archives to guard against decompression bombs.
   * @param options.signal Aborts this request (in addition to any instance-level signal).
   * @param options.timeoutMs Per-request timeout for this fetch.
   * @param options.verifyCrc If set, verify the decompressed output against the
   *   entry's CRC-32 and throw a {@link RemoteZipError} (`CRC_MISMATCH`) on mismatch.
   * @returns Inflated (uncompressed) bytes of the requested file
   * @throws {@link RemoteZipError} if it fails to parse, fetch, or exceeds limits
   */
  public async fetch(
    path: string,
    additionalHeaders?: Headers,
    options?: EntryDecodeOptions,
  ): Promise<Uint8Array> {
    const { file, response } = await this.fetchEntryResponse(path, additionalHeaders, options);
    const localFile = parseOneLocalFile(await response.arrayBuffer(), file.data.compressedSize);
    if (!localFile) {
      throw new RemoteZipError(
        "cannot parse local file header in remote ZIP",
        "LOCAL_HEADER_PARSE_FAILED",
      );
    }
    assertLocalHeaderMatches(file, localFile);
    return this.decodeEntry(
      file,
      new Uint8Array(localFile.meta.compressedData),
      localFile.data.compressionMethod,
      options,
    );
  }

  /**
   * Decrypt (if needed), decompress, and CRC-verify one entry's bytes. Shared by
   * {@link fetch} and the encrypted path of {@link fetchStream}.
   */
  private async decodeEntry(
    file: CentralDirectoryRecord,
    compressed: Uint8Array,
    compressionMethod: number,
    options?: EntryDecodeOptions,
  ): Promise<Uint8Array> {
    let data = compressed;
    let method = compressionMethod;

    const flags = file.data.generalPurposeBitFlag;
    if (flags & 0x1) {
      if (flags & 0x40) {
        throw new RemoteZipError(
          "Strong-encrypted ZIP entries are not supported",
          "UNSUPPORTED_ENCRYPTION",
        );
      }
      if (!options?.password) {
        throw new RemoteZipError(
          `Password required for encrypted entry: ${file.data.filename}`,
          "UNSUPPORTED_ENCRYPTION",
        );
      }
      const password = new TextEncoder().encode(options.password);
      const aes = method === 99 ? parseAesExtra(file.data.extraField) : null;
      if (aes) {
        try {
          data = await decryptWinzipAes(data, password, aes.strength);
        } catch (err) {
          if (err instanceof CryptoError) throw mapCryptoError(err);
          throw new RemoteZipError(`AES decryption failed: ${String(err)}`, "DECRYPTION_FAILED");
        }
        method = aes.actualMethod;
      } else {
        const { plaintext, checkByte } = decryptZipCrypto(data, password);
        // ZipCrypto's 1-byte password check: high byte of the CRC, or of the DOS
        // mod-time when a data descriptor is used.
        const expected =
          flags & 0x8 ? (file.data.lastModifiedTime >> 8) & 0xff : (file.data.crc32 >>> 24) & 0xff;
        if (checkByte !== expected) {
          throw new RemoteZipError(
            `Incorrect password for entry: ${file.data.filename}`,
            "WRONG_PASSWORD",
          );
        }
        data = plaintext;
      }
    }

    const max = options?.maxUncompressedSize;
    let output: Uint8Array;
    if (method === 0) {
      if (max !== undefined && data.byteLength > max) {
        throw new RemoteZipError(
          `Uncompressed size exceeds maxUncompressedSize (${max} bytes)`,
          "DECOMPRESSION_LIMIT_EXCEEDED",
        );
      }
      output = data;
    } else {
      output = inflateRawCapped(data, max);
    }

    if (options?.verifyCrc) {
      const actual = crc32(output);
      if (actual !== file.data.crc32) {
        throw new RemoteZipError(
          `CRC-32 mismatch for ${file.data.filename}: expected ${file.data.crc32}, got ${actual}`,
          "CRC_MISMATCH",
        );
      }
    }

    return output;
  }

  /**
   * Like {@link fetch}, but returns a `ReadableStream` of the uncompressed bytes
   * so large entries can be processed incrementally without buffering the whole
   * file. `maxUncompressedSize` is enforced mid-stream (the stream errors with a
   * {@link RemoteZipError} once exceeded).
   *
   * ```ts
   * const stream = await remoteZip.fetchStream("big.bin");
   * for await (const chunk of stream) {
   *   // process each chunk
   * }
   * ```
   */
  public async fetchStream(
    path: string,
    additionalHeaders?: Headers,
    options?: EntryDecodeOptions,
  ): Promise<ReadableStream<Uint8Array>> {
    const { file, response } = await this.fetchEntryResponse(path, additionalHeaders, options);
    /* v8 ignore next 6 -- defensive: a 200/206 range response always has a body */
    if (!response.body) {
      throw new RemoteZipError(
        "Remote ZIP response has no body to stream",
        "LOCAL_HEADER_PARSE_FAILED",
      );
    }

    // Encrypted entries must be buffered to decrypt/authenticate (AES verifies
    // an HMAC over the whole ciphertext), so decode fully and emit as one chunk.
    if (file.data.generalPurposeBitFlag & 0x1) {
      const localFile = parseOneLocalFile(await response.arrayBuffer(), file.data.compressedSize);
      /* v8 ignore next 6 -- defensive: mirrors the tested buffered fetch() path */
      if (!localFile) {
        throw new RemoteZipError(
          "cannot parse local file header in remote ZIP",
          "LOCAL_HEADER_PARSE_FAILED",
        );
      }
      const bytes = await this.decodeEntry(
        file,
        new Uint8Array(localFile.meta.compressedData),
        localFile.data.compressionMethod,
        options,
      );
      return new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    }

    const reader = response.body.getReader();
    const entries = streamLocalFile(reader, {
      compressedSize: file.data.compressedSize,
      compressionMethod: file.data.compressionMethod,
      expectedFilename: file.data.filename,
      expectedFlags: file.data.generalPurposeBitFlag,
      maxBytes: options?.maxUncompressedSize,
      expectedCrc: options?.verifyCrc ? file.data.crc32 : undefined,
    });

    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await entries.next();
          if (done) {
            controller.close();
          } else {
            controller.enqueue(value);
          }
        } catch (err) {
          // The generator threw (bad header, inflate failure, or the
          // maxUncompressedSize cap). Releasing the consumer side via
          // controller.error() does NOT invoke cancel(), so cancel the
          // underlying network reader here or the HTTP connection leaks.
          await reader.cancel(err);
          controller.error(err);
        }
      },
      async cancel(reason) {
        await reader.cancel(reason);
      },
    });
  }

  /**
   * Find an entry, reject encrypted ones, and issue the Range request that covers
   * its local file header + compressed data. Shared by {@link fetch} and
   * {@link fetchStream}.
   */
  private async fetchEntryResponse(
    path: string,
    additionalHeaders?: Headers,
    options?: { signal?: AbortSignal; timeoutMs?: number },
  ): Promise<{ file: CentralDirectoryRecord; response: Response }> {
    const file = this.centralDirectoryRecords.find((r) => r.data.filename === path);
    if (!file) {
      throw new RemoteZipError(`File not found in remote ZIP: ${path}`, "FILE_NOT_FOUND");
    }

    assertSupportedCompression(file);
    const start = file.data.localFileHeaderRelativeOffset;
    if (start + 30 > this.contentLength) {
      throw new RemoteZipError(
        `Local file header is out of bounds for ${file.data.filename}`,
        "INVALID_ARCHIVE",
      );
    }

    // Read the fixed portion first. The two variable-length fields can each be
    // 65,535 bytes, so no fixed speculative allowance is sufficient.
    const probe = await this.fetchRange(
      start,
      start + 29,
      additionalHeaders,
      options,
      "LOCAL_HEADER_PARSE_FAILED",
    );
    const probeBytes = await probe.arrayBuffer();
    const view = new DataView(probeBytes);
    if (view.getUint32(0) !== SIG_LOCAL_FILE_HEADER) {
      throw new RemoteZipError(
        "cannot parse local file header in remote ZIP",
        "LOCAL_HEADER_PARSE_FAILED",
      );
    }
    const localFlags = view.getUint16(6, true);
    const localMethod = view.getUint16(8, true);
    if (
      localFlags !== file.data.generalPurposeBitFlag ||
      localMethod !== file.data.compressionMethod
    ) {
      throw new RemoteZipError(
        `Local header disagrees with central directory for ${file.data.filename}`,
        "INVALID_ARCHIVE",
      );
    }
    const headerLength = 30 + view.getUint16(26, true) + view.getUint16(28, true);
    const endExclusive = start + headerLength + file.data.compressedSize;
    if (endExclusive > this.contentLength) {
      throw new RemoteZipError(
        `Entry data is out of bounds for ${file.data.filename}`,
        "INVALID_ARCHIVE",
      );
    }
    const response = await this.fetchRange(
      start,
      endExclusive - 1,
      additionalHeaders,
      options,
      "TRUNCATED_ENTRY",
    );
    return { file, response };
  }

  private async fetchRange(
    start: number,
    end: number,
    additionalHeaders?: Headers,
    options?: { signal?: AbortSignal; timeoutMs?: number },
    shortResponseCode?: RemoteZipErrorCode,
  ): Promise<Response> {
    const headers = new Headers(additionalHeaders);
    headers.set("Range", `bytes=${start}-${end}`);
    const response = await fetch(
      this.url.toString(),
      this.requestInitFor(this.method, headers, options),
    );
    assertRangeResponse(response, this.url, start, end, this.contentLength, shortResponseCode);
    return response;
  }
}

const assertSupportedCompression = (file: CentralDirectoryRecord): void => {
  const { compressionMethod: method, generalPurposeBitFlag: flags } = file.data;
  if (method === 99) {
    const aes = parseAesExtra(file.data.extraField);
    if (!(flags & 0x1) || !aes) {
      throw new RemoteZipError(
        `Invalid WinZip AES metadata for ${file.data.filename}`,
        "INVALID_ARCHIVE",
      );
    }
    if (aes.actualMethod !== 0 && aes.actualMethod !== 8) {
      throw new RemoteZipError(
        `Unsupported compression method ${aes.actualMethod} for ${file.data.filename}`,
        "UNSUPPORTED_COMPRESSION",
      );
    }
    return;
  }
  if (method !== 0 && method !== 8) {
    throw new RemoteZipError(
      `Unsupported compression method ${method} for ${file.data.filename}`,
      "UNSUPPORTED_COMPRESSION",
    );
  }
};

const assertLocalHeaderMatches = (file: CentralDirectoryRecord, local: LocalFileHeader): void => {
  if (
    local.data.filename !== file.data.filename ||
    local.data.generalPurposeBitFlag !== file.data.generalPurposeBitFlag ||
    local.data.compressionMethod !== file.data.compressionMethod
  ) {
    throw new RemoteZipError(
      `Local header disagrees with central directory for ${file.data.filename}`,
      "INVALID_ARCHIVE",
    );
  }
};

/**
 * Raw-inflates `data`, aborting with a {@link RemoteZipError} if the decompressed
 * output would exceed `maxBytes`. When `maxBytes` is undefined, inflation is
 * unbounded (back-compat). Uses pako's streaming inflater so we can stop before
 * materialising the full output — the defense against decompression bombs.
 */
const inflateRawCapped = (data: Uint8Array, maxBytes?: number): Uint8Array => {
  if (maxBytes === undefined) {
    try {
      return inflateRaw(data);
    } catch (err) {
      throw new RemoteZipError(`Failed to inflate remote ZIP entry: ${String(err)}`, "UNKNOWN");
    }
  }

  const inflator = new Inflate({ raw: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  let exceeded = false;

  inflator.onData = (chunk) => {
    if (exceeded) {
      return;
    }
    const bytes = chunk as Uint8Array; // raw inflate always yields Uint8Array
    total += bytes.length;
    if (total > maxBytes) {
      exceeded = true;
      return;
    }
    chunks.push(bytes);
  };

  inflator.push(data, true);

  if (exceeded) {
    throw new RemoteZipError(
      `Decompressed size exceeds maxUncompressedSize (${maxBytes} bytes)`,
      "DECOMPRESSION_LIMIT_EXCEEDED",
    );
  }
  if (inflator.err) {
    throw new RemoteZipError(`Failed to inflate remote ZIP entry: ${inflator.msg}`, "UNKNOWN");
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

/**
 * Stream the uncompressed bytes of one entry from a Range response body: parse
 * the local file header incrementally, then either pass through (stored) or
 * raw-inflate (deflate) the `compressedSize` bytes that follow, enforcing
 * `maxBytes` mid-stream. Yields uncompressed chunks as they become available.
 */
async function* streamLocalFile(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  options: {
    compressedSize: number;
    compressionMethod: number;
    expectedFilename: string;
    expectedFlags: number;
    maxBytes?: number;
    expectedCrc?: number;
  },
): AsyncGenerator<Uint8Array> {
  const {
    compressedSize,
    compressionMethod,
    expectedFilename,
    expectedFlags,
    maxBytes,
    expectedCrc,
  } = options;
  const crc = expectedCrc !== undefined ? new Crc32() : undefined;
  let buf = new Uint8Array(0);
  const append = (chunk: Uint8Array) => {
    const next = new Uint8Array(buf.length + chunk.length);
    next.set(buf);
    next.set(chunk, buf.length);
    buf = next;
  };
  // Accumulate from the reader until `buf` holds at least `n` bytes.
  const readUntil = async (n: number): Promise<void> => {
    while (buf.length < n) {
      const { done, value } = await reader.read();
      if (done) {
        throw new RemoteZipError(
          "Truncated local file header in remote ZIP",
          "LOCAL_HEADER_PARSE_FAILED",
        );
      }
      append(value);
    }
  };

  // 1. Read and parse the local file header to locate the compressed data.
  await readUntil(30);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint32(0) !== SIG_LOCAL_FILE_HEADER) {
    throw new RemoteZipError(
      "cannot parse local file header in remote ZIP",
      "LOCAL_HEADER_PARSE_FAILED",
    );
  }
  const headerLen = 30 + dv.getUint16(26, true) + dv.getUint16(28, true);
  await readUntil(headerLen);
  const filenameLength = dv.getUint16(26, true);
  const localFilename = decodeZipString(
    buf.buffer.slice(buf.byteOffset + 30, buf.byteOffset + 30 + filenameLength),
    isUtf8Flag(expectedFlags),
  );
  if (
    dv.getUint16(6, true) !== expectedFlags ||
    dv.getUint16(8, true) !== compressionMethod ||
    localFilename !== expectedFilename
  ) {
    throw new RemoteZipError(
      `Local header disagrees with central directory for ${expectedFilename}`,
      "INVALID_ARCHIVE",
    );
  }

  // 2. Output pipeline: passthrough for stored, streaming raw inflate otherwise,
  //    with a mid-stream size cap (the decompression-bomb guard).
  let total = 0;
  const queue: Uint8Array[] = [];
  const emit = (chunk: Uint8Array) => {
    total += chunk.length;
    if (maxBytes !== undefined && total > maxBytes) {
      throw new RemoteZipError(
        `Decompressed size exceeds maxUncompressedSize (${maxBytes} bytes)`,
        "DECOMPRESSION_LIMIT_EXCEEDED",
      );
    }
    crc?.update(chunk);
    queue.push(chunk);
  };
  const inflator = compressionMethod === 0 ? undefined : new Inflate({ raw: true });
  if (inflator) {
    inflator.onData = (c) => emit(c);
  }

  let remaining = compressedSize;
  const feed = (chunk: Uint8Array) => {
    /* v8 ignore next -- a validated exact Range cannot contain bytes past the entry */
    const piece = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    remaining -= piece.length;
    if (inflator) {
      inflator.push(piece, remaining === 0);
      if (inflator.err) {
        throw new RemoteZipError(`Failed to inflate remote ZIP entry: ${inflator.msg}`, "UNKNOWN");
      }
    } else {
      emit(piece);
    }
  };

  // 3. Stream the compressed data: leftover header-window bytes first, then the
  //    rest straight from the reader.
  feed(buf.subarray(headerLen));
  yield* queue.splice(0);
  while (remaining > 0) {
    const { done, value } = await reader.read();
    if (done) break;
    feed(value);
    yield* queue.splice(0);
  }

  if (remaining !== 0) {
    throw new RemoteZipError(
      `Truncated compressed data for ${expectedFilename}`,
      "TRUNCATED_ENTRY",
    );
  }

  if (crc && crc.digest() !== expectedCrc) {
    throw new RemoteZipError(
      `CRC-32 mismatch: expected ${expectedCrc}, got ${crc.digest()}`,
      "CRC_MISMATCH",
    );
  }
}

/**
 * Network options shared by every request a {@link RemoteZip} / {@link RemoteZipPointer}
 * makes. All are optional with sensible defaults.
 */
export interface RemoteZipRequestOptions {
  /** HTTP method for the Range GET requests. The metadata probe is always a HEAD. Defaults to `"GET"`. */
  method?: string;
  /** Passed to `fetch`. Defaults to `"same-origin"`. */
  credentials?: "include" | "omit" | "same-origin";
  /**
   * Passed to `fetch`. Defaults to `"follow"`. Use `"manual"` or `"error"` to avoid
   * leaking `Authorization`/cookies cross-origin when a server responds with a redirect.
   */
  redirect?: RequestRedirect;
  /** Aborts in-flight requests when this signal fires. */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds; combined with `signal` via `AbortSignal.any`. */
  timeoutMs?: number;
  /** Escape hatch merged into every `fetch` RequestInit (lowest precedence — the options above win). */
  requestInit?: RequestInit;
}

/** Combine an optional caller signal with an optional fresh per-request timeout. */
const combineSignal = (signal?: AbortSignal, timeoutMs?: number): AbortSignal | undefined => {
  const parts: AbortSignal[] = [];
  if (signal) parts.push(signal);
  if (timeoutMs !== undefined) parts.push(AbortSignal.timeout(timeoutMs));
  if (parts.length === 0) return undefined;
  return parts.length === 1 ? parts[0] : AbortSignal.any(parts);
};

/** Build a `fetch` RequestInit from the shared options plus a per-call method/headers. */
const buildRequestInit = (
  options: Omit<RemoteZipRequestOptions, "method">,
  method: string,
  headers?: Headers,
): RequestInit => {
  // Merge requestInit.headers (the escape hatch) under our per-call Range /
  // additional headers, so e.g. an Authorization header there is preserved.
  const merged = new Headers(options.requestInit?.headers);
  if (headers) {
    headers.forEach((value, key) => merged.set(key, value));
  }
  return {
    ...options.requestInit,
    method,
    headers: merged,
    redirect: options.redirect ?? options.requestInit?.redirect ?? "follow",
    credentials: options.credentials,
    signal: combineSignal(options.signal, options.timeoutMs),
  };
};

/**
 * An uninitialised pointer to a remote ZIP file.
 *
 * No network requests are sent until `populate()` is called.
 *
 * ```ts
 * const url = new URL("http://www.example.com/test.zip");
 * const remoteZip = await new RemoteZipPointer({ url }).populate();
 * const fileListing = remoteZip.files(); // RemoteZipFile[]
 * const uncompressedBytes = await remoteZip.fetch("test.txt"); // Uint8Array
 * ```
 */
export class RemoteZipPointer {
  /** URL of the remote ZIP archive */
  url: URL;
  /** URL used when performing the HTTP HEAD request to fetch ZIP metadata */
  headUrl: URL;
  /** Additional headers, if any, passed to `fetch` when calling `url` or `headUrl` */
  additionalHeaders?: Headers;
  /** HTTP method used to fetch ZIP metadata (the initial HEAD request is always sent) */
  method: string;
  /** Credentials passed to `fetch` when retrieving files. Defaults to `same-origin`. */
  credentials: "include" | "omit" | "same-origin";
  /** Redirect mode passed to `fetch`. Defaults to `"follow"`. */
  redirect?: RequestRedirect;
  /** Signal that aborts in-flight requests. */
  signal?: AbortSignal;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Extra RequestInit merged into every `fetch`. */
  requestInit?: RequestInit;

  constructor({
    url,
    headUrl,
    additionalHeaders,
    method = "GET",
    credentials = "same-origin",
    redirect,
    signal,
    timeoutMs,
    requestInit,
  }: {
    /** URL for GET requests */
    url: URL;
    /** Passed to fetch when performing a HTTP GET request for the file */
    additionalHeaders?: Headers;
    /** Passed to fetch when performing a HTTP GET request for the file */
    method?: string;
    /** Passed to fetch when performing a HTTP GET request for the file */
    credentials?: "include" | "omit" | "same-origin";
    /** URL for HEAD request. Defaults to `url`. This can, for example, differ from `url` if you are using a signed URL for S3. */
    headUrl?: URL;
  } & Pick<RemoteZipRequestOptions, "redirect" | "signal" | "timeoutMs" | "requestInit">) {
    this.url = url;
    this.headUrl = headUrl ?? url;
    this.additionalHeaders = additionalHeaders;
    this.method = method;
    this.credentials = credentials;
    this.redirect = redirect;
    this.signal = signal;
    this.timeoutMs = timeoutMs;
    this.requestInit = requestInit;
  }

  /** Build a fetch RequestInit from this pointer's network options. */
  private requestInitFor(method: string, headers?: Headers): RequestInit {
    return buildRequestInit(
      {
        credentials: this.credentials,
        redirect: this.redirect,
        signal: this.signal,
        timeoutMs: this.timeoutMs,
        requestInit: this.requestInit,
      },
      method,
      headers,
    );
  }

  /**
   * Gets metadata about the ZIP file and constructs an initialised `RemoteZip`.
   *
   * @returns An initialised {@link RemoteZip}
   * @throws {@link RemoteZipError} if it fails to parse or fetch
   */
  public async populate(): Promise<RemoteZip> {
    const res = await fetch(
      this.headUrl.toString(),
      this.requestInitFor("HEAD", this.additionalHeaders),
    );
    assertResponseOk(res.status, this.headUrl);
    const contentLengthRaw = res.headers.get("content-length");
    if (!contentLengthRaw) {
      throw new RemoteZipError("Could not get Content-Length of URL", "CONTENT_LENGTH_MISSING");
    }
    if (!/^\d+$/.test(contentLengthRaw)) {
      throw new RemoteZipError(
        `Invalid Content-Length: ${contentLengthRaw}`,
        "INVALID_CONTENT_LENGTH",
      );
    }
    const contentLength = Number(contentLengthRaw);
    if (!Number.isSafeInteger(contentLength) || contentLength < 22) {
      throw new RemoteZipError(
        `Invalid Content-Length: ${contentLengthRaw}`,
        "INVALID_CONTENT_LENGTH",
      );
    }
    const { eocd, cdOffset, cdSize, cdCount } = await this.fetchEndOfCentralDirectory(
      contentLength,
      this.additionalHeaders,
    );
    const centralDirectoryRecords = await this.fetchCentralDirectoryRecords(
      cdOffset,
      cdSize,
      cdCount,
      contentLength,
      this.additionalHeaders,
    );

    return new RemoteZip({
      url: this.url,
      contentLength,
      endOfCentralDirectory: eocd,
      centralDirectoryRecords,
      method: this.method,
      credentials: this.credentials,
      redirect: this.redirect,
      signal: this.signal,
      timeoutMs: this.timeoutMs,
      requestInit: this.requestInit,
    });
  }

  private async fetchEndOfCentralDirectory(
    zipByteLength: number,
    additionalHeaders?: Headers,
  ): Promise<{
    eocd: EndOfCentralDirectory;
    cdOffset: number;
    cdSize: number;
    cdCount: number;
  }> {
    // The EOCD is 22 bytes plus an optional comment of up to 65535 bytes,
    // optionally preceded by a 20-byte ZIP64 locator. Try a small trailing
    // window first (the common no/short-comment case), then re-fetch the
    // maximum-size window if the signature isn't found there.
    const MAX_EOCD_BYTES = 20 + 22 + 0xffff;
    const windows = [128, MAX_EOCD_BYTES];

    for (const window of windows) {
      const offset = Math.max(0, zipByteLength - window);
      const eocdHeaders = new Headers(additionalHeaders);
      eocdHeaders.set("Range", `bytes=${offset}-${zipByteLength - 1}`);
      const eocdRes = await fetch(
        this.url.toString(),
        this.requestInitFor(this.method, eocdHeaders),
      );
      assertRangeResponse(eocdRes, this.url, offset, zipByteLength - 1, zipByteLength);

      const buffer = await eocdRes.arrayBuffer();
      const eocd = parseOneEOCD(buffer);
      if (eocd) {
        let cdOffset = eocd.data.centralDirectoryByteOffset;
        let cdSize = eocd.data.centralDirectoryByteSize;
        let cdCount = eocd.data.centralDirectoryRecordCount;

        if (
          (eocd.data.diskNumber !== 0 && eocd.data.diskNumber !== ZIP64_U16_SENTINEL) ||
          (eocd.data.cdDisk !== 0 && eocd.data.cdDisk !== ZIP64_U16_SENTINEL) ||
          (eocd.data.centralDirectoryDiskNumber !== cdCount &&
            eocd.data.centralDirectoryDiskNumber !== ZIP64_U16_SENTINEL &&
            cdCount !== ZIP64_U16_SENTINEL)
        ) {
          throw new RemoteZipError(
            "Multi-disk ZIP archives are not supported",
            "UNSUPPORTED_MULTI_DISK",
          );
        }

        // ZIP64: the real CD offset/size live in the ZIP64 EOCD record, located
        // via the ZIP64 EOCD locator (the 20 bytes preceding the EOCD).
        if (isZip64(eocd)) {
          const locator = parseZip64EOCDLocator(buffer);
          if (!locator) {
            // With a long comment the EOCD can land in this window while the
            // preceding locator does not. Widen to the next window and retry;
            // only fail if even the widest (whole-file) window lacks it.
            if (window !== windows[windows.length - 1] && offset > 0) {
              continue;
            }
            throw new RemoteZipError("ZIP64 EOCD locator not found", "UNSUPPORTED_ZIP64");
          }
          if (locator.diskWithZip64EOCD !== 0 || locator.totalDisks !== 1) {
            throw new RemoteZipError(
              "Multi-disk ZIP archives are not supported",
              "UNSUPPORTED_MULTI_DISK",
            );
          }
          const z64 = await this.fetchZip64EOCD(
            locator.zip64EOCDOffset,
            zipByteLength,
            additionalHeaders,
          );
          if (
            z64.diskNumber !== 0 ||
            z64.cdDisk !== 0 ||
            z64.centralDirectoryDiskRecordCount !== z64.centralDirectoryRecordCount
          ) {
            throw new RemoteZipError(
              "Multi-disk ZIP archives are not supported",
              "UNSUPPORTED_MULTI_DISK",
            );
          }
          cdOffset = z64.centralDirectoryByteOffset;
          cdSize = z64.centralDirectoryByteSize;
          cdCount = z64.centralDirectoryRecordCount;
        }

        // The central directory must lie within the archive. Reject out-of-bounds
        // offsets/sizes before we use them to build a Range request.
        if (cdOffset + cdSize > zipByteLength) {
          throw new RemoteZipError(
            `Central directory is out of bounds (offset ${cdOffset}, size ${cdSize}, archive ${zipByteLength} bytes)`,
            "CENTRAL_DIRECTORY_OUT_OF_BOUNDS",
          );
        }

        return { eocd, cdOffset, cdSize, cdCount };
      }

      // Not found in this window. If we already fetched from the start of the
      // file, a larger window cannot help.
      if (offset === 0) break;
    }

    throw new RemoteZipError("Could not get EOCD record of remote ZIP", "EOCD_NOT_FOUND");
  }

  private async fetchZip64EOCD(
    offset: number,
    zipByteLength: number,
    additionalHeaders?: Headers,
  ): Promise<Zip64EndOfCentralDirectory> {
    if (offset + 56 > zipByteLength) {
      throw new RemoteZipError("ZIP64 EOCD offset is out of bounds", "INVALID_ARCHIVE");
    }
    const headers = new Headers(additionalHeaders);
    // The fixed part of the ZIP64 EOCD record is 56 bytes.
    headers.set("Range", `bytes=${offset}-${offset + 55}`);
    const res = await fetch(this.url.toString(), this.requestInitFor(this.method, headers));
    assertRangeResponse(res, this.url, offset, offset + 55, zipByteLength);
    const z64 = parseZip64EOCD(await res.arrayBuffer());
    if (!z64) {
      throw new RemoteZipError("ZIP64 EOCD record not found", "UNSUPPORTED_ZIP64");
    }
    return z64;
  }

  private async fetchCentralDirectoryRecords(
    cdOffset: number,
    cdSize: number,
    cdCount: number,
    zipByteLength: number,
    additionalHeaders?: Headers,
  ): Promise<CentralDirectoryRecord[]> {
    if (cdSize === 0) {
      if (cdCount !== 0) {
        throw new RemoteZipError(
          "Central directory record count does not match its size",
          "INVALID_ARCHIVE",
        );
      }
      return [];
    }
    const cdHeaders = new Headers(additionalHeaders);
    cdHeaders.set("Range", `bytes=${cdOffset}-${cdOffset + cdSize - 1}`);
    const cdRes = await fetch(this.url.toString(), this.requestInitFor(this.method, cdHeaders));
    assertRangeResponse(cdRes, this.url, cdOffset, cdOffset + cdSize - 1, zipByteLength);
    const cdBuffer = await cdRes.arrayBuffer();
    const records = parseAllCDs(cdBuffer);
    if (records.length !== cdCount) {
      throw new RemoteZipError(
        `Central directory contains ${records.length} records; expected ${cdCount}`,
        "INVALID_ARCHIVE",
      );
    }
    if (records.some((record) => record.data.startingDiskNumber !== 0)) {
      throw new RemoteZipError(
        "Multi-disk ZIP archives are not supported",
        "UNSUPPORTED_MULTI_DISK",
      );
    }
    return records;
  }
}

/**
 * Parses DOS datetime into an ISO string without timezone.
 *
 * @param zipDate DOS date format
 * @param zipTime DOS time format
 * @returns An ISO datetime without timezone. Defaults to `"1980-01-01T00:00:00"` if the datetime is invalid
 * @see https://github.com/Stuk/jszip/blob/112fcdb9953c6b9a2744afee451d73029f7cd2f8/lib/reader/DataReader.js#L105
 */
export const parseZipDatetime = (zipDate: number, zipTime: number): string => {
  const day = zipDate & 0x1f || 1;
  const month = (zipDate >> 5) & 0x0f || 1;
  const year = ((zipDate >> 9) & 0x7f) + 1980;
  const hour = (zipTime >> 11) & 0x1f;
  const minute = (zipTime >> 5) & 0x3f;
  const second = (zipTime & 0x1f) << 1;

  const pad = (num: number): string => num.toString().padStart(2, "0");

  // ZIP doesn't have timezones, but JS parses it as UTC with `new Date`.
  // Manually construct an ISO timestamp without timezone to represent this.
  const stringFormat = `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(
    minute,
  )}:${pad(second)}`;

  // Date.parse returns NaN (it never throws) for invalid component values such
  // as month 13 or second 62, both of which the DOS bit layout can produce.
  if (Number.isNaN(Date.parse(stringFormat))) {
    return parseZipDatetime(0, 0);
  }

  return stringFormat;
};

/**
 * Detects whether an EOCD record points at ZIP64 structures this library does
 * not parse yet. Any ZIP64 sentinel value (`0xffff` for 16-bit fields,
 * `0xffffffff` for 32-bit fields) means the real value lives in a ZIP64 EOCD.
 */
export const isZip64 = (eocd: EndOfCentralDirectory): boolean =>
  eocd.data.diskNumber === ZIP64_U16_SENTINEL ||
  eocd.data.cdDisk === ZIP64_U16_SENTINEL ||
  eocd.data.centralDirectoryDiskNumber === ZIP64_U16_SENTINEL ||
  eocd.data.centralDirectoryRecordCount === ZIP64_U16_SENTINEL ||
  eocd.data.centralDirectoryByteSize === ZIP64_U32_SENTINEL ||
  eocd.data.centralDirectoryByteOffset === ZIP64_U32_SENTINEL;

/** Effective central-directory location from a ZIP64 End Of Central Directory record. */
export interface Zip64EndOfCentralDirectory {
  diskNumber: number;
  cdDisk: number;
  centralDirectoryDiskRecordCount: number;
  centralDirectoryRecordCount: number;
  centralDirectoryByteSize: number;
  centralDirectoryByteOffset: number;
}

/**
 * Read a little-endian 64-bit unsigned int as a JS number, rejecting values
 * beyond `Number.MAX_SAFE_INTEGER` (≈8 PB — far past any real archive).
 */
const readUint64 = (view: DataView, offset: number): number => {
  const value = view.getBigUint64(offset, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RemoteZipError(
      `ZIP64 value ${value} exceeds Number.MAX_SAFE_INTEGER`,
      "UNSUPPORTED_ZIP64",
    );
  }
  return Number(value);
};

/**
 * Parse the ZIP64 extra field (header id 0x0001) from an entry's extra-field
 * bytes. Only the fields whose 32-bit value was the sentinel are present, in the
 * fixed order: uncompressed size, compressed size, local-header offset, disk.
 */
const parseZip64Extra = (
  extra: ArrayBuffer,
  need: {
    uncompressed: boolean;
    compressed: boolean;
    offset: boolean;
    disk: boolean;
  },
): {
  uncompressedSize?: number;
  compressedSize?: number;
  localHeaderOffset?: number;
  diskStart?: number;
} => {
  const view = new DataView(extra);
  for (let p = 0; p + 4 <= extra.byteLength;) {
    const headerId = view.getUint16(p, true);
    const size = view.getUint16(p + 2, true);
    const dataStart = p + 4;
    const dataEnd = dataStart + size;
    if (dataEnd > extra.byteLength) {
      throw new RemoteZipError("Truncated ZIP extra field", "INVALID_ARCHIVE");
    }
    if (headerId === 0x0001) {
      const result: {
        uncompressedSize?: number;
        compressedSize?: number;
        localHeaderOffset?: number;
        diskStart?: number;
      } = {};
      let q = dataStart;
      const required =
        (need.uncompressed ? 8 : 0) +
        (need.compressed ? 8 : 0) +
        (need.offset ? 8 : 0) +
        (need.disk ? 4 : 0);
      if (size < required) {
        throw new RemoteZipError("ZIP64 extra field is missing required values", "INVALID_ARCHIVE");
      }
      if (need.uncompressed) {
        result.uncompressedSize = readUint64(view, q);
        q += 8;
      }
      if (need.compressed) {
        result.compressedSize = readUint64(view, q);
        q += 8;
      }
      if (need.offset) {
        result.localHeaderOffset = readUint64(view, q);
        q += 8;
      }
      if (need.disk) {
        result.diskStart = view.getUint32(q, true);
      }
      return result;
    }
    p = dataEnd;
  }
  throw new RemoteZipError("ZIP64 sentinel has no ZIP64 extra field", "INVALID_ARCHIVE");
};

/** Locate the ZIP64 EOCD locator in a tail buffer and return the ZIP64 EOCD offset. */
export const parseZip64EOCDLocator = (
  buffer: ArrayBuffer,
): {
  diskWithZip64EOCD: number;
  zip64EOCDOffset: number;
  totalDisks: number;
} | null => {
  const view = new DataView(buffer);
  for (let i = buffer.byteLength - 20; i >= 0; i -= 1) {
    if (view.getUint32(i) === SIG_ZIP64_EOCD_LOCATOR) {
      return {
        diskWithZip64EOCD: view.getUint32(i + 4, true),
        zip64EOCDOffset: readUint64(view, i + 8),
        totalDisks: view.getUint32(i + 16, true),
      };
    }
  }
  return null;
};

/** Parse a ZIP64 End Of Central Directory record (the real CD offset/size/count). */
export const parseZip64EOCD = (buffer: ArrayBuffer): Zip64EndOfCentralDirectory | null => {
  const view = new DataView(buffer);
  for (let i = 0; i <= buffer.byteLength - 56; i += 1) {
    if (view.getUint32(i) === SIG_ZIP64_EOCD) {
      return {
        diskNumber: view.getUint32(i + 16, true),
        cdDisk: view.getUint32(i + 20, true),
        centralDirectoryDiskRecordCount: readUint64(view, i + 24),
        centralDirectoryRecordCount: readUint64(view, i + 32),
        centralDirectoryByteSize: readUint64(view, i + 40),
        centralDirectoryByteOffset: readUint64(view, i + 48),
      };
    }
  }
  return null;
};

// CP437 (the historical ZIP code page) high half, 0x80–0xFF, as Unicode.
// oxfmt-ignore
const CP437_HIGH = String.fromCharCode(
  0xc7, 0xfc, 0xe9, 0xe2, 0xe4, 0xe0, 0xe5, 0xe7, 0xea, 0xeb, 0xe8, 0xef, 0xee, 0xec, 0xc4, 0xc5,
  0xc9, 0xe6, 0xc6, 0xf4, 0xf6, 0xf2, 0xfb, 0xf9, 0xff, 0xd6, 0xdc, 0xa2, 0xa3, 0xa5, 0x20a7, 0x192,
  0xe1, 0xed, 0xf3, 0xfa, 0xf1, 0xd1, 0xaa, 0xba, 0xbf, 0x2310, 0xac, 0xbd, 0xbc, 0xa1, 0xab, 0xbb,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
  0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
  0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
  0x3b1, 0xdf, 0x393, 0x3c0, 0x3a3, 0x3c3, 0xb5, 0x3c4, 0x3a6, 0x398, 0x3a9, 0x3b4, 0x221e, 0x3c6, 0x3b5, 0x2229,
  0x2261, 0xb1, 0x2265, 0x2264, 0x2320, 0x2321, 0xf7, 0x2248, 0xb0, 0x2219, 0xb7, 0x221a, 0x207f, 0xb2, 0x25a0, 0xa0,
);

/**
 * Decode a ZIP filename/comment. ZIP entries use CP437 unless general-purpose
 * bit 11 marks the field as UTF-8; ASCII is identical in both.
 */
export const decodeZipString = (bytes: ArrayBuffer, utf8: boolean): string => {
  if (utf8) {
    return new TextDecoder().decode(bytes);
  }
  let out = "";
  for (const b of new Uint8Array(bytes)) {
    out += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80];
  }
  return out;
};

/** General-purpose bit 11 marks filename/comment fields as UTF-8. */
const isUtf8Flag = (generalPurposeBitFlag: number): boolean =>
  Boolean((generalPurposeBitFlag >> 11) & 1);

export const parseAllCDs = (buffer: ArrayBuffer): CentralDirectoryRecord[] => {
  const cds: CentralDirectoryRecord[] = [];
  const view = new DataView(buffer);

  let offset = 0;
  while (offset + 4 <= buffer.byteLength) {
    const signature = view.getUint32(offset);
    if (signature === SIG_EOCD) break;
    if (signature !== SIG_CD) {
      throw new RemoteZipError(
        `Unexpected data in central directory at offset ${offset}`,
        "INVALID_ARCHIVE",
      );
    }
    const cd = parseOneCD(buffer.slice(offset));
    if (!cd) {
      throw new RemoteZipError(
        `Truncated central directory record at offset ${offset}`,
        "INVALID_ARCHIVE",
      );
    }
    cds.push(cd);
    offset += cd.meta.length;
  }
  if (
    offset !== buffer.byteLength &&
    (offset + 4 > buffer.byteLength || view.getUint32(offset) !== SIG_EOCD)
  ) {
    throw new RemoteZipError("Truncated central directory", "INVALID_ARCHIVE");
  }

  return cds;
};

export const parseOneCD = (buffer: ArrayBuffer): CentralDirectoryRecord | null => {
  const MIN_CD_LENGTH = 46;

  const view = new DataView(buffer);

  // Seek to start of central directory
  for (let i = 0; i <= buffer.byteLength - MIN_CD_LENGTH; i += 1) {
    if (view.getInt32(i) === SIG_CD) {
      const filenameLength = view.getUint16(i + 28, true); // n
      const extraFieldLength = view.getUint16(i + 30, true); // m
      const fileCommentLength = view.getUint16(i + 32, true); // k
      const recordLength = 46 + filenameLength + extraFieldLength + fileCommentLength;
      if (i + recordLength > buffer.byteLength) {
        throw new RemoteZipError("Truncated central directory record", "INVALID_ARCHIVE");
      }

      const rawCompressedSize = view.getUint32(i + 20, true);
      const rawUncompressedSize = view.getUint32(i + 24, true);
      const rawDisk = view.getUint16(i + 34, true);
      const rawOffset = view.getUint32(i + 42, true);
      const extraField = buffer.slice(
        i + 46 + filenameLength,
        i + 46 + filenameLength + extraFieldLength,
      );

      // ZIP64: any 0xffffffff / 0xffff field has its real value in the extra.
      const need = {
        uncompressed: rawUncompressedSize === ZIP64_U32_SENTINEL,
        compressed: rawCompressedSize === ZIP64_U32_SENTINEL,
        offset: rawOffset === ZIP64_U32_SENTINEL,
        disk: rawDisk === ZIP64_U16_SENTINEL,
      };
      const z64 =
        need.uncompressed || need.compressed || need.offset || need.disk
          ? parseZip64Extra(extraField, need)
          : {};

      const utf8 = isUtf8Flag(view.getUint16(i + 8, true));

      return {
        meta: {
          length: recordLength,
        },
        data: {
          signature: buffer.slice(i, i + 4),
          versionMadeBy: view.getUint16(i + 4, true),
          versionToExtract: view.getUint16(i + 6, true),
          generalPurposeBitFlag: view.getUint16(i + 8, true),
          compressionMethod: view.getUint16(i + 10, true),
          lastModifiedTime: view.getUint16(i + 12, true),
          lastModifiedDate: view.getUint16(i + 14, true),
          crc32: view.getUint32(i + 16, true),
          compressedSize: z64.compressedSize ?? rawCompressedSize,
          uncompressedSize: z64.uncompressedSize ?? rawUncompressedSize,
          filenameLength,
          extraFieldLength,
          fileCommentLength,
          startingDiskNumber: z64.diskStart ?? rawDisk,
          internalFileAttributes: view.getUint16(i + 36, true),
          externalFileAttributes: view.getUint32(i + 38, true),
          localFileHeaderRelativeOffset: z64.localHeaderOffset ?? rawOffset,
          filename: decodeZipString(buffer.slice(i + 46, i + 46 + filenameLength), utf8),
          extraField,
          fileComment: decodeZipString(
            buffer.slice(
              i + 46 + filenameLength + extraFieldLength,
              i + 46 + filenameLength + extraFieldLength + fileCommentLength,
            ),
            utf8,
          ),
        },
      };
    }
  }

  return null;
};

export const parseOneEOCD = (buffer: ArrayBuffer): EndOfCentralDirectory | null => {
  const MIN_EOCD_LENGTH = 22;

  const view = new DataView(buffer);
  const decoder = new TextDecoder();

  // The real EOCD is the LAST occurrence of the signature in the file — a zip
  // comment can legitimately contain bytes that look like the signature — so
  // scan backwards from the end of the buffer and return the first hit.
  for (let i = buffer.byteLength - MIN_EOCD_LENGTH; i >= 0; i -= 1) {
    if (view.getUint32(i) === SIG_EOCD) {
      const commentLength = view.getUint16(i + 20, true);
      if (i + MIN_EOCD_LENGTH + commentLength !== buffer.byteLength) {
        continue;
      }

      // https://en.wikipedia.org/wiki/ZIP_(file_format)#End_of_central_directory_record_(EOCD)
      return {
        meta: {},
        data: {
          signature: buffer.slice(i, i + 4),
          diskNumber: view.getUint16(i + 4, true),
          cdDisk: view.getUint16(i + 6, true),
          centralDirectoryDiskNumber: view.getUint16(i + 8, true),
          centralDirectoryRecordCount: view.getUint16(i + 10, true),
          centralDirectoryByteSize: view.getUint32(i + 12, true),
          centralDirectoryByteOffset: view.getUint32(i + 16, true),
          commentLength: commentLength,
          comment: decoder.decode(buffer.slice(i + 22, i + 22 + commentLength)),
        },
      };
    }
  }

  return null;
};

export const parseOneLocalFile = (
  buffer: ArrayBuffer,
  /** Sometimes, the local header does not have the compressed size and a data descriptor is used after the compressed data.
   * If provided, will be used if the local header indicates a data descriptor block.
   * It is used to find the correct offset for the data descriptor. */
  compressedSizeOverride = 0,
): LocalFileHeader | null => {
  const MIN_LOCAL_FILE_LENGTH = 30;

  const view = new DataView(buffer);

  // Seek to first local file
  for (let i = 0; i <= buffer.byteLength - MIN_LOCAL_FILE_LENGTH; i += 1) {
    if (view.getUint32(i) === SIG_LOCAL_FILE_HEADER) {
      const filenameLength = view.getUint16(i + 26, true); // n
      const extraFieldLength = view.getUint16(i + 28, true); // m

      const bitflags = view.getUint16(i + 6, true);
      const hasDataDescriptor = Boolean((bitflags >> 3) & 1);

      const headerEndOffset = i + 30 + filenameLength + extraFieldLength;
      if (headerEndOffset > buffer.byteLength) {
        throw new RemoteZipError("Truncated local file header", "INVALID_ARCHIVE");
      }
      const rawCompressedSize = view.getUint32(i + 18, true);
      const rawUncompressedSize = view.getUint32(i + 22, true);

      // ZIP64: resolve sentinel sizes from the local header's extra field.
      const localExtra = buffer.slice(i + 30 + filenameLength, headerEndOffset);
      const z64Need = {
        uncompressed: rawUncompressedSize === ZIP64_U32_SENTINEL,
        compressed: rawCompressedSize === ZIP64_U32_SENTINEL,
        offset: false,
        disk: false,
      };
      const z64 =
        z64Need.uncompressed || z64Need.compressed ? parseZip64Extra(localExtra, z64Need) : {};
      const regularCompressedSize = z64.compressedSize ?? rawCompressedSize;
      const uncompressedSize = z64.uncompressedSize ?? rawUncompressedSize;

      const compressedSize = hasDataDescriptor ? compressedSizeOverride : regularCompressedSize;
      const dataEndOffset = headerEndOffset + compressedSize;
      if (dataEndOffset > buffer.byteLength) {
        throw new RemoteZipError("Truncated local file data", "TRUNCATED_ENTRY");
      }

      const hasOptionalSignature =
        hasDataDescriptor &&
        dataEndOffset + 4 <= buffer.byteLength &&
        view.getUint32(dataEndOffset) === SIG_DATA_DESCRIPTOR;
      const optionalSignatureOffset = hasOptionalSignature ? 4 : 0;
      const descriptorOffset = dataEndOffset + optionalSignatureOffset;
      const hasCompleteDescriptor = hasDataDescriptor && descriptorOffset + 12 <= buffer.byteLength;

      return {
        meta: {
          dataDescriptor: hasCompleteDescriptor
            ? {
                optionalSignature: hasOptionalSignature
                  ? buffer.slice(dataEndOffset, dataEndOffset + optionalSignatureOffset)
                  : undefined,
                crc32: view.getUint32(descriptorOffset, true),
                compressedSize: view.getUint32(descriptorOffset + 4, true),
                uncompressedSize: view.getUint32(descriptorOffset + 8, true),
              }
            : undefined,
          compressedData: hasDataDescriptor
            ? buffer.slice(headerEndOffset, dataEndOffset)
            : buffer.slice(headerEndOffset, headerEndOffset + regularCompressedSize),
        },
        data: {
          signature: buffer.slice(i, i + 4),
          versionToExtract: view.getUint16(i + 4, true),
          generalPurposeBitFlag: view.getUint16(i + 6, true),
          compressionMethod: view.getUint16(i + 8, true),
          lastModifiedTime: view.getUint16(i + 10, true),
          lastModifiedDate: view.getUint16(i + 12, true),
          crc32: view.getUint32(i + 14, true),
          compressedSize: regularCompressedSize,
          uncompressedSize,
          filenameLength,
          extraFieldLength,
          filename: decodeZipString(
            buffer.slice(i + 30, i + 30 + filenameLength),
            isUtf8Flag(bitflags),
          ),
          extraField: localExtra,
        },
      };
    }
  }

  return null;
};
