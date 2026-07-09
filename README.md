# remote-zip

[API documentation](https://gyng.github.io/remote-zip)

Fetch file listings and individual files from a remote ZIP file.

## Features

Without downloading the entire ZIP:

- Fetch individual files in a remote ZIP (buffered or streaming)
- Fetch file listings
- ZIP64 archives (>4 GiB / >65,535 entries)
- Encrypted entries: traditional ZipCrypto and WinZip AES (AE-1/AE-2)
- CP437 and UTF-8 filenames; optional CRC-32 verification

The gist of what the library does is:

1. Get the content size of the ZIP file using a HTTP HEAD request.
2. Range-fetch the archive tail, widening up to the maximum EOCD comment size when needed.
3. Using the EOCD, read the central directory (CD) section with a Range request. This section contains a complete file listing and file byte offsets in the ZIP.
4. To get individual files, use another Range request with an offset to get the local file header + compressed data.

## Limitations

- PKWare _strong_ encryption (general-purpose bit 6) is detected and rejected
- Multi-disk / split archives are not supported

Range responses are validated against `Content-Range`; servers that ignore Range
requests are rejected instead of causing a whole-archive download.

> Decrypting WinZip AES entries uses the Web Crypto API (`crypto.subtle`), which
> in browsers is only available in a secure context (HTTPS or `localhost`).
> Traditional ZipCrypto works everywhere but is cryptographically weak.

## Install

```bash
npm install @gyng/remote-zip
```

```bash
yarn add @gyng/remote-zip
```

## Usage

See the [generated API documentation](https://gyng.github.io/remote-zip/).

### Server requirements (CORS & Range)

The remote server must support **HTTP Range** requests (respond `206 Partial
Content`). When used cross-origin from a browser, it must also send the right
CORS headers. The browser issues the CORS preflight (`OPTIONS`) automatically —
there is nothing to configure on the client — but the server needs to allow it:

- `Access-Control-Allow-Origin: <your origin>`
- `Access-Control-Allow-Methods: GET, HEAD` (add `POST` if you set a custom `method`)
- `Access-Control-Allow-Headers: Range` (plus `Authorization` / any custom headers you pass)
- `Access-Control-Expose-Headers: Content-Length, Content-Range` — **required**, or
  the browser hides those response headers and `populate()` cannot read the archive size

`Range` is not a CORS-safelisted request header, so any cross-origin request
triggers a preflight. Static hosts like S3, GitHub Pages, and nginx support Range
out of the box; you only need to configure the CORS headers above.

### Basic

```ts
const url = new URL("http://www.example.com/test.zip");
const remoteZip = await new RemoteZipPointer({ url }).populate();
const fileListing = remoteZip.files(); // RemoteZipFile[]
const uncompressedBytes = await remoteZip.fetch("test.txt"); // Uint8Array
```

### Streaming

For large entries, `fetchStream` returns a `ReadableStream<Uint8Array>` of the
uncompressed bytes so you can process them incrementally without buffering the
whole file. `maxUncompressedSize`, if set, is enforced mid-stream.

```ts
const stream = await remoteZip.fetchStream("big.bin");
for await (const chunk of stream) {
  // handle each chunk
}
```

### With more features

```ts
const additionalHeaders = new Headers();
additionalHeaders.append("X-Example", "foobar");
const url = new URL("http://www.example.com/test.zip");

const remoteZip = await new RemoteZipPointer({
  url,
  additionalHeaders,
  method: "POST",
  credentials: "include",
  // New request options (all optional), applied to every request:
  redirect: "error", // avoid leaking auth headers cross-origin on a 30x
  timeoutMs: 10_000, // per-request timeout
  signal: AbortSignal.timeout(30_000), // or your own AbortController signal
  requestInit: { cache: "no-store" }, // escape hatch merged into every fetch
}).populate();

// Guard untrusted archives against decompression bombs, and pass a per-call
// signal/timeout if you like:
const uncompressedBytes = await remoteZip.fetch("test.txt", additionalHeaders, {
  maxUncompressedSize: 50 * 1024 * 1024,
  verifyCrc: true, // check the decompressed bytes against the entry's CRC-32
  password: "hunter2", // for ZipCrypto / WinZip AES encrypted entries
});
```

## Dev

<details>
<summary>Dev instructions</summary>
See `scripts` in `package.json` for more scripts.

Requires Node >= 22.

```bash
npm ci            # install (reproducible, honours .npmrc cooldown)
npm run d         # watch and build
npm run t:watch   # watch and test
npm run lint      # prettier + eslint
npm run typecheck # tsc --noEmit (also checks tests)
npm run build     # type declarations + esm/cjs bundles
npm test          # run the test suite once
```

### Publish

#### Run

1. Create a new release.

   ```
   https://github.com/$YOUR_USERNAME/$YOUR_REPO_NAME/releases
   ```

   The workflow at `.github/workflows/publish.yml` publishes to npm through
   Trusted Publishing (OIDC), attests the bundles, and publishes to GitHub
   Packages. The npm package must have this repository configured as a Trusted
   Publisher.

   Don't forget to bump your version number in `package.json` before this.
   </details>

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
