# Security Policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/gyng/remote-zip/security/advisories/new)
rather than opening a public issue. We aim to acknowledge reports within a few days.

## Threat model

`remote-zip` parses ZIP metadata and file contents fetched from a **remote, possibly
untrusted** origin. Treat everything the archive tells you as attacker-controlled:

- **Decompression**: a small compressed entry can inflate to a very large output (a "zip
  bomb"). `RemoteZip.fetch` accepts a `maxUncompressedSize` cap; set it when handling
  untrusted archives to bound memory use.
- **Header fields** (sizes, offsets, lengths, comments): these are validated before they
  are used to build HTTP `Range` requests or allocate buffers, but you should still set
  sane limits at the call site.
- **Entry names**: filenames are returned verbatim and may contain path-traversal
  sequences (`../`) or absolute paths. This library never writes to disk — if **you**
  extract entries to the filesystem, normalize and contain the paths yourself.
- **Credentials & redirects**: when you pass `credentials: "include"` or custom auth
  headers, be aware that following an HTTP redirect can forward them cross-origin.
  Prefer not following redirects to origins you do not control.

## Supported versions

Only the latest published version receives security fixes.
