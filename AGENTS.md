# AGENTS.md

Guidance for agents and humans working in this repository. Read this before making
changes. It encodes how we want code written here, not just what the code does.

## What this project is

`@gyng/remote-zip` lists and fetches **individual files from a remote ZIP over HTTP
Range requests, without downloading the whole archive**. It runs in both Node (>=18)
and the browser. The whole library is intentionally small — keep it that way.

The mechanism:

1. `HEAD` to get the archive's `Content-Length`.
2. Range-fetch the tail to read the End Of Central Directory (EOCD) record.
3. Range-fetch the Central Directory (CD) — the file listing + per-file byte offsets.
4. Range-fetch a single local file header + its compressed bytes, then inflate.

## Core engineering principles

These are the bar for any change. A change that ignores them is incomplete.

### 1. Concentric (onion) design — keep the core pure

Picture the code as concentric rings. The **inner ring is pure**: byte-buffer parsers
(`parseOneEOCD`, `parseOneCD`, `parseAllCDs`, `parseOneLocalFile`, `parseZipDatetime`)
take bytes in and return data out — no `fetch`, no clock, no globals, no I/O. The
**outer ring is the shell**: `RemoteZipPointer`/`RemoteZip` do the HTTP and orchestrate.

Dependencies point inward only. The shell may call the core; the core must never reach
outward for I/O. When adding a feature, ask "is this parsing (inner) or I/O (outer)?"
and put it in the right ring. This is what makes the parsers unit-testable from a raw
`ArrayBuffer` with zero network, and it's why ZIP64 / streaming / encryption work
should land as pure-core additions wherever possible.

### 2. Test-driven development

Write the failing test first, then the code that makes it pass, then refactor.

- Bug fixes start with a **red test that reproduces the bug** against a known byte
  layout, then the fix turns it green. No fix lands without the test that would have
  caught it.
- Prefer fast **unit tests on the pure core** (hand-built `ArrayBuffer`s / fixtures)
  over slow integration tests through the network shell. Reach for an integration test
  only when you're exercising the shell itself.
- Every documented limitation that we _reject_ (ZIP64, encrypted entries, oversized
  comments) deserves a test asserting the clean, typed rejection.

### 3. Type honesty

The public types must not lie about runtime. If a function can return a `Uint8Array`,
it must not be typed `Promise<ArrayBuffer>`. Keep `strict` on; do not weaken
`noImplicitAny`. Annotate public surfaces explicitly — they ship in the `.d.ts`.

### 4. Never trust the archive

Header fields (sizes, offsets, lengths, comments, filenames) come from an
attacker-influenceable source. Validate before you allocate or before you build a
Range header. Cap decompression output. Bounds-check offsets against `Content-Length`.
Decoded filenames are untrusted data — never feed them to a filesystem sink without the
caller opting in. See `SECURITY.md`.

### 5. Small, reviewable, green commits

- One concern per commit; keep the tree green (`build` + `lint` + `test`) at each one.
- Mechanical churn (a formatter bump, a mass rename) goes in its **own** commit,
  separate from behavioural change, so diffs stay reviewable.
- Don't mix a dependency upgrade with a logic fix.

### 6. Leave the campsite cleaner

Match the surrounding style. Delete dead code rather than commenting it out. If you find
a `TODO` you can close cheaply while you're in the file, close it. Prefer clarity over
cleverness — this is a parser; correctness and readability beat micro-optimization.

## Commands

```bash
yarn build     # type-declarations (tsc) + esbuild esm/cjs bundles into lib/
yarn test      # run the test suite
yarn lint      # prettier --check + eslint
yarn lint:fix  # auto-fix formatting + lint
```

Always run `build`, `lint`, and `test` before considering a change done.

## Code style & conventions

- TypeScript, `strict`. Formatting is owned by Prettier — never hand-format; run
  `yarn lint:fix`. ESLint config is the source of truth for lint rules.
- Parsers read with `DataView`; use the **correct endianness** (ZIP integer fields are
  little-endian) and **unsigned** reads for sizes/offsets. Comment any non-obvious byte
  offset with the field it maps to.
- Throw `RemoteZipError` (never a bare `Error`) for every expected failure so callers
  can catch one type. Prefer a discriminating `code` over message-string matching.
- Keep the dependency footprint minimal. A new runtime dependency needs justification;
  the platform (`fetch`, `TextDecoder`, `DataView`) usually already has what you need.

## Architecture map

| File              | Ring | Responsibility                                                |
| ----------------- | ---- | ------------------------------------------------------------- |
| `src/zip.ts`      | both | All logic. Pure parsers + the `RemoteZip*` I/O classes.       |
| `src/index.ts`    | —    | Public barrel; re-exports `./zip`. The package's API surface. |
| `src/zip.test.ts` | —    | Tests. Integration (via a local HTTP server) + parser units.  |
| `fixtures/`       | —    | Test archives. Add new fixtures here for new ZIP shapes.      |

If `src/zip.ts` grows, split it along the ring boundary (`parse.ts` pure core vs
`remote.ts` shell) rather than by accident.

## Definition of done

- [ ] A test that fails without your change and passes with it.
- [ ] `yarn build && yarn lint && yarn test` all green.
- [ ] Public types match runtime behaviour; no new `any` / `@ts-expect-error`.
- [ ] Untrusted input is validated/bounded.
- [ ] One concern per commit; README/JSDoc updated if behaviour changed.
